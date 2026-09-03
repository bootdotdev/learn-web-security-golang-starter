package httpserver

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/auth/passwords"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

const totpLoginChallengeCookieName = "totp_login_challenge"

type totpLoginPage struct {
	templates.Page
	Error    string
	ReturnTo string
}

type recoveryPage struct {
	templates.Page
	Error string
}

type passwordResetRequestPage struct {
	templates.Page
	Error            string
	ShowConfirmation bool
	ResetLink        string
}

type passwordResetPage struct {
	templates.Page
	Error string
	Token string
	Email string
}

func (handler *authHandler) TOTPLoginPage(responseWriter http.ResponseWriter, request *http.Request) {
	challengeToken := totpLoginChallengeToken(request)
	if challengeToken == "" {
		clearTOTPLoginChallengeCookie(responseWriter)
		http.Redirect(responseWriter, request, "/login", http.StatusFound)
		return
	}
	challenge, found, err := handler.mfa.Challenge(request.Context(), challengeToken)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		clearTOTPLoginChallengeCookie(responseWriter)
		http.Redirect(responseWriter, request, verificationRestartLoginPath("/"), http.StatusFound)
		return
	}
	user, userFound, err := handler.accounts.FindUserByID(request.Context(), challenge.UserID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !userFound || !user.HasTOTP {
		if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		clearTOTPLoginChallengeCookie(responseWriter)
		http.Redirect(responseWriter, request, verificationRestartLoginPath("/"), http.StatusFound)
		return
	}
	if err := handler.renderTOTPLogin(responseWriter, http.StatusOK, challenge.ReturnTo, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) TOTPLogin(responseWriter http.ResponseWriter, request *http.Request) {
	requestedReturnTo, err := httpx.FormValue(request, "returnTo")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	requestedReturnTo = safeReturnTo(requestedReturnTo)
	challengeToken := totpLoginChallengeToken(request)
	challenge, found, err := handler.mfa.Challenge(request.Context(), challengeToken)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if challengeToken == "" || !found {
		clearTOTPLoginChallengeCookie(responseWriter)
		http.Redirect(responseWriter, request, verificationRestartLoginPath(requestedReturnTo), http.StatusFound)
		return
	}
	user, userFound, err := handler.accounts.FindUserByID(request.Context(), challenge.UserID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	secret, secretFound, err := handler.mfa.Secret(request.Context(), challenge.UserID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !userFound || !secretFound {
		if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		clearTOTPLoginChallengeCookie(responseWriter)
		http.Redirect(responseWriter, request, verificationRestartLoginPath(challenge.ReturnTo), http.StatusFound)
		return
	}
	mfaCode, err := httpx.FormValue(request, "mfaCode")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	verified, err := handler.mfa.VerifyAndConsume(request.Context(), user.ID, strings.TrimSpace(mfaCode), secret)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !verified {
		exhausted, err := handler.mfa.RecordChallengeFailure(request.Context(), challengeToken)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		handler.logAuthenticationEvent(request, "login_attempt", map[string]any{
			"email":         user.Email,
			"userId":        user.ID,
			"success":       false,
			"failureReason": "totp code mismatch",
			"returnTo":      challenge.ReturnTo,
		})
		if exhausted {
			clearTOTPLoginChallengeCookie(responseWriter)
			http.Redirect(responseWriter, request, verificationRestartLoginPath(challenge.ReturnTo), http.StatusFound)
			return
		}
		if err := handler.renderTOTPLogin(responseWriter, http.StatusUnauthorized, challenge.ReturnTo, "Authenticator code is incorrect."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	session, err := handler.accounts.CreateSession(request.Context(), user.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.logAuthenticationEvent(request, "login_attempt", map[string]any{
		"email":     user.Email,
		"userId":    user.ID,
		"role":      user.Role,
		"success":   true,
		"sessionId": session.Token,
		"returnTo":  challenge.ReturnTo,
	})
	sessions.SetCookie(responseWriter, session)
	clearTOTPLoginChallengeCookie(responseWriter)
	http.Redirect(responseWriter, request, challenge.ReturnTo, http.StatusFound)
}

func (handler *authHandler) CancelTOTPLogin(responseWriter http.ResponseWriter, request *http.Request) {
	if err := handler.mfa.DeleteChallenge(request.Context(), totpLoginChallengeToken(request)); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	clearTOTPLoginChallengeCookie(responseWriter)
	http.Redirect(responseWriter, request, "/login", http.StatusFound)
}

func (handler *authHandler) MFARecoveryPage(responseWriter http.ResponseWriter, _ *http.Request) {
	if err := handler.renderMFARecovery(responseWriter, http.StatusOK, ""); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *authHandler) RecoverMFA(responseWriter http.ResponseWriter, request *http.Request) {
	email, emailErr := httpx.FormValue(request, "email")
	password, passwordErr := httpx.FormValue(request, "password")
	backupCode, backupCodeErr := httpx.FormValue(request, "backupCode")
	if emailErr != nil || passwordErr != nil || backupCodeErr != nil {
		handler.invalidForm(responseWriter)
		return
	}
	email = accounts.NormalizeEmail(email)
	backupCode = strings.TrimSpace(backupCode)
	user, found, err := handler.accounts.FindUserByEmail(request.Context(), email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	recentFailures, err := handler.mfa.CountRecentRecoveryFailures(request.Context(), email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if recentFailures >= 5 {
		handler.logMFARecovery(email, nullableUserID(user, found), false, "too many recovery attempts")
		if err := handler.renderMFARecovery(responseWriter, http.StatusTooManyRequests, "Too many recovery attempts. Try again later."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if !found || !passwords.Verify(password, user.PasswordHash) {
		userID := nullableInt64(user.ID, found)
		if err := handler.mfa.RecordRecoveryAttempt(request.Context(), email, userID, false); err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		handler.logMFARecovery(email, nullableUserID(user, found), false, loginFailureReason(found))
		if err := handler.renderMFARecovery(responseWriter, http.StatusUnauthorized, "Invalid recovery details."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	consumed, err := handler.mfa.ConsumeBackupCode(request.Context(), user.ID, backupCode)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !consumed {
		if err := handler.mfa.RecordRecoveryAttempt(request.Context(), email, &user.ID, false); err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		handler.logMFARecovery(user.Email, user.ID, false, "backup code rejected")
		if err := handler.renderMFARecovery(responseWriter, http.StatusUnauthorized, "Invalid recovery details."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	challengeToken := totpLoginChallengeToken(request)
	if err := handler.mfa.DeleteChallenge(request.Context(), challengeToken); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if err := handler.mfa.Clear(request.Context(), user.ID); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	session, err := handler.accounts.CreateSession(request.Context(), user.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if err := handler.mfa.RecordRecoveryAttempt(request.Context(), user.Email, &user.ID, true); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.logMFARecovery(user.Email, user.ID, true, "")
	sessions.SetCookie(responseWriter, session)
	if challengeToken != "" {
		clearTOTPLoginChallengeCookie(responseWriter)
	}
	http.Redirect(responseWriter, request, "/account/totp", http.StatusFound)
}

func (handler *authHandler) PasswordResetRequestPage(responseWriter http.ResponseWriter, _ *http.Request) {
	if err := handler.renderPasswordResetRequest(responseWriter, http.StatusOK, false, "", ""); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *authHandler) RequestPasswordReset(responseWriter http.ResponseWriter, request *http.Request) {
	email, err := httpx.FormValue(request, "email")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	email = accounts.NormalizeEmail(email)
	user, found, err := handler.accounts.FindUserByEmail(request.Context(), email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		handler.logAuthenticationEvent(request, "password_reset_request", map[string]any{
			"email":         email,
			"success":       false,
			"failureReason": "email not found",
		})
		if err := handler.renderPasswordResetRequest(responseWriter, http.StatusNotFound, false, "No account exists for that email.", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	resetToken, err := handler.passwordResets.Create(request.Context(), user.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	resetLink := fmt.Sprintf("%s/password-reset/%s", handler.appOrigin, resetToken.Value)
	appURL, err := url.Parse(handler.appOrigin)
	if err == nil && appURL.Hostname() == "localhost" {
		fmt.Printf("Bear Mail to %s:\nReset your password: %s\n", email, resetLink)
	}
	handler.logAuthenticationEvent(request, "password_reset_request", map[string]any{
		"email":      user.Email,
		"userId":     user.ID,
		"success":    true,
		"resetToken": resetToken.Value,
		"resetLink":  resetLink,
	})
	if err := handler.renderPasswordResetRequest(responseWriter, http.StatusOK, true, "", "/password-reset/"+resetToken.Value); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) PasswordResetPage(responseWriter http.ResponseWriter, request *http.Request) {
	token := request.PathValue("token")
	_, found, err := handler.passwordResets.Validate(request.Context(), token)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		if err := handler.renderPasswordReset(responseWriter, http.StatusNotFound, token, "Reset link not found or expired", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if err := handler.renderPasswordReset(responseWriter, http.StatusOK, token, "", ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) ResetPassword(responseWriter http.ResponseWriter, request *http.Request) {
	token := request.PathValue("token")
	resetToken, found, err := handler.passwordResets.Validate(request.Context(), token)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		if err := handler.renderPasswordReset(responseWriter, http.StatusNotFound, token, "Reset link not found or expired", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	user, userFound, err := handler.accounts.FindUserByID(request.Context(), resetToken.UserID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !userFound {
		if err := handler.renderPasswordReset(responseWriter, http.StatusNotFound, token, "Account not found", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	password, err := httpx.FormValue(request, "password")
	if err != nil {
		handler.invalidForm(responseWriter)
		return
	}
	passwordLength := utf8.RuneCountInString(password)
	if passwordLength < minimumPasswordLength {
		if err := handler.renderPasswordReset(responseWriter, http.StatusBadRequest, token, "Password must be at least 8 characters", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if passwordLength > passwords.MaxLength {
		if err := handler.renderPasswordReset(responseWriter, http.StatusBadRequest, token, "Password must not exceed 128 characters", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	passwordHash, err := passwords.Hash(password)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	reset, err := handler.passwordResets.ResetPassword(request.Context(), token, passwordHash)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !reset {
		if err := handler.renderPasswordReset(responseWriter, http.StatusNotFound, token, "Reset link not found or expired", ""); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if err := handler.renderPasswordReset(responseWriter, http.StatusOK, "", "", user.Email); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *authHandler) renderTOTPLogin(responseWriter http.ResponseWriter, statusCode int, returnTo, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "totp-login", totpLoginPage{
		Title: "Two-Step Verification", Error: errorMessage, ReturnTo: safeReturnTo(returnTo),
	})
}

func (handler *authHandler) renderMFARecovery(responseWriter http.ResponseWriter, statusCode int, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "mfa-recovery", recoveryPage{Title: "Use a Backup Code", Error: errorMessage})
}

func (handler *authHandler) renderPasswordResetRequest(responseWriter http.ResponseWriter, statusCode int, showConfirmation bool, errorMessage, resetLink string) error {
	return handler.renderer.Render(responseWriter, statusCode, "password-reset-request", passwordResetRequestPage{
		Title: "Reset Password", Error: errorMessage, ShowConfirmation: showConfirmation, ResetLink: resetLink,
	})
}

func (handler *authHandler) renderPasswordReset(responseWriter http.ResponseWriter, statusCode int, token, errorMessage, email string) error {
	templateName := "password-reset"
	title := "Choose New Password"
	if email != "" {
		templateName = "password-reset-complete"
		title = "Password Reset Complete"
	}
	return handler.renderer.Render(responseWriter, statusCode, templateName, passwordResetPage{
		Title: title, Error: errorMessage, Token: token, Email: email,
	})
}

func (handler *authHandler) logMFARecovery(email string, userID any, succeeded bool, failureReason string) {
	fields := map[string]any{"email": email, "userId": userID, "success": succeeded}
	if failureReason != "" {
		fields["failureReason"] = failureReason
	}
	_ = handler.logger.Event("mfa_recovery_attempt", fields)
}

func totpLoginChallengeToken(request *http.Request) string {
	cookie, err := request.Cookie(totpLoginChallengeCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func setTOTPLoginChallengeCookie(responseWriter http.ResponseWriter, challenge mfa.Challenge) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name: totpLoginChallengeCookieName, Value: challenge.Token, Path: "/", Expires: challenge.ExpiresAt,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearTOTPLoginChallengeCookie(responseWriter http.ResponseWriter) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name: totpLoginChallengeCookieName, Path: "/", Expires: time.Unix(0, 0), MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

func verificationRestartLoginPath(returnTo string) string {
	loginPath := "/login?verification=restart"
	if safePath := safeReturnTo(returnTo); safePath != "/" {
		loginPath += "&returnTo=" + url.QueryEscape(safePath)
	}
	return loginPath
}

func nullableInt64(value int64, include bool) *int64 {
	if !include {
		return nil
	}
	return &value
}
