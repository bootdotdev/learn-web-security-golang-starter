package account

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type pageView struct {
	templates.Page
	Current   accounts.CurrentSession
	ExpiresAt string
	Error     string
	IsSupport bool
	IsAdmin   bool
}

type Handler struct {
	accountStore *accounts.Store
	mfaStore     *mfa.Store
	renderer     *templates.Renderer
	logger       *logging.Logger
}

func NewHandler(accountStore *accounts.Store, mfaStore *mfa.Store, renderer *templates.Renderer, logger *logging.Logger) *Handler {
	return &Handler{accountStore: accountStore, mfaStore: mfaStore, renderer: renderer, logger: logger}
}

type totpSetupView struct {
	templates.Page
	DisplayName string
	Secret      string
	QRDataURL   template.URL
	Error       string
}

type totpEnabledView struct {
	templates.Page
	DisplayName string
	CSRFToken   string
}

type totpBackupCodesView struct {
	templates.Page
	DisplayName string
	BackupCodes []string
}

func (handler *Handler) Page(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if err := handler.renderPage(responseWriter, http.StatusOK, current, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) UpdateEmail(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	email, emailErr := httpx.FormValue(request, "email")
	if emailErr != nil {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid.")
		return
	}
	email = accounts.NormalizeEmail(email)
	if email == "" {
		if err := handler.renderPage(responseWriter, http.StatusBadRequest, current, "Email is required."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	existingUser, found, err := handler.accountStore.FindUserByEmail(request.Context(), email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if found && existingUser.ID != current.User.ID {
		if err := handler.renderPage(responseWriter, http.StatusConflict, current, "Email is already in use."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if err := handler.accountStore.UpdateEmail(request.Context(), current.User.ID, email); errors.Is(err, accounts.ErrEmailExists) {
		if renderErr := handler.renderPage(responseWriter, http.StatusConflict, current, "Email is already in use."); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	} else if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, "/account", http.StatusFound)
}

func (handler *Handler) TOTPPage(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireRecentAuth(responseWriter, request)
	if !ok {
		return
	}
	if current.User.HasTOTP {
		if err := handler.renderer.Render(responseWriter, http.StatusOK, "totp-enabled", totpEnabledView{
			Title: "Two-Step Verification Enabled", DisplayName: current.User.DisplayName, CSRFToken: current.Session.CSRFToken,
		}); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	secret, qrDataURL, found, err := handler.mfaStore.PendingEnrollment(request.Context(), current.User.ID, current.User.Email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		secret, qrDataURL, err = handler.mfaStore.StartEnrollment(request.Context(), current.User.ID, current.User.Email)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		_ = handler.logger.Event("totp_enrollment_started", map[string]any{"userId": current.User.ID, "email": current.User.Email})
	}
	if err := handler.renderTOTPSetup(responseWriter, http.StatusOK, current.User.DisplayName, secret, qrDataURL, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) ConfirmTOTP(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireRecentAuth(responseWriter, request)
	if !ok {
		return
	}
	secret, qrDataURL, found, err := handler.mfaStore.PendingEnrollment(request.Context(), current.User.ID, current.User.Email)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		http.Redirect(responseWriter, request, "/account/totp", http.StatusFound)
		return
	}
	code, err := httpx.FormValue(request, "code")
	if err != nil {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid.")
		return
	}
	if !handler.mfaStore.Verify(strings.TrimSpace(code), secret) {
		_ = handler.logger.Event("totp_enrollment_failed", map[string]any{"userId": current.User.ID, "email": current.User.Email})
		if err := handler.renderTOTPSetup(responseWriter, http.StatusBadRequest, current.User.DisplayName, secret, qrDataURL, "Invalid code. Try again."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	backupCodes, err := handler.mfaStore.ConfirmEnrollment(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("totp_enrollment_confirmed", map[string]any{"userId": current.User.ID, "email": current.User.Email})
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "totp-backup-codes", totpBackupCodesView{
		Title: "Two-Step Verification Enabled", DisplayName: current.User.DisplayName, BackupCodes: backupCodes,
	}); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) DisableTOTP(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireRecentAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	if !current.User.HasTOTP {
		http.Redirect(responseWriter, request, "/account", http.StatusFound)
		return
	}
	if err := handler.mfaStore.Clear(request.Context(), current.User.ID); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("totp_disabled", map[string]any{"userId": current.User.ID, "email": current.User.Email})
	http.Redirect(responseWriter, request, "/account", http.StatusFound)
}

func (handler *Handler) renderPage(responseWriter http.ResponseWriter, statusCode int, current accounts.CurrentSession, errorMessage string) error {
	isAdmin := current.User.Role == "admin"
	return handler.renderer.Render(responseWriter, statusCode, "account", pageView{
		Title:     "Your Account",
		Current:   current,
		ExpiresAt: formatTimestamp(current.Session.ExpiresAt),
		Error:     errorMessage,
		IsSupport: current.User.Role == "support" || isAdmin,
		IsAdmin:   isAdmin,
	})
}

func (handler *Handler) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) requireRecentAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	loginPath := "/login?" + url.Values{"returnTo": {"/account/totp"}}.Encode()
	if !found {
		http.Redirect(responseWriter, request, loginPath, http.StatusFound)
		return accounts.CurrentSession{}, false
	}
	if !sessions.HasRecentAuthentication(current, time.Now()) {
		http.Redirect(responseWriter, request, loginPath, http.StatusFound)
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) verifyCSRF(responseWriter http.ResponseWriter, request *http.Request, expectedToken string) bool {
	actualToken, err := httpx.FormValue(request, "csrfToken")
	if err != nil {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid.")
		return false
	}
	if sessions.CSRFTokensMatch(expectedToken, actualToken) {
		return true
	}
	handler.errorPage(responseWriter, http.StatusForbidden, "Forbidden", "Your request could not be verified.")
	return false
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, heading, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, heading, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}

func (handler *Handler) renderTOTPSetup(responseWriter http.ResponseWriter, statusCode int, displayName, secret, qrDataURL, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "totp-setup", totpSetupView{
		Title: "Set Up Two-Step Verification", DisplayName: displayName, Secret: secret, QRDataURL: template.URL(qrDataURL), Error: errorMessage,
	})
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
