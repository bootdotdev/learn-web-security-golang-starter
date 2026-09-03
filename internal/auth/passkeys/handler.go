package passkeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
	"github.com/go-webauthn/webauthn/protocol"
	webauthn "github.com/go-webauthn/webauthn/webauthn"
)

const (
	challengeLifetime            = 5 * time.Minute
	totpLoginChallengeCookieName = "totp_login_challenge"
)

type loginPageView struct {
	templates.Page
	Error    string
	ReturnTo string
}

type managePageView struct {
	templates.Page
	Credentials []Credential
	DisplayName string
	Error       string
}

type Handler struct {
	accounts            *accounts.Store
	mfa                 *mfa.Store
	passkeys            *Store
	renderer            *templates.Renderer
	logger              *logging.Logger
	webauthn            *webauthn.WebAuthn
	maximumRequestBytes int64
}

func NewHandler(appOrigin string, accountStore *accounts.Store, mfaStore *mfa.Store, passkeyStore *Store, renderer *templates.Renderer, logger *logging.Logger, maximumRequestBytes int64) (*Handler, error) {
	parsedOrigin, err := url.Parse(appOrigin)
	if err != nil {
		return nil, fmt.Errorf("parse app origin for passkeys: %w", err)
	}
	if parsedOrigin.Scheme == "" || parsedOrigin.Hostname() == "" {
		return nil, errors.New("passkey app origin requires a scheme and hostname")
	}
	if maximumRequestBytes <= 0 {
		return nil, errors.New("maximum passkey request size must be positive")
	}
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPID:                 parsedOrigin.Hostname(),
		RPDisplayName:        "Bearly Secure",
		RPOrigins:            []string{appOrigin},
		EncodeUserIDAsString: true,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: challengeLifetime},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: challengeLifetime},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure WebAuthn: %w", err)
	}
	return &Handler{
		accounts: accountStore, mfa: mfaStore, passkeys: passkeyStore, renderer: renderer, logger: logger,
		webauthn: webAuthn, maximumRequestBytes: maximumRequestBytes,
	}, nil
}

func (handler *Handler) LoginPage(responseWriter http.ResponseWriter, request *http.Request) {
	returnTo := unsafeReturnTo(request.URL.Query().Get("returnTo"))
	if err := handler.renderLogin(responseWriter, http.StatusOK, "", returnTo); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) BeginLogin(responseWriter http.ResponseWriter, request *http.Request) {
	options, sessionData, err := handler.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	challenge, err := handler.passkeys.CreateChallenge(request.Context(), nil, *sessionData)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"challengeId": challenge.ID, "publicKey": options.Response})
}

func (handler *Handler) CompleteLogin(responseWriter http.ResponseWriter, request *http.Request) {
	challengeID, returnTo, assertion, err := handler.passkeyResponse(responseWriter, request, true)
	if err != nil {
		if renderErr := handler.renderLogin(responseWriter, http.StatusBadRequest, "Invalid passkey response.", "/"); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	challenge, found, err := handler.passkeys.ConsumeChallenge(request.Context(), challengeID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		if renderErr := handler.renderLogin(responseWriter, http.StatusBadRequest, "Challenge expired. Try again.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	credentialID, found := responseCredentialID(assertion)
	if !found {
		if renderErr := handler.renderLogin(responseWriter, http.StatusBadRequest, "Invalid passkey response.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	credentialAccountID, found, err := handler.passkeys.CredentialAccountID(request.Context(), credentialID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		if renderErr := handler.renderLogin(responseWriter, http.StatusUnauthorized, "Passkey not recognised.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(request)
	if err != nil {
		_ = handler.logger.Event("passkey_login_failed", map[string]any{"credentialId": credentialID, "error": err.Error()})
		if renderErr := handler.renderLogin(responseWriter, http.StatusUnauthorized, "Passkey verification failed.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	if encodeBase64URL(parsedResponse.RawID) != credentialID {
		if renderErr := handler.renderLogin(responseWriter, http.StatusUnauthorized, "Passkey verification failed.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	account, found, err := handler.accounts.FindUserByID(request.Context(), credentialAccountID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		if renderErr := handler.renderLogin(responseWriter, http.StatusInternalServerError, "User not found.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	user, err := handler.passkeys.User(request.Context(), account)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	sessionData := challenge.SessionData
	sessionData.UserID = user.WebAuthnID()
	var credential *webauthn.Credential
	err = errors.New("passkey assertion validation is not implemented")
	if err != nil {
		_ = handler.logger.Event("passkey_login_failed", map[string]any{"credentialId": credentialID, "error": err.Error()})
		if renderErr := handler.renderLogin(responseWriter, http.StatusUnauthorized, "Passkey verification failed.", returnTo); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	if err := handler.passkeys.UpdateCounter(request.Context(), *credential); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	session, err := handler.accounts.CreateSession(request.Context(), account.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if err := handler.mfa.DeleteChallenge(request.Context(), totpLoginChallengeToken(request)); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("passkey_login_success", map[string]any{"userId": account.ID, "email": account.Email, "credentialId": credentialID})
	sessions.SetCookie(responseWriter, session)
	if totpLoginChallengeToken(request) != "" {
		clearTOTPLoginChallengeCookie(responseWriter)
	}
	http.Redirect(responseWriter, request, returnTo, http.StatusFound)
}

func (handler *Handler) ManagePage(responseWriter http.ResponseWriter, request *http.Request) {
	current, found, err := sessions.RequireWithReturnTo(responseWriter, request, handler.accounts, "/account/passkey")
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		return
	}
	if err := handler.renderManage(request.Context(), responseWriter, http.StatusOK, current, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) BeginRegistration(responseWriter http.ResponseWriter, request *http.Request) {
	current, found, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		httpx.RespondWithError(responseWriter, http.StatusUnauthorized, "Not authenticated")
		return
	}
	if !sessions.HasRecentAuthentication(current, time.Now()) {
		httpx.RespondWithError(responseWriter, http.StatusForbidden, "Log in again before registering a passkey")
		return
	}
	user, err := handler.passkeys.User(request.Context(), current.User)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	exclusions := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for _, credential := range user.credentials {
		exclusions = append(exclusions, credential.Descriptor())
	}
	options, sessionData, err := handler.webauthn.BeginRegistration(user,
		webauthn.WithExclusions(exclusions),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	challenge, err := handler.passkeys.CreateChallenge(request.Context(), &current.User.ID, *sessionData)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"challengeId": challenge.ID, "publicKey": options.Response})
}

func (handler *Handler) CompleteRegistration(responseWriter http.ResponseWriter, request *http.Request) {
	current, found, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		httpx.RespondWithError(responseWriter, http.StatusUnauthorized, "Not authenticated")
		return
	}
	if !sessions.HasRecentAuthentication(current, time.Now()) {
		if renderErr := handler.renderManage(request.Context(), responseWriter, http.StatusForbidden, current, "Log in again before registering a passkey."); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	challengeID, _, _, err := handler.passkeyResponse(responseWriter, request, false)
	if err != nil {
		if renderErr := handler.renderManage(request.Context(), responseWriter, http.StatusBadRequest, current, "Challenge expired. Try again."); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	challenge, found, err := handler.passkeys.ConsumeChallenge(request.Context(), challengeID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || challenge.UserID == nil || *challenge.UserID != current.User.ID {
		if renderErr := handler.renderManage(request.Context(), responseWriter, http.StatusBadRequest, current, "Challenge expired. Try again."); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	user, err := handler.passkeys.User(request.Context(), current.User)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	credential, err := handler.webauthn.FinishRegistration(user, challenge.SessionData, request)
	if err != nil {
		_ = handler.logger.Event("passkey_registration_failed", map[string]any{"userId": current.User.ID, "error": err.Error()})
		if renderErr := handler.renderManage(request.Context(), responseWriter, http.StatusBadRequest, current, "Registration failed. Try again."); renderErr != nil {
			handler.internalError(responseWriter, request, renderErr)
		}
		return
	}
	if err := handler.passkeys.StoreCredential(request.Context(), current.User.ID, *credential); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("passkey_registered", map[string]any{"userId": current.User.ID, "email": current.User.Email, "credentialId": encodeBase64URL(credential.ID)})
	http.Redirect(responseWriter, request, "/account/passkey", http.StatusFound)
}

func (handler *Handler) DeleteCredential(responseWriter http.ResponseWriter, request *http.Request) {
	current, found, err := sessions.Current(request, handler.accounts)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || !sessions.HasRecentAuthentication(current, time.Now()) {
		http.Redirect(responseWriter, request, "/login?returnTo=%2Faccount%2Fpasskey", http.StatusFound)
		return
	}
	credentialID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.errorPage(responseWriter, http.StatusNotFound, "Passkey Not Found", "We couldn't find that passkey.")
		return
	}
	if err := handler.passkeys.DeleteCredential(request.Context(), credentialID, current.User.ID); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("passkey_deleted", map[string]any{"userId": current.User.ID, "passkeyId": credentialID})
	http.Redirect(responseWriter, request, "/account/passkey", http.StatusFound)
}

func (handler *Handler) passkeyResponse(responseWriter http.ResponseWriter, request *http.Request, hasReturnTo bool) (string, string, map[string]json.RawMessage, error) {
	request.Body = http.MaxBytesReader(responseWriter, request.Body, handler.maximumRequestBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", "/", nil, fmt.Errorf("read passkey response: %w", err)
	}
	var responseFields map[string]json.RawMessage
	if err := json.Unmarshal(body, &responseFields); err != nil || responseFields == nil {
		return "", "/", nil, errors.New("passkey response must be a JSON object")
	}
	challengeID, err := stringField(responseFields, "challengeId")
	if err != nil || challengeID == "" {
		return "", "/", nil, errors.New("passkey challenge ID is required")
	}
	delete(responseFields, "challengeId")
	returnTo := "/"
	if hasReturnTo {
		if _, found := responseFields["returnTo"]; found {
			returnToValue, err := stringField(responseFields, "returnTo")
			if err != nil {
				return "", "/", nil, err
			}
			returnTo = unsafeReturnTo(returnToValue)
		}
		delete(responseFields, "returnTo")
	}
	encodedResponse, err := json.Marshal(responseFields)
	if err != nil {
		return "", "/", nil, fmt.Errorf("encode passkey response: %w", err)
	}
	request.Body = io.NopCloser(bytes.NewReader(encodedResponse))
	request.ContentLength = int64(len(encodedResponse))
	return challengeID, returnTo, responseFields, nil
}

func unsafeReturnTo(value string) string {
	if value == "" {
		return "/"
	}
	return value
}

func responseCredentialID(responseFields map[string]json.RawMessage) (string, bool) {
	credentialID, err := stringField(responseFields, "id")
	return credentialID, err == nil && credentialID != ""
}

func stringField(fields map[string]json.RawMessage, name string) (string, error) {
	rawValue, found := fields[name]
	if !found {
		return "", fmt.Errorf("%s is required", name)
	}
	var value string
	if err := json.Unmarshal(rawValue, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return value, nil
}

func (handler *Handler) renderLogin(responseWriter http.ResponseWriter, statusCode int, errorMessage, returnTo string) error {
	return handler.renderer.Render(responseWriter, statusCode, "passkey-login", loginPageView{
		Title: "Sign In with Passkey", Error: errorMessage, ReturnTo: returnTo,
	})
}

func (handler *Handler) renderManage(ctx context.Context, responseWriter http.ResponseWriter, statusCode int, current accounts.CurrentSession, errorMessage string) error {
	credentials, err := handler.passkeys.ListCredentials(ctx, current.User.ID)
	if err != nil {
		return err
	}
	return handler.renderer.Render(responseWriter, statusCode, "passkey-manage", managePageView{
		Title: "Passkeys", Credentials: credentials, DisplayName: current.User.DisplayName, Error: errorMessage,
	})
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, title, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, title, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}

func totpLoginChallengeToken(request *http.Request) string {
	cookie, err := request.Cookie(totpLoginChallengeCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func clearTOTPLoginChallengeCookie(responseWriter http.ResponseWriter) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name: totpLoginChallengeCookieName, Path: "/", Expires: time.Unix(0, 0), MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
