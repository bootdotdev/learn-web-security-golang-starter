package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/pquerna/otp/totp"
)

const (
	applicationOrigin = "http://localhost:3030"
	seededTOTPSecret  = "KXDYU6DRQPRQXLPY236SJJXPNGHQJVUF"
)

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type checkResult struct {
	AuthenticationStatusesValid    bool `json:"authenticationStatusesValid"`
	RequestIDsGlobal               bool `json:"requestIdsGlobal"`
	RequestIDsServerGenerated      bool `json:"requestIdsServerGenerated"`
	AuthenticationEventsCorrelated bool `json:"authEventsCorrelated"`
	AuthenticationSecretsAbsent    bool `json:"authSecretsAbsent"`
}

type requestObservation struct {
	StatusCode int
	RequestID  string
	Cookies    []*http.Cookie
}

type logEntry map[string]any

func main() {
	observabilityResult, err := checkAuthenticationObservability(context.Background(), applicationOrigin)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(observabilityResult); err != nil {
		log.Fatal(err)
	}
}

func checkAuthenticationObservability(ctx context.Context, origin string) (checkResult, error) {
	logPath := filepath.Join("data", "bearly-secure.log")
	logOffset, err := logSize(logPath)
	if err != nil {
		return checkResult{}, err
	}

	httpClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	clientSuppliedRequestID := "client-supplied-request-id"
	firstHealth, err := get(ctx, httpClient, origin+"/health", map[string]string{"X-Request-ID": clientSuppliedRequestID})
	if err != nil {
		return checkResult{}, err
	}
	secondHealth, err := get(ctx, httpClient, origin+"/health", nil)
	if err != nil {
		return checkResult{}, err
	}

	unknownEmail := "observability-unknown@example.com"
	knownEmail := "mabel@example.com"
	knownPassword := "password123"
	incorrectPassword := "observability-incorrect-password"
	unknownLogin, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {unknownEmail},
		"password": {incorrectPassword},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	knownFailedLogin, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {knownEmail},
		"password": {incorrectPassword},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	successfulLogin, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {knownEmail},
		"password": {knownPassword},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}

	totpEmail := "wendy@example.com"
	totpPasswordStep, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {totpEmail},
		"password": {knownPassword},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	challengeCookie := namedCookie(totpPasswordStep.Cookies, "totp_login_challenge")
	if challengeCookie == nil {
		return checkResult{}, fmt.Errorf("TOTP password step did not set a challenge cookie")
	}
	invalidTOTPCode := "not-a-code"
	failedTOTPLogin, err := postForm(ctx, httpClient, origin+"/login/totp", url.Values{
		"mfaCode": {invalidTOTPCode},
	}, []*http.Cookie{challengeCookie})
	if err != nil {
		return checkResult{}, err
	}
	validTOTPCode, err := totp.GenerateCode(seededTOTPSecret, time.Now())
	if err != nil {
		return checkResult{}, fmt.Errorf("generate seeded TOTP code: %w", err)
	}
	successfulTOTPLogin, err := postForm(ctx, httpClient, origin+"/login/totp", url.Values{
		"mfaCode": {validTOTPCode},
	}, []*http.Cookie{challengeCookie})
	if err != nil {
		return checkResult{}, err
	}

	knownResetRequest, err := postForm(ctx, httpClient, origin+"/password-reset", url.Values{
		"email": {knownEmail},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	unknownResetEmail := "observability-reset-unknown@example.com"
	unknownResetRequest, err := postForm(ctx, httpClient, origin+"/password-reset", url.Values{
		"email": {unknownResetEmail},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}

	entries, err := appendedEntries(logPath, logOffset)
	if err != nil {
		return checkResult{}, err
	}
	unknownLoginEntry := findEvent(entries, "login_attempt", unknownLogin.RequestID)
	knownFailedLoginEntry := findEvent(entries, "login_attempt", knownFailedLogin.RequestID)
	successfulLoginEntry := findEvent(entries, "login_attempt", successfulLogin.RequestID)
	failedTOTPEntry := findEvent(entries, "login_attempt", failedTOTPLogin.RequestID)
	successfulTOTPEntry := findEvent(entries, "login_attempt", successfulTOTPLogin.RequestID)
	knownResetEntry := findEvent(entries, "password_reset_request", knownResetRequest.RequestID)
	unknownResetEntry := findEvent(entries, "password_reset_request", unknownResetRequest.RequestID)

	requestObservations := []requestObservation{
		firstHealth,
		secondHealth,
		unknownLogin,
		knownFailedLogin,
		successfulLogin,
		totpPasswordStep,
		failedTOTPLogin,
		successfulTOTPLogin,
		knownResetRequest,
		unknownResetRequest,
	}
	requestIDs := make([]string, 0, len(requestObservations))
	for _, observation := range requestObservations {
		requestIDs = append(requestIDs, observation.RequestID)
	}

	return checkResult{
		AuthenticationStatusesValid: unknownLogin.StatusCode == http.StatusUnauthorized &&
			knownFailedLogin.StatusCode == http.StatusUnauthorized &&
			successfulLogin.StatusCode == http.StatusFound &&
			totpPasswordStep.StatusCode == http.StatusFound &&
			failedTOTPLogin.StatusCode == http.StatusUnauthorized &&
			successfulTOTPLogin.StatusCode == http.StatusFound &&
			knownResetRequest.StatusCode == http.StatusOK &&
			unknownResetRequest.StatusCode == http.StatusOK,
		RequestIDsGlobal:          validUniqueRequestIDs(requestIDs),
		RequestIDsServerGenerated: firstHealth.RequestID != clientSuppliedRequestID,
		AuthenticationEventsCorrelated: validAuthenticationEvent(unknownLoginEntry, "failure", false) &&
			validAuthenticationEvent(knownFailedLoginEntry, "failure", false) &&
			validAuthenticationEvent(successfulLoginEntry, "success", true) &&
			validAuthenticationEvent(failedTOTPEntry, "failure", true) &&
			validAuthenticationEvent(successfulTOTPEntry, "success", true) &&
			validAuthenticationEvent(knownResetEntry, "success", true) &&
			validAuthenticationEvent(unknownResetEntry, "failure", false) &&
			failedTOTPEntry["userId"] == successfulTOTPEntry["userId"],
		AuthenticationSecretsAbsent: authenticationSecretsAbsent(entries, []string{
			unknownEmail,
			knownEmail,
			totpEmail,
			unknownResetEmail,
			knownPassword,
			incorrectPassword,
			invalidTOTPCode,
			validTOTPCode,
		}),
	}, nil
}

func get(ctx context.Context, httpClient *http.Client, endpoint string, headers map[string]string) (requestObservation, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return requestObservation{}, fmt.Errorf("create GET request for %s: %w", endpoint, err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return observeResponse(httpClient.Do(request))
}

func postForm(ctx context.Context, httpClient *http.Client, endpoint string, form url.Values, cookies []*http.Cookie) (requestObservation, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return requestObservation{}, fmt.Errorf("create POST request for %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("User-Agent", "Bootdev-Lesson-Checker")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return observeResponse(httpClient.Do(request))
}

func observeResponse(response *http.Response, err error) (requestObservation, error) {
	if err != nil {
		return requestObservation{}, err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return requestObservation{}, fmt.Errorf("read response body: %w", err)
	}
	return requestObservation{
		StatusCode: response.StatusCode,
		RequestID:  response.Header.Get("X-Request-ID"),
		Cookies:    response.Cookies(),
	}, nil
}

func namedCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func logSize(logPath string) (int64, error) {
	fileInfo, err := os.Stat(logPath)
	if err != nil {
		return 0, fmt.Errorf("stat application log: %w", err)
	}
	return fileInfo.Size(), nil
}

func appendedEntries(logPath string, offset int64) ([]logEntry, error) {
	logFile, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("open application log: %w", err)
	}
	defer logFile.Close()
	if _, err := logFile.Seek(offset, 0); err != nil {
		return nil, fmt.Errorf("seek application log: %w", err)
	}

	entries := make([]logEntry, 0)
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		var entry logEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse application log: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read application log: %w", err)
	}
	return entries, nil
}

func findEvent(entries []logEntry, eventName, requestID string) logEntry {
	for _, entry := range entries {
		if entry["event"] == eventName && entry["requestId"] == requestID {
			return entry
		}
	}
	return nil
}

func validAuthenticationEvent(entry logEntry, outcome string, expectUserID bool) bool {
	if entry == nil || entry["outcome"] != outcome || entry["requestId"] == "" {
		return false
	}
	if sourceIP, ok := entry["sourceIp"].(string); !ok || sourceIP == "" {
		return false
	}
	if expectUserID {
		return entry["userId"] != nil
	}
	return entry["userId"] == nil
}

func validUniqueRequestIDs(requestIDs []string) bool {
	uniqueRequestIDs := make(map[string]struct{}, len(requestIDs))
	for _, requestID := range requestIDs {
		if !requestIDPattern.MatchString(requestID) {
			return false
		}
		uniqueRequestIDs[requestID] = struct{}{}
	}
	return len(uniqueRequestIDs) == len(requestIDs)
}

func authenticationSecretsAbsent(entries []logEntry, sensitiveValues []string) bool {
	forbiddenFields := map[string]struct{}{
		"email":      {},
		"password":   {},
		"mfaCode":    {},
		"resetToken": {},
		"resetLink":  {},
		"sessionId":  {},
	}
	sensitiveValueSet := make(map[string]struct{}, len(sensitiveValues))
	for _, sensitiveValue := range sensitiveValues {
		sensitiveValueSet[sensitiveValue] = struct{}{}
	}
	for _, entry := range entries {
		for fieldName, fieldValue := range entry {
			if _, forbidden := forbiddenFields[fieldName]; forbidden && fieldValue != "[REDACTED]" {
				return false
			}
			stringValue, isString := fieldValue.(string)
			if !isString {
				continue
			}
			if _, sensitive := sensitiveValueSet[stringValue]; sensitive {
				return false
			}
		}
	}
	return true
}
