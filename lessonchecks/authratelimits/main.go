package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const applicationProbe = `package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

const lessonAuthOrigin = "http://bearly-secure.test"
const lessonNeutralResetMessage = "If an account exists for that email, Bear Mail will send a reset link"

type lessonAuthAttempt struct {
	statusCode int
	body       string
	retryAfter string
}

func TestLessonAuthenticationRateLimits(t *testing.T) {
	application := newAuthenticationRateLimitApplication(t)
	loginEmailVariants := []string{
		" MABEL@EXAMPLE.COM ",
		"mabel@example.com",
		"Mabel@Example.Com",
		"mabel@example.com ",
		" Mabel@example.com",
		"MABEL@example.com",
	}
	unknownLoginVariants := make([]string, len(loginEmailVariants))
	for index, email := range loginEmailVariants {
		unknownLoginVariants[index] = strings.Replace(strings.ToLower(email), "mabel", "nobody", 1)
	}

	knownLogin := lessonAttemptSeries(t, application, "/login", loginEmailVariants, func(index int) string {
		return fmt.Sprintf("192.0.2.%d", index+1)
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})
	unknownLogin := lessonAttemptSeries(t, application, "/login", unknownLoginVariants, func(index int) string {
		return fmt.Sprintf("192.0.2.%d", index+21)
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})

	loginEmails := make([]string, 21)
	for index := range loginEmails {
		loginEmails[index] = fmt.Sprintf("login-ip-%d@example.com", index)
	}
	loginByIP := lessonAttemptSeries(t, application, "/login", loginEmails, func(int) string {
		return "192.0.2.100"
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})
	totpByIP := lessonAttemptSeries(t, application, "/login/totp", make([]string, 21), func(int) string {
		return "192.0.2.101"
	}, url.Values{"returnTo": {"/"}})

	knownReset := lessonAttemptSeries(t, application, "/password-reset", loginEmailVariants[:4], func(index int) string {
		return fmt.Sprintf("198.51.100.%d", index+1)
	}, nil)
	unknownReset := lessonAttemptSeries(t, application, "/password-reset", unknownLoginVariants[:4], func(index int) string {
		return fmt.Sprintf("198.51.100.%d", index+21)
	}, nil)
	resetEmails := make([]string, 11)
	for index := range resetEmails {
		resetEmails[index] = fmt.Sprintf("reset-ip-%d@example.com", index)
	}
	resetByIP := lessonAttemptSeries(t, application, "/password-reset", resetEmails, func(int) string {
		return "198.51.100.100"
	}, nil)

	assertLessonStatuses(t, "known-account login", knownLogin, []int{401, 401, 401, 401, 401, 429})
	assertLessonStatuses(t, "unknown-account login", unknownLogin, []int{401, 401, 401, 401, 401, 429})
	assertLessonStatuses(t, "login IP", loginByIP, append(repeatedLessonStatus(20, http.StatusUnauthorized), http.StatusTooManyRequests))
	assertLessonStatuses(t, "TOTP IP", totpByIP, append(repeatedLessonStatus(20, http.StatusFound), http.StatusTooManyRequests))
	assertLessonStatuses(t, "known-account reset", knownReset, []int{200, 200, 200, 429})
	assertLessonStatuses(t, "unknown-account reset", unknownReset, []int{200, 200, 200, 429})
	assertLessonStatuses(t, "reset IP", resetByIP, append(repeatedLessonStatus(10, http.StatusOK), http.StatusTooManyRequests))

	if knownLogin[len(knownLogin)-1].body != unknownLogin[len(unknownLogin)-1].body {
		t.Fatal("known and unknown accounts received different login limit responses")
	}
	if knownReset[len(knownReset)-1].body != unknownReset[len(unknownReset)-1].body {
		t.Fatal("known and unknown accounts received different password-reset limit responses")
	}
	if !strings.Contains(knownReset[0].body, lessonNeutralResetMessage) || !strings.Contains(unknownReset[0].body, lessonNeutralResetMessage) {
		t.Fatal("known and unknown accounts did not receive neutral password-reset responses")
	}
	blockedAttempts := []lessonAuthAttempt{
		knownLogin[len(knownLogin)-1],
		unknownLogin[len(unknownLogin)-1],
		loginByIP[len(loginByIP)-1],
		totpByIP[len(totpByIP)-1],
		knownReset[len(knownReset)-1],
		unknownReset[len(unknownReset)-1],
		resetByIP[len(resetByIP)-1],
	}
	for _, attempt := range blockedAttempts {
		if attempt.retryAfter == "" || attempt.retryAfter == "0" {
			t.Fatal("a blocked authentication attempt did not include Retry-After")
		}
	}
}

func lessonAttemptSeries(t *testing.T, application *Application, path string, emails []string, sourceAddress func(int) string, extraValues url.Values) []lessonAuthAttempt {
	t.Helper()
	attempts := make([]lessonAuthAttempt, 0, len(emails))
	for index, email := range emails {
		values := cloneLessonValues(extraValues)
		values.Set("email", email)
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		request.RemoteAddr = net.JoinHostPort(sourceAddress(index), "1234")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", lessonAuthOrigin)
		response := httptest.NewRecorder()
		application.Handler.ServeHTTP(response, request)
		attempts = append(attempts, lessonAuthAttempt{
			statusCode: response.Code,
			body:       response.Body.String(),
			retryAfter: response.Header().Get("Retry-After"),
		})
	}
	return attempts
}

func cloneLessonValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values)+1)
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func assertLessonStatuses(t *testing.T, name string, attempts []lessonAuthAttempt, expected []int) {
	t.Helper()
	actual := make([]int, len(attempts))
	for index, attempt := range attempts {
		actual[index] = attempt.statusCode
	}
	if !slices.Equal(actual, expected) {
		t.Fatalf("%s statuses = %v, want %v", name, actual, expected)
	}
}

func repeatedLessonStatus(count, status int) []int {
	statuses := make([]int, count)
	for index := range statuses {
		statuses[index] = status
	}
	return statuses
}

func newAuthenticationRateLimitApplication(t *testing.T) *Application {
	t.Helper()

	repositoryRoot := filepath.Join("..", "..")
	dataDirectory := t.TempDir()
	databaseConnection, err := database.Open(t.Context(), filepath.Join(dataDirectory, "lesson-check.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = databaseConnection.Close() })
	if err := database.Migrate(t.Context(), databaseConnection); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConnection.ExecContext(t.Context(), "INSERT INTO users (email, display_name, role, password_hash) VALUES ('mabel@example.com', 'Mabel Pines', 'customer', '0000000000000000000000000000000000000000000000000000000000000000')"); err != nil {
		t.Fatal(err)
	}

	logger, err := logging.Open(filepath.Join(dataDirectory, "lesson-check.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	var encryptionKey [32]byte
	encryptionKey[0] = 1
	keyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": encryptionKey})
	if err != nil {
		t.Fatal(err)
	}

	application, err := New(databaseConnection, logger, Options{
		AppOrigin:               lessonAuthOrigin,
		MaxPublicProductResults: 50,
		MaxRequestBodyBytes:     32 * 1024,
		MaxUploadBytes:          1024 * 1024,
		PawPalAPIKey:            "lesson-check",
		EncryptionKeyring:       keyring,
		DataDirectory:           dataDirectory,
		FixtureDirectory:        filepath.Join(repositoryRoot, "data", "fixtures"),
		TemplateDirectory:       filepath.Join(repositoryRoot, "web", "templates"),
		PublicDirectory:         filepath.Join(repositoryRoot, "web", "public"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = application.Close() })
	return application
}
`

type result struct {
	KnownLoginStatuses            []int `json:"knownLoginStatuses"`
	UnknownLoginStatuses          []int `json:"unknownLoginStatuses"`
	LoginIPStatuses               []int `json:"loginIpStatuses"`
	TOTPIPStatuses                []int `json:"totpIpStatuses"`
	KnownResetStatuses            []int `json:"knownResetStatuses"`
	UnknownResetStatuses          []int `json:"unknownResetStatuses"`
	ResetIPStatuses               []int `json:"resetIpStatuses"`
	LoginLimitBodiesMatch         bool  `json:"loginLimitBodiesMatch"`
	ResetLimitBodiesMatch         bool  `json:"resetLimitBodiesMatch"`
	ResetNeutralBodiesMatch       bool  `json:"resetNeutralBodiesMatch"`
	BlockedAttemptsHaveRetryAfter bool  `json:"blockedAttemptsHaveRetryAfter"`
}

func main() {
	output := failedResult()
	if runApplicationProbe() {
		output = successfulResult()
	}
	writeResult(output)
}

func runApplicationProbe() bool {
	probePath := filepath.Join("internal", "httpserver", "lesson_auth_rate_limits_test.go")
	if _, err := os.Stat(probePath); err == nil {
		log.Fatalf("temporary probe path already exists: %s", probePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	if err := os.WriteFile(probePath, []byte(applicationProbe), 0o600); err != nil {
		log.Fatal(err)
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./internal/httpserver", "-run", "^TestLessonAuthenticationRateLimits$", "-count=1")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	err := command.Run()
	if err == nil {
		return true
	}
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return false
	}
	log.Fatal(err)
	return false
}

func successfulResult() result {
	return result{
		KnownLoginStatuses:            []int{401, 401, 401, 401, 401, 429},
		UnknownLoginStatuses:          []int{401, 401, 401, 401, 401, 429},
		LoginIPStatuses:               []int{401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 401, 429},
		TOTPIPStatuses:                []int{302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 302, 429},
		KnownResetStatuses:            []int{200, 200, 200, 429},
		UnknownResetStatuses:          []int{200, 200, 200, 429},
		ResetIPStatuses:               []int{200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 429},
		LoginLimitBodiesMatch:         true,
		ResetLimitBodiesMatch:         true,
		ResetNeutralBodiesMatch:       true,
		BlockedAttemptsHaveRetryAfter: true,
	}
}

func failedResult() result {
	return result{
		KnownLoginStatuses:   []int{},
		UnknownLoginStatuses: []int{},
		LoginIPStatuses:      []int{},
		TOTPIPStatuses:       []int{},
		KnownResetStatuses:   []int{},
		UnknownResetStatuses: []int{},
		ResetIPStatuses:      []int{},
	}
}

func writeResult(output result) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}
