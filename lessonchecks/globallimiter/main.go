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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

func TestLessonFixedWindowRateLimiter(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := fixedWindowRateLimiter(rateLimitOptions{
		window:  time.Minute,
		maximum: 2,
		now:     func() time.Time { return now },
	})
	handler := limiter(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))

	request := func(remoteAddress string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		httpRequest := httptest.NewRequest(http.MethodGet, "/work", nil)
		httpRequest.RemoteAddr = remoteAddress
		handler.ServeHTTP(recorder, httpRequest)
		return recorder
	}

	first := request("192.0.2.10:1000")
	second := request("192.0.2.10:1001")
	otherClient := request("192.0.2.11:1000")
	blocked := request("192.0.2.10:1002")
	now = now.Add(time.Minute)
	recovered := request("192.0.2.10:1003")

	if first.Code != http.StatusNoContent || first.Header().Get("RateLimit-Limit") != "2" || first.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatal("first request did not receive the expected allowance")
	}
	if second.Code != http.StatusNoContent || second.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatal("second request did not consume the allowance")
	}
	if otherClient.Code != http.StatusNoContent || otherClient.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatal("different client addresses did not receive separate allowances")
	}
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("RateLimit-Reset") != "1060" || blocked.Header().Get("Retry-After") != "60" {
		t.Fatal("excess request did not receive deterministic retry metadata")
	}
	if recovered.Code != http.StatusNoContent || recovered.Header().Get("RateLimit-Remaining") != "1" || recovered.Header().Get("RateLimit-Reset") != "1120" {
		t.Fatal("allowance did not reset in a new fixed window")
	}
}

func TestLessonApplicationGlobalLimiter(t *testing.T) {
	application := newLessonApplication(t)

	request := func(path, remoteAddress string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		httpRequest := httptest.NewRequest(http.MethodGet, path, nil)
		httpRequest.RemoteAddr = remoteAddress
		application.Handler.ServeHTTP(recorder, httpRequest)
		return recorder
	}

	for requestNumber := range 100 {
		response := request("/lesson-check-missing", "192.0.2.10:"+strconv.Itoa(1_000+requestNumber))
		if response.Code != http.StatusNotFound {
			t.Fatalf("allowed request %d returned status %d", requestNumber+1, response.Code)
		}
		if response.Header().Get("RateLimit-Limit") != "100" {
			t.Fatalf("allowed request %d did not report the global limit", requestNumber+1)
		}
	}

	blocked := request("/lesson-check-missing", "192.0.2.10:1100")
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatal("the application did not enforce the global allowance")
	}
	if retryAfter, err := strconv.Atoi(blocked.Header().Get("Retry-After")); err != nil || retryAfter <= 0 {
		t.Fatal("the application did not report when the client can retry")
	}

	otherClient := request("/lesson-check-missing", "192.0.2.11:1000")
	if otherClient.Code != http.StatusNotFound || otherClient.Header().Get("RateLimit-Limit") != "100" || otherClient.Header().Get("RateLimit-Remaining") != "99" {
		t.Fatal("the application did not maintain a separate allowance for another client")
	}

	health := request("/health", "192.0.2.10:1101")
	if health.Code != http.StatusOK || health.Header().Get("RateLimit-Limit") != "" {
		t.Fatal("the health endpoint was not excluded from the global limiter")
	}
}

func newLessonApplication(t *testing.T) *Application {
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
		AppOrigin:               "http://localhost:3030",
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
	FixedWindowBehavior       bool `json:"fixedWindowBehavior"`
	GlobalAllowanceEnforced   bool `json:"globalAllowanceEnforced"`
	ClientIsolationMaintained bool `json:"clientIsolationMaintained"`
	HealthExcluded            bool `json:"healthExcluded"`
}

func main() {
	probePassed := runApplicationProbe()
	writeResult(result{
		FixedWindowBehavior:       probePassed,
		GlobalAllowanceEnforced:   probePassed,
		ClientIsolationMaintained: probePassed,
		HealthExcluded:            probePassed,
	})
}

func runApplicationProbe() bool {
	probePath := filepath.Join("internal", "httpserver", "lesson_global_limiter_test.go")
	if _, err := os.Stat(probePath); err == nil {
		log.Fatalf("temporary probe path already exists: %s", probePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	if err := os.WriteFile(probePath, []byte(applicationProbe), 0o600); err != nil {
		log.Fatal(err)
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./internal/httpserver", "-run", "^TestLesson", "-count=1")
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

func writeResult(output result) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}
