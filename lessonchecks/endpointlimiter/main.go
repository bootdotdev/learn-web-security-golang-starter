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
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

func TestLessonEndpointRateLimiter(t *testing.T) {
	application := newEndpointLimiterApplication(t)

	request := func(path, remoteAddress, origin string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		httpRequest := httptest.NewRequest(http.MethodGet, path, nil)
		httpRequest.RemoteAddr = remoteAddress
		if origin != "" {
			httpRequest.Header.Set("Origin", origin)
		}
		application.Handler.ServeHTTP(recorder, httpRequest)
		return recorder
	}

	for requestNumber := range 30 {
		response := request("/api/products", "192.0.2.10:"+strconv.Itoa(1_000+requestNumber), "http://localhost:4000")
		if response.Code != http.StatusOK {
			t.Fatalf("allowed product request %d returned status %d", requestNumber+1, response.Code)
		}
		if response.Header().Get("RateLimit-Limit") != "30" {
			t.Fatalf("allowed product request %d did not report the endpoint limit", requestNumber+1)
		}
		if response.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("allowed product request %d did not retain public CORS", requestNumber+1)
		}
		if requestNumber == 0 && !strings.Contains(response.Body.String(), "Rate Limit Raccoon") {
			t.Fatal("the product API did not retain its normal response")
		}
	}

	blocked := request("/api/products", "192.0.2.10:1030", "http://localhost:4000")
	if blocked.Code != http.StatusTooManyRequests ||
		blocked.Header().Get("RateLimit-Limit") != "30" ||
		blocked.Header().Get("RateLimit-Remaining") != "0" ||
		blocked.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("the product API did not enforce its endpoint allowance")
	}
	if retryAfter, err := strconv.Atoi(blocked.Header().Get("Retry-After")); err != nil || retryAfter <= 0 {
		t.Fatal("the product API did not report when the client can retry")
	}

	global := request("/", "192.0.2.10:1031", "")
	if global.Code != http.StatusOK || global.Header().Get("RateLimit-Limit") != "100" {
		t.Fatal("the endpoint limiter changed the global allowance")
	}
}

func newEndpointLimiterApplication(t *testing.T) *Application {
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
	if _, err := databaseConnection.ExecContext(t.Context(), "INSERT INTO products (name, description, image_path, price_cents, cost_cents, inventory_count, is_active) VALUES ('Rate Limit Raccoon', 'Five hugs per minute, max!', '/rate-limit-raccoon.webp', 1599, 500, 24, 1)"); err != nil {
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
	EndpointAllowanceEnforced bool `json:"endpointAllowanceEnforced"`
	PublicCORSRetained        bool `json:"publicCORSRetained"`
	NormalProductsRetained    bool `json:"normalProductsRetained"`
	GlobalAllowanceRetained   bool `json:"globalAllowanceRetained"`
}

func main() {
	probePassed := runApplicationProbe()
	writeResult(result{
		EndpointAllowanceEnforced: probePassed,
		PublicCORSRetained:        probePassed,
		NormalProductsRetained:    probePassed,
		GlobalAllowanceRetained:   probePassed,
	})
}

func runApplicationProbe() bool {
	probePath := filepath.Join("internal", "httpserver", "lesson_endpoint_limiter_test.go")
	if _, err := os.Stat(probePath); err == nil {
		log.Fatalf("temporary probe path already exists: %s", probePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	if err := os.WriteFile(probePath, []byte(applicationProbe), 0o600); err != nil {
		log.Fatal(err)
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./internal/httpserver", "-run", "^TestLessonEndpointRateLimiter$", "-count=1")
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
