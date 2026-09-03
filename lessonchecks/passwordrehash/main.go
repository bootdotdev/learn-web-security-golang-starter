package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/auth/passwords"
	"github.com/bootdotdev/learn-web-security/internal/database"
)

const seededBackupCode = "a6f31c8d94e2b7504d8a1f3c6b9e2075"

type result struct {
	CurrentHashAccepted      bool `json:"currentHashAccepted"`
	LegacyHashNeedsRehash    bool `json:"legacyHashNeedsRehash"`
	StaleHashNeedsRehash     bool `json:"staleHashNeedsRehash"`
	SuccessfulLoginUpgraded  bool `json:"successfulLoginUpgraded"`
	FailedLoginPreservedHash bool `json:"failedLoginPreservedHash"`
	MFARecoveryUpgraded      bool `json:"mfaRecoveryUpgraded"`
}

func main() {
	ctx := context.Background()
	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = "data/bearly-secure.sqlite"
	}
	databaseConnection, err := database.Open(ctx, databasePath)
	if err != nil {
		writeResult(result{})
		return
	}
	defer databaseConnection.Close()

	currentHash, err := passwords.Hash("current policy password")
	if err != nil {
		writeResult(result{})
		return
	}
	legacyPassword := "password123"
	legacyHash := legacyPasswordHash(legacyPassword)
	staleHash := encodedStaleArgon2id()

	if _, err := databaseConnection.ExecContext(ctx, "UPDATE users SET password_hash = ? WHERE email = ?", legacyHash, "mabel@example.com"); err != nil {
		writeResult(result{})
		return
	}
	loginStatus := postForm("/login", url.Values{
		"email": {"mabel@example.com"}, "password": {legacyPassword}, "returnTo": {"/"},
	})
	mabelHash := readHash(ctx, databaseConnection, "mabel@example.com")

	if _, err := databaseConnection.ExecContext(ctx, "UPDATE users SET password_hash = ? WHERE email = ?", legacyHash, "sancho@example.com"); err != nil {
		writeResult(result{})
		return
	}
	failedStatus := postForm("/login", url.Values{
		"email": {"sancho@example.com"}, "password": {"incorrect"}, "returnTo": {"/"},
	})
	sanchoHash := readHash(ctx, databaseConnection, "sancho@example.com")

	if _, err := databaseConnection.ExecContext(ctx, "UPDATE users SET password_hash = ? WHERE email = ?", legacyHash, "wendy@example.com"); err != nil {
		writeResult(result{})
		return
	}
	recoveryStatus := postForm("/recover-mfa", url.Values{
		"email": {"wendy@example.com"}, "password": {legacyPassword}, "backupCode": {seededBackupCode},
	})
	wendyHash := readHash(ctx, databaseConnection, "wendy@example.com")

	writeResult(result{
		CurrentHashAccepted:      !passwords.NeedsRehash(currentHash),
		LegacyHashNeedsRehash:    passwords.NeedsRehash(legacyHash),
		StaleHashNeedsRehash:     passwords.NeedsRehash(staleHash),
		SuccessfulLoginUpgraded:  loginStatus == http.StatusFound && mabelHash != legacyHash && passwords.Verify(legacyPassword, mabelHash) && !passwords.NeedsRehash(mabelHash),
		FailedLoginPreservedHash: failedStatus == http.StatusUnauthorized && sanchoHash == legacyHash,
		MFARecoveryUpgraded:      recoveryStatus == http.StatusFound && wendyHash != legacyHash && passwords.Verify(legacyPassword, wendyHash) && !passwords.NeedsRehash(wendyHash),
	})
}

func legacyPasswordHash(password string) string {
	digest := sha256.Sum256([]byte(password))
	return hex.EncodeToString(digest[:])
}

func encodedStaleArgon2id() string {
	salt := []byte("stale-salt-value")
	derivedKey := make([]byte, 32)
	return "$argon2id$v=19$m=12288,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derivedKey)
}

func postForm(path string, values url.Values) int {
	origin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodPost, origin+path, strings.NewReader(values.Encode()))
	if err != nil {
		return 0
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}

func readHash(ctx context.Context, databaseConnection *sql.DB, email string) string {
	var hash string
	_ = databaseConnection.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE email = ?", email).Scan(&hash)
	return hash
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
