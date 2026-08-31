package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/auth/passwordreset"
	"github.com/bootdotdev/learn-web-security/internal/database"
)

const testChallengeToken = "bs_test_password_reset_challenge"

func main() {
	arguments := os.Args[1:]
	command := ""
	token := ""
	if len(arguments) > 0 {
		command = arguments[0]
	}
	if len(arguments) > 1 {
		token = arguments[1]
	}
	validCommand := command == "inspect" || command == "expire" || command == "create-challenge" || command == "challenge-status" || command == "race"
	tokenRequired := command == "inspect" || command == "expire" || command == "create-challenge"
	if !validCommand || (tokenRequired && token == "") {
		fmt.Fprintln(os.Stderr, "Usage: go run ./lessonchecks/passwordreset <inspect|expire|create-challenge> <token> | challenge-status | race")
		os.Exit(1)
	}

	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = filepath.Join("data", "bearly-secure.sqlite")
	}
	ctx := context.Background()
	databaseHandle, err := database.Open(ctx, databasePath)
	if err != nil {
		fatal(err)
	}
	defer databaseHandle.Close()

	tokenHash := ""
	if token != "" {
		digest := sha256.Sum256([]byte(token))
		tokenHash = hex.EncodeToString(digest[:])
	}
	challengeDigest := sha256.Sum256([]byte(testChallengeToken))
	challengeHash := hex.EncodeToString(challengeDigest[:])

	switch command {
	case "inspect":
		var storedHash, expiresAt string
		err := databaseHandle.QueryRowContext(ctx, "SELECT token_hash, expires_at FROM password_reset_tokens WHERE token_hash IN (?, ?)", tokenHash, token).Scan(&storedHash, &expiresAt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			fatal(err)
		}
		remaining := time.Duration(0)
		if expiration, parseErr := time.Parse(time.RFC3339, expiresAt); parseErr == nil {
			remaining = time.Until(expiration)
		}
		printJSON(map[string]bool{
			"hashMatches":                storedHash == tokenHash,
			"rawTokenStored":             storedHash == token,
			"expiresAboutFifteenMinutes": remaining > 14*time.Minute && remaining <= 15*time.Minute,
		})
	case "expire":
		result, err := databaseHandle.ExecContext(ctx, "UPDATE password_reset_tokens SET expires_at = ? WHERE token_hash = ?", time.Unix(0, 0).UTC().Format(time.RFC3339), tokenHash)
		if err != nil {
			fatal(err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]bool{"expired": changed == 1})
	case "create-challenge":
		var userID int64
		if err := databaseHandle.QueryRowContext(ctx, "SELECT user_id FROM password_reset_tokens WHERE token_hash = ?", tokenHash).Scan(&userID); err != nil {
			fatal(fmt.Errorf("password reset token not found: %w", err))
		}
		_, err := databaseHandle.ExecContext(ctx, `INSERT INTO totp_login_challenges (token_hash, user_id, return_to, attempts_remaining, expires_at)
			VALUES (?, ?, '/account', 5, ?)
			ON CONFLICT(token_hash) DO UPDATE SET
				user_id = excluded.user_id,
				return_to = excluded.return_to,
				attempts_remaining = excluded.attempts_remaining,
				expires_at = excluded.expires_at`,
			challengeHash, userID, time.Now().UTC().Add(5*time.Minute).Format(time.RFC3339))
		if err != nil {
			fatal(err)
		}
		printJSON(map[string]bool{"pendingChallengeExists": pendingChallengeExists(ctx, databaseHandle, challengeHash)})
	case "challenge-status":
		printJSON(map[string]bool{"pendingChallengeExists": pendingChallengeExists(ctx, databaseHandle, challengeHash)})
	case "race":
		var userID int64
		if err := databaseHandle.QueryRowContext(ctx, "SELECT id FROM users WHERE email = ?", "grenda@example.com").Scan(&userID); err != nil {
			fatal(err)
		}
		store := passwordreset.NewStore(databaseHandle)
		raceToken, err := store.Create(ctx, userID)
		if err != nil {
			fatal(err)
		}
		type resetResult struct {
			reset bool
			err   error
		}
		start := make(chan struct{})
		results := make(chan resetResult, 2)
		var waitGroup sync.WaitGroup
		for range 2 {
			waitGroup.Go(func() {
				<-start
				reset, resetErr := store.ResetPassword(ctx, raceToken.Value, "password-reset-check-hash")
				results <- resetResult{reset: reset, err: resetErr}
			})
		}
		close(start)
		waitGroup.Wait()
		close(results)
		successes := 0
		failuresWithoutError := 0
		for result := range results {
			if result.err == nil && result.reset {
				successes++
			}
			if result.err == nil && !result.reset {
				failuresWithoutError++
			}
		}
		printJSON(map[string]bool{"atomicSingleUse": successes == 1 && failuresWithoutError == 1})
	}
}

func pendingChallengeExists(ctx context.Context, databaseHandle *sql.DB, challengeHash string) bool {
	var one int
	err := databaseHandle.QueryRowContext(ctx, "SELECT 1 FROM totp_login_challenges WHERE token_hash = ?", challengeHash).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		fatal(err)
	}
	return true
}

func printJSON(value map[string]bool) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
