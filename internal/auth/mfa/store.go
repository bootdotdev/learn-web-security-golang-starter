package mfa

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net/url"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
	"github.com/bootdotdev/learn-web-security/internal/storage"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	challengeTTL                 = 5 * time.Minute
	challengeAttempts            = 5
	recoveryAttemptWindow        = 15 * time.Minute
	defaultBackupCodeCount       = 8
	totpPeriodSeconds      int64 = 30
)

type Challenge struct {
	UserID            int64
	ReturnTo          string
	AttemptsRemaining int64
	ExpiresAt         time.Time
	Token             string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
	keyring  *storage.Keyring
	now      func() time.Time
	random   io.Reader
}

func NewStore(database *sql.DB, keyring *storage.Keyring) *Store {
	return &Store{
		database: database,
		queries:  dbgen.New(database),
		keyring:  keyring,
		now:      time.Now,
		random:   rand.Reader,
	}
}

func (store *Store) StartEnrollment(ctx context.Context, userID int64, email string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Bearly Secure",
		AccountName: email,
		Period:      uint(totpPeriodSeconds),
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        store.random,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	if store.keyring == nil {
		if _, err := store.database.ExecContext(ctx, "UPDATE users SET pending_totp_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", key.Secret(), userID); err != nil {
			return "", "", fmt.Errorf("store pending TOTP secret: %w", err)
		}
	} else {
		encryptedSecret, err := store.keyring.Encrypt([]byte(key.Secret()))
		if err != nil {
			return "", "", fmt.Errorf("encrypt pending TOTP secret: %w", err)
		}
		if err := store.queries.SetPendingTOTPSecret(ctx, dbgen.SetPendingTOTPSecretParams{
			PendingTotpSecretEncrypted: &encryptedSecret,
			ID:                         userID,
		}); err != nil {
			return "", "", fmt.Errorf("store pending TOTP secret: %w", err)
		}
	}
	qrDataURL, err := qrDataURL(key)
	if err != nil {
		return "", "", err
	}
	return key.Secret(), qrDataURL, nil
}

func (store *Store) PendingEnrollment(ctx context.Context, userID int64, email string) (string, string, bool, error) {
	secret, found, err := store.decryptSecret(ctx, userID, true)
	if err != nil || !found {
		return "", "", found, err
	}
	key, err := keyFromSecret(email, secret)
	if err != nil {
		return "", "", false, fmt.Errorf("parse pending TOTP key: %w", err)
	}
	qrDataURL, err := qrDataURL(key)
	if err != nil {
		return "", "", false, err
	}
	return secret, qrDataURL, true, nil
}

func (store *Store) Secret(ctx context.Context, userID int64) (string, bool, error) {
	return store.decryptSecret(ctx, userID, false)
}

func (store *Store) Verify(code, secret string) bool {
	return verifyAt(code, secret, store.now())
}

func verifyAt(code, secret string, timestamp time.Time) bool {
	if code == "" {
		return false
	}
	valid, err := totp.ValidateCustom(code, secret, timestamp, totp.ValidateOpts{
		Period:    uint(totpPeriodSeconds),
		Skew:      0,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

func (store *Store) VerifyAndConsume(ctx context.Context, userID int64, code, secret string) (bool, error) {
	return verifyAt(code, secret, store.now()), nil
}

func (store *Store) ConfirmEnrollment(ctx context.Context, userID int64) ([]string, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin TOTP enrollment confirmation: %w", err)
	}
	defer transaction.Rollback()

	queries := store.queries.WithTx(transaction)
	if store.keyring == nil {
		if _, err := transaction.ExecContext(ctx, `
			UPDATE users
			SET totp_secret = pending_totp_secret,
				pending_totp_secret = NULL,
				last_totp_step = NULL,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, userID); err != nil {
			return nil, fmt.Errorf("confirm TOTP secret: %w", err)
		}
	} else if err := queries.ConfirmTOTPSecret(ctx, userID); err != nil {
		return nil, fmt.Errorf("confirm TOTP secret: %w", err)
	}
	backupCodes, err := generateBackupCodes(store.random, defaultBackupCodeCount)
	if err != nil {
		return nil, err
	}
	if err := queries.DeleteTOTPBackupCodesForUser(ctx, userID); err != nil {
		return nil, fmt.Errorf("delete prior TOTP backup codes: %w", err)
	}
	for _, backupCode := range backupCodes {
		if err := queries.CreateTOTPBackupCode(ctx, dbgen.CreateTOTPBackupCodeParams{
			UserID:   userID,
			CodeHash: hashToken(backupCode),
		}); err != nil {
			return nil, fmt.Errorf("store TOTP backup code: %w", err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return nil, fmt.Errorf("commit TOTP enrollment confirmation: %w", err)
	}
	return backupCodes, nil
}

func (store *Store) Clear(ctx context.Context, userID int64) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP reset: %w", err)
	}
	defer transaction.Rollback()
	queries := store.queries.WithTx(transaction)
	if err := queries.ClearTOTPSecrets(ctx, userID); err != nil {
		return fmt.Errorf("clear TOTP secrets: %w", err)
	}
	if err := queries.DeleteTOTPBackupCodesForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete TOTP backup codes: %w", err)
	}
	if err := queries.DeleteTOTPLoginChallengesForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete TOTP login challenges: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit TOTP reset: %w", err)
	}
	return nil
}

func (store *Store) CreateChallenge(ctx context.Context, userID int64, returnTo string) (Challenge, error) {
	now := store.now().UTC()
	if err := store.queries.PruneTOTPLoginChallenges(ctx, formatTimestamp(now)); err != nil {
		return Challenge{}, fmt.Errorf("prune TOTP login challenges: %w", err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(store.random, tokenBytes); err != nil {
		return Challenge{}, fmt.Errorf("generate TOTP login challenge: %w", err)
	}
	challenge := Challenge{
		UserID:            userID,
		ReturnTo:          returnTo,
		AttemptsRemaining: challengeAttempts,
		ExpiresAt:         now.Add(challengeTTL),
		Token:             base64.RawURLEncoding.EncodeToString(tokenBytes),
	}
	if err := store.queries.CreateTOTPLoginChallenge(ctx, dbgen.CreateTOTPLoginChallengeParams{
		TokenHash:         hashToken(challenge.Token),
		UserID:            challenge.UserID,
		ReturnTo:          challenge.ReturnTo,
		AttemptsRemaining: challenge.AttemptsRemaining,
		ExpiresAt:         formatTimestamp(challenge.ExpiresAt),
		CreatedAt:         formatTimestamp(now),
	}); err != nil {
		return Challenge{}, fmt.Errorf("create TOTP login challenge: %w", err)
	}
	return challenge, nil
}

func (store *Store) Challenge(ctx context.Context, token string) (Challenge, bool, error) {
	row, err := store.queries.GetTOTPLoginChallenge(ctx, hashToken(token))
	if errors.Is(err, sql.ErrNoRows) {
		return Challenge{}, false, nil
	}
	if err != nil {
		return Challenge{}, false, fmt.Errorf("find TOTP login challenge: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, row.ExpiresAt)
	if err != nil || row.AttemptsRemaining <= 0 || !store.now().Before(expiresAt) {
		if deleteErr := store.DeleteChallenge(ctx, token); deleteErr != nil {
			return Challenge{}, false, deleteErr
		}
		return Challenge{}, false, nil
	}
	return Challenge{
		UserID:            row.UserID,
		ReturnTo:          row.ReturnTo,
		AttemptsRemaining: row.AttemptsRemaining,
		ExpiresAt:         expiresAt,
		Token:             token,
	}, true, nil
}

func (store *Store) RecordChallengeFailure(ctx context.Context, token string) (bool, error) {
	attemptsRemaining, err := store.queries.RecordTOTPLoginChallengeFailure(ctx, dbgen.RecordTOTPLoginChallengeFailureParams{
		TokenHash: hashToken(token),
		Now:       formatTimestamp(store.now().UTC()),
	})
	if errors.Is(err, sql.ErrNoRows) || (err == nil && attemptsRemaining <= 0) {
		if deleteErr := store.DeleteChallenge(ctx, token); deleteErr != nil {
			return false, deleteErr
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("record TOTP login challenge failure: %w", err)
	}
	return false, nil
}

func (store *Store) DeleteChallenge(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if err := store.queries.DeleteTOTPLoginChallenge(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("delete TOTP login challenge: %w", err)
	}
	return nil
}

func (store *Store) ConsumeBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	var count int
	if err := store.database.QueryRowContext(ctx, "SELECT COUNT(*) FROM totp_backup_codes WHERE user_id = ? AND code_hash = ?", userID, hashToken(code)).Scan(&count); err != nil {
		return false, fmt.Errorf("find TOTP backup code: %w", err)
	}
	return count == 1, nil
}

func (store *Store) CountRecentRecoveryFailures(ctx context.Context, email string) (int64, error) {
	cutoff := formatTimestamp(store.now().UTC().Add(-recoveryAttemptWindow))
	if err := store.queries.PruneMFARecoveryAttempts(ctx, cutoff); err != nil {
		return 0, fmt.Errorf("prune MFA recovery attempts: %w", err)
	}
	count, err := store.queries.CountRecentMFARecoveryFailures(ctx, dbgen.CountRecentMFARecoveryFailuresParams{
		Email:  email,
		Cutoff: cutoff,
	})
	if err != nil {
		return 0, fmt.Errorf("count recent MFA recovery attempts: %w", err)
	}
	return count, nil
}

func (store *Store) RecordRecoveryAttempt(ctx context.Context, email string, userID *int64, succeeded bool) error {
	success := int64(0)
	if succeeded {
		success = 1
	}
	if err := store.queries.RecordMFARecoveryAttempt(ctx, dbgen.RecordMFARecoveryAttemptParams{
		Email:     email,
		UserID:    userID,
		Success:   success,
		CreatedAt: formatTimestamp(store.now().UTC()),
	}); err != nil {
		return fmt.Errorf("record MFA recovery attempt: %w", err)
	}
	return nil
}

func (store *Store) decryptSecret(ctx context.Context, userID int64, pending bool) (string, bool, error) {
	if store.keyring == nil {
		column := "totp_secret"
		if pending {
			column = "pending_totp_secret"
		}
		var secret *string
		err := store.database.QueryRowContext(ctx, "SELECT "+column+" FROM users WHERE id = ?", userID).Scan(&secret)
		if errors.Is(err, sql.ErrNoRows) || secret == nil {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("get TOTP secret: %w", err)
		}
		return *secret, true, nil
	}

	var encryptedSecret *string
	var err error
	if pending {
		encryptedSecret, err = store.queries.GetPendingTOTPSecret(ctx, userID)
	} else {
		encryptedSecret, err = store.queries.GetTOTPSecret(ctx, userID)
	}
	if errors.Is(err, sql.ErrNoRows) || encryptedSecret == nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("get encrypted TOTP secret: %w", err)
	}
	plaintext, err := store.keyring.Decrypt(*encryptedSecret)
	if err != nil {
		return "", false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	return string(plaintext), true, nil
}

func generateBackupCodes(randomSource io.Reader, count int) ([]string, error) {
	backupCodes := make([]string, count)
	for index := range backupCodes {
		codeBytes := make([]byte, 16)
		if _, err := io.ReadFull(randomSource, codeBytes); err != nil {
			return nil, fmt.Errorf("generate TOTP backup code: %w", err)
		}
		backupCodes[index] = hex.EncodeToString(codeBytes)
	}
	return backupCodes, nil
}

func qrDataURL(key *otp.Key) (string, error) {
	qrImage, err := key.Image(200, 200)
	if err != nil {
		return "", fmt.Errorf("generate TOTP QR code: %w", err)
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, qrImage); err != nil {
		return "", fmt.Errorf("encode TOTP QR code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(encoded.Bytes()), nil
}

func keyFromSecret(email, secret string) (*otp.Key, error) {
	parameters := url.Values{}
	parameters.Set("secret", secret)
	parameters.Set("issuer", "Bearly Secure")
	parameters.Set("period", "30")
	parameters.Set("algorithm", "SHA1")
	parameters.Set("digits", "6")
	keyURL := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/Bearly Secure:" + email,
		RawQuery: parameters.Encode(),
	}
	return otp.NewKeyFromURL(keyURL.String())
}

func hashToken(token string) string {
	tokenHash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(tokenHash[:])
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
