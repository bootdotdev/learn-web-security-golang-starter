package passwordreset

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

const tokenTTL = 30 * 24 * time.Hour

type Token struct {
	ID        int64
	UserID    int64
	ExpiresAt time.Time
	UsedAt    *string
	Value     string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
	now      func() time.Time
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database), now: time.Now}
}

func (store *Store) Create(ctx context.Context, userID int64) (Token, error) {
	now := store.now().UTC()
	value := fmt.Sprintf("reset-%d-%d", userID, now.UnixNano())
	expiresAt := now.Add(tokenTTL)
	if err := store.queries.CreatePasswordResetToken(ctx, dbgen.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: hashToken(value),
		ExpiresAt: formatTimestamp(expiresAt),
	}); err != nil {
		return Token{}, fmt.Errorf("create password reset token: %w", err)
	}
	token, found, err := store.Validate(ctx, value)
	if err != nil {
		return Token{}, err
	}
	if !found {
		return Token{}, errors.New("created password reset token was not found")
	}
	token.Value = value
	return token, nil
}

func (store *Store) Validate(ctx context.Context, value string) (Token, bool, error) {
	row, err := store.queries.GetPasswordResetToken(ctx, hashToken(value))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, fmt.Errorf("find password reset token: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, row.ExpiresAt)
	if err != nil || row.UsedAt != nil || !store.now().Before(expiresAt) {
		return Token{}, false, nil
	}
	return Token{ID: row.ID, UserID: row.UserID, ExpiresAt: expiresAt, UsedAt: row.UsedAt, Value: value}, true, nil
}

func (store *Store) ResetPassword(ctx context.Context, value, passwordHash string) (bool, error) {
	now := formatTimestamp(store.now().UTC())
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin password reset: %w", err)
	}
	defer transaction.Rollback()
	queries := store.queries.WithTx(transaction)
	userID, err := queries.ConsumePasswordResetToken(ctx, dbgen.ConsumePasswordResetTokenParams{
		Now:       &now,
		TokenHash: hashToken(value),
	})
	if errors.Is(err, sql.ErrNoRows) {
		if commitErr := transaction.Commit(); commitErr != nil {
			return false, fmt.Errorf("commit unused password reset: %w", commitErr)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume password reset token: %w", err)
	}
	result, err := queries.ResetUserPasswordHash(ctx, dbgen.ResetUserPasswordHashParams{
		PasswordHash: passwordHash,
		Now:          now,
		UserID:       userID,
	})
	if err != nil {
		return false, fmt.Errorf("reset user password: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count reset users: %w", err)
	}
	if rowsAffected != 1 {
		return false, errors.New("password reset user was not found")
	}
	if err := queries.ConsumeRemainingPasswordResetTokens(ctx, dbgen.ConsumeRemainingPasswordResetTokensParams{Now: &now, UserID: userID}); err != nil {
		return false, fmt.Errorf("consume remaining password reset tokens: %w", err)
	}
	if err := queries.RevokeUserSessions(ctx, dbgen.RevokeUserSessionsParams{Now: &now, UserID: userID}); err != nil {
		return false, fmt.Errorf("revoke user sessions: %w", err)
	}
	if err := queries.DeleteTOTPLoginChallengesForUser(ctx, userID); err != nil {
		return false, fmt.Errorf("delete TOTP login challenges: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return false, fmt.Errorf("commit password reset: %w", err)
	}
	return true, nil
}

func hashToken(value string) string {
	return value
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
