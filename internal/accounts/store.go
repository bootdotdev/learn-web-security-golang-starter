package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

const defaultSessionTTL = 30 * 24 * time.Hour

var ErrEmailExists = errors.New("an account already exists for that email")

func NormalizeEmail(email string) string {
	return email
}

type User struct {
	ID             int64
	Email          string
	DisplayName    string
	Role           string
	PasswordHash   string
	HasTOTP        bool
	HasPendingTOTP bool
	CreatedAt      string
	UpdatedAt      string
}

type Session struct {
	UserID              int64
	CSRFToken           string
	ExpiresAt           time.Time
	RevokedAt           *string
	LastAuthenticatedAt string
	CreatedAt           string
	Token               string
}

type CurrentSession struct {
	Session Session
	User    User
}

type Store struct {
	queries *dbgen.Queries
	now     func() time.Time
	random  io.Reader
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database), now: time.Now, random: rand.Reader}
}

func (store *Store) FindUserByEmail(ctx context.Context, email string) (User, bool, error) {
	row, err := store.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, fmt.Errorf("find user by email: %w", err)
	}
	return User{
		ID:             row.ID,
		Email:          row.Email,
		DisplayName:    row.DisplayName,
		Role:           row.Role,
		PasswordHash:   row.PasswordHash,
		HasTOTP:        row.HasTotp == 1,
		HasPendingTOTP: row.HasPendingTotp == 1,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}, true, nil
}

func (store *Store) FindUserByID(ctx context.Context, userID int64) (User, bool, error) {
	row, err := store.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, fmt.Errorf("find user by ID: %w", err)
	}
	return User{
		ID:             row.ID,
		Email:          row.Email,
		DisplayName:    row.DisplayName,
		Role:           row.Role,
		PasswordHash:   row.PasswordHash,
		HasTOTP:        row.HasTotp == 1,
		HasPendingTOTP: row.HasPendingTotp == 1,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}, true, nil
}

func (store *Store) CreateCustomer(ctx context.Context, email, displayName, passwordHash string) (User, error) {
	userID, err := store.queries.CreateCustomer(ctx, dbgen.CreateCustomerParams{
		Email:        email,
		DisplayName:  displayName,
		PasswordHash: passwordHash,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrEmailExists
		}
		return User{}, fmt.Errorf("create customer: %w", err)
	}
	user, found, err := store.FindUserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, errors.New("created customer was not found")
	}
	return user, nil
}

func (store *Store) UpdatePasswordHash(ctx context.Context, userID int64, passwordHash string) error {
	if err := store.queries.UpdateUserPasswordHash(ctx, dbgen.UpdateUserPasswordHashParams{PasswordHash: passwordHash, ID: userID}); err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	return nil
}

func (store *Store) UpdateEmail(ctx context.Context, userID int64, email string) error {
	_, err := store.queries.UpdateUserEmail(ctx, dbgen.UpdateUserEmailParams{Email: email, ID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrEmailExists
	}
	if err != nil {
		return fmt.Errorf("update user email: %w", err)
	}
	return nil
}

func (store *Store) CreateSession(ctx context.Context, userID int64) (Session, error) {
	now := store.now().UTC()
	expiresAt := now.Add(defaultSessionTTL)
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(store.random, tokenBytes); err != nil {
		return Session{}, fmt.Errorf("generate session token: %w", err)
	}
	csrfBytes := make([]byte, 32)
	if _, err := io.ReadFull(store.random, csrfBytes); err != nil {
		return Session{}, fmt.Errorf("generate CSRF token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	csrfToken := base64.RawURLEncoding.EncodeToString(csrfBytes)
	nowISO := formatTimestamp(now)
	if err := store.queries.CreateSession(ctx, dbgen.CreateSessionParams{
		TokenHash:           HashSessionToken(token),
		UserID:              userID,
		CsrfToken:           csrfToken,
		ExpiresAt:           formatTimestamp(expiresAt),
		LastAuthenticatedAt: nowISO,
		CreatedAt:           nowISO,
	}); err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}
	return Session{
		UserID:              userID,
		CSRFToken:           csrfToken,
		ExpiresAt:           expiresAt,
		LastAuthenticatedAt: nowISO,
		CreatedAt:           nowISO,
		Token:               token,
	}, nil
}

func (store *Store) CurrentSession(ctx context.Context, token string) (CurrentSession, bool, error) {
	if token == "" {
		return CurrentSession{}, false, nil
	}
	row, err := store.queries.GetSessionByTokenHash(ctx, HashSessionToken(token))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CurrentSession{}, false, nil
		}
		return CurrentSession{}, false, fmt.Errorf("find session: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, row.ExpiresAt)
	if err != nil || !store.now().Before(expiresAt) {
		return CurrentSession{}, false, nil
	}
	user, found, err := store.FindUserByID(ctx, row.UserID)
	if err != nil || !found {
		return CurrentSession{}, false, err
	}
	return CurrentSession{
		Session: Session{
			UserID:              row.UserID,
			CSRFToken:           row.CsrfToken,
			ExpiresAt:           expiresAt,
			RevokedAt:           row.RevokedAt,
			LastAuthenticatedAt: row.LastAuthenticatedAt,
			CreatedAt:           row.CreatedAt,
			Token:               token,
		},
		User: user,
	}, true, nil
}

func (store *Store) RevokeSession(ctx context.Context, token string) error {
	revokedAt := formatTimestamp(store.now().UTC())
	if err := store.queries.RevokeSession(ctx, dbgen.RevokeSessionParams{
		RevokedAt: &revokedAt,
		TokenHash: HashSessionToken(token),
	}); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (store *Store) CartQuantities(ctx context.Context, userID int64) (map[int64]int64, error) {
	rows, err := store.queries.ListCartQuantities(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list cart quantities: %w", err)
	}
	quantities := make(map[int64]int64, len(rows))
	for _, row := range rows {
		quantities[row.ProductID] = row.Quantity
	}
	return quantities, nil
}

func HashSessionToken(token string) string {
	tokenHash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(tokenHash[:])
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
