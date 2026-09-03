package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

const warehouseDailyQuota = 5

type Key struct {
	ID    int64
	Name  string
	Scope string
}

type Quota struct {
	Allowed           bool
	Limit             int64
	Used              int64
	Remaining         int64
	ResetsAt          string
	RetryAfterSeconds int64
}

type Store struct {
	queries *dbgen.Queries
	now     func() time.Time
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database), now: time.Now}
}

func (store *Store) FindKey(ctx context.Context, rawKey string) (Key, bool, error) {
	if rawKey == "" {
		return Key{}, false, nil
	}
	digest := sha256.Sum256([]byte(rawKey))
	row, err := store.queries.GetActiveAPIKeyByHash(ctx, hex.EncodeToString(digest[:]))
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, false, nil
	}
	if err != nil {
		return Key{}, false, fmt.Errorf("find API key: %w", err)
	}
	return Key{ID: row.ID, Name: row.Name, Scope: row.Scope}, true, nil
}

func (store *Store) ConsumeQuota(ctx context.Context, keyID int64) (Quota, error) {
	now := store.now().UTC()
	periodStart := now.Format("2006-01-02")
	requestCount, err := store.queries.ConsumeAPIKeyQuota(ctx, dbgen.ConsumeAPIKeyQuotaParams{ApiKeyID: keyID, PeriodStart: periodStart})
	allowed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Quota{}, fmt.Errorf("consume API key quota: %w", err)
	}
	if !allowed {
		requestCount, err = store.queries.GetAPIKeyUsage(ctx, dbgen.GetAPIKeyUsageParams{ApiKeyID: keyID, PeriodStart: periodStart})
		if err != nil {
			return Quota{}, fmt.Errorf("read API key quota: %w", err)
		}
	}
	reset := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	retryAfterSeconds := int64(math.Max(1, math.Ceil(reset.Sub(now).Seconds())))
	return Quota{
		Allowed: allowed, Limit: warehouseDailyQuota, Used: requestCount,
		Remaining: max(int64(0), warehouseDailyQuota-requestCount),
		ResetsAt:  reset.Format("2006-01-02T15:04:05.000Z"), RetryAfterSeconds: retryAfterSeconds,
	}, nil
}
