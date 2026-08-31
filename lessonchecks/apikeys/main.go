package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database"
)

const seededWarehouseKey = "bs_whsec_8f2d1b7a4c6e9d0f3a5b"

type result struct {
	SeededKeyStoredAsHash bool `json:"seededKeyStoredAsHash"`
}

func main() {
	ctx := context.Background()
	databaseHandle, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{})
		return
	}
	defer databaseHandle.Close()
	output := result{}
	seededDigest := sha256.Sum256([]byte(seededWarehouseKey))
	var storedHash string
	if err := databaseHandle.QueryRowContext(ctx, "SELECT key_hash FROM api_keys WHERE name = ?", "Warehouse Fulfillment Integration").Scan(&storedHash); err == nil {
		output.SeededKeyStoredAsHash = storedHash == hex.EncodeToString(seededDigest[:]) && storedHash != seededWarehouseKey
	}

	wrongScopeKey := "bs_catalog_scope_check"
	revokedKey := "bs_revoked_warehouse_check"
	insertKey(ctx, databaseHandle, "Catalog Check", wrongScopeKey, "catalog:read", nil)
	revokedAt := time.Now().UTC().Format(time.RFC3339)
	insertKey(ctx, databaseHandle, "Revoked Warehouse Check", revokedKey, "orders:read", &revokedAt)

	_ = json.NewEncoder(os.Stdout).Encode(output)
}

func insertKey(ctx context.Context, databaseHandle *sql.DB, name, rawKey, scope string, revokedAt *string) {
	digest := sha256.Sum256([]byte(rawKey))
	_, _ = databaseHandle.ExecContext(ctx, `
		INSERT INTO api_keys (name, key_hash, scope, revoked_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key_hash) DO UPDATE SET
			name = excluded.name,
			scope = excluded.scope,
			revoked_at = excluded.revoked_at
	`, name, hex.EncodeToString(digest[:]), scope, revokedAt)
}
