package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"

	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/database"
)

const seededBackupCode = "a6f31c8d94e2b7504d8a1f3c6b9e2075"

type result struct {
	BackupCodeAcceptedOnce bool `json:"backupCodeAcceptedOnce"`
	BackupCodeConsumed     bool `json:"backupCodeConsumed"`
}

type attempt struct {
	accepted bool
	err      error
}

func main() {
	ctx := context.Background()
	databaseHandle, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		writeResult(result{})
		return
	}
	defer databaseHandle.Close()
	var userID int64
	if err := databaseHandle.QueryRowContext(ctx, "SELECT id FROM users WHERE email = ?", "wendy@example.com").Scan(&userID); err != nil {
		writeResult(result{})
		return
	}

	store := newMFAStore(databaseHandle)
	start := make(chan struct{})
	attempts := make(chan attempt, 2)
	for range 2 {
		go func() {
			<-start
			accepted, consumeErr := store.ConsumeBackupCode(ctx, userID, seededBackupCode)
			attempts <- attempt{accepted: accepted, err: consumeErr}
		}()
	}
	close(start)
	acceptedCount := 0
	for range 2 {
		attempt := <-attempts
		if attempt.err != nil {
			writeResult(result{})
			return
		}
		if attempt.accepted {
			acceptedCount++
		}
	}

	var usedAt sql.NullString
	if err := databaseHandle.QueryRowContext(ctx, "SELECT used_at FROM totp_backup_codes WHERE user_id = ?", userID).Scan(&usedAt); err != nil {
		writeResult(result{})
		return
	}
	writeResult(result{
		BackupCodeAcceptedOnce: acceptedCount == 1,
		BackupCodeConsumed:     usedAt.Valid,
	})
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}

func newMFAStore(databaseHandle *sql.DB) *mfa.Store {
	constructor := reflect.ValueOf(mfa.NewStore)
	arguments := []reflect.Value{reflect.ValueOf(databaseHandle)}
	for index := 1; index < constructor.Type().NumIn(); index++ {
		arguments = append(arguments, reflect.Zero(constructor.Type().In(index)))
	}
	return constructor.Call(arguments)[0].Interface().(*mfa.Store)
}
