package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/pquerna/otp/totp"
)

type result struct {
	ValidCodeAccepted         bool `json:"validCodeAccepted"`
	ReplayRejected            bool `json:"replayRejected"`
	SingleConsumptionRecorded bool `json:"singleConsumptionRecorded"`
}

type attempt struct {
	accepted bool
	err      error
}

func main() {
	ctx := context.Background()
	databasePath := os.Getenv("DATABASE_URL")
	if databasePath == "" {
		databasePath = "data/bearly-secure.sqlite"
	}
	databaseHandle, err := database.Open(ctx, databasePath)
	if err != nil {
		writeResult(result{})
		return
	}
	defer databaseHandle.Close()

	var userID int64
	var secret string
	if err := databaseHandle.QueryRowContext(ctx, "SELECT id, totp_secret FROM users WHERE email = ?", "wendy@example.com").Scan(&userID, &secret); err != nil {
		writeResult(result{})
		return
	}

	now := time.Now()
	if remainder := now.Unix() % 30; remainder >= 28 {
		time.Sleep(time.Duration(30-remainder)*time.Second + 50*time.Millisecond)
		now = time.Now()
	}
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		writeResult(result{})
		return
	}

	store := newMFAStore(databaseHandle)
	start := make(chan struct{})
	attempts := make(chan attempt, 2)
	for range 2 {
		go func() {
			<-start
			accepted, verifyErr := store.VerifyAndConsume(ctx, userID, code, secret)
			attempts <- attempt{accepted: accepted, err: verifyErr}
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

	var consumedStep sql.NullInt64
	if err := databaseHandle.QueryRowContext(ctx, "SELECT last_totp_step FROM users WHERE id = ?", userID).Scan(&consumedStep); err != nil {
		writeResult(result{})
		return
	}
	writeResult(result{
		ValidCodeAccepted:         acceptedCount >= 1,
		ReplayRejected:            acceptedCount == 1,
		SingleConsumptionRecorded: consumedStep.Valid && consumedStep.Int64 == now.Unix()/30,
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
