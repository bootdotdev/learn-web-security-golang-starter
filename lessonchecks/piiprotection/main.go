package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
)

type result struct {
	ShippingEncryptedAtRest bool `json:"shippingEncryptedAtRest"`
	InternalNotesExcludePII bool `json:"internalNotesExcludePII"`
	CentralPolicyRedactsPII bool `json:"centralPolicyRedactsPII"`
}

func main() {
	if len(os.Args) != 2 {
		writeResult(result{})
		return
	}
	orderID, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil || orderID <= 0 {
		writeResult(result{})
		return
	}

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

	var encryptedShipping sql.NullString
	var adminNotes string
	if err := databaseConnection.QueryRowContext(
		ctx,
		"SELECT shipping_details_encrypted, admin_notes FROM orders WHERE id = ?",
		orderID,
	).Scan(&encryptedShipping, &adminNotes); err != nil {
		writeResult(result{})
		return
	}

	var envelope struct {
		KeyVersion string `json:"keyVersion"`
	}
	encryptedAtRest := encryptedShipping.Valid &&
		json.Unmarshal([]byte(encryptedShipping.String), &envelope) == nil &&
		envelope.KeyVersion == "v1" &&
		!containsAny(encryptedShipping.String, "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030")

	writeResult(result{
		ShippingEncryptedAtRest: encryptedAtRest,
		InternalNotesExcludePII: adminNotes == "Awaiting PawPal payment.",
		CentralPolicyRedactsPII: centralPolicyRedactsPII(),
	})
}

func centralPolicyRedactsPII() bool {
	directory, err := os.MkdirTemp("", "pii-redaction-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(directory)
	logPath := filepath.Join(directory, "probe.log")
	logger, err := logging.Open(logPath)
	if err != nil {
		return false
	}
	fields := map[string]any{
		"email": "customer@example.com", "shippingName": "Cipher Bear",
		"shippingAddress": "12 Encryption Lane", "shippingCity": "Lockbox",
		"shippingRegion": "VA", "shippingPostalCode": "22030",
		"originalName": "customer-tax-document.pdf", "userId": 42,
	}
	if logger.Event("pii_probe", fields) != nil || logger.Close() != nil {
		return false
	}
	contents, err := os.ReadFile(logPath)
	if err != nil || containsAny(string(contents), "customer@example.com", "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030", "customer-tax-document.pdf") {
		return false
	}
	var record map[string]any
	if json.Unmarshal(contents, &record) != nil || record["userId"] != float64(42) {
		return false
	}
	for name := range fields {
		if name != "userId" && record[name] != "[REDACTED]" {
			return false
		}
	}
	return true
}

func containsAny(value string, expected ...string) bool {
	for _, item := range expected {
		if strings.Contains(value, item) {
			return true
		}
	}
	return false
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
