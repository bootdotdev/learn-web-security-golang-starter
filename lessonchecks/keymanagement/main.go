package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

const probeSource = `package keymanagementprobe

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/config"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

func TestLessonKeyManagementPolicy(t *testing.T) {
	var firstKey, secondKey [32]byte
	for index := range firstKey {
		firstKey[index] = 0x11
		secondKey[index] = 0x22
	}
	oldKeyring, err := storage.NewKeyring("v1", map[string][32]byte{"v1": firstKey})
	if err != nil {
		t.Fatal(err)
	}
	oldPayload, err := oldKeyring.Encrypt([]byte("rotation probe"))
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeyring, err := storage.NewKeyring("v2", map[string][32]byte{"v1": firstKey, "v2": secondKey})
	if err != nil || rotatedKeyring.ActiveVersion() != "v2" {
		t.Fatal("active key version was not retained")
	}
	newPayload, err := rotatedKeyring.Encrypt([]byte("current probe"))
	if err != nil || !strings.Contains(newPayload, "\"keyVersion\":\"v2\"") {
		t.Fatal("new ciphertext did not record the active version")
	}
	decryptedOld, err := rotatedKeyring.Decrypt(oldPayload)
	if err != nil || !bytes.Equal(decryptedOld, []byte("rotation probe")) {
		t.Fatal("retained key could not decrypt old ciphertext")
	}
	currentOnly, err := storage.NewKeyring("v2", map[string][32]byte{"v2": secondKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := currentOnly.Decrypt(oldPayload); err == nil {
		t.Fatal("unknown key version was accepted")
	}
	var missingKeyring *storage.Keyring
	if _, err := missingKeyring.Encrypt([]byte("missing keyring")); err == nil {
		t.Fatal("encryption without a configured keyring was accepted")
	}
	if _, err := missingKeyring.Decrypt(oldPayload); err == nil {
		t.Fatal("decryption without a configured keyring was accepted")
	}
	if _, err := oldKeyring.Decrypt("not-json"); err == nil {
		t.Fatal("malformed encrypted payload was accepted")
	}

	baseEnvironment := map[string]string{
		"PAWPAL_API_KEY": "pawpal-test-key",
		"DOWNLOAD_SIGNING_KEY": strings.Repeat("ab", 32),
		"DATA_ENCRYPTION_ACTIVE_VERSION": "v2",
		"DATA_ENCRYPTION_KEY_V1": strings.Repeat("11", 32),
		"DATA_ENCRYPTION_KEY_V2": strings.Repeat("22", 32),
	}
	parsed, err := config.Parse(baseEnvironment, ".")
	if err != nil || parsed.ActiveEncryptionKeyVersion != "v2" || len(parsed.EncryptionKeys) != 2 {
		t.Fatal("valid key configuration was rejected")
	}
	missing := cloneEnvironment(baseEnvironment)
	delete(missing, "DATA_ENCRYPTION_ACTIVE_VERSION")
	if _, err := config.Parse(missing, "."); err == nil {
		t.Fatal("missing active key version was accepted")
	}
	missingAll := cloneEnvironment(baseEnvironment)
	delete(missingAll, "DATA_ENCRYPTION_ACTIVE_VERSION")
	delete(missingAll, "DATA_ENCRYPTION_KEY_V1")
	delete(missingAll, "DATA_ENCRYPTION_KEY_V2")
	if _, err := config.Parse(missingAll, "."); err == nil {
		t.Fatal("missing encryption key configuration was accepted")
	}
	malformed := cloneEnvironment(baseEnvironment)
	malformed["DATA_ENCRYPTION_KEY_V2"] = "not-a-key"
	if _, err := config.Parse(malformed, "."); err == nil {
		t.Fatal("malformed encryption key was accepted")
	}

	runtimeConfig, err := config.Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	runtimeConfigValue := reflect.ValueOf(runtimeConfig)
	activeVersionValue := runtimeConfigValue.FieldByName("ActiveEncryptionKeyVersion")
	encryptionKeysValue := runtimeConfigValue.FieldByName("EncryptionKeys")
	if !activeVersionValue.IsValid() || !encryptionKeysValue.IsValid() {
		t.Fatal("encryption key configuration was not available")
	}
	activeVersion, activeVersionOK := activeVersionValue.Interface().(string)
	encryptionKeys, encryptionKeysOK := encryptionKeysValue.Interface().(map[string][32]byte)
	if !activeVersionOK || !encryptionKeysOK {
		t.Fatal("encryption key configuration had the wrong type")
	}
	runtimeKeyring, err := storage.NewKeyring(activeVersion, encryptionKeys)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	databaseConnection, err := database.Open(ctx, runtimeConfig.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer databaseConnection.Close()
	var userID int64
	var plaintext sql.NullString
	var encrypted sql.NullString
	if err := databaseConnection.QueryRowContext(ctx, "SELECT id, totp_secret, totp_secret_encrypted FROM users WHERE email = ?", "wendy@example.com").Scan(&userID, &plaintext, &encrypted); err != nil {
		t.Fatal(err)
	}
	if plaintext.Valid || !encrypted.Valid {
		t.Fatal("seeded TOTP secret was not migrated")
	}
	decryptedSecret, err := runtimeKeyring.Decrypt(encrypted.String)
	if err != nil || string(decryptedSecret) != "KXDYU6DRQPRQXLPY236SJJXPNGHQJVUF" {
		t.Fatal("migrated TOTP secret could not be decrypted")
	}

	store := mfa.NewStore(databaseConnection, runtimeKeyring)
	secret, _, err := store.StartEnrollment(ctx, 1, "mabel@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var pendingPlaintext sql.NullString
	var pendingEncrypted sql.NullString
	if err := databaseConnection.QueryRowContext(ctx, "SELECT pending_totp_secret, pending_totp_secret_encrypted FROM users WHERE id = ?", 1).Scan(&pendingPlaintext, &pendingEncrypted); err != nil {
		t.Fatal(err)
	}
	decryptedPending, err := runtimeKeyring.Decrypt(pendingEncrypted.String)
	if err != nil || pendingPlaintext.Valid || !pendingEncrypted.Valid || string(decryptedPending) != secret {
		t.Fatal("new pending TOTP secret was not encrypted")
	}
	readPending, _, found, err := store.PendingEnrollment(ctx, 1, "mabel@example.com")
	if err != nil || !found || readPending != secret {
		t.Fatal("encrypted pending TOTP secret could not be read")
	}
}

func cloneEnvironment(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for name, value := range source {
		cloned[name] = value
	}
	return cloned
}
`

type result struct {
	KeyManagementPolicySatisfied bool `json:"keyManagementPolicySatisfied"`
}

func main() {
	probeDirectory := filepath.Join("lessonchecks", "keymanagementprobe")
	if err := os.MkdirAll(probeDirectory, 0o755); err != nil {
		writeResult(false)
		return
	}
	defer os.RemoveAll(probeDirectory)
	probePath := filepath.Join(probeDirectory, "keymanagement_lessoncheck_test.go")
	if err := os.WriteFile(probePath, []byte(probeSource), 0o600); err != nil {
		writeResult(false)
		return
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./lessonchecks/keymanagementprobe", "-run", "^TestLessonKeyManagementPolicy$")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	writeResult(command.Run() == nil)
}

func writeResult(satisfied bool) {
	_ = json.NewEncoder(os.Stdout).Encode(result{KeyManagementPolicySatisfied: satisfied})
}
