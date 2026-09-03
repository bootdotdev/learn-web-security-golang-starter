package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
	"github.com/bootdotdev/learn-web-security/internal/uploads"
)

const seededTaxDocumentName = "mystery-shack-tax-exemption.pdf"

type updateTaxDocumentStorage func(context.Context, *dbgen.Queries, uploads.StoredDocument) error

func MigrateSensitiveDataAtRest(ctx context.Context, database *sql.DB, keyring *Keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory string) error {
	if err := MigrateTOTPSecrets(ctx, database, keyring); err != nil {
		return err
	}
	return migrateTaxDocuments(ctx, database, keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory)
}

func MigrateTOTPSecrets(ctx context.Context, database *sql.DB, keyring *Keyring) error {
	if keyring == nil {
		return nil
	}
	queries := dbgen.New(database)
	rows, err := queries.ListLegacyTOTPSecrets(ctx)
	if err != nil {
		return fmt.Errorf("list plaintext TOTP secrets: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}

	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP secret migration: %w", err)
	}
	defer transaction.Rollback()

	transactionQueries := queries.WithTx(transaction)
	for _, row := range rows {
		activeSecret, err := encryptMigratedSecret(row.TotpSecret, row.TotpSecretEncrypted, keyring)
		if err != nil {
			return fmt.Errorf("encrypt TOTP secret for user %d: %w", row.ID, err)
		}
		pendingSecret, err := encryptMigratedSecret(row.PendingTotpSecret, row.PendingTotpSecretEncrypted, keyring)
		if err != nil {
			return fmt.Errorf("encrypt pending TOTP secret for user %d: %w", row.ID, err)
		}
		if err := transactionQueries.MigrateTOTPSecrets(ctx, dbgen.MigrateTOTPSecretsParams{
			TotpSecretEncrypted:        activeSecret,
			PendingTotpSecretEncrypted: pendingSecret,
			ID:                         row.ID,
		}); err != nil {
			return fmt.Errorf("migrate TOTP secrets for user %d: %w", row.ID, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit TOTP secret migration: %w", err)
	}
	return nil
}

func encryptMigratedSecret(plaintext, encrypted *string, keyring *Keyring) (*string, error) {
	if plaintext == nil {
		return encrypted, nil
	}
	serialized, err := keyring.Encrypt([]byte(*plaintext))
	if err != nil {
		return nil, err
	}
	return &serialized, nil
}

func migrateTaxDocuments(ctx context.Context, database *sql.DB, keyring *Keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory string) error {
	if keyring == nil {
		return nil
	}
	queries := dbgen.New(database)
	uploadedRows, err := queries.ListPlaintextUploadedFiles(ctx)
	if err != nil {
		return fmt.Errorf("list plaintext uploaded tax documents: %w", err)
	}
	for _, row := range uploadedRows {
		updateStorage := func(ctx context.Context, queries *dbgen.Queries, stored uploads.StoredDocument) error {
			return queries.UpdateUploadedFileStorage(ctx, dbgen.UpdateUploadedFileStorageParams{
				StoragePath: stored.StoragePath,
				ContentType: stored.ContentType,
				ID:          row.ID,
			})
		}
		if err := migrateTaxDocument(ctx, database, keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory, row.ID, row.OriginalName, row.StoragePath, updateStorage); err != nil {
			return err
		}
	}

	importedRows, err := queries.ListPlaintextImportedTaxDocuments(ctx)
	if err != nil {
		return fmt.Errorf("list plaintext imported tax documents: %w", err)
	}
	for _, row := range importedRows {
		updateStorage := func(ctx context.Context, queries *dbgen.Queries, stored uploads.StoredDocument) error {
			return queries.UpdateImportedTaxDocumentStorage(ctx, dbgen.UpdateImportedTaxDocumentStorageParams{
				StoragePath: stored.StoragePath,
				ContentType: stored.ContentType,
				ID:          row.ID,
			})
		}
		if err := migrateTaxDocument(ctx, database, keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory, row.ID, row.OriginalName, row.StoragePath, updateStorage); err != nil {
			return err
		}
	}
	return nil
}

func migrateTaxDocument(ctx context.Context, database *sql.DB, keyring *Keyring, uploadDirectory, bulkImportDirectory, fixtureDirectory string, documentID int64, originalName, storagePath string, updateStorage updateTaxDocumentStorage) error {
	configuredPath, err := filepath.Abs(storagePath)
	if err != nil {
		return fmt.Errorf("resolve plaintext tax document path: %w", err)
	}
	configuredExists := fileExists(configuredPath)
	if configuredExists && !isRuntimeDocumentPath(uploadDirectory, configuredPath) && !isRuntimeDocumentPath(bulkImportDirectory, configuredPath) {
		return fmt.Errorf("unsafe plaintext tax document path: %s", storagePath)
	}

	fixturePath := filepath.Join(fixtureDirectory, seededTaxDocumentName)
	sourcePath := configuredPath
	removeSource := configuredExists
	if !configuredExists {
		if originalName != seededTaxDocumentName || !fileExists(fixturePath) {
			return fmt.Errorf("missing plaintext tax document: %s", storagePath)
		}
		sourcePath = fixturePath
		removeSource = false
	}
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read plaintext tax document: %w", err)
	}
	fileMode := fs.FileMode(0o644)
	if sourceInfo, err := os.Stat(sourcePath); err == nil {
		fileMode = sourceInfo.Mode().Perm()
	}

	stored, valid, err := uploads.StoreDocument(contents, uploadDirectory, keyring)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid plaintext tax document: %s", storagePath)
	}
	if filepath.Ext(stored.StoragePath) != ".enc" {
		return uploads.RemoveDocument(stored.StoragePath)
	}

	transaction, err := database.BeginTx(ctx, nil)
	if err != nil {
		return discardMigratedDocument(stored.StoragePath, fmt.Errorf("begin tax document migration: %w", err))
	}
	defer transaction.Rollback()
	if err := updateStorage(ctx, dbgen.New(transaction), stored); err != nil {
		return discardMigratedDocument(stored.StoragePath, fmt.Errorf("migrate tax document %d: %w", documentID, err))
	}
	if removeSource {
		if err := os.Remove(configuredPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return discardMigratedDocument(stored.StoragePath, fmt.Errorf("remove plaintext tax document: %w", err))
		}
	}
	if err := transaction.Commit(); err != nil {
		migrationErr := fmt.Errorf("commit tax document migration: %w", err)
		if removeSource {
			migrationErr = errors.Join(migrationErr, restorePlaintextDocument(configuredPath, contents, fileMode))
		}
		return discardMigratedDocument(stored.StoragePath, migrationErr)
	}
	return nil
}

func discardMigratedDocument(storagePath string, migrationErr error) error {
	if err := uploads.RemoveDocument(storagePath); err != nil {
		return errors.Join(migrationErr, err)
	}
	return migrationErr
}

func restorePlaintextDocument(storagePath string, contents []byte, fileMode fs.FileMode) error {
	file, err := os.OpenFile(storagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("restore plaintext tax document: %w", err)
	}
	_, writeErr := file.Write(contents)
	closeErr := file.Close()
	if writeErr != nil {
		return errors.Join(fmt.Errorf("restore plaintext tax document: %w", writeErr), os.Remove(storagePath))
	}
	if closeErr != nil {
		return errors.Join(fmt.Errorf("restore plaintext tax document: %w", closeErr), os.Remove(storagePath))
	}
	return nil
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	return err == nil && !fileInfo.IsDir()
}

func isRuntimeDocumentPath(uploadDirectory, path string) bool {
	relativePath, err := filepath.Rel(uploadDirectory, path)
	if err != nil {
		return false
	}
	return relativePath != "" && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator))
}
