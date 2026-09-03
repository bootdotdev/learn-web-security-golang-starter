package main

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database"
)

type result struct {
	SeededDocumentEncrypted   bool `json:"seededDocumentEncrypted"`
	SeededDocumentReadable    bool `json:"seededDocumentReadable"`
	IndividualUploadEncrypted bool `json:"individualUploadEncrypted"`
	IndividualUploadReadable  bool `json:"individualUploadReadable"`
	ArchiveImportEncrypted    bool `json:"archiveImportEncrypted"`
	ArchiveImportReadable     bool `json:"archiveImportReadable"`
	TamperedDocumentRejected  bool `json:"tamperedDocumentRejected"`
	FixturePolicyPreserved    bool `json:"fixturePolicyPreserved"`
}

type storedDocument struct {
	id          int64
	storagePath string
}

func main() {
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

	seeded, seededFound := findDocument(ctx, databaseConnection, "uploaded_files", "mystery-shack-tax-exemption.pdf")
	seededEncrypted := seededFound && encryptedAtRest(seeded.storagePath)
	mabelClient, err := authenticatedClient(ctx, "mabel@example.com")
	if err != nil {
		writeResult(result{})
		return
	}
	seededReadable := seededFound && signedDownloadMatches(ctx, mabelClient, seeded.id, []byte("%PDF"))
	individualName := fmt.Sprintf("encrypted-upload-%d.pdf", time.Now().UnixNano())
	individualContents := []byte("%PDF-1.7\nencrypted individual upload probe")
	individualStatus := submitUpload(ctx, mabelClient, "/account/tax-exemption/files", "document", individualName, individualContents)
	individual, individualFound := findDocument(ctx, databaseConnection, "uploaded_files", individualName)
	individualEncrypted := individualStatus == http.StatusFound && individualFound && encryptedAtRest(individual.storagePath)
	individualReadable := individualFound && signedDownloadMatches(ctx, mabelClient, individual.id, individualContents)
	tamperedRejected := individualFound && tamperedDownloadRejected(ctx, mabelClient, individual)

	archiveName := fmt.Sprintf("encrypted-archive-%d.pdf", time.Now().UnixNano())
	archiveContents := []byte("%PDF-1.7\nencrypted archive probe")
	archive, err := createArchive(archiveName, archiveContents)
	if err != nil {
		writeResult(result{})
		return
	}
	supportClient, err := authenticatedClient(ctx, "sancho@example.com")
	if err != nil || submitUpload(ctx, supportClient, "/support/tax-exemptions/import", "archive", archiveName+".zip", archive) != http.StatusSeeOther {
		writeResult(result{})
		return
	}
	imported, importedFound := findDocument(ctx, databaseConnection, "imported_tax_documents", archiveName)
	importedEncrypted := importedFound && encryptedAtRest(imported.storagePath)
	importedReadable := importedFound && downloadMatches(ctx, supportClient, "/support/files/imports/"+strconv.FormatInt(imported.id, 10)+"/download", archiveContents)

	fixtureContents, fixtureErr := os.ReadFile(filepath.Join("data", "fixtures", "mystery-shack-tax-exemption.pdf"))
	dockerfile, _ := os.ReadFile("Dockerfile")
	_, oldFixtureErr := os.Stat(filepath.Join("data", "uploads", "mystery-shack-tax-exemption.pdf"))
	writeResult(result{
		SeededDocumentEncrypted:   seededEncrypted,
		SeededDocumentReadable:    seededReadable,
		IndividualUploadEncrypted: individualEncrypted,
		IndividualUploadReadable:  individualReadable,
		ArchiveImportEncrypted:    importedEncrypted,
		ArchiveImportReadable:     importedReadable,
		TamperedDocumentRejected:  tamperedRejected,
		FixturePolicyPreserved:    fixtureErr == nil && bytes.HasPrefix(fixtureContents, []byte("%PDF")) && os.IsNotExist(oldFixtureErr) && bytes.Contains(dockerfile, []byte("data/fixtures")),
	})
}

func findDocument(ctx context.Context, databaseConnection *sql.DB, tableName, originalName string) (storedDocument, bool) {
	var document storedDocument
	err := databaseConnection.QueryRowContext(ctx, "SELECT id, storage_path FROM "+tableName+" WHERE original_name = ? ORDER BY id DESC LIMIT 1", originalName).Scan(&document.id, &document.storagePath)
	return document, err == nil
}

func encryptedAtRest(storagePath string) bool {
	contents, err := os.ReadFile(storagePath)
	if err != nil || filepath.Ext(storagePath) != ".enc" || bytes.Contains(contents, []byte("%PDF")) {
		return false
	}
	var envelope struct {
		KeyVersion string `json:"keyVersion"`
	}
	return json.Unmarshal(contents, &envelope) == nil && envelope.KeyVersion == "v1"
}

func tamperedDownloadRejected(ctx context.Context, client *http.Client, document storedDocument) bool {
	storedContents, err := os.ReadFile(document.storagePath)
	if err != nil {
		return false
	}
	var envelope map[string]any
	if json.Unmarshal(storedContents, &envelope) != nil {
		return false
	}
	ciphertext, ok := envelope["ciphertext"].(string)
	if !ok || len(ciphertext) == 0 {
		return false
	}
	if ciphertext[0] == 'A' {
		envelope["ciphertext"] = "B" + ciphertext[1:]
	} else {
		envelope["ciphertext"] = "A" + ciphertext[1:]
	}
	tamperedContents, err := json.Marshal(envelope)
	if err != nil || os.WriteFile(document.storagePath, tamperedContents, 0o600) != nil {
		return false
	}
	response, err := request(ctx, client, "/files/"+strconv.FormatInt(document.id, 10)+"/download")
	if err != nil {
		return false
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") == "" {
		return false
	}
	response, err = request(ctx, client, response.Header.Get("Location"))
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusInternalServerError
}

func authenticatedClient(ctx context.Context, email string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := submitForm(ctx, client, "/login", url.Values{
		"email": {email}, "password": {"password123"}, "returnTo": {"/"},
	})
	if err != nil || response.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in %s", email)
	}
	response.Body.Close()
	return client, nil
}

func signedDownloadMatches(ctx context.Context, client *http.Client, fileID int64, expectedPrefix []byte) bool {
	response, err := request(ctx, client, "/files/"+strconv.FormatInt(fileID, 10)+"/download")
	if err != nil {
		return false
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") == "" {
		return false
	}
	return downloadMatches(ctx, client, response.Header.Get("Location"), expectedPrefix)
}

func downloadMatches(ctx context.Context, client *http.Client, path string, expected []byte) bool {
	response, err := request(ctx, client, path)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	return err == nil && response.StatusCode == http.StatusOK && bytes.HasPrefix(contents, expected)
}

func createArchive(filename string, contents []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	part, err := writer.Create(filename)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(contents); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func submitUpload(ctx context.Context, client *http.Client, path, fieldName, filename string, contents []byte) int {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		return 0
	}
	_, _ = part.Write(contents)
	_ = writer.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin()+path, &body)
	if err != nil {
		return 0
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Origin", origin())
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}

func submitForm(ctx context.Context, client *http.Client, path string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin()+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin())
	return client.Do(request)
}

func request(ctx context.Context, client *http.Client, path string) (*http.Response, error) {
	target := path
	if strings.HasPrefix(path, "/") {
		target = origin() + path
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(request)
}

func origin() string {
	return strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
