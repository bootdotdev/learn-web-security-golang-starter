package uploads

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/identifiers"
)

const (
	maxArchiveEntries           = 100
	maxArchiveUncompressedBytes = 20 * 1024 * 1024
)

type ArchiveImportError struct {
	Message    string
	StatusCode int
}

func (err *ArchiveImportError) Error() string {
	return err.Message
}

type ExtractedTaxDocument struct {
	OriginalName string
	StoragePath  string
	ContentType  string
}

type ExtractedTaxDocumentArchive struct {
	ImportDirectory     string
	extractionDirectory string
	Documents           []ExtractedTaxDocument
}

type plannedArchiveEntry struct {
	directory   bool
	destination string
	contents    string
	encrypted   bool
	document    ExtractedTaxDocument
}

func ExtractTaxDocumentArchive(encryptionKeyring Keyring, contents []byte, extractionDirectory string) (ExtractedTaxDocumentArchive, error) {
	archiveReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return ExtractedTaxDocumentArchive{}, &ArchiveImportError{Message: "Choose a valid ZIP archive.", StatusCode: 400}
	}
	if len(archiveReader.File) > maxArchiveEntries {
		return ExtractedTaxDocumentArchive{}, &ArchiveImportError{Message: fmt.Sprintf("Archive contains more than %d entries.", maxArchiveEntries), StatusCode: 413}
	}
	var uncompressedBytes uint64
	for _, entry := range archiveReader.File {
		if entry.UncompressedSize64 > uint64(maxArchiveUncompressedBytes) || uncompressedBytes > uint64(maxArchiveUncompressedBytes)-entry.UncompressedSize64 {
			return ExtractedTaxDocumentArchive{}, &ArchiveImportError{Message: "Archive expands beyond 20 MiB.", StatusCode: 413}
		}
		uncompressedBytes += entry.UncompressedSize64
	}

	identifier, err := identifiers.NewUUID()
	if err != nil {
		return ExtractedTaxDocumentArchive{}, err
	}
	importDirectory := filepath.Join(extractionDirectory, identifier)
	plannedEntries := make([]plannedArchiveEntry, 0, len(archiveReader.File))
	for _, entry := range archiveReader.File {
		entryDestination := filepath.Join(importDirectory, entry.Name)
		if isIgnoredArchiveEntry(entry.Name) {
			continue
		}
		if strings.HasSuffix(entry.Name, "/") {
			plannedEntries = append(plannedEntries, plannedArchiveEntry{directory: true, destination: entryDestination})
			continue
		}
		entryContents, err := readArchiveEntry(entry)
		if err != nil {
			return ExtractedTaxDocumentArchive{}, &ArchiveImportError{Message: "Choose a valid ZIP archive.", StatusCode: 400}
		}
		contentType := mime.TypeByExtension(filepath.Ext(entry.Name))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		storedContents, encrypted, err := encryptDocument(entryContents, encryptionKeyring)
		if err != nil {
			return ExtractedTaxDocumentArchive{}, err
		}
		storagePath := entryDestination
		if encrypted {
			storagePath += ".enc"
		}
		plannedEntries = append(plannedEntries, plannedArchiveEntry{
			destination: storagePath, contents: storedContents, encrypted: encrypted,
			document: ExtractedTaxDocument{OriginalName: entry.Name, StoragePath: storagePath, ContentType: contentType},
		})
	}

	archive := ExtractedTaxDocumentArchive{ImportDirectory: importDirectory, extractionDirectory: extractionDirectory}
	for _, entry := range plannedEntries {
		if !entry.directory {
			archive.Documents = append(archive.Documents, entry.document)
		}
	}
	if len(archive.Documents) == 0 {
		return archive, nil
	}
	if err := os.MkdirAll(importDirectory, 0o755); err != nil {
		return ExtractedTaxDocumentArchive{}, fmt.Errorf("create archive import directory: %w", err)
	}
	for _, entry := range plannedEntries {
		if entry.directory {
			if err := os.MkdirAll(entry.destination, 0o755); err != nil {
				return discardArchiveAfterWriteFailure(archive, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(entry.destination), 0o755); err != nil {
			return discardArchiveAfterWriteFailure(archive, err)
		}
		fileMode := os.FileMode(0o644)
		fileFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		if entry.encrypted {
			fileMode = 0o600
			fileFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
		}
		file, err := os.OpenFile(entry.destination, fileFlags, fileMode)
		if err != nil {
			return discardArchiveAfterWriteFailure(archive, err)
		}
		_, writeErr := file.WriteString(entry.contents)
		closeErr := file.Close()
		if writeErr != nil {
			return discardArchiveAfterWriteFailure(archive, writeErr)
		}
		if closeErr != nil {
			return discardArchiveAfterWriteFailure(archive, closeErr)
		}
	}
	return archive, nil
}

func isIgnoredArchiveEntry(entryName string) bool {
	if entryName == "__MACOSX" || strings.HasPrefix(entryName, "__MACOSX/") {
		return true
	}

	baseName := entryName
	if separator := strings.LastIndexByte(entryName, '/'); separator >= 0 {
		baseName = entryName[separator+1:]
	}
	baseName = strings.ToLower(baseName)
	return baseName == ".ds_store" ||
		strings.HasPrefix(baseName, "._") ||
		baseName == "thumbs.db" ||
		baseName == "desktop.ini"
}

func DiscardExtractedTaxDocumentArchive(archive ExtractedTaxDocumentArchive) error {
	relativePath, err := filepath.Rel(archive.extractionDirectory, archive.ImportDirectory)
	if err != nil || relativePath == "" || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) || strings.Contains(relativePath, string(filepath.Separator)) || filepath.IsAbs(relativePath) {
		return fmt.Errorf("refuse to remove path outside the import directory: %s", archive.ImportDirectory)
	}
	if err := os.RemoveAll(archive.ImportDirectory); err != nil {
		return fmt.Errorf("remove archive import directory: %w", err)
	}
	return nil
}

func readArchiveEntry(entry *zip.File) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	contents, err := io.ReadAll(io.LimitReader(reader, int64(entry.UncompressedSize64)+1))
	if err != nil || uint64(len(contents)) != entry.UncompressedSize64 {
		return nil, errors.New("read archive entry")
	}
	return contents, nil
}

func discardArchiveAfterWriteFailure(archive ExtractedTaxDocumentArchive, err error) (ExtractedTaxDocumentArchive, error) {
	if discardErr := DiscardExtractedTaxDocumentArchive(archive); discardErr != nil {
		return ExtractedTaxDocumentArchive{}, errors.Join(err, discardErr)
	}
	return ExtractedTaxDocumentArchive{}, err
}
