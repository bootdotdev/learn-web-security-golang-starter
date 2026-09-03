//lint:file-ignore U1000 Some code in this file is used later

package storage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var keyVersionPattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

type Keyring struct {
	activeVersion string
	keys          map[string][32]byte
	randomSource  io.Reader
}

type versionedEncryptedPayload struct {
	KeyVersion string
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

type serializedEncryptedPayload struct {
	KeyVersion string `json:"keyVersion"`
	Nonce      string `json:"nonce"`
	AuthTag    string `json:"authTag"`
	Ciphertext string `json:"ciphertext"`
}

func NewKeyring(activeVersion string, keys map[string][32]byte) (*Keyring, error) {
	activeVersion = strings.ToLower(strings.TrimSpace(activeVersion))
	if !keyVersionPattern.MatchString(activeVersion) {
		return nil, fmt.Errorf("invalid encryption key version: %s", activeVersion)
	}
	keyCopies := make(map[string][32]byte, len(keys))
	for version, key := range keys {
		normalizedVersion := strings.ToLower(strings.TrimSpace(version))
		if !keyVersionPattern.MatchString(normalizedVersion) {
			return nil, fmt.Errorf("invalid encryption key version: %s", version)
		}
		if _, exists := keyCopies[normalizedVersion]; exists {
			return nil, fmt.Errorf("duplicate encryption key version: %s", normalizedVersion)
		}
		keyCopies[normalizedVersion] = key
	}
	if _, exists := keyCopies[activeVersion]; !exists {
		return nil, fmt.Errorf("no encryption key configured for active version: %s", activeVersion)
	}
	return &Keyring{activeVersion: activeVersion, keys: keyCopies, randomSource: rand.Reader}, nil
}

func (keyring *Keyring) ActiveVersion() string {
	return keyring.activeVersion
}

func (keyring *Keyring) Encrypt(plaintext []byte) (string, error) {
	return string(plaintext), nil
}

func (keyring *Keyring) Decrypt(serialized string) ([]byte, error) {
	return []byte(serialized), nil
}

func requireKeyring(keyring *Keyring) (*Keyring, error) {
	if keyring == nil {
		return nil, errors.New("data encryption requires a configured keyring")
	}
	return keyring, nil
}

func serializeEncryptedPayload(payload versionedEncryptedPayload) (string, error) {
	serialized, err := json.Marshal(serializedEncryptedPayload{
		KeyVersion: payload.KeyVersion,
		Nonce:      base64.StdEncoding.EncodeToString(payload.Nonce),
		AuthTag:    base64.StdEncoding.EncodeToString(payload.AuthTag),
		Ciphertext: base64.StdEncoding.EncodeToString(payload.Ciphertext),
	})
	if err != nil {
		return "", fmt.Errorf("serialize encrypted payload: %w", err)
	}
	return string(serialized), nil
}

func deserializeEncryptedPayload(serialized string) (versionedEncryptedPayload, error) {
	var serializedPayload serializedEncryptedPayload
	if err := json.Unmarshal([]byte(serialized), &serializedPayload); err != nil {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	keyVersion := strings.ToLower(strings.TrimSpace(serializedPayload.KeyVersion))
	if !keyVersionPattern.MatchString(keyVersion) {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	nonce, err := decodeBase64(serializedPayload.Nonce)
	if err != nil || len(nonce) != 12 {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	authTag, err := decodeBase64(serializedPayload.AuthTag)
	if err != nil || len(authTag) != 16 {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	ciphertext, err := decodeBase64(serializedPayload.Ciphertext)
	if err != nil {
		return versionedEncryptedPayload{}, errors.New("invalid serialized encrypted payload")
	}
	return versionedEncryptedPayload{
		KeyVersion: keyVersion,
		Nonce:      nonce,
		AuthTag:    authTag,
		Ciphertext: ciphertext,
	}, nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid base64")
	}
	return decoded, nil
}
