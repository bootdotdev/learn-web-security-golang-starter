package passwords

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

const MaxLength = 128

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	passwordHash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(passwordHash[:]), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if !ok {
		return false
	}
	candidateHash := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
}

func NeedsRehash(string) bool {
	return false
}
