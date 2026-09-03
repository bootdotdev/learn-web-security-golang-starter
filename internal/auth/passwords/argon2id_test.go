package passwords

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeAndParseArgon2idHash(t *testing.T) {
	originalHash := argon2idHash{
		version:     19,
		memoryKiB:   19 * 1024,
		iterations:  2,
		parallelism: 1,
		salt:        []byte("0123456789abcdef"),
		derivedKey:  bytes.Repeat([]byte{0x42}, 32),
	}
	encodedHash := encodeArgon2idHash(originalHash)
	parsedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		t.Fatal("parseArgon2idHash() rejected a valid encoded hash")
	}
	if parsedHash.version != originalHash.version ||
		parsedHash.memoryKiB != originalHash.memoryKiB ||
		parsedHash.iterations != originalHash.iterations ||
		parsedHash.parallelism != originalHash.parallelism ||
		!bytes.Equal(parsedHash.salt, originalHash.salt) ||
		!bytes.Equal(parsedHash.derivedKey, originalHash.derivedKey) {
		t.Fatal("parsed Argon2id hash did not match the encoded values")
	}
}

func TestParseArgon2idHashRejectsMalformedValues(t *testing.T) {
	validSalt := "MDEyMzQ1Njc4OWFiY2RlZg"
	validDerivedKey := strings.Repeat("QkJC", 10) + "QkI"
	testCases := []string{
		"not-a-hash",
		"$argon2i$v=19$m=19456,t=2,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=0$m=19456,t=2,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=019$m=19456,t=2,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$m=019456,t=2,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$t=2,m=19456,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$m=262145,t=2,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$m=19456,t=101,p=1$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$m=19456,t=2,p=65$" + validSalt + "$" + validDerivedKey,
		"$argon2id$v=19$m=19456,t=2,p=1$invalid*$" + validDerivedKey,
		"$argon2id$v=19$m=19456,t=2,p=1$" + validSalt[:4] + "\n" + validSalt[4:] + "$" + validDerivedKey,
		"$argon2id$v=19$m=19456,t=2,p=1$" + validSalt + "$invalid*",
	}
	for _, encodedHash := range testCases {
		if _, ok := parseArgon2idHash(encodedHash); ok {
			t.Fatalf("parseArgon2idHash() accepted %q", encodedHash)
		}
	}
}
