package passwords

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

const (
	minimumArgon2idSaltLength       = 8
	maximumArgon2idSaltLength       = 1024
	minimumArgon2idDerivedKeyLength = 16
	maximumArgon2idDerivedKeyLength = 1024
	maximumArgon2idMemoryKiB        = 256 * 1024
	maximumArgon2idIterations       = 100
	maximumArgon2idParallelism      = 64
)

type argon2idHash struct {
	version     int
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	derivedKey  []byte
}

func encodeArgon2idHash(passwordHash argon2idHash) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		passwordHash.version,
		passwordHash.memoryKiB,
		passwordHash.iterations,
		passwordHash.parallelism,
		base64.RawStdEncoding.EncodeToString(passwordHash.salt),
		base64.RawStdEncoding.EncodeToString(passwordHash.derivedKey),
	)
}

func parseArgon2idHash(encodedHash string) (argon2idHash, bool) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || !strings.HasPrefix(parts[2], "v=") {
		return argon2idHash{}, false
	}
	version, versionOK := parseCanonicalUint(strings.TrimPrefix(parts[2], "v="), strconv.IntSize)
	if !versionOK || version == 0 {
		return argon2idHash{}, false
	}

	parameterParts := strings.Split(parts[3], ",")
	if len(parameterParts) != 3 {
		return argon2idHash{}, false
	}
	memoryValue, memoryOK := strings.CutPrefix(parameterParts[0], "m=")
	iterationValue, iterationOK := strings.CutPrefix(parameterParts[1], "t=")
	parallelismValue, parallelismOK := strings.CutPrefix(parameterParts[2], "p=")
	if !memoryOK || !iterationOK || !parallelismOK {
		return argon2idHash{}, false
	}
	memory, memoryValid := parseCanonicalUint(memoryValue, 32)
	if !memoryValid || memory == 0 || memory > maximumArgon2idMemoryKiB {
		return argon2idHash{}, false
	}
	iterationCount, iterationValid := parseCanonicalUint(iterationValue, 32)
	if !iterationValid || iterationCount == 0 || iterationCount > maximumArgon2idIterations {
		return argon2idHash{}, false
	}
	parallelismCount, parallelismValid := parseCanonicalUint(parallelismValue, 8)
	if !parallelismValid || parallelismCount == 0 || parallelismCount > maximumArgon2idParallelism {
		return argon2idHash{}, false
	}

	salt, saltValid := decodeArgon2idBase64(parts[4])
	if !saltValid || len(salt) < minimumArgon2idSaltLength || len(salt) > maximumArgon2idSaltLength {
		return argon2idHash{}, false
	}
	derivedKey, derivedKeyValid := decodeArgon2idBase64(parts[5])
	if !derivedKeyValid || len(derivedKey) < minimumArgon2idDerivedKeyLength || len(derivedKey) > maximumArgon2idDerivedKeyLength {
		return argon2idHash{}, false
	}

	return argon2idHash{
		version:     int(version),
		memoryKiB:   uint32(memory),
		iterations:  uint32(iterationCount),
		parallelism: uint8(parallelismCount),
		salt:        salt,
		derivedKey:  derivedKey,
	}, true
}

func parseCanonicalUint(value string, bitSize int) (uint64, bool) {
	parsedValue, err := strconv.ParseUint(value, 10, bitSize)
	return parsedValue, err == nil && strconv.FormatUint(parsedValue, 10) == value
}

func decodeArgon2idBase64(value string) ([]byte, bool) {
	decodedValue, err := base64.RawStdEncoding.Strict().DecodeString(value)
	return decodedValue, err == nil && base64.RawStdEncoding.EncodeToString(decodedValue) == value
}

func decodeLegacyHash(encodedHash string) ([]byte, bool) {
	if len(encodedHash) != sha256.Size*2 {
		return nil, false
	}
	decodedHash, err := hex.DecodeString(encodedHash)
	return decodedHash, err == nil
}
