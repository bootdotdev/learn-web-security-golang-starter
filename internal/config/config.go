package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort                = 3030
	defaultAttackerLabPort     = 4040
	defaultAppOrigin           = "http://localhost:3030"
	defaultDatabaseFilename    = "bearly-secure.sqlite"
	MaxRequestBodyBytes        = 32 * 1024
	MaxUploadBytes             = 1024 * 1024
	MaxPublicProductResults    = 50
	activeEncryptionVersionEnv = "DATA_ENCRYPTION_ACTIVE_VERSION"
	encryptionKeyEnvPrefix     = "DATA_ENCRYPTION_KEY_"
)

type Config struct {
	PawPalAPIKey               string
	AppOrigin                  string
	Port                       int
	DatabasePath               string
	AcornFulfillmentDelay      time.Duration
	MaxRequestBodyBytes        int64
	MaxUploadBytes             int64
	MaxPublicProductResults    int
	ActiveEncryptionKeyVersion string
	EncryptionKeys             map[string][32]byte
}

type AttackerLabConfig struct {
	Port int
}

func Load(workingDirectory string) (Config, error) {
	return Parse(processEnvironment(), workingDirectory)
}

func LoadAttackerLab(workingDirectory string) (AttackerLabConfig, error) {
	return ParseAttackerLab(processEnvironment())
}

func Parse(environment map[string]string, workingDirectory string) (Config, error) {
	port, err := parseNonNegativeInteger(valueOrDefault(environment, "PORT", strconv.Itoa(defaultPort)), "PORT")
	if err != nil {
		return Config{}, err
	}
	if port > 65_535 {
		return Config{}, errors.New("PORT must be no greater than 65535")
	}
	appOrigin, err := parseOrigin(valueOrDefault(environment, "APP_ORIGIN", defaultAppOrigin))
	if err != nil {
		return Config{}, err
	}

	acornFulfillmentDelay, err := parseDelay(valueOrDefault(environment, "ACORN_FULFILLMENT_DELAY_MS", "0"))
	if err != nil {
		return Config{}, err
	}

	activeEncryptionKeyVersion, encryptionKeys, err := parseOptionalEncryptionKeys(environment)
	if err != nil {
		return Config{}, err
	}

	databasePath := environment["DATABASE_URL"]
	if databasePath == "" {
		databasePath = filepath.Join(workingDirectory, "data", defaultDatabaseFilename)
	}

	return Config{
		PawPalAPIKey:               "bs_test_pawpal_starter_key",
		AppOrigin:                  appOrigin,
		Port:                       port,
		DatabasePath:               databasePath,
		AcornFulfillmentDelay:      acornFulfillmentDelay,
		MaxRequestBodyBytes:        MaxRequestBodyBytes,
		MaxUploadBytes:             MaxUploadBytes,
		MaxPublicProductResults:    MaxPublicProductResults,
		ActiveEncryptionKeyVersion: activeEncryptionKeyVersion,
		EncryptionKeys:             encryptionKeys,
	}, nil
}

func ParseAttackerLab(environment map[string]string) (AttackerLabConfig, error) {
	port, err := parseNonNegativeInteger(valueOrDefault(environment, "ATTACKER_LAB_PORT", strconv.Itoa(defaultAttackerLabPort)), "ATTACKER_LAB_PORT")
	if err != nil {
		return AttackerLabConfig{}, err
	}
	if port > 65_535 {
		return AttackerLabConfig{}, errors.New("ATTACKER_LAB_PORT must be no greater than 65535")
	}
	return AttackerLabConfig{Port: port}, nil
}

func processEnvironment() map[string]string {
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found {
			environment[name] = value
		}
	}
	return environment
}

func valueOrDefault(environment map[string]string, name, fallback string) string {
	if value := environment[name]; value != "" {
		return value
	}
	return fallback
}

func parseNonNegativeInteger(value, name string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return parsed, nil
}

func parseOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("APP_ORIGIN must be an absolute URL")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func parseDelay(value string) (time.Duration, error) {
	milliseconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(milliseconds) || math.IsInf(milliseconds, 0) || milliseconds < 0 {
		return 0, errors.New("ACORN_FULFILLMENT_DELAY_MS must be a non-negative number")
	}
	if milliseconds > float64(math.MaxInt64)/float64(time.Millisecond) {
		return 0, errors.New("ACORN_FULFILLMENT_DELAY_MS is too large")
	}
	return time.Duration(milliseconds * float64(time.Millisecond)), nil
}

func parseOptionalEncryptionKeys(environment map[string]string) (string, map[string][32]byte, error) {
	_, hasActiveVersion := environment[activeEncryptionVersionEnv]
	hasEncryptionKey := false
	for name := range environment {
		if strings.HasPrefix(name, encryptionKeyEnvPrefix) {
			hasEncryptionKey = true
			break
		}
	}
	if !hasActiveVersion && !hasEncryptionKey {
		return "", nil, nil
	}
	return parseEncryptionKeys(environment)
}

func parseEncryptionKeys(environment map[string]string) (string, map[string][32]byte, error) {
	configuredVersion := environment[activeEncryptionVersionEnv]
	if configuredVersion == "" {
		return "", nil, fmt.Errorf("missing required environment variable: %s", activeEncryptionVersionEnv)
	}
	activeVersion, err := normalizeEncryptionVersion(configuredVersion)
	if err != nil {
		return "", nil, err
	}

	keys := make(map[string][32]byte)
	for name, value := range environment {
		if !strings.HasPrefix(name, encryptionKeyEnvPrefix) {
			continue
		}
		version, err := normalizeEncryptionVersion(strings.TrimPrefix(name, encryptionKeyEnvPrefix))
		if err != nil {
			return "", nil, err
		}
		if _, exists := keys[version]; exists {
			return "", nil, fmt.Errorf("duplicate encryption key version: %s", version)
		}
		key, err := parseEncryptionKey(value, name)
		if err != nil {
			return "", nil, err
		}
		keys[version] = key
	}
	if _, exists := keys[activeVersion]; !exists {
		return "", nil, fmt.Errorf("no encryption key configured for active version: %s", activeVersion)
	}
	return activeVersion, keys, nil
}

func parseEncryptionKey(value, name string) ([32]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("%s must be exactly 64 hexadecimal characters", name)
	}
	return [32]byte(decoded), nil
}

func normalizeEncryptionVersion(version string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(version))
	if normalized == "" {
		return "", fmt.Errorf("invalid encryption key version: %s", version)
	}
	for index, character := range normalized {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if character != '_' || index == 0 || index == len(normalized)-1 || normalized[index-1] == '_' {
			return "", fmt.Errorf("invalid encryption key version: %s", version)
		}
	}
	return normalized, nil
}
