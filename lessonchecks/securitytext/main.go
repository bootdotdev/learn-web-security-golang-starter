package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	applicationOrigin   = "http://localhost:3030"
	maximumResponseSize = 64 * 1024
)

type checkResult struct {
	OneExpiresField      bool `json:"oneExpiresField"`
	ExpiresIsRFC3339     bool `json:"expiresIsRfc3339"`
	ExpiresIsFuture      bool `json:"expiresIsFuture"`
	ExpiresWithinOneYear bool `json:"expiresWithinOneYear"`
}

func main() {
	result, err := checkSecurityText(context.Background(), http.DefaultClient, applicationOrigin)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

func checkSecurityText(ctx context.Context, httpClient *http.Client, origin string) (checkResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/.well-known/security.txt", nil)
	if err != nil {
		return checkResult{}, fmt.Errorf("create security.txt request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return checkResult{}, fmt.Errorf("request security.txt: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseSize))
	if err != nil {
		return checkResult{}, fmt.Errorf("read security.txt response: %w", err)
	}
	responseLines := strings.Split(strings.ReplaceAll(string(responseBody), "\r\n", "\n"), "\n")
	expiresValues := findFieldValues(responseLines, "Expires")
	checkedAt := time.Now().UTC()
	expiresAt, expiresIsRFC3339 := parseRFC3339(firstValue(expiresValues))

	return checkResult{
		OneExpiresField:      len(expiresValues) == 1,
		ExpiresIsRFC3339:     expiresIsRFC3339,
		ExpiresIsFuture:      expiresIsRFC3339 && expiresAt.After(checkedAt),
		ExpiresWithinOneYear: expiresIsRFC3339 && expiresAt.Before(checkedAt.AddDate(1, 0, 0)),
	}, nil
}

func findFieldValues(lines []string, fieldName string) []string {
	fieldValues := make([]string, 0, 1)
	for _, line := range lines {
		name, fieldValue, found := strings.Cut(line, ":")
		if found && strings.EqualFold(name, fieldName) {
			fieldValues = append(fieldValues, strings.TrimSpace(fieldValue))
		}
	}
	return fieldValues
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func parseRFC3339(value string) (time.Time, bool) {
	if len(value) > len("2006-01-02T") && value[10] == 't' {
		value = value[:10] + "T" + value[11:]
	}
	if strings.HasSuffix(value, "z") {
		value = value[:len(value)-1] + "Z"
	}
	parsedTime, err := time.Parse(time.RFC3339Nano, value)
	return parsedTime, err == nil
}
