package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/database"
)

var csrfPattern = regexp.MustCompile(`name="csrfToken"\s+type="hidden"\s+value="([^"]+)"`)

type result struct {
	InvalidKeyRejected           bool `json:"invalidKeyRejected"`
	InvalidKeyLeftOrderPending   bool `json:"invalidKeyLeftOrderPending"`
	MalformedPayloadRejected     bool `json:"malformedPayloadRejected"`
	MalformedPayloadLeftPending  bool `json:"malformedPayloadLeftOrderPending"`
	UnapprovedStatusRejected     bool `json:"unapprovedStatusRejected"`
	UnapprovedStatusLeftPending  bool `json:"unapprovedStatusLeftOrderPending"`
	ApprovedWebhookAccepted      bool `json:"approvedWebhookAccepted"`
	OrderMarkedPaid              bool `json:"orderMarkedPaid"`
	ServerCalculatedTotal        bool `json:"serverCalculatedTotal"`
	NoRawPaymentColumns          bool `json:"noRawPaymentColumns"`
	WebhookKeyAbsentFromLogs     bool `json:"webhookKeyAbsentFromLogs"`
	CheckoutLogKeepsOrderContext bool `json:"checkoutLogKeepsOrderContext"`
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
	pawPalAPIKey := environmentValue("PAWPAL_API_KEY")
	client, err := authenticatedClient(ctx)
	if err != nil || pawPalAPIKey == "" {
		writeResult(result{})
		return
	}
	csrfToken, err := findCSRFToken(ctx, client)
	if err != nil {
		writeResult(result{})
		return
	}
	resetCart(ctx, databaseConnection)
	checkoutResponse, err := submitForm(ctx, client, "/checkout", checkoutValues(csrfToken))
	if err != nil {
		writeResult(result{})
		return
	}
	checkoutResponse.Body.Close()
	orderID, err := redirectedOrderID(checkoutResponse)
	if err != nil {
		writeResult(result{})
		return
	}

	invalidKeyStatus := submitWebhook(ctx, "wrong-key", fmt.Sprintf(`{"orderId":%d,"status":"approved"}`, orderID))
	statusAfterInvalidKey, _ := readOrder(ctx, databaseConnection, orderID)
	malformedStatus := submitWebhook(ctx, pawPalAPIKey, fmt.Sprintf(`{"customerId":%d,"status":"approved"}`, orderID))
	statusAfterMalformed, _ := readOrder(ctx, databaseConnection, orderID)
	unapprovedStatus := submitWebhook(ctx, pawPalAPIKey, fmt.Sprintf(`{"orderId":%d,"status":"declined"}`, orderID))
	statusAfterUnapproved, _ := readOrder(ctx, databaseConnection, orderID)
	approvedStatus := submitWebhook(ctx, pawPalAPIKey, fmt.Sprintf(`{"orderId":%d,"status":"approved"}`, orderID))
	statusAfterApproval, totalCents := readOrder(ctx, databaseConnection, orderID)
	noRawPaymentColumns := rawPaymentColumnsAbsent(ctx, databaseConnection)
	keyAbsent, logKeepsContext := inspectLog(orderID, pawPalAPIKey)

	writeResult(result{
		InvalidKeyRejected:           invalidKeyStatus == http.StatusUnauthorized,
		InvalidKeyLeftOrderPending:   statusAfterInvalidKey == "pending",
		MalformedPayloadRejected:     malformedStatus == http.StatusBadRequest,
		MalformedPayloadLeftPending:  statusAfterMalformed == "pending",
		UnapprovedStatusRejected:     unapprovedStatus == http.StatusBadRequest,
		UnapprovedStatusLeftPending:  statusAfterUnapproved == "pending",
		ApprovedWebhookAccepted:      approvedStatus == http.StatusNoContent,
		OrderMarkedPaid:              statusAfterApproval == "paid",
		ServerCalculatedTotal:        totalCents == 2499,
		NoRawPaymentColumns:          noRawPaymentColumns,
		WebhookKeyAbsentFromLogs:     keyAbsent,
		CheckoutLogKeepsOrderContext: logKeepsContext,
	})
}

func redirectedOrderID(response *http.Response) (int64, error) {
	if response.StatusCode != http.StatusFound {
		return 0, fmt.Errorf("checkout status: %d", response.StatusCode)
	}
	location, err := response.Location()
	if err != nil || location.Scheme != "https" || location.Host != "pawpal.example" || location.Path != "/checkout" {
		return 0, fmt.Errorf("invalid PawPal redirect")
	}
	orderID, err := strconv.ParseInt(location.Query().Get("orderId"), 10, 64)
	if err != nil || orderID <= 0 {
		return 0, fmt.Errorf("invalid order ID")
	}
	return orderID, nil
}

func readOrder(ctx context.Context, databaseConnection *sql.DB, orderID int64) (string, int64) {
	var status string
	var totalCents int64
	_ = databaseConnection.QueryRowContext(ctx, "SELECT status, total_cents FROM orders WHERE id = ?", orderID).Scan(&status, &totalCents)
	return status, totalCents
}

func rawPaymentColumnsAbsent(ctx context.Context, databaseConnection *sql.DB) bool {
	rows, err := databaseConnection.QueryContext(ctx, "PRAGMA table_info(orders)")
	if err != nil {
		return false
	}
	defer rows.Close()
	forbidden := map[string]bool{"card_number": true, "cardNumber": true, "cvv": true, "expiry": true, "payment_token": true, "paymentToken": true}
	for rows.Next() {
		var columnID int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey) != nil || forbidden[name] {
			return false
		}
	}
	return rows.Err() == nil
}

func inspectLog(orderID int64, pawPalAPIKey string) (bool, bool) {
	contents, err := os.ReadFile(filepath.Join("data", "bearly-secure.log"))
	if err != nil {
		return false, false
	}
	keyAbsent := !strings.Contains(string(contents), pawPalAPIKey)
	logKeepsContext := false
	scanner := bufio.NewScanner(strings.NewReader(string(contents)))
	for scanner.Scan() {
		var record map[string]any
		if json.Unmarshal(scanner.Bytes(), &record) == nil && record["event"] == "checkout_started" && record["orderId"] == float64(orderID) {
			_, hasCardNumber := record["cardNumber"]
			_, hasPaymentToken := record["paymentToken"]
			logKeepsContext = record["totalCents"] == float64(2499) && !hasCardNumber && !hasPaymentToken
		}
	}
	return keyAbsent, logKeepsContext
}

func submitWebhook(ctx context.Context, apiKey, body string) int {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin()+"/integrations/pawpal/webhook", strings.NewReader(body))
	if err != nil {
		return 0
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-PawPal-Key", apiKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}

func resetCart(ctx context.Context, databaseConnection *sql.DB) {
	_, _ = databaseConnection.ExecContext(ctx, "DELETE FROM cart_items WHERE user_id = 1")
	_, _ = databaseConnection.ExecContext(ctx, "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (1, 1, 1)")
}

func checkoutValues(csrfToken string) url.Values {
	return url.Values{
		"csrfToken": {csrfToken}, "shippingName": {"Payment Bear"},
		"shippingAddress": {"12 Hosted Lane"}, "shippingCity": {"Lockbox"},
		"shippingRegion": {"VA"}, "shippingPostalCode": {"22030"},
		"amountCents": {"1"},
	}
}

func authenticatedClient(ctx context.Context) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := submitForm(ctx, client, "/login", url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/"},
	})
	if err != nil || response.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in")
	}
	response.Body.Close()
	return client, nil
}

func findCSRFToken(ctx context.Context, client *http.Client) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin()+"/", nil)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	match := csrfPattern.FindSubmatch(body)
	if err != nil || len(match) != 2 {
		return "", fmt.Errorf("find CSRF token")
	}
	return string(match[1]), nil
}

func submitForm(ctx context.Context, client *http.Client, requestPath string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin()+requestPath, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin())
	return client.Do(request)
}

func environmentValue(name string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	file, err := os.Open(".env")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found && strings.TrimSpace(key) == name {
			return strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return ""
}

func origin() string {
	return strings.TrimRight(environmentValue("APP_ORIGIN"), "/")
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
