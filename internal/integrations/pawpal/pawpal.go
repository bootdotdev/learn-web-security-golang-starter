package pawpal

import "fmt"

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(payload any) WebhookVerification {
	payloadRecord, _ := payload.(map[string]any)
	orderID, _ := payloadRecord["orderId"].(float64)
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
