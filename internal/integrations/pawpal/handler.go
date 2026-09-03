package pawpal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
)

const maxWebhookBodyBytes int64 = 64 * 1024

type Handler struct {
	orderStore *orders.Store
	logger     *logging.Logger
	apiKey     string
}

func NewHandler(orderStore *orders.Store, logger *logging.Logger, apiKey string) *Handler {
	return &Handler{orderStore: orderStore, logger: logger, apiKey: apiKey}
}

func (handler *Handler) Webhook(responseWriter http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxWebhookBodyBytes)
	decoder := json.NewDecoder(request.Body)
	var payload any
	if err := decoder.Decode(&payload); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(responseWriter, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	verification := VerifyWebhook(payload)
	switch verification.Outcome {
	case WebhookUnauthorized:
		http.Error(responseWriter, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	case WebhookMalformed:
		http.Error(responseWriter, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	approved, err := handler.orderStore.ApprovePawPalOrder(request.Context(), verification.OrderID)
	if err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if !approved {
		http.Error(responseWriter, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	_ = handler.logger.Event("pawpal_payment_approved", map[string]any{"orderId": verification.OrderID})
	responseWriter.WriteHeader(http.StatusNoContent)
}
