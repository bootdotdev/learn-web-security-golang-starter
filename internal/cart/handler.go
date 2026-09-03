package cart

import (
	"math"
	"net/http"
	"strconv"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type itemView struct {
	Item
	Availability Availability
	Maximum      int64
}

type pageView struct {
	templates.Page
	DisplayName     string
	CSRFToken       string
	Items           []itemView
	HasItems        bool
	CheckoutBlocked bool
	TotalCents      int64
}

type Handler struct {
	store        *Store
	accountStore *accounts.Store
	renderer     *templates.Renderer
	logger       *logging.Logger
}

func NewHandler(store *Store, accountStore *accounts.Store, renderer *templates.Renderer, logger *logging.Logger) *Handler {
	return &Handler{store: store, accountStore: accountStore, renderer: renderer, logger: logger}
}

func (handler *Handler) Page(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	items, err := handler.store.ListItems(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	view := pageView{
		Title:       "Your Cart",
		DisplayName: current.User.DisplayName,
		CSRFToken:   current.Session.CSRFToken,
		Items:       makeItemViews(items),
		HasItems:    len(items) > 0,
	}
	for _, item := range items {
		view.TotalCents += item.LineTotalCents
		if ItemAvailability(item) != Available {
			view.CheckoutBlocked = true
		}
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "cart", view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) AddItem(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	productValue, productErr := httpx.FormValue(request, "productId")
	quantityValue, quantityErr := httpx.FormValue(request, "quantity")
	if productErr != nil || quantityErr != nil {
		handler.invalidRequest(responseWriter)
		return
	}
	productID, validProductID := httpx.ParseSafeInteger(productValue)
	quantity, validQuantity := parseQuantity(quantityValue, 1)
	productExists, err := handler.store.ActiveProductExists(request.Context(), productID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !validProductID || !productExists {
		handler.errorPage(responseWriter, http.StatusNotFound, "Product Not Found", "We couldn't find that product.")
		return
	}
	if !validQuantity {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Quantity", "Enter a valid quantity.")
		return
	}
	updated, err := handler.store.AddItem(request.Context(), current.User.ID, productID, quantity)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !updated {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Unable to Update Cart", "That quantity is no longer available.")
		return
	}
	http.Redirect(responseWriter, request, "/cart", http.StatusFound)
}

func (handler *Handler) UpdateItem(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	quantityValue, err := httpx.FormValue(request, "quantity")
	if err != nil {
		handler.invalidRequest(responseWriter)
		return
	}
	productID, validProductID := httpx.ParseSafeInteger(request.PathValue("productId"))
	quantity, validQuantity := parseQuantity(quantityValue, 0)
	if !validProductID {
		handler.errorPage(responseWriter, http.StatusNotFound, "Product Not Found", "We couldn't find that product.")
		return
	}
	if !validQuantity {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Quantity", "Enter a valid quantity.")
		return
	}
	updated, err := handler.store.UpdateItem(request.Context(), current.User.ID, productID, quantity)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !updated {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Unable to Update Cart", "That quantity is no longer available.")
		return
	}
	http.Redirect(responseWriter, request, "/cart", http.StatusFound)
}

func (handler *Handler) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) verifyCSRF(responseWriter http.ResponseWriter, request *http.Request, expectedToken string) bool {
	actualToken, err := httpx.FormValue(request, "csrfToken")
	if err != nil {
		handler.invalidRequest(responseWriter)
		return false
	}
	if sessions.CSRFTokensMatch(expectedToken, actualToken) {
		return true
	}
	handler.errorPage(responseWriter, http.StatusForbidden, "Forbidden", "Your request could not be verified.")
	return false
}

func (handler *Handler) invalidRequest(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid.")
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, heading, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, heading, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}

func makeItemViews(items []Item) []itemView {
	viewItems := make([]itemView, 0, len(items))
	for _, item := range items {
		viewItems = append(viewItems, itemView{
			Item:         item,
			Availability: ItemAvailability(item),
			Maximum:      min(int64(MaximumQuantity), item.InventoryCount),
		})
	}
	return viewItems
}

func parseQuantity(value string, minimum int64) (int64, bool) {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed != math.Trunc(parsed) {
		return 0, false
	}
	quantity := int64(parsed)
	return quantity, quantity >= minimum && quantity <= MaximumQuantity
}
