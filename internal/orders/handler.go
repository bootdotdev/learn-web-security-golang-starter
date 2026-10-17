package orders

import (
	"net/http"
	"strconv"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type listPageView struct {
	templates.Page
	DisplayName string
	Orders      []Order
	HasOrders   bool
}

type detailPageView struct {
	templates.Page
	DisplayName string
	Order       Order
	Items       []Item
}

type Handler struct {
	orderStore   *Store
	accountStore *accounts.Store
	renderer     *templates.Renderer
	logger       *logging.Logger
}

func NewHandler(orderStore *Store, accountStore *accounts.Store, renderer *templates.Renderer, logger *logging.Logger) *Handler {
	return &Handler{orderStore: orderStore, accountStore: accountStore, renderer: renderer, logger: logger}
}

func (handler *Handler) List(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	userOrders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	view := listPageView{
		Title:       "Your Orders",
		DisplayName: current.User.DisplayName,
		Orders:      userOrders,
		HasOrders:   len(userOrders) > 0,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "orders", view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) Detail(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.orderNotFound(responseWriter)
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || order.UserID != current.User.ID {
		handler.orderNotFound(responseWriter)
		return
	}
	orderItems, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	view := detailPageView{
		Title:       "Order #" + strconv.FormatInt(order.ID, 10),
		DisplayName: current.User.DisplayName,
		Order:       order,
		Items:       orderItems,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "order", view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) orderNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "Order Not Found", "We couldn't find that order.")
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
