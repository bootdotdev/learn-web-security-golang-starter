package storefront

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

const maxCartQuantity = 99

type productCard struct {
	Product
	OutOfStock         bool
	AllInventoryInCart bool
	CSRFToken          string
}

type storefrontView struct {
	templates.Page
	Current  *currentUserView
	Products []productCard
}

type searchView struct {
	templates.Page
	Current       *currentUserView
	Query         string
	ResultSummary string
	Products      []productCard
	HasProducts   bool
}

type productView struct {
	templates.Page
	Current             *currentUserView
	Product             Product
	Reviews             []reviewView
	HasReviews          bool
	OutOfStock          bool
	AllInventoryInCart  bool
	MaximumCartQuantity int64
}

type currentUserView struct {
	ID          int64
	DisplayName string
	CSRFToken   string
	IsAdmin     bool
}

type reviewView struct {
	Review
	BodyHTML template.HTML
	CanEdit  bool
}

type Handler struct {
	store             *Store
	accountStore      *accounts.Store
	renderer          *templates.Renderer
	logger            *logging.Logger
	maxProductResults int64
}

func NewHandler(store *Store, accountStore *accounts.Store, renderer *templates.Renderer, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		store:             store,
		accountStore:      accountStore,
		renderer:          renderer,
		logger:            logger,
		maxProductResults: int64(maxProductResults),
	}
}

func (handler *Handler) Storefront(responseWriter http.ResponseWriter, request *http.Request) {
	current, cartQuantities, ok := handler.requestContext(responseWriter, request)
	if !ok {
		return
	}
	products, err := handler.store.ListProducts(request.Context(), handler.maxProductResults)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}

	view := storefrontView{
		Title:    "Bearly Secure",
		Current:  current,
		Products: makeProductCards(products, cartQuantities, csrfToken(current)),
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "storefront", view); err != nil {
		handler.renderFailure(responseWriter, request, err)
	}
}

func (handler *Handler) Search(responseWriter http.ResponseWriter, request *http.Request) {
	current, cartQuantities, ok := handler.requestContext(responseWriter, request)
	if !ok {
		return
	}
	query := strings.TrimSpace(strings.Join(request.URL.Query()["q"], ","))
	products := []Product{}
	var err error
	if query != "" {
		products, err = handler.store.SearchProducts(request.Context(), query, handler.maxProductResults)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
	}

	resultSummary := "Enter a search term to find plushies."
	if query != "" {
		pluralSuffix := "s"
		if len(products) == 1 {
			pluralSuffix = ""
		}
		resultSummary = fmt.Sprintf("%d result%s for “%s”", len(products), pluralSuffix, query)
	}
	view := searchView{
		Title:         "Search",
		Current:       current,
		Query:         query,
		ResultSummary: resultSummary,
		Products:      makeProductCards(products, cartQuantities, csrfToken(current)),
		HasProducts:   len(products) > 0,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "search", view); err != nil {
		handler.renderFailure(responseWriter, request, err)
	}
}

func (handler *Handler) Product(responseWriter http.ResponseWriter, request *http.Request) {
	current, cartQuantities, ok := handler.requestContext(responseWriter, request)
	if !ok {
		return
	}
	productID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.productNotFound(responseWriter)
		return
	}

	product, found, err := handler.store.FindProduct(request.Context(), productID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		handler.productNotFound(responseWriter)
		return
	}

	reviews, err := handler.store.ListReviews(request.Context(), product.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	remainingInventory := max(int64(0), product.InventoryCount-cartQuantities[product.ID])
	maximumCartQuantity := min(int64(maxCartQuantity), remainingInventory)
	view := productView{
		Title:               product.Name,
		Current:             current,
		Product:             product,
		Reviews:             makeReviewViews(reviews, current),
		HasReviews:          len(reviews) > 0,
		OutOfStock:          product.InventoryCount == 0,
		AllInventoryInCart:  current != nil && remainingInventory == 0 && product.InventoryCount != 0,
		MaximumCartQuantity: maximumCartQuantity,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "product", view); err != nil {
		handler.renderFailure(responseWriter, request, err)
	}
}

func (handler *Handler) productNotFound(responseWriter http.ResponseWriter) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, http.StatusNotFound, "Product Not Found", "We couldn't find that product."); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	if logErr := handler.logger.Event("unhandled_error", map[string]any{
		"method":  request.Method,
		"path":    request.URL.Path,
		"message": err.Error(),
	}); logErr != nil {
		fmt.Printf("Error logging unhandled error: %v\n", logErr)
	}
	if renderErr := httpx.RespondWithErrorPage(responseWriter, handler.renderer, http.StatusInternalServerError, "Unhandled Error", err.Error()); renderErr != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) renderFailure(responseWriter http.ResponseWriter, request *http.Request, err error) {
	if logErr := handler.logger.Event("unhandled_error", map[string]any{
		"method":  request.Method,
		"path":    request.URL.Path,
		"message": err.Error(),
	}); logErr != nil {
		fmt.Printf("Error logging template failure: %v\n", logErr)
	}
	http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (handler *Handler) requestContext(responseWriter http.ResponseWriter, request *http.Request) (*currentUserView, map[int64]int64, bool) {
	currentSession, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return nil, nil, false
	}
	if !found {
		return nil, map[int64]int64{}, true
	}
	cartQuantities, err := handler.accountStore.CartQuantities(request.Context(), currentSession.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return nil, nil, false
	}
	return &currentUserView{
		ID:          currentSession.User.ID,
		DisplayName: currentSession.User.DisplayName,
		CSRFToken:   currentSession.Session.CSRFToken,
		IsAdmin:     currentSession.User.Role == "admin",
	}, cartQuantities, true
}

func csrfToken(current *currentUserView) string {
	if current == nil {
		return ""
	}
	return current.CSRFToken
}

func makeReviewViews(reviews []Review, current *currentUserView) []reviewView {
	viewReviews := make([]reviewView, 0, len(reviews))
	for _, review := range reviews {
		viewReviews = append(viewReviews, reviewView{
			Review:   review,
			BodyHTML: template.HTML(review.Body), // Intentionally unsafe starter behavior for the XSS lesson.
			CanEdit:  current != nil && current.ID == review.UserID,
		})
	}
	return viewReviews
}

func makeProductCards(products []Product, cartQuantities map[int64]int64, csrfToken string) []productCard {
	cards := make([]productCard, 0, len(products))
	for _, product := range products {
		remainingInventory := max(int64(0), product.InventoryCount-cartQuantities[product.ID])
		cards = append(cards, productCard{
			Product:            product,
			OutOfStock:         product.InventoryCount == 0,
			AllInventoryInCart: remainingInventory == 0 && product.InventoryCount != 0,
			CSRFToken:          csrfToken,
		})
	}
	return cards
}
