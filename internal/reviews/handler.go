package reviews

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
	Reviews     []Review
	HasReviews  bool
}

type formPageView struct {
	templates.Page
	DisplayName string
	CSRFToken   string
	Review      Review
	Error       string
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

func (handler *Handler) Create(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	productID, validProductID := httpx.ParseSafeInteger(request.PathValue("id"))
	productExists, err := handler.store.ActiveProductExists(request.Context(), productID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !validProductID || !productExists {
		handler.errorPage(responseWriter, http.StatusNotFound, "Product Not Found", "We couldn't find that product.")
		return
	}
	ratingValue, ratingErr := httpx.FormValue(request, "rating")
	bodyValue, bodyErr := httpx.FormValue(request, "body")
	if ratingErr != nil || bodyErr != nil {
		handler.invalidRequest(responseWriter)
		return
	}
	rating, validRating := parseRating(ratingValue)
	body, validBody := parseBody(bodyValue)
	if !validRating || !validBody {
		handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Review", "Enter a rating and review text.")
		return
	}
	if err := handler.store.Create(request.Context(), current.User.ID, productID, rating, body); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, "/products/"+strconv.FormatInt(productID, 10), http.StatusFound)
}

func (handler *Handler) List(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	userReviews, err := handler.store.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	view := listPageView{
		Title:       "Your Reviews",
		DisplayName: current.User.DisplayName,
		Reviews:     userReviews,
		HasReviews:  len(userReviews) > 0,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "account-reviews", view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) Edit(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	review, found := handler.requireReview(responseWriter, request)
	if !found {
		return
	}
	if err := handler.renderForm(responseWriter, http.StatusOK, current, review, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) Update(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	review, found := handler.requireReview(responseWriter, request)
	if !found {
		return
	}
	ratingValue, ratingErr := httpx.FormValue(request, "rating")
	bodyValue, bodyErr := httpx.FormValue(request, "body")
	if ratingErr != nil || bodyErr != nil {
		handler.invalidRequest(responseWriter)
		return
	}
	rating, validRating := parseRating(ratingValue)
	body, validBody := parseBody(bodyValue)
	if !validRating || !validBody {
		review.Rating = rating
		if validBody {
			review.Body = body
		} else {
			review.Body = ""
		}
		if err := handler.renderForm(responseWriter, http.StatusBadRequest, current, review, "Invalid review."); err != nil {
			handler.internalError(responseWriter, request, err)
		}
		return
	}
	if err := handler.store.Update(request.Context(), review.ID, rating, body); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, "/account/reviews", http.StatusFound)
}

func (handler *Handler) Delete(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok || !handler.verifyCSRF(responseWriter, request, current.Session.CSRFToken) {
		return
	}
	review, found := handler.requireReview(responseWriter, request)
	if !found {
		return
	}
	if err := handler.store.Delete(request.Context(), review.ID); err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, "/account/reviews", http.StatusFound)
}

func (handler *Handler) requireReview(responseWriter http.ResponseWriter, request *http.Request) (Review, bool) {
	reviewID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.reviewNotFound(responseWriter)
		return Review{}, false
	}
	review, found, err := handler.store.FindByID(request.Context(), reviewID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return Review{}, false
	}
	if !found {
		handler.reviewNotFound(responseWriter)
		return Review{}, false
	}
	return review, true
}

func (handler *Handler) renderForm(responseWriter http.ResponseWriter, statusCode int, current accounts.CurrentSession, review Review, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "review-form", formPageView{
		Title:       "Edit Review #" + strconv.FormatInt(review.ID, 10),
		DisplayName: current.User.DisplayName,
		CSRFToken:   current.Session.CSRFToken,
		Review:      review,
		Error:       errorMessage,
	})
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

func (handler *Handler) reviewNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "Review Not Found", "We couldn't find that review.")
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

func parseRating(value string) (int64, bool) {
	rating, valid := httpx.ParseSafeInteger(value)
	return rating, valid && rating >= 1 && rating <= 5
}

func parseBody(value string) (string, bool) {
	return value, value != ""
}
