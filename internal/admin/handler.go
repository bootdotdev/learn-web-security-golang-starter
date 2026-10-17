package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/imagepreview"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type dashboardPage struct {
	templates.Page
	DisplayName string
}

type productsPage struct {
	templates.Page
	DisplayName string
	Products    []Product
}

type productPage struct {
	templates.Page
	DisplayName string
	Product     Product
	MarginCents int64
}

type productFormPage struct {
	templates.Page
	DisplayName string
	Heading     string
	Action      string
	Product     ProductInput
	SubmitLabel string
	Error       string
}

type imagePreviewPage struct {
	templates.Page
	DisplayName string
	Error       string
	Preview     *imagepreview.Result
}

type Handler struct {
	store         *Store
	accountStore  *accounts.Store
	renderer      *templates.Renderer
	logger        *logging.Logger
	imagePreview  *imagepreview.Service
	maxImageBytes int64
}

func NewHandler(store *Store, accountStore *accounts.Store, renderer *templates.Renderer, logger *logging.Logger, imagePreview *imagepreview.Service, maxImageBytes int64) *Handler {
	return &Handler{
		store: store, accountStore: accountStore, renderer: renderer, logger: logger,
		imagePreview: imagePreview, maxImageBytes: maxImageBytes,
	}
}

func (handler *Handler) Dashboard(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "admin-dashboard", dashboardPage{
		Title: "Admin Dashboard", DisplayName: current.User.DisplayName,
	})
}

func (handler *Handler) ListProducts(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	products, err := handler.store.ListProducts(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "admin-products", productsPage{
		Title: "Admin Products", DisplayName: current.User.DisplayName, Products: products,
	})
}

func (handler *Handler) NewProduct(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	handler.renderProductForm(responseWriter, request, http.StatusOK, current, "Create Product", "Create Product", "/admin/products", ProductInput{
		ImagePath: "/product-photos/placeholder.png", IsActive: true,
	}, "Create product", "")
}

func (handler *Handler) CreateProduct(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	input, validationMessage := parseProductInput(request)
	if validationMessage != "" {
		handler.renderProductForm(responseWriter, request, http.StatusBadRequest, current, "Create Product", "Create Product", "/admin/products", input, "Create product", validationMessage)
		return
	}
	product, err := handler.store.CreateProduct(request.Context(), input)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, productPath(product.ID), http.StatusFound)
}

func (handler *Handler) EditProduct(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	product, found := handler.requireProduct(responseWriter, request)
	if !found {
		return
	}
	handler.renderProductForm(responseWriter, request, http.StatusOK, current, "Edit "+product.Name, "Edit Product", productPath(product.ID), productInput(product), "Save changes", "")
}

func (handler *Handler) UpdateProduct(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	product, found := handler.requireProduct(responseWriter, request)
	if !found {
		return
	}
	input, validationMessage := parseProductInput(request)
	if validationMessage != "" {
		handler.renderProductForm(responseWriter, request, http.StatusBadRequest, current, "Edit "+product.Name, "Edit Product", productPath(product.ID), input, "Save changes", validationMessage)
		return
	}
	_, updated, err := handler.store.UpdateProduct(request.Context(), product.ID, input)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !updated {
		handler.productNotFound(responseWriter)
		return
	}
	http.Redirect(responseWriter, request, productPath(product.ID), http.StatusFound)
}

func (handler *Handler) Product(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	product, found := handler.requireProduct(responseWriter, request)
	if !found {
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "admin-product", productPage{
		Title: "Admin Product #" + formatID(product.ID), DisplayName: current.User.DisplayName,
		Product: product, MarginCents: product.PriceCents - product.CostCents,
	})
}

func (handler *Handler) ImagePreviewPage(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	handler.renderImagePreview(responseWriter, request, http.StatusOK, current.User.DisplayName, "", nil)
}

func (handler *Handler) PreviewImage(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAdmin(responseWriter, request)
	if !ok {
		return
	}
	rawURL, err := httpx.FormValue(request, "imageUrl")
	if err != nil {
		handler.renderImagePreview(responseWriter, request, http.StatusBadRequest, current.User.DisplayName, "Enter an image URL.", nil)
		return
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		handler.renderImagePreview(responseWriter, request, http.StatusBadRequest, current.User.DisplayName, "Enter an image URL.", nil)
		return
	}
	preview, err := handler.imagePreview.Fetch(request.Context(), rawURL, handler.maxImageBytes)
	if err != nil {
		if previewError, ok := errors.AsType[*imagepreview.Error](err); ok {
			handler.renderImagePreview(responseWriter, request, http.StatusBadGateway, current.User.DisplayName, previewError.Message, nil)
			return
		}
		handler.renderImagePreview(responseWriter, request, http.StatusBadGateway, current.User.DisplayName, "Bearly Secure could not fetch that URL.", nil)
		return
	}
	handler.renderImagePreview(responseWriter, request, http.StatusOK, current.User.DisplayName, "", &preview)
}

func (handler *Handler) requireAdmin(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		return accounts.CurrentSession{}, false
	}
	if current.User.Role != "admin" {
		handler.errorPage(responseWriter, http.StatusForbidden, "Forbidden", "You don't have permission to view this page.")
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) requireProductEditor(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		return accounts.CurrentSession{}, false
	}
	if current.User.Role != "support" && current.User.Role != "admin" {
		handler.errorPage(responseWriter, http.StatusForbidden, "Forbidden", "You don't have permission to view this page.")
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) requireProduct(responseWriter http.ResponseWriter, request *http.Request) (Product, bool) {
	productID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		handler.productNotFound(responseWriter)
		return Product{}, false
	}
	product, found, err := handler.store.FindProduct(request.Context(), productID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return Product{}, false
	}
	if !found {
		handler.productNotFound(responseWriter)
		return Product{}, false
	}
	return product, true
}

func (handler *Handler) renderProductForm(responseWriter http.ResponseWriter, request *http.Request, statusCode int, current accounts.CurrentSession, title, heading, action string, product ProductInput, submitLabel, errorMessage string) {
	handler.render(responseWriter, request, statusCode, "admin-product-form", productFormPage{
		Title: title, DisplayName: current.User.DisplayName, Heading: heading, Action: action,
		Product: product, SubmitLabel: submitLabel, Error: errorMessage,
	})
}

func (handler *Handler) renderImagePreview(responseWriter http.ResponseWriter, request *http.Request, statusCode int, displayName, errorMessage string, preview *imagepreview.Result) {
	handler.render(responseWriter, request, statusCode, "image-preview", imagePreviewPage{
		Title: "Remote Image Preview", DisplayName: displayName, Error: errorMessage, Preview: preview,
	})
}

func (handler *Handler) render(responseWriter http.ResponseWriter, request *http.Request, statusCode int, templateName string, view any) {
	if err := handler.renderer.Render(responseWriter, statusCode, templateName, view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) productNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "Product Not Found", "We couldn't find that product.")
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, title, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, title, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}

func parseProductInput(request *http.Request) (ProductInput, string) {
	name, namePresent := oneFormValue(request, "name")
	description, descriptionPresent := oneFormValue(request, "description")
	imagePath, imagePathPresent := oneFormValue(request, "imagePath")
	priceCents, pricePresent := nonnegativeWholeFormValue(request, "priceCents")
	costCents, costPresent := nonnegativeWholeFormValue(request, "costCents")
	inventoryCount, inventoryPresent := nonnegativeWholeFormValue(request, "inventoryCount")
	isActiveValue, isActivePresent := oneFormValue(request, "isActive")
	input := ProductInput{
		Name: strings.TrimSpace(name), Description: strings.TrimSpace(description), ImagePath: strings.TrimSpace(imagePath),
		PriceCents: priceCents, CostCents: costCents, InventoryCount: inventoryCount,
		IsActive: isActivePresent && isActiveValue == "1",
	}
	validText := namePresent && descriptionPresent && imagePathPresent && input.Name != "" && input.Description != "" && input.ImagePath != ""
	if !validText {
		return input, "Name, description, and image path are required."
	}
	if !pricePresent || !costPresent {
		return input, "Price and cost must be whole cents."
	}
	if !inventoryPresent {
		return input, "Inventory count must be a whole number."
	}
	return input, ""
}

func oneFormValue(request *http.Request, name string) (string, bool) {
	values, present := request.PostForm[name]
	if !present || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func nonnegativeWholeFormValue(request *http.Request, name string) (int64, bool) {
	value, present := oneFormValue(request, name)
	if !present {
		return 0, false
	}
	if strings.TrimSpace(value) == "" {
		return 0, true
	}
	parsed, valid := httpx.ParseSafeInteger(value)
	return parsed, valid && parsed >= 0
}

func productInput(product Product) ProductInput {
	return ProductInput{
		Name: product.Name, Description: product.Description, ImagePath: product.ImagePath, PriceCents: product.PriceCents,
		CostCents: product.CostCents, InventoryCount: product.InventoryCount, IsActive: product.IsActive,
	}
}

func productPath(productID int64) string {
	return "/admin/products/" + formatID(productID)
}

func formatID(identifier int64) string {
	return strconv.FormatInt(identifier, 10)
}
