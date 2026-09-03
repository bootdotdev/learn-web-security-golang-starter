package support

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storage"
	"github.com/bootdotdev/learn-web-security/internal/templates"
	"github.com/bootdotdev/learn-web-security/internal/uploads"
)

type dashboardPage struct {
	templates.Page
	DisplayName string
	IsAdmin     bool
}

type ordersPage struct {
	templates.Page
	DisplayName string
	IsAdmin     bool
	Orders      []orders.Order
}

type taxExemptionsPage struct {
	templates.Page
	DisplayName       string
	IsAdmin           bool
	Files             []uploads.File
	ImportedDocuments []uploads.ImportedDocument
}

type orderPage struct {
	templates.Page
	DisplayName string
	IsAdmin     bool
	Order       orders.Order
	Items       []orders.Item
	Shipping    *orders.ShippingDetails
}

type archivePage struct {
	templates.Page
	DisplayName      string
	IsAdmin          bool
	HasImportedCount bool
	ImportedCount    int
	Error            string
}

type Handler struct {
	accountStore        *accounts.Store
	orderStore          *orders.Store
	uploadStore         *uploads.Store
	renderer            *templates.Renderer
	logger              *logging.Logger
	encryptionKeyring   *storage.Keyring
	bulkImportDirectory string
	maxUploadBytes      int64
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, uploadStore *uploads.Store, renderer *templates.Renderer, logger *logging.Logger, encryptionKeyring *storage.Keyring, bulkImportDirectory string, maxUploadBytes int64) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, uploadStore: uploadStore, renderer: renderer,
		logger: logger, encryptionKeyring: encryptionKeyring, bulkImportDirectory: bulkImportDirectory, maxUploadBytes: maxUploadBytes,
	}
}

func (handler *Handler) Dashboard(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupport(responseWriter, request)
	if !ok {
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "support-dashboard", dashboardPage{
		Title: "Support Dashboard", DisplayName: current.User.DisplayName, IsAdmin: current.User.Role == "admin",
	})
}

func (handler *Handler) ListOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupport(responseWriter, request)
	if !ok {
		return
	}
	allOrders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "support-orders", ordersPage{
		Title: "Support Orders", DisplayName: current.User.DisplayName, IsAdmin: current.User.Role == "admin", Orders: allOrders,
	})
}

func (handler *Handler) TaxExemptions(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupport(responseWriter, request)
	if !ok {
		return
	}
	files, err := handler.uploadStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	importedDocuments, err := handler.uploadStore.ListImported(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	handler.render(responseWriter, request, http.StatusOK, "support-tax-exemptions", taxExemptionsPage{
		Title: "Tax Exemption Documents", DisplayName: current.User.DisplayName, IsAdmin: current.User.Role == "admin",
		Files: files, ImportedDocuments: importedDocuments,
	})
}

func (handler *Handler) ImportTaxDocumentsPage(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupportWithReturnTo(responseWriter, request, "/support/tax-exemptions/import")
	if !ok {
		return
	}
	importedCount, hasImportedCount := parseImportedCount(request.URL.Query())
	handler.renderArchivePage(responseWriter, request, http.StatusOK, current, hasImportedCount, importedCount, "")
}

func (handler *Handler) ImportTaxDocuments(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupportWithReturnTo(responseWriter, request, "/support/tax-exemptions/import")
	if !ok {
		return
	}
	contents, err := handler.readArchive(responseWriter, request)
	if err != nil {
		if errors.Is(err, errArchiveTooLarge) {
			handler.errorPage(responseWriter, http.StatusRequestEntityTooLarge, "Content Too Large", "The submitted request exceeds the allowed size.")
			return
		}
		handler.renderArchivePage(responseWriter, request, http.StatusBadRequest, current, false, 0, "Choose a ZIP archive.")
		return
	}
	extractedArchive, err := uploads.ExtractTaxDocumentArchive(handler.encryptionKeyring, contents, handler.bulkImportDirectory)
	if err != nil {
		if archiveError, ok := errors.AsType[*uploads.ArchiveImportError](err); ok {
			handler.renderArchivePage(responseWriter, request, archiveError.StatusCode, current, false, 0, archiveError.Message)
			return
		}
		handler.internalError(responseWriter, request, err)
		return
	}
	importedDocuments, err := handler.uploadStore.CreateImported(request.Context(), current.User.ID, extractedArchive)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	http.Redirect(responseWriter, request, "/support/tax-exemptions/import?imported="+strconv.Itoa(len(importedDocuments)), http.StatusSeeOther)
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireSupport(responseWriter, request)
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
	if !found {
		handler.orderNotFound(responseWriter)
		return
	}
	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	var shipping *orders.ShippingDetails
	if order.ShippingDetailsEncrypted != nil {
		decrypted, err := orders.DecryptShippingDetails(*order.ShippingDetailsEncrypted, handler.encryptionKeyring)
		if err != nil {
			handler.internalError(responseWriter, request, err)
			return
		}
		shipping = &decrypted
	}
	handler.render(responseWriter, request, http.StatusOK, "support-order", orderPage{
		Title: "Support Order #" + strconv.FormatInt(order.ID, 10), DisplayName: current.User.DisplayName,
		IsAdmin: current.User.Role == "admin", Order: order, Items: items, Shipping: shipping,
	})
}

func (handler *Handler) requireSupport(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	return handler.requireSupportWithReturnTo(responseWriter, request, "")
}

func (handler *Handler) requireSupportWithReturnTo(responseWriter http.ResponseWriter, request *http.Request, returnTo string) (accounts.CurrentSession, bool) {
	current, found, err := sessions.RequireWithReturnTo(responseWriter, request, handler.accountStore, returnTo)
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

var errArchiveTooLarge = errors.New("archive upload is too large")

func (handler *Handler) readArchive(responseWriter http.ResponseWriter, request *http.Request) ([]byte, error) {
	request.Body = http.MaxBytesReader(responseWriter, request.Body, handler.maxUploadBytes+1024*1024)
	if err := request.ParseMultipartForm(handler.maxUploadBytes); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, errArchiveTooLarge
		}
		return nil, fmt.Errorf("parse archive upload: %w", err)
	}
	files := request.MultipartForm.File["archive"]
	if len(files) == 0 {
		return nil, errors.New("missing archive upload")
	}
	file, err := files[0].Open()
	if err != nil {
		return nil, fmt.Errorf("open archive upload: %w", err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, handler.maxUploadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read archive upload: %w", err)
	}
	if int64(len(contents)) > handler.maxUploadBytes {
		return nil, errArchiveTooLarge
	}
	return contents, nil
}

func (handler *Handler) renderArchivePage(responseWriter http.ResponseWriter, request *http.Request, statusCode int, current accounts.CurrentSession, hasImportedCount bool, importedCount int, errorMessage string) {
	handler.render(responseWriter, request, statusCode, "support-archive", archivePage{
		Title: "Import Tax Documents", DisplayName: current.User.DisplayName, IsAdmin: current.User.Role == "admin",
		HasImportedCount: hasImportedCount, ImportedCount: importedCount, Error: errorMessage,
	})
}

func parseImportedCount(query map[string][]string) (int, bool) {
	values := query["imported"]
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 3 || (len(values[0]) > 1 && values[0][0] == '0') {
		return 0, false
	}
	for _, character := range values[0] {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	count, err := strconv.Atoi(values[0])
	return count, err == nil && count <= 100
}

func (handler *Handler) render(responseWriter http.ResponseWriter, request *http.Request, statusCode int, templateName string, view any) {
	if err := handler.renderer.Render(responseWriter, statusCode, templateName, view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) orderNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "Order Not Found", "We couldn't find that order.")
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
