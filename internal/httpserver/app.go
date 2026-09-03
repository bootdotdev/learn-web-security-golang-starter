package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/account"
	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/admin"
	"github.com/bootdotdev/learn-web-security/internal/api"
	"github.com/bootdotdev/learn-web-security/internal/assistant"
	"github.com/bootdotdev/learn-web-security/internal/auth/mfa"
	"github.com/bootdotdev/learn-web-security/internal/auth/passkeys"
	"github.com/bootdotdev/learn-web-security/internal/auth/passwordreset"
	"github.com/bootdotdev/learn-web-security/internal/cart"
	"github.com/bootdotdev/learn-web-security/internal/checkout"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/imagepreview"
	"github.com/bootdotdev/learn-web-security/internal/integrations/pawpal"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/reviews"
	"github.com/bootdotdev/learn-web-security/internal/storage"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
	"github.com/bootdotdev/learn-web-security/internal/support"
	"github.com/bootdotdev/learn-web-security/internal/templates"
	"github.com/bootdotdev/learn-web-security/internal/uploads"
)

const (
	defaultUploadBytes            = 5 * 1024 * 1024
	unboundedPublicProductResults = -1
)

type Options struct {
	AppOrigin               string
	MaxPublicProductResults int
	MaxRequestBodyBytes     int64
	MaxUploadBytes          int64
	PawPalAPIKey            string
	AcornFulfillmentDelay   time.Duration
	EncryptionKeyring       *storage.Keyring
	DataDirectory           string
	FixtureDirectory        string
	TemplateDirectory       string
	PublicDirectory         string
}

type Application struct {
	Handler    http.Handler
	publicRoot *os.Root
}

func New(database *sql.DB, logger *logging.Logger, options Options) (*Application, error) {
	if options.DataDirectory == "" {
		return nil, fmt.Errorf("data directory is required")
	}
	if options.FixtureDirectory == "" {
		options.FixtureDirectory = filepath.Join(options.DataDirectory, "fixtures")
	}
	if options.MaxUploadBytes <= 0 {
		return nil, fmt.Errorf("maximum upload size must be positive")
	}
	uploadDirectory := filepath.Join(options.DataDirectory, "uploads")
	if err := storage.MigrateSensitiveDataAtRest(context.Background(), database, options.EncryptionKeyring, uploadDirectory, filepath.Join(options.DataDirectory, "bulk-tax-documents"), options.FixtureDirectory); err != nil {
		return nil, err
	}
	renderer, err := templates.Load(options.TemplateDirectory)
	if err != nil {
		return nil, err
	}
	publicRoot, err := os.OpenRoot(options.PublicDirectory)
	if err != nil {
		return nil, fmt.Errorf("open public directory: %w", err)
	}

	accountStore := accounts.NewStore(database)
	mfaStore := mfa.NewStore(database, options.EncryptionKeyring)
	passwordResetStore := passwordreset.NewStore(database)
	uploadStore := uploads.NewStore(database)
	accountHandler := account.NewHandler(accountStore, mfaStore, renderer, logger)
	cartStore := cart.NewStore(database)
	cartHandler := cart.NewHandler(cartStore, accountStore, renderer, logger)
	orderStore := orders.NewStore(database)
	orderHandler := orders.NewHandler(orderStore, accountStore, renderer, logger)
	checkoutHandler := checkout.NewHandler(cartStore, orderStore, accountStore, options.EncryptionKeyring, renderer, logger, options.AcornFulfillmentDelay)
	pawPalHandler := pawpal.NewHandler(orderStore, logger, options.PawPalAPIKey)
	reviewHandler := reviews.NewHandler(reviews.NewStore(database), accountStore, renderer, logger)
	productStore := storefront.NewStore(database)
	storefrontHandler := storefront.NewHandler(
		productStore,
		accountStore,
		renderer,
		logger,
		unboundedPublicProductResults,
	)
	var downloadSigningKey [32]byte
	if _, err := rand.Read(downloadSigningKey[:]); err != nil {
		return nil, fmt.Errorf("generate download signing key: %w", err)
	}
	uploadHandler := uploads.NewHandler(
		accountStore,
		uploadStore,
		renderer,
		logger,
		options.EncryptionKeyring,
		uploadDirectory,
		defaultUploadBytes,
		downloadSigningKey,
	)
	adminHandler := admin.NewHandler(admin.NewStore(database), accountStore, renderer, logger, imagepreview.NewService(), options.MaxUploadBytes)
	apiHandler := api.NewHandler(accountStore, orderStore, productStore, api.NewStore(database), logger, unboundedPublicProductResults)
	assistantHandler := assistant.NewHandler(accountStore, assistant.NewService(orderStore), renderer, logger)
	supportHandler := support.NewHandler(
		accountStore,
		orderStore,
		uploadStore,
		renderer,
		logger,
		options.EncryptionKeyring,
		filepath.Join(options.DataDirectory, "bulk-tax-documents"),
		defaultUploadBytes,
	)
	authenticationHandler := newAuthHandler(accountStore, mfaStore, passwordResetStore, renderer, logger, options.AppOrigin)
	passkeyHandler, err := passkeys.NewHandler(
		options.AppOrigin,
		accountStore,
		mfaStore,
		passkeys.NewStore(database),
		renderer,
		logger,
		options.MaxRequestBodyBytes,
	)
	if err != nil {
		return nil, err
	}
	dynamicMux := http.NewServeMux()
	dynamicMux.HandleFunc("GET /{$}", storefrontHandler.Storefront)
	dynamicMux.HandleFunc("GET /search", storefrontHandler.Search)
	dynamicMux.HandleFunc("GET /products/{id}", storefrontHandler.Product)
	dynamicMux.HandleFunc("GET /api/account/orders", apiHandler.AccountOrders)
	dynamicMux.HandleFunc("GET /api/orders/{id}", apiHandler.Order)
	dynamicMux.HandleFunc("GET /api/products", apiHandler.Products)
	dynamicMux.HandleFunc("GET /api/integrations/warehouse/orders", apiHandler.WarehouseOrders)
	dynamicMux.Handle("POST /products/{id}/reviews", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(reviewHandler.Create)))
	dynamicMux.HandleFunc("GET /login", authenticationHandler.LoginPage)
	dynamicMux.Handle("POST /login", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.Login)))
	dynamicMux.HandleFunc("GET /login/totp", authenticationHandler.TOTPLoginPage)
	dynamicMux.Handle("POST /login/totp", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.TOTPLogin)))
	dynamicMux.HandleFunc("POST /login/totp/cancel", authenticationHandler.CancelTOTPLogin)
	dynamicMux.HandleFunc("GET /signup", authenticationHandler.SignupPage)
	dynamicMux.Handle("POST /signup", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.Signup)))
	dynamicMux.HandleFunc("GET /recover-mfa", authenticationHandler.MFARecoveryPage)
	dynamicMux.Handle("POST /recover-mfa", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.RecoverMFA)))
	dynamicMux.HandleFunc("GET /password-reset", authenticationHandler.PasswordResetRequestPage)
	dynamicMux.Handle("POST /password-reset", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.RequestPasswordReset)))
	dynamicMux.HandleFunc("GET /password-reset/{token}", authenticationHandler.PasswordResetPage)
	dynamicMux.Handle("POST /password-reset/{token}", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(authenticationHandler.ResetPassword)))
	dynamicMux.HandleFunc("POST /logout", authenticationHandler.Logout)
	dynamicMux.HandleFunc("GET /auth/passkey", passkeyHandler.LoginPage)
	dynamicMux.HandleFunc("POST /auth/passkey/begin", passkeyHandler.BeginLogin)
	dynamicMux.HandleFunc("POST /auth/passkey", passkeyHandler.CompleteLogin)
	dynamicMux.HandleFunc("GET /account", accountHandler.Page)
	dynamicMux.HandleFunc("GET /account/passkey", passkeyHandler.ManagePage)
	dynamicMux.HandleFunc("POST /account/passkey/begin", passkeyHandler.BeginRegistration)
	dynamicMux.HandleFunc("POST /account/passkey/verify", passkeyHandler.CompleteRegistration)
	dynamicMux.HandleFunc("POST /account/passkey/{id}/delete", passkeyHandler.DeleteCredential)
	dynamicMux.HandleFunc("GET /account/assistant", assistantHandler.Page)
	dynamicMux.Handle("POST /account/assistant", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(assistantHandler.Ask)))
	dynamicMux.Handle("POST /account/email", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(accountHandler.UpdateEmail)))
	dynamicMux.HandleFunc("GET /account/totp", accountHandler.TOTPPage)
	dynamicMux.Handle("POST /account/totp/confirm", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(accountHandler.ConfirmTOTP)))
	dynamicMux.Handle("POST /account/totp/disable", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(accountHandler.DisableTOTP)))
	dynamicMux.HandleFunc("GET /account/tax-exemption", uploadHandler.TaxExemptionPage)
	dynamicMux.HandleFunc("POST /account/tax-exemption/files", uploadHandler.Upload)
	dynamicMux.HandleFunc("GET /account/reviews", reviewHandler.List)
	dynamicMux.HandleFunc("GET /account/reviews/{id}/edit", reviewHandler.Edit)
	dynamicMux.Handle("POST /account/reviews/{id}", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(reviewHandler.Update)))
	dynamicMux.Handle("POST /account/reviews/{id}/delete", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(reviewHandler.Delete)))
	dynamicMux.HandleFunc("GET /cart", cartHandler.Page)
	dynamicMux.Handle("POST /cart/items", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(cartHandler.AddItem)))
	dynamicMux.Handle("POST /cart/items/{productId}", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(cartHandler.UpdateItem)))
	dynamicMux.HandleFunc("GET /checkout", checkoutHandler.Page)
	dynamicMux.Handle("POST /checkout", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(checkoutHandler.Submit)))
	dynamicMux.HandleFunc("GET /pawpal/processing/{orderId}", checkoutHandler.Processing)
	dynamicMux.HandleFunc("GET /account/orders", orderHandler.List)
	dynamicMux.HandleFunc("GET /orders/{id}", orderHandler.Detail)
	dynamicMux.HandleFunc("GET /files/{id}/download", uploadHandler.Download)
	dynamicMux.HandleFunc("GET /files/{id}/signed-download", uploadHandler.SignedDownload)
	dynamicMux.HandleFunc("GET /support/files/imports/{id}/download", uploadHandler.ImportedDownload)
	dynamicMux.HandleFunc("GET /support", supportHandler.Dashboard)
	dynamicMux.HandleFunc("GET /support/orders", supportHandler.ListOrders)
	dynamicMux.HandleFunc("GET /support/orders/{id}", supportHandler.Order)
	dynamicMux.HandleFunc("GET /support/tax-exemptions", supportHandler.TaxExemptions)
	dynamicMux.HandleFunc("GET /support/tax-exemptions/import", supportHandler.ImportTaxDocumentsPage)
	dynamicMux.HandleFunc("POST /support/tax-exemptions/import", supportHandler.ImportTaxDocuments)
	dynamicMux.HandleFunc("GET /admin", adminHandler.Dashboard)
	dynamicMux.HandleFunc("GET /admin/image-preview", adminHandler.ImagePreviewPage)
	dynamicMux.Handle("POST /admin/image-preview", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(adminHandler.PreviewImage)))
	dynamicMux.HandleFunc("GET /admin/products", adminHandler.ListProducts)
	dynamicMux.HandleFunc("GET /admin/products/new", adminHandler.NewProduct)
	dynamicMux.Handle("POST /admin/products", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(adminHandler.CreateProduct)))
	dynamicMux.HandleFunc("GET /admin/products/{id}/edit", adminHandler.EditProduct)
	dynamicMux.Handle("POST /admin/products/{id}", parseForm(options.MaxRequestBodyBytes, renderer)(http.HandlerFunc(adminHandler.UpdateProduct)))
	dynamicMux.HandleFunc("GET /admin/products/{id}", adminHandler.Product)
	dynamicMux.HandleFunc("/", func(responseWriter http.ResponseWriter, _ *http.Request) {
		if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusNotFound, "Page Not Found", "We couldn't find the page you requested."); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})

	dynamicHandler := permissiveCORS(dynamicMux)

	mainMux := http.NewServeMux()
	mainMux.HandleFunc("GET /health", func(responseWriter http.ResponseWriter, _ *http.Request) {
		httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"ok": true, "app": "bearly-secure"})
	})
	staticHandler := newStaticHandler(publicRoot)
	mainMux.Handle("GET /reset.css", staticHandler)
	mainMux.Handle("GET /styles.css", staticHandler)
	mainMux.Handle("GET /passkey.js", staticHandler)
	mainMux.Handle("GET /vendor/simplewebauthn/index.umd.min.js", staticHandler)
	mainMux.Handle("GET /shipping-widget.css", staticHandler)
	mainMux.Handle("GET /shipping-widget.html", staticHandler)
	mainMux.Handle("GET /shipping-widget.js", staticHandler)
	mainMux.Handle("GET /product-photos/{filename}", staticHandler)
	mainMux.HandleFunc("POST /integrations/pawpal/webhook", pawPalHandler.Webhook)
	mainMux.Handle("/", dynamicHandler)

	handler := applyMiddleware(
		mainMux,
		cspNonce,
		recoverPanics(logger, renderer),
	)
	return &Application{Handler: handler, publicRoot: publicRoot}, nil
}

func (application *Application) Close() error {
	return application.publicRoot.Close()
}

func newStaticHandler(publicRoot *os.Root) http.Handler {
	fileServer := http.FileServerFS(publicRoot.FS())
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		relativePath := request.URL.Path[1:]
		fileInfo, err := publicRoot.Stat(relativePath)
		if err != nil || fileInfo.IsDir() {
			http.NotFound(responseWriter, request)
			return
		}
		fileServer.ServeHTTP(responseWriter, request)
	})
}
