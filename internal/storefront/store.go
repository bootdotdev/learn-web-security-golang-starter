package storefront

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

type Product struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	ImagePath      string `json:"image_path"`
	PriceCents     int64  `json:"price_cents"`
	CostCents      int64  `json:"cost_cents"`
	InventoryCount int64  `json:"inventory_count"`
	IsActive       bool   `json:"is_active"`
	CreatedAt      string `json:"created_at"`
}

type Review struct {
	ID           int64
	UserID       int64
	ProductID    int64
	ProductName  string
	ReviewerName string
	Rating       int64
	Body         string
	CreatedAt    string
	UpdatedAt    string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database)}
}

func (store *Store) ListProducts(ctx context.Context, maxResults int64) ([]Product, error) {
	rows, err := store.queries.ListActiveProducts(ctx, maxResults)
	if err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	return mapProducts(rows), nil
}

func (store *Store) SearchProducts(ctx context.Context, query string, maxResults int64) ([]Product, error) {
	
	params := dbgen.SearchActiveProductsParams {
		Pattern: "%" + query + "%",
		MaxResults: maxResults,
	}
	
	rows, err := store.queries.SearchActiveProducts(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("search products: %w", err)
	}
	return mapProducts(rows), nil
}

func (store *Store) ListAllProducts(ctx context.Context) ([]Product, error) {
	rows, err := store.database.QueryContext(ctx, `
		SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
		FROM products
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("list all products: %w", err)
	}
	defer rows.Close()
	return scanProducts(rows)
}

func (store *Store) FindProduct(ctx context.Context, productID int64) (Product, bool, error) {
	row, err := store.queries.GetActiveProduct(ctx, productID)
	if err != nil {
		if err == sql.ErrNoRows {
			return Product{}, false, nil
		}
		return Product{}, false, fmt.Errorf("find product: %w", err)
	}
	return mapProduct(row), true, nil
}

func (store *Store) ListReviews(ctx context.Context, productID int64) ([]Review, error) {
	rows, err := store.queries.ListReviewsForProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list product reviews: %w", err)
	}
	reviews := make([]Review, 0, len(rows))
	for _, row := range rows {
		reviews = append(reviews, Review{
			ID:           row.ID,
			UserID:       row.UserID,
			ProductID:    row.ProductID,
			ProductName:  row.ProductName,
			ReviewerName: row.ReviewerName,
			Rating:       row.Rating,
			Body:         row.Body,
			CreatedAt:    row.CreatedAt,
			UpdatedAt:    row.UpdatedAt,
		})
	}
	return reviews, nil
}

func mapProducts(rows []dbgen.Product) []Product {
	products := make([]Product, 0, len(rows))
	for _, row := range rows {
		products = append(products, mapProduct(row))
	}
	return products
}

func mapProduct(row dbgen.Product) Product {
	return Product{
		ID:             row.ID,
		Name:           row.Name,
		Description:    row.Description,
		ImagePath:      row.ImagePath,
		PriceCents:     row.PriceCents,
		CostCents:      row.CostCents,
		InventoryCount: row.InventoryCount,
		IsActive:       row.IsActive == 1,
		CreatedAt:      row.CreatedAt,
	}
}

func scanProducts(rows *sql.Rows) ([]Product, error) {
	products := make([]Product, 0)
	for rows.Next() {
		var product Product
		var active int64
		if err := rows.Scan(&product.ID, &product.Name, &product.Description, &product.ImagePath, &product.PriceCents, &product.CostCents, &product.InventoryCount, &active, &product.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan product: %w", err)
		}
		product.IsActive = active == 1
		products = append(products, product)
	}
	return products, rows.Err()
}
