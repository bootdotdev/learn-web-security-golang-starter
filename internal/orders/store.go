package orders

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/cart"
	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
	"github.com/bootdotdev/learn-web-security/internal/storage"
)

var ErrInsufficientInventory = errors.New("one or more cart items are no longer available in the requested quantity")

const InsufficientInventoryMessage = "One or more cart items are no longer available in the requested quantity."

type Order struct {
	ID                       int64
	UserID                   int64
	CustomerName             string
	CustomerEmail            string
	Status                   string
	TotalCents               int64
	AdminNotes               string
	ShippingDetailsEncrypted *string
	CreatedAt                string
}

type Item struct {
	ID          int64
	OrderID     int64
	ProductID   int64
	ProductName string
	Quantity    int64
	PriceCents  int64
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database)}
}

func (store *Store) CreateFromCart(ctx context.Context, userID int64, cartItems []cart.Item, discountCents int64, shippingDetails ShippingDetails, adminNotes string, keyring *storage.Keyring) (Order, error) {
	encryptedShippingDetails, err := EncryptShippingDetails(shippingDetails, keyring)
	if err != nil {
		return Order{}, err
	}
	var totalCents int64
	for _, cartItem := range cartItems {
		totalCents += cartItem.LineTotalCents
	}
	totalCents -= discountCents
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Order{}, fmt.Errorf("begin order transaction: %w", err)
	}
	defer transaction.Rollback()
	queries := store.queries.WithTx(transaction)
	orderID, err := queries.CreateOrder(ctx, dbgen.CreateOrderParams{
		UserID:                   userID,
		TotalCents:               totalCents,
		AdminNotes:               adminNotes,
		ShippingDetailsEncrypted: &encryptedShippingDetails,
	})
	if err != nil {
		return Order{}, fmt.Errorf("create order: %w", err)
	}
	for _, cartItem := range cartItems {
		result, err := queries.DecrementProductInventory(ctx, dbgen.DecrementProductInventoryParams{
			Quantity:  cartItem.Quantity,
			ProductID: cartItem.ProductID,
		})
		if err != nil {
			return Order{}, fmt.Errorf("decrement product inventory: %w", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return Order{}, fmt.Errorf("read inventory update: %w", err)
		}
		if rowsAffected != 1 {
			return Order{}, ErrInsufficientInventory
		}
		if err := queries.CreateOrderItem(ctx, dbgen.CreateOrderItemParams{
			OrderID:    orderID,
			ProductID:  cartItem.ProductID,
			Quantity:   cartItem.Quantity,
			PriceCents: cartItem.PriceCents,
		}); err != nil {
			return Order{}, fmt.Errorf("create order item: %w", err)
		}
	}
	if err := queries.DeleteOrderCartItems(ctx, userID); err != nil {
		return Order{}, fmt.Errorf("clear ordered cart: %w", err)
	}
	order, found, err := findByID(ctx, queries, orderID)
	if err != nil {
		return Order{}, err
	}
	if !found {
		return Order{}, errors.New("created order was not found")
	}
	if err := transaction.Commit(); err != nil {
		return Order{}, fmt.Errorf("commit order transaction: %w", err)
	}
	return order, nil
}

func (store *Store) ListForUser(ctx context.Context, userID int64) ([]Order, error) {
	rows, err := store.queries.ListOrdersForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list orders for user: %w", err)
	}
	orders := make([]Order, 0, len(rows))
	for _, row := range rows {
		orders = append(orders, mapListOrder(row))
	}
	return orders, nil
}

func (store *Store) ListAll(ctx context.Context) ([]Order, error) {
	rows, err := store.queries.ListAllOrders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all orders: %w", err)
	}
	orders := make([]Order, 0, len(rows))
	for _, row := range rows {
		orders = append(orders, Order{
			ID:                       row.ID,
			UserID:                   row.UserID,
			CustomerName:             row.CustomerName,
			CustomerEmail:            row.CustomerEmail,
			Status:                   row.Status,
			TotalCents:               row.TotalCents,
			AdminNotes:               row.AdminNotes,
			ShippingDetailsEncrypted: row.ShippingDetailsEncrypted,
			CreatedAt:                row.CreatedAt,
		})
	}
	return orders, nil
}

func (store *Store) FindByID(ctx context.Context, orderID int64) (Order, bool, error) {
	return findByID(ctx, store.queries, orderID)
}

func (store *Store) ApprovePawPalOrder(ctx context.Context, orderID int64) (bool, error) {
	rowsAffected, err := store.queries.ApprovePawPalOrder(ctx, orderID)
	if err != nil {
		return false, fmt.Errorf("approve PawPal order: %w", err)
	}
	return rowsAffected == 1, nil
}

func (store *Store) ListItems(ctx context.Context, orderID int64) ([]Item, error) {
	rows, err := store.queries.ListOrderItems(ctx, orderID)
	if err != nil {
		return nil, fmt.Errorf("list order items: %w", err)
	}
	items := make([]Item, 0, len(rows))
	for _, row := range rows {
		items = append(items, Item{
			ID:          row.ID,
			OrderID:     row.OrderID,
			ProductID:   row.ProductID,
			ProductName: row.ProductName,
			Quantity:    row.Quantity,
			PriceCents:  row.PriceCents,
		})
	}
	return items, nil
}

func findByID(ctx context.Context, queries *dbgen.Queries, orderID int64) (Order, bool, error) {
	row, err := queries.GetOrderByID(ctx, orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Order{}, false, nil
		}
		return Order{}, false, fmt.Errorf("find order: %w", err)
	}
	return mapOrder(row), true, nil
}

func mapListOrder(row dbgen.ListOrdersForUserRow) Order {
	return Order{
		ID:                       row.ID,
		UserID:                   row.UserID,
		CustomerName:             row.CustomerName,
		CustomerEmail:            row.CustomerEmail,
		Status:                   row.Status,
		TotalCents:               row.TotalCents,
		AdminNotes:               row.AdminNotes,
		ShippingDetailsEncrypted: row.ShippingDetailsEncrypted,
		CreatedAt:                row.CreatedAt,
	}
}

func mapOrder(row dbgen.GetOrderByIDRow) Order {
	return Order{
		ID:                       row.ID,
		UserID:                   row.UserID,
		CustomerName:             row.CustomerName,
		CustomerEmail:            row.CustomerEmail,
		Status:                   row.Status,
		TotalCents:               row.TotalCents,
		AdminNotes:               row.AdminNotes,
		ShippingDetailsEncrypted: row.ShippingDetailsEncrypted,
		CreatedAt:                row.CreatedAt,
	}
}
