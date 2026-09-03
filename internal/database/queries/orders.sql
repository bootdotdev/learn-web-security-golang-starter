-- name: ListOrdersForUser :many
SELECT
  orders.id,
  orders.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  orders.status,
  orders.total_cents,
  orders.admin_notes,
  orders.shipping_details_encrypted,
  orders.created_at
FROM orders
JOIN users ON users.id = orders.user_id
WHERE orders.user_id = ?
ORDER BY orders.created_at DESC, orders.id DESC;

-- name: ListAllOrders :many
SELECT
  orders.id,
  orders.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  orders.status,
  orders.total_cents,
  orders.admin_notes,
  orders.shipping_details_encrypted,
  orders.created_at
FROM orders
JOIN users ON users.id = orders.user_id
ORDER BY orders.created_at DESC, orders.id DESC;

-- name: GetOrderByID :one
SELECT
  orders.id,
  orders.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  orders.status,
  orders.total_cents,
  orders.admin_notes,
  orders.shipping_details_encrypted,
  orders.created_at
FROM orders
JOIN users ON users.id = orders.user_id
WHERE orders.id = ?;

-- name: ListOrderItems :many
SELECT
  order_items.id,
  order_items.order_id,
  order_items.product_id,
  products.name AS product_name,
  order_items.quantity,
  order_items.price_cents
FROM order_items
JOIN products ON products.id = order_items.product_id
WHERE order_items.order_id = ?
ORDER BY order_items.id;

-- name: CreateOrder :one
INSERT INTO orders (
  user_id,
  status,
  total_cents,
  admin_notes,
  shipping_details_encrypted
)
VALUES (?, 'pending', ?, ?, ?)
RETURNING id;

-- name: ApprovePawPalOrder :execrows
UPDATE orders
SET status = 'paid'
WHERE id = ? AND status = 'pending';

-- name: DecrementProductInventory :execresult
UPDATE products
SET inventory_count = inventory_count - sqlc.arg(quantity)
WHERE id = sqlc.arg(product_id)
  AND is_active = 1
  AND inventory_count >= sqlc.arg(quantity);

-- name: CreateOrderItem :exec
INSERT INTO order_items (order_id, product_id, quantity, price_cents)
VALUES (?, ?, ?, ?);

-- name: DeleteOrderCartItems :exec
DELETE FROM cart_items
WHERE user_id = ?;
