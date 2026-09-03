package httpx

import "context"

type contextKey string

const cspNonceContextKey contextKey = "csp-nonce"

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, cspNonceContextKey, nonce)
}

func CSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(cspNonceContextKey).(string)
	return nonce
}
