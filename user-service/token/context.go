package token

import (
	"context"
)

// contextKey для хранения claims в контексте
type contextKey string

// userClaimsKey - ключ для хранения информации о пользователе в контексте
const userClaimsKey = contextKey("user_claims")

// WithUserClaims добавляет информацию о пользователе в контекст
func WithUserClaims(ctx context.Context, claims *TokenClaims) context.Context {
	return context.WithValue(ctx, userClaimsKey, claims)
}

// UserClaimsFromContext извлекает информацию о пользователе из контекста
func UserClaimsFromContext(ctx context.Context) *TokenClaims {
	claims, ok := ctx.Value(userClaimsKey).(*TokenClaims)
	if !ok {
		return nil
	}
	return claims
}
