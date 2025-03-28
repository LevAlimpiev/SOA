package main

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"
	
	"github.com/dgrijalva/jwt-go"
)

// JWTClaims представляет собой набор полей JWT-токена
type JWTClaims struct {
	UserID   int32  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

// getUserIDFromContext извлекает ID пользователя из контекста запроса после аутентификации
func getUserIDFromContext(ctx context.Context) (int32, bool) {
	// Получаем токен из контекста
	tokenVal := ctx.Value("token")
	if tokenVal == nil {
		return 0, false
	}

	token, ok := tokenVal.(string)
	if !ok || token == "" {
		return 0, false
	}

	// Проверяем и извлекаем информацию из токена
	// В реальной системе здесь должна быть проверка JWT токена
	claims, err := ValidateAccessToken(ctx, token)
	if err != nil {
		log.Printf("Failed to validate token: %v", err)
		return 0, false
	}

	// Проверяем, что у нас есть subject claim с ID пользователя
	if claims.Subject == "" {
		log.Printf("Missing subject claim in token")
		return 0, false
	}

	// Преобразуем ID пользователя из строки в int32
	userID, err := strconv.ParseInt(claims.Subject, 10, 32)
	if err != nil {
		log.Printf("Failed to parse user ID from token: %v", err)
		return 0, false
	}

	return int32(userID), true
}

// ValidateAccessToken проверяет JWT токен и возвращает его claims
func ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.StandardClaims, error) {
	// Секретный ключ для проверки токена
	secretKey := []byte(getEnv("JWT_SECRET", "your-super-secret-key-for-jwt-tokens"))
	
	// Парсим и проверяем токен
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем, что используется правильный алгоритм
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("неверный метод подписи токена")
		}
		return secretKey, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Проверяем валидность токена
	if !token.Valid {
		return nil, errors.New("недействительный токен")
	}
	
	// Извлекаем claims
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, errors.New("неверный формат claims")
	}
	
	// Проверяем срок действия токена
	if claims.ExpiresAt > 0 && claims.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("срок действия токена истек")
	}
	
	return claims, nil
} 