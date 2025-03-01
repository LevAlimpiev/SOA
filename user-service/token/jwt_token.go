package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTTokenService - реализация TokenService на основе JWT
type JWTTokenService struct {
	secretKey       []byte
	tokenExpiration int
}

// JWTClaims определяет структуру JWT токена
type JWTClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

// NewJWTTokenService создает новый экземпляр JWTTokenService
func NewJWTTokenService(secretKey string, expirationHours int) *JWTTokenService {
	if expirationHours <= 0 {
		expirationHours = 24 // По умолчанию 24 часа
	}

	if len(secretKey) == 0 {
		secretKey = "default-secret-key-change-in-production" // Значение по умолчанию
	}

	return &JWTTokenService{
		secretKey:       []byte(secretKey),
		tokenExpiration: expirationHours,
	}
}

// GenerateToken создает новый JWT токен для пользователя
func (s *JWTTokenService) GenerateToken(userID int, username, email string) (string, error) {
	// Устанавливаем время создания и истечения токена
	now := time.Now()
	expires := now.Add(time.Duration(s.tokenExpiration) * time.Hour)

	// Создаем набор claims (утверждений) для токена
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expires),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "user-service",
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	// Создаем токен с определенным алгоритмом подписи
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Подписываем токен секретным ключом
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", fmt.Errorf("ошибка при подписи токена: %w", err)
	}

	return tokenString, nil
}

// VerifyToken проверяет JWT токен и возвращает информацию о пользователе
func (s *JWTTokenService) VerifyToken(tokenString string) (*TokenClaims, error) {
	// Парсим и проверяем токен
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Убеждаемся, что используется ожидаемый алгоритм подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
		}
		return s.secretKey, nil
	})

	// Обрабатываем ошибки
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	// Проверяем валидность токена
	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Получаем claims из токена
	jwtClaims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Преобразуем в TokenClaims для совместимости с интерфейсом
	claims := &TokenClaims{
		UserID:    jwtClaims.UserID,
		Username:  jwtClaims.Username,
		Email:     jwtClaims.Email,
		IssuedAt:  jwtClaims.IssuedAt.Time,
		ExpiresAt: jwtClaims.ExpiresAt.Time,
	}

	return claims, nil
}
