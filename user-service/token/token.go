package token

import (
	"errors"
	"fmt"
	"time"
)

// Errors
var (
	ErrInvalidToken = errors.New("неверный токен")
	ErrExpiredToken = errors.New("токен истек")
)

// TokenClaims содержит информацию, внедренную в токен
type TokenClaims struct {
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TokenService определяет интерфейс для работы с токенами
type TokenService interface {
	// GenerateToken создает новый токен для пользователя
	GenerateToken(userID int, username, email string) (string, error)

	// VerifyToken проверяет токен и возвращает информацию о пользователе
	VerifyToken(token string) (*TokenClaims, error)
}

// SimpleTokenService - простая реализация сервиса токенов
type SimpleTokenService struct {
	// Токены хранятся в памяти в формате token -> claims
	tokens map[string]TokenClaims
	// Срок действия токена в часах
	tokenExpiration int
}

// NewSimpleTokenService создает новый экземпляр SimpleTokenService
func NewSimpleTokenService(expirationHours int) *SimpleTokenService {
	if expirationHours <= 0 {
		expirationHours = 24 // По умолчанию 24 часа
	}

	return &SimpleTokenService{
		tokens:          make(map[string]TokenClaims),
		tokenExpiration: expirationHours,
	}
}

// GenerateToken создает новый токен для пользователя
func (s *SimpleTokenService) GenerateToken(userID int, username, email string) (string, error) {
	now := time.Now()
	expires := now.Add(time.Duration(s.tokenExpiration) * time.Hour)

	claims := TokenClaims{
		UserID:    userID,
		Username:  username,
		Email:     email,
		IssuedAt:  now,
		ExpiresAt: expires,
	}

	// В простой реализации используем предсказуемый формат токена
	// В реальном приложении здесь использовался бы JWT или другой формат
	tokenString := fmt.Sprintf("user_token_%d_%d", userID, now.Unix())

	// Сохраняем токен в памяти
	s.tokens[tokenString] = claims

	return tokenString, nil
}

// VerifyToken проверяет токен и возвращает информацию о пользователе
func (s *SimpleTokenService) VerifyToken(token string) (*TokenClaims, error) {
	claims, exists := s.tokens[token]
	if !exists {
		return nil, ErrInvalidToken
	}

	// Проверяем срок действия
	if time.Now().After(claims.ExpiresAt) {
		delete(s.tokens, token) // Удаляем просроченный токен
		return nil, ErrExpiredToken
	}

	return &claims, nil
}
