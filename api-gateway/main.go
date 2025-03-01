package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Базовый URL для gRPC сервиса пользователей
var userServiceGRPCAddr string

func main() {
	// Получение URL сервиса пользователей из переменной окружения
	userServiceGRPCAddr = getEnv("USER_SERVICE_GRPC", "user-service:50051")

	// Инициализация gRPC клиента
	err := InitGRPCClient(userServiceGRPCAddr)
	if err != nil {
		log.Fatalf("Failed to initialize gRPC client: %v", err)
	}
	defer CloseGRPCClient()

	log.Printf("User service gRPC available at: %s", userServiceGRPCAddr)

	// Создание маршрутизатора
	r := mux.NewRouter()

	// Определение публичных маршрутов
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")

	// Запуск сервера
	port := getEnv("PORT", "8080")
	log.Printf("API Gateway started on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Структура для запроса регистрации
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Структура для запроса аутентификации
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authMiddleware проверяет валидность токена
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получение токена из заголовка
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Проверка формата токена "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Authorization header format must be 'Bearer <token>'", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Токен передается в сервис пользователей для проверки
		// через заголовок запроса
		ctx := context.WithValue(r.Context(), "token", token)

		// Вызов следующего обработчика с обновленным контекстом
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Обработчик для регистрации пользователей
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Установка таймаута для gRPC запроса
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Вызов gRPC метода
	resp, err := RegisterUser(ctx, req.Username, req.Email, req.Password)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Формирование JSON-ответа
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// Обработчик для аутентификации пользователей
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Установка таймаута для gRPC запроса
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Вызов gRPC метода
	resp, err := LoginUser(ctx, req.Username, req.Password)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Формирование JSON-ответа
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Вспомогательная функция для получения значений из переменных окружения
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// Обработка ошибок gRPC
func handleGRPCError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	switch st.Code() {
	case codes.InvalidArgument:
		http.Error(w, st.Message(), http.StatusBadRequest)
	case codes.AlreadyExists:
		http.Error(w, st.Message(), http.StatusConflict)
	case codes.NotFound, codes.Unauthenticated:
		http.Error(w, st.Message(), http.StatusUnauthorized)
	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// setupRoutes настраивает HTTP маршруты для API gateway
func setupRoutes(router *mux.Router) {
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
}
