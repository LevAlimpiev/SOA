package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Main function to start the API gateway server
func main() {
	// Get environment variables
	port := getEnv("PORT", "8080")
	userServiceAddr := getEnv("USER_SERVICE_ADDR", "localhost:50051")
	postServiceAddr := getEnv("POST_SERVICE_ADDR", "localhost:50052")

	// Set up gRPC connection to the user service
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(userServiceAddr, opts...)
	if err != nil {
		log.Fatalf("Failed to connect to user service: %v", err)
	}
	defer conn.Close()

	// Initialize gRPC clients
	InitGRPCClient(userServiceAddr)
	
	// Initialize Post service client
	err = InitPostGRPCClient(postServiceAddr)
	if err != nil {
		log.Fatalf("Failed to initialize post service client: %v", err)
	}
	defer ClosePostGRPCClient()

	// Create router and set up routes
	r := mux.NewRouter()
	setupRoutes(r)

	// Start HTTP server
	log.Printf("API Gateway is running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Data structures for request handling

// RegisterRequest represents user registration data
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UpdateProfileRequest represents user profile update data
type UpdateProfileRequest struct {
	FirstName   string     `json:"first_name,omitempty"`
	LastName    string     `json:"last_name,omitempty"`
	Email       string     `json:"email,omitempty"`
	PhoneNumber string     `json:"phone_number,omitempty"`
	BirthDate   *time.Time `json:"birth_date,omitempty"`
}

// Middleware for authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		token := r.Header.Get("Authorization")
		if token == "" || !strings.HasPrefix(token, "Bearer ") {
			http.Error(w, "Authorization token required", http.StatusUnauthorized)
			return
		}
		token = strings.TrimPrefix(token, "Bearer ")

		// Add token to request context
		ctx := context.WithValue(r.Context(), "token", token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler for user registration
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Check request method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode JSON request
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Forward request to gRPC service
	resp, err := RegisterUser(r.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// Handler for user login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Check request method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode JSON request
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Forward request to gRPC service
	resp, err := LoginUser(r.Context(), req.Username, req.Password)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Handler for user profile retrieval
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Check request method
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from request header
	token := r.Header.Get("Authorization")
	if token != "" && strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Get user ID from query parameters
	userIDParam := r.URL.Query().Get("user_id")
	var userID int32 = 0
	if userIDParam != "" {
		id, err := strconv.Atoi(userIDParam)
		if err != nil {
			http.Error(w, "Authorization token required", http.StatusUnauthorized)
			return
		}
		userID = int32(id)
	}

	// Require token for security
	if token == "" {
		http.Error(w, "Authorization token required", http.StatusUnauthorized)
		return
	}

	// Forward request to gRPC service
	ctx := r.Context()
	resp, err := GetUserProfile(ctx, token, userID)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Format JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Handler for user profile update
func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Check request method
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from Authorization header
	token := r.Header.Get("Authorization")
	if token == "" || !strings.HasPrefix(token, "Bearer ") {
		log.Printf("Error: token missing or invalid format: %s", token)
		http.Error(w, "Authorization token required", http.StatusUnauthorized)
		return
	}
	token = strings.TrimPrefix(token, "Bearer ")
	log.Printf("Token received in updateProfileHandler: %s", token)

	// Decode JSON request
	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check for empty request
	if req.FirstName == "" && req.LastName == "" && req.Email == "" && req.PhoneNumber == "" && req.BirthDate == nil {
		http.Error(w, "No profile data provided for update", http.StatusBadRequest)
		return
	}

	// Forward request to gRPC service
	resp, err := UpdateUserProfile(r.Context(), token, req)
	if err != nil {
		handleGRPCError(w, err)
		return
	}

	// Format JSON response
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
	case codes.NotFound:
		http.Error(w, st.Message(), http.StatusNotFound)
	case codes.AlreadyExists:
		http.Error(w, st.Message(), http.StatusConflict)
	case codes.Unauthenticated:
		http.Error(w, st.Message(), http.StatusUnauthorized)
	case codes.PermissionDenied:
		http.Error(w, st.Message(), http.StatusForbidden)
	default:
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// setupRoutes настраивает HTTP маршруты для API gateway
func setupRoutes(router *mux.Router) {
	// Маршруты для пользователей
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/profile", profileHandler).Methods("GET")
	router.HandleFunc("/api/update-profile", updateProfileHandler).Methods("PUT")

	// Регистрируем маршруты для постов
	RegisterPostHandlers(router)
}
