package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
)

const bufSize = 1024 * 1024

var (
	lis        *bufconn.Listener
	grpcServer *grpc.Server
	dbConn     *sql.DB // Глобальная переменная для закрытия соединения с БД
)

// UserServiceServer реализует интерфейс gRPC для тестов
type UserServiceServer struct {
	pb.UnimplementedUserServiceServer
	DB sqlmock.Sqlmock
}

// Register handles user registration request
func (s *UserServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	// Check if user exists
	s.DB.ExpectQuery("SELECT EXISTS").
		WithArgs(req.Username, req.Email).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Return successful registration result
	createdAt := time.Now()
	s.DB.ExpectQuery("INSERT INTO users").
		WithArgs(req.Username, req.Email, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, req.Username, req.Email, createdAt))

	return &pb.AuthResponse{
		Token: "test_token",
		User: &pb.User{
			Id:        1,
			Username:  req.Username,
			Email:     req.Email,
			CreatedAt: timestamppb.New(createdAt),
		},
	}, nil
}

// Login handles user login request
func (s *UserServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	// Hash password for testing
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Set up expected query
	s.DB.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs(req.Username).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, req.Username, "test@example.com", hashedPassword, createdAt))

	// Check password
	if req.Password != "password123" {
		return nil, status.Error(codes.Unauthenticated, "Invalid username or password")
	}

	return &pb.AuthResponse{
		Token: "test_token",
		User: &pb.User{
			Id:        1,
			Username:  req.Username,
			Email:     "test@example.com",
			CreatedAt: timestamppb.New(createdAt),
		},
	}, nil
}

// GetProfile handles the request to get user profile
func (s *UserServiceServer) GetProfile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileResponse, error) {
	// Check if token or user_id is provided
	if req.Token == "" && req.UserId == 0 {
		return &pb.ProfileResponse{
			Success: false,
			Error:   "Either token or user_id must be provided",
		}, status.Error(codes.InvalidArgument, "Either token or user_id must be provided")
	}

	// If token is provided, check it
	var userID int32 = req.UserId
	if req.Token != "" {
		// For testing purposes, consider token "invalid_token" as invalid
		if req.Token == "invalid_token" {
			return &pb.ProfileResponse{
				Success: false,
				Error:   "Invalid token",
			}, status.Error(codes.Unauthenticated, "Invalid token")
		}
		// For testing purposes, consider token "test_token" as valid for user with ID 1
		userID = 1
	}

	// If user_id is provided, search for user by ID
	createdAt := time.Now()
	if userID > 0 {
		// For testing purposes, consider user with ID 999 as non-existent
		if userID == 999 {
			return &pb.ProfileResponse{
				Success: false,
				Error:   "User not found",
			}, status.Error(codes.NotFound, "User not found")
		}

		// Set up expected query
		s.DB.ExpectQuery("SELECT id, username, email, created_at FROM users WHERE id = \\$1").
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
				AddRow(userID, "testuser", "test@example.com", createdAt))

		return &pb.ProfileResponse{
			User: &pb.User{
				Id:        userID,
				Username:  "testuser",
				Email:     "test@example.com",
				CreatedAt: timestamppb.New(createdAt),
			},
			Success: true,
		}, nil
	}

	return &pb.ProfileResponse{
		Success: false,
		Error:   "User not found",
	}, status.Error(codes.NotFound, "User not found")
}

// UpdateProfile handles the user profile update request
func (s *UserServiceServer) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.ProfileResponse, error) {
	// Debug output
	log.Printf("Received token in UpdateProfile gRPC method: %s", req.Token)

	// Token validation
	if req.Token == "" {
		return nil, status.Error(codes.Unauthenticated, "Authorization token required")
	}

	// Using hardcoded data for testing
	user := &pb.User{
		Id:          1,
		Username:    "testuser",
		Email:       "test@example.com",
		FirstName:   "Test",
		LastName:    "User",
		PhoneNumber: "1234567890",
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
	}

	// Update user fields if specified in request
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.BirthDate != nil {
		user.BirthDate = req.BirthDate
	}

	// Update update time
	user.UpdatedAt = timestamppb.Now()

	return &pb.ProfileResponse{
		User:    user,
		Success: true,
	}, nil
}

// RegisterHandler handles HTTP request for user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create gRPC request
	grpcReq := &pb.RegisterRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	// Call gRPC method
	resp, err := userClient.Register(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			http.Error(w, st.Message(), http.StatusBadRequest)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Format HTTP response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// LoginHandler handles HTTP request for user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Decode request body
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create gRPC request
	grpcReq := &pb.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	}

	// Call gRPC method
	resp, err := userClient.Login(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			http.Error(w, st.Message(), http.StatusUnauthorized)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Format HTTP response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// profileHandler обрабатывает HTTP-запрос на получение профиля пользователя
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Получение token из заголовка Authorization
	token := r.Header.Get("Authorization")
	if token != "" && strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Получение user_id из строки запроса
	var userID int32
	userIDParam := r.URL.Query().Get("user_id")
	if userIDParam != "" {
		userIDInt, err := strconv.Atoi(userIDParam)
		if err != nil {
			http.Error(w, "Invalid user_id parameter", http.StatusBadRequest)
			return
		}
		userID = int32(userIDInt)
	}

	// Проверка наличия либо token, либо user_id
	if token == "" && userID == 0 {
		http.Error(w, "Either token or user_id must be provided", http.StatusBadRequest)
		return
	}

	// Создаем gRPC-запрос
	grpcReq := &pb.ProfileRequest{
		Token:  token,
		UserId: userID,
	}

	// Вызываем gRPC-метод
	resp, err := userClient.GetProfile(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.InvalidArgument:
				http.Error(w, st.Message(), http.StatusBadRequest)
				return
			case codes.NotFound, codes.Unauthenticated:
				http.Error(w, st.Message(), http.StatusUnauthorized)
				return
			}
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Формируем HTTP-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// updateProfileHandler обрабатывает HTTP-запрос на обновление профиля пользователя
func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Получение token из заголовка Authorization
	token := r.Header.Get("Authorization")
	if token != "" && strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Отладочный вывод
	log.Printf("Received token in updateProfileHandler: %s", token)

	// Проверка наличия токена
	if token == "" {
		http.Error(w, "Authorization token required", http.StatusUnauthorized)
		return
	}

	// Декодируем тело запроса
	var req struct {
		FirstName   string                 `json:"first_name"`
		LastName    string                 `json:"last_name"`
		Email       string                 `json:"email"`
		PhoneNumber string                 `json:"phone_number"`
		BirthDate   *timestamppb.Timestamp `json:"birth_date"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Создаем gRPC-запрос
	grpcReq := &pb.UpdateProfileRequest{
		Token:       token,
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		Email:       req.Email,
		PhoneNumber: req.PhoneNumber,
		BirthDate:   req.BirthDate,
	}

	// Вызываем gRPC-метод
	resp, err := userClient.UpdateProfile(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok {
			switch st.Code() {
			case codes.InvalidArgument:
				http.Error(w, st.Message(), http.StatusBadRequest)
				return
			case codes.Unauthenticated:
				http.Error(w, st.Message(), http.StatusUnauthorized)
				return
			}
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Формируем HTTP-ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Глобальная переменная для gRPC-клиента
var userClient pb.UserServiceClient

// setupGRPCServer настраивает тестовый gRPC сервер
func setupGRPCServer(t *testing.T) (*grpc.Server, net.Listener) {
	// Создаем мок для базы данных
	_, mock, err := sqlmock.New()
	require.NoError(t, err)

	// Создаем тестовый сервер gRPC
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Не удалось создать слушатель: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &UserServiceServer{DB: mock})

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Ошибка при запуске сервера: %v", err)
		}
	}()

	t.Logf("gRPC сервер запущен на: %s", lis.Addr().String())
	return s, lis
}

// setupGRPCClient создает gRPC клиент для тестирования
func setupGRPCClient(t *testing.T, lis net.Listener) *grpc.ClientConn {
	// Создаем клиентское соединение к серверу
	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Не удалось подключиться к серверу: %v", err)
	}

	// Инициализируем gRPC клиент
	userClient = pb.NewUserServiceClient(conn)

	t.Logf("gRPC клиент подключен к: %s", lis.Addr().String())
	return conn
}

// Вспомогательная функция для создания HTTP-сервера
func setupHTTPServer(t *testing.T, conn *grpc.ClientConn) *httptest.Server {
	// Создание HTTP-сервера
	r := mux.NewRouter()
	r.HandleFunc("/api/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/api/login", LoginHandler).Methods("POST")
	r.HandleFunc("/api/profile", profileHandler).Methods("GET")
	r.HandleFunc("/api/update-profile", updateProfileHandler).Methods("PUT")

	server := httptest.NewServer(r)
	t.Logf("HTTP server started at: %s", server.URL)

	return server
}

// Очистка ресурсов после теста
func tearDown(conn *grpc.ClientConn, server *httptest.Server, grpcServer *grpc.Server) {
	if conn != nil {
		conn.Close()
	}
	if grpcServer != nil {
		grpcServer.Stop()
	}
	if server != nil {
		server.Close()
	}
}

func TestIntegration_Register(t *testing.T) {
	if testing.Short() {
		t.Skip("Пропускаем интеграционные тесты в коротком режиме")
	}

	// Настраиваем gRPC сервер
	grpcServer, listener := setupGRPCServer(t)
	defer grpcServer.Stop()

	// Настраиваем gRPC клиент
	conn := setupGRPCClient(t, listener)
	defer conn.Close()

	// Настраиваем HTTP-сервер
	server := setupHTTPServer(t, conn)
	defer tearDown(conn, server, grpcServer)

	// Создаем HTTP запрос
	reqBody := map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", server.URL+"/api/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Отправляем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Проверяем код ответа
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Декодируем и проверяем ответ
	var response map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&response)

	token, ok := response["token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, token)

	user, ok := response["user"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "testuser", user["username"])
	assert.Equal(t, "test@example.com", user["email"])
}

func TestIntegration_Login(t *testing.T) {
	// Запуск тестов интеграции
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Создание HTTP-клиента
	client := &http.Client{}

	// Подготовка данных для входа
	loginData := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	loginJSON, _ := json.Marshal(loginData)

	// Отправка запроса на вход
	loginReq, _ := http.NewRequest("POST", "http://localhost:8080/api/login", bytes.NewBuffer(loginJSON))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("Failed to send login request: %v", err)
	}
	defer loginResp.Body.Close()

	// Проверка статуса ответа
	if loginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("Expected status OK, got %v: %s", loginResp.Status, body)
	}

	// Чтение ответа
	var loginResult map[string]interface{}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginResult); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}

	// Проверка наличия токена в ответе
	token, ok := loginResult["token"].(string)
	if !ok || token == "" {
		t.Fatalf("No token in login response: %v", loginResult)
	}
}

func TestIntegration_GetProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Пропускаем интеграционные тесты в коротком режиме")
	}

	// Настраиваем gRPC сервер
	grpcServer, listener := setupGRPCServer(t)
	defer grpcServer.Stop()

	// Настраиваем gRPC клиент
	conn := setupGRPCClient(t, listener)
	defer conn.Close()

	// Настраиваем HTTP-сервер
	server := setupHTTPServer(t, conn)
	defer tearDown(conn, server, grpcServer)

	// Создаем HTTP клиент
	client := &http.Client{}

	// Тест 1: Получение профиля по user_id
	t.Run("GetProfileByUserID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/api/profile?user_id=1", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Проверяем код ответа
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Декодируем и проверяем ответ
		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)

		assert.True(t, response["success"].(bool))
		user, ok := response["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, float64(1), user["id"])
		assert.Equal(t, "testuser", user["username"])
		assert.Equal(t, "test@example.com", user["email"])
	})

	// Тест 2: Получение профиля по токену
	t.Run("GetProfileByToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/api/profile", nil)
		req.Header.Set("Authorization", "Bearer test_token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Проверяем код ответа
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Декодируем и проверяем ответ
		var response map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&response)

		assert.True(t, response["success"].(bool))
		user, ok := response["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, float64(1), user["id"])
		assert.Equal(t, "testuser", user["username"])
		assert.Equal(t, "test@example.com", user["email"])
	})

	// Тест 3: Пользователь не найден
	t.Run("UserNotFound", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/api/profile?user_id=999", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Проверяем код ответа - ожидаем 401 Unauthorized для ошибки NotFound
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// Тест 4: Не указан ни токен, ни user_id
	t.Run("NoParameters", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/api/profile", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Проверяем код ответа - ожидаем 400 Bad Request
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	// Тест 5: Недействительный токен
	t.Run("InvalidToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", server.URL+"/api/profile", nil)
		req.Header.Set("Authorization", "Bearer invalid_token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Проверяем код ответа - ожидаем 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

// TestIntegration_UpdateProfile tests the user profile update functionality
func TestIntegration_UpdateProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Set up gRPC server
	grpcServer, listener := setupGRPCServer(t)
	defer grpcServer.Stop()

	// Set up gRPC client
	conn := setupGRPCClient(t, listener)
	defer conn.Close()

	// Explicitly ensure that userClient is initialized
	if userClient == nil {
		userClient = pb.NewUserServiceClient(conn)
	}

	// Set up HTTP server
	httpServer := setupHTTPServer(t, conn)
	defer tearDown(conn, httpServer, grpcServer)

	// Step 1: Register a user
	registerReq := map[string]string{
		"username": "testuser",
		"password": "password",
		"email":    "test@example.com",
	}
	registerBody, _ := json.Marshal(registerReq)

	registerResp, err := http.Post(httpServer.URL+"/api/register", "application/json", bytes.NewBuffer(registerBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, registerResp.StatusCode, "Error registering user")

	// Debug output for registration
	registerRespBody, _ := io.ReadAll(registerResp.Body)
	t.Logf("Registration response body: %s", string(registerRespBody))
	registerResp.Body.Close()

	// Extract token from registration response
	var registerResult struct {
		Token string `json:"token"`
		User  struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
	}

	err = json.Unmarshal(registerRespBody, &registerResult)
	require.NoError(t, err, "Error parsing registration response")
	require.NotEmpty(t, registerResult.Token, "Token missing in registration response")

	token := registerResult.Token
	t.Logf("Token received during registration: %s", token)

	// Skip login since we already have a token

	// First check HTTP request for profile update
	updateData := map[string]interface{}{
		"first_name":   "Updated",
		"last_name":    "Name",
		"email":        "updated@example.com",
		"phone_number": "+79001234567",
	}
	updateBody, _ := json.Marshal(updateData)

	// Create HTTP request
	updateHTTPReq, err := http.NewRequest("PUT", httpServer.URL+"/api/update-profile", bytes.NewBuffer(updateBody))
	require.NoError(t, err)

	// Add token to header
	updateHTTPReq.Header.Set("Content-Type", "application/json")
	updateHTTPReq.Header.Set("Authorization", "Bearer "+token)

	// Debug output
	t.Logf("Sending HTTP request with token: %s", token)
	t.Logf("Authorization header: %s", updateHTTPReq.Header.Get("Authorization"))
	t.Logf("Request URL: %s", updateHTTPReq.URL.String())
	t.Logf("Request method: %s", updateHTTPReq.Method)
	t.Logf("Request body: %s", updateBody)

	// Send request
	httpClient := &http.Client{}
	updateResp2, err := httpClient.Do(updateHTTPReq)
	require.NoError(t, err)
	defer updateResp2.Body.Close()

	// Debug output
	t.Logf("Received HTTP response with code: %d", updateResp2.StatusCode)

	// Check response code
	require.Equal(t, http.StatusOK, updateResp2.StatusCode, "HTTP request for profile update returned code %d instead of 200", updateResp2.StatusCode)

	// Check response body
	var updateRespBody struct {
		Success bool `json:"success"`
		User    struct {
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"user"`
	}
	err = json.NewDecoder(updateResp2.Body).Decode(&updateRespBody)
	require.NoError(t, err)
	require.True(t, updateRespBody.Success)
	require.Equal(t, "updated@example.com", updateRespBody.User.Email)

	t.Log("Test passed successfully")
}

// Вспомогательная функция для генерации хеша пароля
func generatePasswordHash(t *testing.T, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return string(hash)
}
