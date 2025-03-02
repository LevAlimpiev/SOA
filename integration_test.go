package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
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

// Register обрабатывает запрос на регистрацию пользователя
func (s *UserServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	// Проверяем, существует ли пользователь
	s.DB.ExpectQuery("SELECT EXISTS").
		WithArgs(req.Username, req.Email).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Возвращаем успешный результат регистрации
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

// Login обрабатывает запрос на вход пользователя
func (s *UserServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	// Хешируем пароль для тестирования
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Настраиваем ожидаемый запрос
	s.DB.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs(req.Username).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, req.Username, "test@example.com", hashedPassword, createdAt))

	// Проверяем пароль
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

// GetProfile обрабатывает запрос на получение профиля пользователя
func (s *UserServiceServer) GetProfile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileResponse, error) {
	// Проверяем наличие токена или user_id
	if req.Token == "" && req.UserId == 0 {
		return &pb.ProfileResponse{
			Success: false,
			Error:   "Either token or user_id must be provided",
		}, status.Error(codes.InvalidArgument, "Either token or user_id must be provided")
	}

	// Если указан токен, проверяем его
	var userID int32 = req.UserId
	if req.Token != "" {
		// Для тестирования считаем, что токен "invalid_token" недействителен
		if req.Token == "invalid_token" {
			return &pb.ProfileResponse{
				Success: false,
				Error:   "Invalid token",
			}, status.Error(codes.Unauthenticated, "Invalid token")
		}
		// Для тестирования считаем, что токен "test_token" соответствует пользователю с ID 1
		userID = 1
	}

	// Если указан user_id, ищем пользователя по ID
	createdAt := time.Now()
	if userID > 0 {
		// Для тестирования считаем, что пользователь с ID 999 не существует
		if userID == 999 {
			return &pb.ProfileResponse{
				Success: false,
				Error:   "User not found",
			}, status.Error(codes.NotFound, "User not found")
		}

		// Настраиваем ожидаемый запрос
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

// RegisterHandler обрабатывает HTTP-запрос на регистрацию
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Декодируем тело запроса
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Создаем gRPC-запрос
	grpcReq := &pb.RegisterRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}

	// Вызываем gRPC-метод
	resp, err := userClient.Register(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.AlreadyExists {
			http.Error(w, st.Message(), http.StatusConflict)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Формируем HTTP-ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(resp)
}

// LoginHandler обрабатывает HTTP-запрос на вход
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Декодируем тело запроса
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Создаем gRPC-запрос
	grpcReq := &pb.LoginRequest{
		Username: req.Username,
		Password: req.Password,
	}

	// Вызываем gRPC-метод
	resp, err := userClient.Login(r.Context(), grpcReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unauthenticated {
			http.Error(w, st.Message(), http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Формируем HTTP-ответ
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

// Глобальная переменная для gRPC-клиента
var userClient pb.UserServiceClient

// Вспомогательная функция для настройки gRPC-сервера
func setupGRPCServer(t *testing.T) {
	var err error
	// Создаем мок для базы данных
	var mockSQL sqlmock.Sqlmock
	dbConn, mockSQL, err = sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}

	lis = bufconn.Listen(bufSize)
	grpcServer = grpc.NewServer()

	// Регистрируем gRPC-сервер
	pb.RegisterUserServiceServer(grpcServer, &UserServiceServer{DB: mockSQL})

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()
}

// Диалер для gRPC через буфер вместо сети
func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

// Вспомогательная функция для создания HTTP-сервера
func setupHTTPServer(t *testing.T, conn *grpc.ClientConn) *httptest.Server {
	// Инициализация gRPC-клиента
	userClient = pb.NewUserServiceClient(conn)

	// Создание HTTP-сервера
	r := mux.NewRouter()
	r.HandleFunc("/api/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/api/login", LoginHandler).Methods("POST")
	r.HandleFunc("/api/profile", profileHandler).Methods("GET")

	// Запуск тестового HTTP-сервера
	return httptest.NewServer(r)
}

// Очистка ресурсов после теста
func tearDown(conn *grpc.ClientConn, server *httptest.Server) {
	conn.Close()
	grpcServer.Stop()
	server.Close()
	if dbConn != nil {
		dbConn.Close()
	}
}

func TestIntegration_Register(t *testing.T) {
	// Настраиваем gRPC-сервер
	setupGRPCServer(t)

	// Устанавливаем gRPC соединение
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	// Настраиваем HTTP-сервер
	server := setupHTTPServer(t, conn)
	defer tearDown(conn, server)

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
	// Настраиваем gRPC-сервер
	setupGRPCServer(t)

	// Устанавливаем gRPC соединение
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	// Настраиваем HTTP-сервер
	server := setupHTTPServer(t, conn)
	defer tearDown(conn, server)

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

// Вспомогательная функция для генерации хеша пароля
func generatePasswordHash(t *testing.T, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return string(hash)
}
