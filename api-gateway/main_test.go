package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
)

// Реализация мока для gRPC клиента
type MockUserClient struct {
	mock.Mock
}

func (m *MockUserClient) Register(ctx context.Context, in *pb.RegisterRequest, opts ...grpc.CallOption) (*pb.AuthResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.AuthResponse), args.Error(1)
}

func (m *MockUserClient) Login(ctx context.Context, in *pb.LoginRequest, opts ...grpc.CallOption) (*pb.AuthResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.AuthResponse), args.Error(1)
}

// Реализация метода GetProfile для MockUserClient
func (m *MockUserClient) GetProfile(ctx context.Context, in *pb.ProfileRequest, opts ...grpc.CallOption) (*pb.ProfileResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.ProfileResponse), args.Error(1)
}

// Настройка тестового окружения
func setupTestAPI(t *testing.T) (*MockUserClient, *mux.Router) {
	mockClient := new(MockUserClient)
	userClient = mockClient // Заменяем глобальную переменную на мок

	r := mux.NewRouter()
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/profile", profileHandler).Methods("GET")

	return mockClient, r
}

func TestRegisterHandlerAPI(t *testing.T) {
	// Настройка теста
	mockClient, router := setupTestAPI(t)

	// Подготавливаем ожидаемый ответ от gRPC-сервера
	createdAt := time.Now()
	expectedResp := &pb.AuthResponse{
		Token: "user_token_1",
		User: &pb.User{
			Id:        1,
			Username:  "testuser",
			Email:     "test@example.com",
			CreatedAt: timestamppb.New(createdAt),
		},
	}

	// Настраиваем поведение мока
	mockClient.On("Register", mock.Anything, mock.MatchedBy(func(req *pb.RegisterRequest) bool {
		return req.Username == "testuser" && req.Email == "test@example.com" && req.Password == "password123"
	})).Return(expectedResp, nil)

	// Создаем HTTP запрос
	reqBody := map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Проверяем код ответа
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Проверяем структуру ответа
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Проверяем поля ответа
	assert.Equal(t, "user_token_1", response["token"])
	user := response["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "testuser", user["username"])
	assert.Equal(t, "test@example.com", user["email"])

	// Проверяем, что все ожидаемые вызовы были выполнены
	mockClient.AssertExpectations(t)
}

func TestRegisterHandlerAPI_Error(t *testing.T) {
	// Настройка теста
	mockClient, router := setupTestAPI(t)

	// Настраиваем поведение мока - возвращаем ошибку (пользователь уже существует)
	mockClient.On("Register", mock.Anything, mock.MatchedBy(func(req *pb.RegisterRequest) bool {
		return req.Username == "existinguser"
	})).Return(nil, status.Error(codes.AlreadyExists, "User with this username or email already exists"))

	// Создаем HTTP запрос
	reqBody := map[string]string{
		"username": "existinguser",
		"email":    "existing@example.com",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Проверяем код ответа - ожидаем конфликт
	assert.Equal(t, http.StatusConflict, rr.Code)

	// Проверяем текст ошибки
	assert.Contains(t, rr.Body.String(), "User with this username or email already exists")

	// Проверяем, что все ожидаемые вызовы были выполнены
	mockClient.AssertExpectations(t)
}

func TestLoginHandlerAPI(t *testing.T) {
	// Настройка теста
	mockClient, router := setupTestAPI(t)

	// Подготавливаем ожидаемый ответ от gRPC-сервера
	createdAt := time.Now()
	expectedResp := &pb.AuthResponse{
		Token: "user_token_1",
		User: &pb.User{
			Id:        1,
			Username:  "testuser",
			Email:     "test@example.com",
			CreatedAt: timestamppb.New(createdAt),
		},
	}

	// Настраиваем поведение мока
	mockClient.On("Login", mock.Anything, mock.MatchedBy(func(req *pb.LoginRequest) bool {
		return req.Username == "testuser" && req.Password == "password123"
	})).Return(expectedResp, nil)

	// Создаем HTTP запрос
	reqBody := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Проверяем код ответа
	assert.Equal(t, http.StatusOK, rr.Code)

	// Проверяем структуру ответа
	var response map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Проверяем поля ответа
	assert.Equal(t, "user_token_1", response["token"])
	user := response["user"].(map[string]interface{})
	assert.Equal(t, float64(1), user["id"])
	assert.Equal(t, "testuser", user["username"])
	assert.Equal(t, "test@example.com", user["email"])

	// Проверяем, что все ожидаемые вызовы были выполнены
	mockClient.AssertExpectations(t)
}

func TestLoginHandlerAPI_InvalidCredentials(t *testing.T) {
	// Настройка теста
	mockClient, router := setupTestAPI(t)

	// Настраиваем поведение мока - возвращаем ошибку (неверные учетные данные)
	mockClient.On("Login", mock.Anything, mock.MatchedBy(func(req *pb.LoginRequest) bool {
		return req.Username == "testuser" && req.Password == "wrong_password"
	})).Return(nil, status.Error(codes.Unauthenticated, "Invalid username or password"))

	// Создаем HTTP запрос
	reqBody := map[string]string{
		"username": "testuser",
		"password": "wrong_password",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Проверяем код ответа - ожидаем Unauthorized
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// Проверяем текст ошибки
	assert.Contains(t, rr.Body.String(), "Invalid username or password")

	// Проверяем, что все ожидаемые вызовы были выполнены
	mockClient.AssertExpectations(t)
}

func TestInvalidRequestBody(t *testing.T) {
	// Настройка теста
	_, router := setupTestAPI(t)

	// Создаем HTTP запрос с невалидным JSON
	req, _ := http.NewRequest("POST", "/api/register", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	// Выполняем запрос
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Проверяем код ответа - ожидаем Bad Request
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Проверяем текст ошибки
	assert.Contains(t, rr.Body.String(), "Invalid request")
}

func TestProfileHandlerAPI_ByUserID(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// Создание запроса только с user_id (без токена)
	req := httptest.NewRequest("GET", "/api/profile?user_id=1", nil)
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - должен быть отказ в доступе
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	// Проверяем текст ошибки
	assert.Contains(t, resp.Body.String(), "Authorization token required")
}

func TestProfileHandlerAPI_ByToken(t *testing.T) {
	// Настройка API для тестирования
	mockClient, router := setupTestAPI(t)

	// Подготовка данных для тестирования
	testUser := &pb.User{
		Id:       1,
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Настройка ожидаемого ответа от mock сервиса
	mockResponse := &pb.ProfileResponse{
		User:    testUser,
		Success: true,
		Error:   "",
	}

	// JWT токен для тестирования
	testToken := "test.jwt.token"

	// Настройка mock для метода GetProfile
	mockClient.On("GetProfile", mock.Anything, mock.MatchedBy(func(req *pb.ProfileRequest) bool {
		return req.Token == testToken && req.UserId == 0
	})).Return(mockResponse, nil)

	// Создание запроса с token в заголовке
	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата
	assert.Equal(t, http.StatusOK, resp.Code)

	// Проверка возвращаемых данных
	var response pb.ProfileResponse
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, testUser.Id, response.User.Id)
	assert.Equal(t, testUser.Username, response.User.Username)
	assert.Equal(t, testUser.Email, response.User.Email)
	assert.True(t, response.Success)
	assert.Empty(t, response.Error)

	// Проверка, что mock метод был вызван
	mockClient.AssertExpectations(t)
}

func TestProfileHandlerAPI_UserNotFound(t *testing.T) {
	// Настройка API для тестирования
	mockClient, router := setupTestAPI(t)

	// JWT токен для тестирования
	testToken := "invalid.jwt.token"

	// Настройка ответа с ошибкой "пользователь не найден"
	mockError := status.Error(codes.NotFound, "User not found")

	// Настройка mock для метода GetProfile
	mockClient.On("GetProfile", mock.Anything, mock.MatchedBy(func(req *pb.ProfileRequest) bool {
		return req.Token == testToken
	})).Return(nil, mockError)

	// Создание запроса с токеном
	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - ожидаем 404 Not Found для ошибки NotFound
	assert.Equal(t, http.StatusNotFound, resp.Code)

	// Проверка, что mock метод был вызван
	mockClient.AssertExpectations(t)
}

func TestProfileHandlerAPI_NoParameters(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// Создание запроса без параметров
	req := httptest.NewRequest("GET", "/api/profile", nil)
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - ожидаем ошибку "Authorization token required"
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "Authorization token required")
}

func TestProfileHandlerAPI_InvalidUserID(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// Создание запроса с некорректным user_id (без токена)
	req := httptest.NewRequest("GET", "/api/profile?user_id=abc", nil)
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - ожидаем ошибку "Authorization token required"
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "Authorization token required")
}
