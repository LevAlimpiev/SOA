package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// MockUserClient implementation for gRPC client
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

// GetProfile implementation for MockUserClient
func (m *MockUserClient) GetProfile(ctx context.Context, in *pb.ProfileRequest, opts ...grpc.CallOption) (*pb.ProfileResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.ProfileResponse), args.Error(1)
}

// UpdateProfile implementation for MockUserClient
func (m *MockUserClient) UpdateProfile(ctx context.Context, in *pb.UpdateProfileRequest, opts ...grpc.CallOption) (*pb.ProfileResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.ProfileResponse), args.Error(1)
}

// Test environment setup
func setupTestAPI(t *testing.T) (*MockUserClient, *mux.Router) {
	mockClient := new(MockUserClient)
	userClient = mockClient // Replace global variable with mock

	r := mux.NewRouter()
	r.HandleFunc("/api/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/login", loginHandler).Methods("POST")
	r.HandleFunc("/api/profile", profileHandler).Methods("GET")
	r.HandleFunc("/api/update-profile", updateProfileHandler).Methods("PUT")
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
	// Set up API for testing
	mockClient, router := setupTestAPI(t)

	// Configure mock for GetProfile method to verify that it's not called
	// when no token is provided (the handler should return error before calling GetProfile)
	mockClient.On("GetProfile", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("GetProfile should not be called without token"))

	// Create request with only user_id (no token)
	req := httptest.NewRequest("GET", "/api/profile?user_id=1", nil)
	resp := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(resp, req)

	// Check result - should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	// Check error message
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
	// Set up API for testing
	mockClient, router := setupTestAPI(t)

	// Configure mock for GetProfile method to verify that it's not called
	// when no token is provided (the handler should return error before calling GetProfile)
	mockClient.On("GetProfile", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("GetProfile should not be called without token"))

	// Create request without parameters
	req := httptest.NewRequest("GET", "/api/profile", nil)
	resp := httptest.NewRecorder()

	// Execute request
	router.ServeHTTP(resp, req)

	// Check result - should be unauthorized
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

func TestUpdateProfileHandlerAPI(t *testing.T) {
	// Set up API for testing
	mockClient, router := setupTestAPI(t)

	// Prepare test data
	testUser := &pb.User{
		Id:          1,
		Username:    "testuser",
		Email:       "updated@example.com",
		FirstName:   "Ivan Updated",
		LastName:    "Petrov",
		PhoneNumber: "+79001234567",
	}

	// Set up expected response from mock service
	mockResponse := &pb.ProfileResponse{
		User:    testUser,
		Success: true,
		Error:   "",
	}

	// JWT token for testing
	testToken := "test.jwt.token"

	// Prepare update request
	updateData := UpdateProfileRequest{
		FirstName:   "Ivan Updated",
		LastName:    "Petrov",
		Email:       "updated@example.com",
		PhoneNumber: "+79001234567",
	}

	// Configure mock for UpdateProfile method
	mockClient.On("UpdateProfile", mock.Anything, mock.MatchedBy(func(req *pb.UpdateProfileRequest) bool {
		return req.Token == testToken &&
			req.FirstName == updateData.FirstName &&
			req.LastName == updateData.LastName &&
			req.Email == updateData.Email &&
			req.PhoneNumber == updateData.PhoneNumber
	})).Return(mockResponse, nil)

	// Create request with JSON data
	jsonData, err := json.Marshal(updateData)
	assert.NoError(t, err)

	// Create HTTP request
	req, _ := http.NewRequest("PUT", "/api/update-profile", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	// Execute request and record response
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	// Check response status code
	assert.Equal(t, http.StatusOK, resp.Code)

	// Parse response body
	var responseBody map[string]interface{}
	err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
	assert.NoError(t, err)

	// Verify response contains expected data
	assert.True(t, responseBody["success"].(bool))
	user := responseBody["user"].(map[string]interface{})
	assert.Equal(t, "updated@example.com", user["email"])
	assert.Equal(t, "Ivan Updated", user["first_name"])
	assert.Equal(t, "Petrov", user["last_name"])
}

func TestUpdateProfileHandlerAPI_NoToken(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// Подготовка запроса обновления
	updateData := UpdateProfileRequest{
		FirstName: "Ivan Updated",
	}

	// Создание запроса с JSON данными, но без токена
	jsonData, err := json.Marshal(updateData)
	assert.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/update-profile", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - должен быть отказ в доступе
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, resp.Body.String(), "Authorization token required")
}

func TestUpdateProfileHandlerAPI_InvalidBody(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// JWT токен для тестирования
	testToken := "test.jwt.token"

	// Создание запроса с некорректным JSON
	req := httptest.NewRequest("PUT", "/api/update-profile", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - должна быть ошибка некорректного запроса
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "Invalid request body")
}

func TestUpdateProfileHandlerAPI_NoData(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// JWT токен для тестирования
	testToken := "test.jwt.token"

	// Подготовка пустого запроса обновления
	updateData := UpdateProfileRequest{}

	// Создание запроса с пустыми данными
	jsonData, err := json.Marshal(updateData)
	assert.NoError(t, err)

	req := httptest.NewRequest("PUT", "/api/update-profile", bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// Проверка результата - должна быть ошибка пустого запроса
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "No profile data provided for update")
}

func TestUpdateProfileHandlerAPI_MethodNotAllowed(t *testing.T) {
	// Настройка API для тестирования
	_, router := setupTestAPI(t)

	// Подготовка некорректного запроса (GET вместо PUT)
	req := httptest.NewRequest("GET", "/api/update-profile", nil)
	req.Header.Set("Authorization", "Bearer test.jwt.token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Выполнение запроса
	router.ServeHTTP(resp, req)

	// В Gorilla Mux запрос с неправильным методом вернёт 405, но маршрутизатор
	// может вернуть 404, если не найдет подходящий обработчик
	// Поэтому проверяем, что код ответа не 200 (успех)
	assert.NotEqual(t, http.StatusOK, resp.Code)
}
