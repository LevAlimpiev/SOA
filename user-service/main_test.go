package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

// Переменные для тестов
var mock sqlmock.Sqlmock

func setupTest(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	// Создаем мок для базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}

	// Заменяем глобальную переменную db на мок
	db = mockDB

	return mockDB, mock
}

func TestRegisterHandler(t *testing.T) {
	// Настройка теста
	mockDB, mock := setupTest(t)
	defer mockDB.Close()

	// Определяем ожидаемые запросы и ответы
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	// Ожидаем вставку и возврат данных пользователя
	createdAt := time.Now()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, "testuser", "test@example.com", createdAt))

	// Создаем HTTP запрос для тестирования
	reqBody := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/users/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Напрямую вызываем обработчик
	registerHandler(rr, req)

	// Проверяем статус-код ответа
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Декодируем ответ
	var response AuthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err)

	// Проверяем содержимое ответа
	assert.Equal(t, "user_token_1", response.Token)
	assert.Equal(t, 1, response.User.ID)
	assert.Equal(t, "testuser", response.User.Username)
	assert.Equal(t, "test@example.com", response.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterHandler_UserAlreadyExists(t *testing.T) {
	// Настройка теста
	mockDB, mock := setupTest(t)
	defer mockDB.Close()

	// Определяем ожидаемые запросы и ответы - пользователь уже существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	// Создаем HTTP запрос для тестирования
	reqBody := RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/users/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Напрямую вызываем обработчик
	registerHandler(rr, req)

	// Проверяем статус-код ответа - ожидаем конфликт
	assert.Equal(t, http.StatusConflict, rr.Code)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandler(t *testing.T) {
	// Настройка теста
	mockDB, mock := setupTest(t)
	defer mockDB.Close()

	// Создаем хеш пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Определяем ожидаемые запросы и ответы
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", hashedPassword, createdAt))

	// Создаем HTTP запрос для тестирования
	reqBody := LoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/users/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Напрямую вызываем обработчик
	loginHandler(rr, req)

	// Проверяем статус-код ответа
	assert.Equal(t, http.StatusOK, rr.Code)

	// Декодируем ответ
	var response AuthResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err)

	// Проверяем содержимое ответа
	assert.Equal(t, "user_token_1", response.Token)
	assert.Equal(t, 1, response.User.ID)
	assert.Equal(t, "testuser", response.User.Username)
	assert.Equal(t, "test@example.com", response.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginHandler_InvalidPassword(t *testing.T) {
	// Настройка теста
	mockDB, mock := setupTest(t)
	defer mockDB.Close()

	// Создаем хеш пароля для ДРУГОГО пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("different_password"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Определяем ожидаемые запросы и ответы
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", hashedPassword, createdAt))

	// Создаем HTTP запрос для тестирования с неверным паролем
	reqBody := LoginRequest{
		Username: "testuser",
		Password: "wrong_password",
	}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/users/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Напрямую вызываем обработчик
	loginHandler(rr, req)

	// Проверяем статус-код ответа - ожидаем Unauthorized
	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRoutes(t *testing.T) {
	// Проверяем правильность настройки маршрутов
	r := mux.NewRouter()
	r.HandleFunc("/api/users/register", registerHandler).Methods("POST")
	r.HandleFunc("/api/users/login", loginHandler).Methods("POST")

	// Проверяем маршрут для регистрации
	req, _ := http.NewRequest("POST", "/api/users/register", nil)
	match := &mux.RouteMatch{}
	assert.True(t, r.Match(req, match))
	assert.NotNil(t, match.Route)
	assert.NotNil(t, match.Handler)

	// Проверяем маршрут для входа
	req, _ = http.NewRequest("POST", "/api/users/login", nil)
	match = &mux.RouteMatch{}
	assert.True(t, r.Match(req, match))
	assert.NotNil(t, match.Route)
	assert.NotNil(t, match.Handler)
}

// SetupTestDB инициализирует тестовую БД
func setupTestDB() {
	var err error
	// Создаем фиктивное подключение к БД для тестов
	db, mock, err = sqlmock.New()
	if err != nil {
		panic(err)
	}

	// Настраиваем ожидаемые вызовы для регистрации
	mock.ExpectQuery("SELECT EXISTS").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	mock.ExpectQuery("INSERT INTO users").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, "testuser", "test@example.com", time.Now()))

	// Настраиваем ожидаемые вызовы для входа
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", "$2a$10$eSrOIYZ5YdJsGpPF7wIZTOVZZQ8jDWWLfC6qvxmLrq9AHN4V3qKV.", time.Now()))

	// Настраиваем ожидаемые вызовы для получения профиля
	mock.ExpectQuery("SELECT id, username, email, created_at FROM users WHERE id").
		WithArgs(1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, "testuser", "test@example.com", time.Now()))
}

// TestMain инициализирует глобальный setup для тестов
func TestMain(m *testing.M) {
	// Инициализируем тестовую БД
	setupTestDB()

	// Инициализируем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Запускаем тесты
	m.Run()
}

// Добавим тест для проверки работы middleware и endpoint профиля
func TestGetProfile(t *testing.T) {
	// Подготовка - очистка БД и добавление тестового пользователя
	db.Exec("DELETE FROM users")
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users (id, username, email, password, created_at) VALUES (1, 'testuser', 'test@example.com', $1, $2)",
		hashedPassword, time.Now())

	// Создаем токен для пользователя
	token, err := tokenService.GenerateToken(1, "testuser", "test@example.com")
	assert.NoError(t, err)

	// Создаем запрос с токеном авторизации
	req, _ := http.NewRequest("GET", "/protected/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Создаем ResponseRecorder для записи ответа
	rr := httptest.NewRecorder()

	// Создаем маршрутизатор и регистрируем обработчики
	r := mux.NewRouter()
	protected := r.PathPrefix("/protected").Subrouter()
	protected.Use(authMiddleware)
	protected.HandleFunc("/profile", getProfileHandler)

	// Выполняем запрос
	r.ServeHTTP(rr, req)

	// Проверяем статус ответа
	assert.Equal(t, http.StatusOK, rr.Code)

	// Проверяем содержимое ответа
	var response User
	json.Unmarshal(rr.Body.Bytes(), &response)

	assert.Equal(t, 1, response.ID)
	assert.Equal(t, "testuser", response.Username)
	assert.Equal(t, "test@example.com", response.Email)
}
