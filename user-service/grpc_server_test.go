package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang-jwt/jwt/v5"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
)

// Создаем мок для TokenService
type MockTokenService struct {
	mock.Mock
}

func NewTokenService(t *testing.T) *MockTokenService {
	return &MockTokenService{}
}

func (m *MockTokenService) GenerateToken(userID int, username, email string) (string, error) {
	args := m.Called(userID, username, email)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) VerifyToken(tokenStr string) (*token.TokenClaims, error) {
	args := m.Called(tokenStr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	// Преобразуем MapClaims в TokenClaims
	if claims, ok := args.Get(0).(jwt.MapClaims); ok {
		// Проверяем, что user_id существует и не nil
		if userIDValue, exists := claims["user_id"]; exists && userIDValue != nil {
			userID := int(userIDValue.(float64))
			return &token.TokenClaims{
				UserID: userID,
			}, args.Error(1)
		}
		// Если user_id отсутствует или nil, возвращаем nil claims
		return nil, args.Error(1)
	}

	return args.Get(0).(*token.TokenClaims), args.Error(1)
}

// Объявляем переменные, которые используются в тестах
var (
	db           *sql.DB
	tokenService token.TokenService
)

func TestRegisterRPC(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	createdAt := time.Now()
	// Обновляем ожидаемый SQL-запрос с учетом новых полей
	mock.ExpectQuery("INSERT INTO users").
		WithArgs(
			"testuser", "test@example.com", sqlmock.AnyArg(), // username, email, password
			"", "", nil, "", // first_name, last_name, birth_date, phone_number
			sqlmock.AnyArg(), sqlmock.AnyArg(), // created_at, updated_at
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "email", "first_name", "last_name",
			"birth_date", "phone_number", "created_at", "updated_at",
		}).AddRow(
			1, "testuser", "test@example.com", "", "",
			nil, "", createdAt, createdAt,
		))

	// Создаем запрос
	req := &pb.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	// Вызываем RPC
	resp, err := server.Register(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegisterRPC_UserExists(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Мокаем запросы к БД - пользователь уже существует
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	// Создаем запрос
	req := &pb.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	// Вызываем RPC
	resp, err := server.Register(context.Background(), req)

	// Проверяем наличие ошибки
	assert.Error(t, err)

	// Проверяем статус ошибки
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())

	// Ответ должен быть nil при ошибке
	assert.Nil(t, resp)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginRPC(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Создаем хеш пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", hashedPassword, createdAt))

	// Создаем запрос
	req := &pb.LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	// Вызываем RPC
	resp, err := server.Login(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginRPC_InvalidPassword(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Создаем хеш пароля для ДРУГОГО пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("different_password"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", hashedPassword, createdAt))

	// Создаем запрос с неверным паролем
	req := &pb.LoginRequest{
		Username: "testuser",
		Password: "wrong_password",
	}

	// Вызываем RPC
	resp, err := server.Login(context.Background(), req)

	// Проверяем наличие ошибки
	assert.Error(t, err)

	// Проверяем статус ошибки
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())

	// Ответ должен быть nil при ошибке
	assert.Nil(t, resp)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLoginRPC_UserNotFound(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Мокаем запросы к БД - пользователь не найден
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	// Создаем запрос
	req := &pb.LoginRequest{
		Username: "nonexistent",
		Password: "password",
	}

	// Вызываем RPC
	resp, err := server.Login(context.Background(), req)

	// Проверяем наличие ошибки
	assert.Error(t, err)

	// Проверяем статус ошибки
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	// Ответ должен быть nil при ошибке
	assert.Nil(t, resp)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegister(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Инициализируем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	createdAt := time.Now()
	// Обновляем ожидаемый SQL-запрос с учетом новых полей
	mock.ExpectQuery("INSERT INTO users").
		WithArgs(
			"testuser", "test@example.com", sqlmock.AnyArg(), // username, email, password
			"", "", nil, "", // first_name, last_name, birth_date, phone_number
			sqlmock.AnyArg(), sqlmock.AnyArg(), // created_at, updated_at
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "email", "first_name", "last_name",
			"birth_date", "phone_number", "created_at", "updated_at",
		}).AddRow(
			1, "testuser", "test@example.com", "", "",
			nil, "", createdAt, createdAt,
		))

	// Создаем запрос
	req := &pb.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	// Вызываем RPC
	resp, err := server.Register(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestLogin(t *testing.T) {
	// Настраиваем мок базы данных
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Error creating mock database: %v", err)
	}
	defer mockDB.Close()

	// Заменяем глобальную переменную db на мок
	db = mockDB

	// Создаем сервер с нужными зависимостями
	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	// Инициализируем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Создаем хеш пароля
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	createdAt := time.Now()

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT id, username, email, password, created_at FROM users WHERE username = \\$1").
		WithArgs("testuser").
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "password", "created_at"}).
			AddRow(1, "testuser", "test@example.com", hashedPassword, createdAt))

	// Создаем запрос
	req := &pb.LoginRequest{
		Username: "testuser",
		Password: "password123",
	}

	// Вызываем RPC
	resp, err := server.Login(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetProfileRPC(t *testing.T) {
	// Создаем мок для базы данных
	mockDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer mockDB.Close()

	tokenService := NewTokenService(t)

	server := NewUserServiceServer(mockDB, tokenService)

	// Тестовые данные
	userID := int32(1)
	username := "testuser"
	email := "test@example.com"
	firstName := "Иван"
	lastName := "Иванов"
	phoneNumber := "+79123456789"
	createdAt := time.Now().Add(-24 * time.Hour)
	updatedAt := time.Now()
	birthDate := time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC)

	// Тест 1: Получение профиля по user_id
	t.Run("Получение профиля по user_id", func(t *testing.T) {
		// Настраиваем ожидаемый запрос к базе данных
		rows := sqlmock.NewRows([]string{"id", "username", "email", "first_name", "last_name", "birth_date", "phone_number", "created_at", "updated_at"}).
			AddRow(userID, username, email, firstName, lastName, birthDate, phoneNumber, createdAt, updatedAt)

		mock.ExpectQuery("SELECT id, username, email, first_name, last_name, birth_date, phone_number, created_at, updated_at FROM users WHERE").
			WithArgs(userID).
			WillReturnRows(rows)

		// Выполняем запрос
		req := &pb.ProfileRequest{
			UserId: userID,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем результаты
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
		require.Equal(t, userID, resp.User.Id)
		require.Equal(t, username, resp.User.Username)
		require.Equal(t, email, resp.User.Email)
		require.Equal(t, firstName, resp.User.FirstName)
		require.Equal(t, lastName, resp.User.LastName)
		require.Equal(t, phoneNumber, resp.User.PhoneNumber)

		// Проверяем timestamp полей
		require.NotNil(t, resp.User.CreatedAt)
		require.NotNil(t, resp.User.UpdatedAt)
		require.NotNil(t, resp.User.BirthDate)

		// Проверяем, что все ожидания были выполнены
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	// Тест 2: Получение профиля по токену
	t.Run("Получение профиля по токену", func(t *testing.T) {
		// Мокаем проверку токена
		token := "valid_token"
		tokenService.On("VerifyToken", token).Return(jwt.MapClaims{"user_id": float64(userID)}, nil)

		// Настраиваем ожидаемый запрос к базе данных
		rows := sqlmock.NewRows([]string{"id", "username", "email", "first_name", "last_name", "birth_date", "phone_number", "created_at", "updated_at"}).
			AddRow(userID, username, email, firstName, lastName, birthDate, phoneNumber, createdAt, updatedAt)

		mock.ExpectQuery("SELECT id, username, email, first_name, last_name, birth_date, phone_number, created_at, updated_at FROM users WHERE").
			WithArgs(userID).
			WillReturnRows(rows)

		// Выполняем запрос
		req := &pb.ProfileRequest{
			Token: token,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем результаты
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
		require.Equal(t, userID, resp.User.Id)

		// Проверяем, что все ожидания были выполнены
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
		tokenService.AssertExpectations(t)
	})

	// Тест 3: Пользователь не найден
	t.Run("Пользователь не найден", func(t *testing.T) {
		// Настраиваем ожидаемый запрос к базе данных, который не находит пользователя
		mock.ExpectQuery("SELECT id, username, email, first_name, last_name, birth_date, phone_number, created_at, updated_at FROM users WHERE").
			WithArgs(userID).
			WillReturnError(sql.ErrNoRows)

		// Выполняем запрос
		req := &pb.ProfileRequest{
			UserId: userID,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем результаты
		require.Error(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Equal(t, "User not found", resp.Error)

		// Проверяем код ошибки gRPC
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())

		// Проверяем, что все ожидания были выполнены
		err = mock.ExpectationsWereMet()
		require.NoError(t, err)
	})

	// Тест 4: Не указан ни токен, ни user_id
	t.Run("Не указан ни токен, ни user_id", func(t *testing.T) {
		// Выполняем запрос без токена и user_id
		req := &pb.ProfileRequest{}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем результаты
		require.Error(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Equal(t, "Token or user ID is required", resp.Error)

		// Проверяем код ошибки gRPC
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
	})

	// Тест 5: Недействительный токен
	t.Run("Недействительный токен", func(t *testing.T) {
		// Мокаем проверку недействительного токена
		invalidToken := "invalid_token"
		tokenService.On("VerifyToken", invalidToken).Return(jwt.MapClaims{}, errors.New("invalid token"))

		// Выполняем запрос с недействительным токеном
		req := &pb.ProfileRequest{
			Token: invalidToken,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем результаты
		require.Error(t, err)
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Equal(t, "Invalid token", resp.Error)

		// Проверяем код ошибки gRPC
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unauthenticated, st.Code())

		// Проверяем, что все ожидания были выполнены
		tokenService.AssertExpectations(t)
	})
}
