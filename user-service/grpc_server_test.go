package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	"google.golang.org/protobuf/types/known/timestamppb"
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

	// Создаем валидный токен для тестов
	validToken := "valid_token"
	tokenService.On("VerifyToken", validToken).Return(&token.TokenClaims{
		UserID:    int(userID),
		Username:  username,
		Email:     email,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil)

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
			Token:  validToken,
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
		// Настраиваем ожидаемый запрос к базе данных
		rows := sqlmock.NewRows([]string{"id", "username", "email", "first_name", "last_name", "birth_date", "phone_number", "created_at", "updated_at"}).
			AddRow(userID, username, email, firstName, lastName, birthDate, phoneNumber, createdAt, updatedAt)

		mock.ExpectQuery("SELECT id, username, email, first_name, last_name, birth_date, phone_number, created_at, updated_at FROM users WHERE").
			WithArgs(userID).
			WillReturnRows(rows)

		// Выполняем запрос только с токеном
		req := &pb.ProfileRequest{
			Token: validToken,
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
	})

	// Тест 3: Пользователь не найден
	t.Run("Пользователь не найден", func(t *testing.T) {
		// Настраиваем ожидание, что пользователь не найден
		mock.ExpectQuery("SELECT id, username, email, first_name, last_name, birth_date, phone_number, created_at, updated_at FROM users WHERE").
			WithArgs(userID).
			WillReturnError(sql.ErrNoRows)

		// Выполняем запрос
		req := &pb.ProfileRequest{
			UserId: userID,
			Token:  validToken,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем ошибку
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.NotFound, st.Code())
		require.Equal(t, "User not found", st.Message())
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Equal(t, "User not found", resp.Error)
	})

	// Тест 4: Не указан ни токен, ни user_id
	t.Run("Не указан ни токен, ни user_id", func(t *testing.T) {
		// Выполняем запрос без токена
		req := &pb.ProfileRequest{}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем ошибку
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unauthenticated, st.Code())
		require.Equal(t, "Authorization token is required", st.Message())
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Equal(t, "Authorization token is required", resp.Error)
	})

	// Тест 5: Недействительный токен
	t.Run("Недействительный токен", func(t *testing.T) {
		// Мокаем проверку недействительного токена
		invalidToken := "invalid_token"
		tokenService.On("VerifyToken", invalidToken).Return(nil, token.ErrInvalidToken)

		// Выполняем запрос с недействительным токеном
		req := &pb.ProfileRequest{
			Token: invalidToken,
		}
		resp, err := server.GetProfile(context.Background(), req)

		// Проверяем ошибку
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.Unauthenticated, st.Code())
		require.NotNil(t, resp)
		require.False(t, resp.Success)
		require.Contains(t, resp.Error, "Invalid token")
	})
}

// TestUpdateProfileRPC тестирует функцию обновления профиля пользователя
func TestUpdateProfileRPC(t *testing.T) {
	// Создаем мок для базы данных
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Создаем мок для токен-сервиса
	tokenService := new(MockTokenService)

	// Создаем инстанс сервера для тестирования
	server := NewUserServiceServer(db, tokenService)

	// Параметры для тестов
	userID := int32(1)
	username := "testuser"
	email := "test@example.com"
	tokenString := "valid_token"

	// Настраиваем для токен-сервиса возврат валидных данных
	tokenService.On("VerifyToken", tokenString).Return(&token.TokenClaims{
		UserID:    int(userID),
		Username:  username,
		Email:     email,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil)

	// Тест 1: Обновление всех полей профиля
	t.Run("Обновление всех полей профиля", func(t *testing.T) {
		// Создаем новые данные для обновления
		newFirstName := "Петр"
		newLastName := "Петров"
		newEmail := "peter@example.com"
		newPhoneNumber := "+79998887766"
		newBirthDate := time.Date(1992, 10, 20, 0, 0, 0, 0, time.UTC)

		// Настраиваем ожидания для запроса обновления
		mock.ExpectBegin()

		rows := sqlmock.NewRows([]string{
			"id", "username", "email", "first_name", "last_name",
			"birth_date", "phone_number", "created_at", "updated_at",
		}).AddRow(
			userID, username, newEmail, newFirstName, newLastName,
			newBirthDate, newPhoneNumber, time.Now(), time.Now(),
		)

		mock.ExpectQuery("UPDATE users SET").
			WithArgs(
				&newFirstName, &newLastName, &newPhoneNumber,
				&newEmail, &newBirthDate, userID,
			).
			WillReturnRows(rows)

		mock.ExpectCommit()

		// Создаем запрос
		req := &pb.UpdateProfileRequest{
			Token:       tokenString,
			FirstName:   newFirstName,
			LastName:    newLastName,
			Email:       newEmail,
			PhoneNumber: newPhoneNumber,
			BirthDate:   timestamppb.New(newBirthDate),
		}

		// Выполняем запрос
		resp, err := server.UpdateProfile(context.Background(), req)

		// Проверяем результаты
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
		require.Equal(t, userID, resp.User.Id)
		require.Equal(t, username, resp.User.Username)
		require.Equal(t, newEmail, resp.User.Email)
		require.Equal(t, newFirstName, resp.User.FirstName)
		require.Equal(t, newLastName, resp.User.LastName)
		require.Equal(t, newPhoneNumber, resp.User.PhoneNumber)

		// Проверяем timestamp полей
		require.NotNil(t, resp.User.CreatedAt)
		require.NotNil(t, resp.User.UpdatedAt)
		require.NotNil(t, resp.User.BirthDate)

		// Проверяем, что все ожидания были выполнены
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Тест 2: Обновление только части полей
	t.Run("Обновление только части полей", func(t *testing.T) {
		// Сбрасываем ожидания
		mock.ExpectationsWereMet()

		// Создаем новые данные для обновления
		newFirstName := "Алексей"

		// Настраиваем ожидания для запроса обновления
		mock.ExpectBegin()

		rows := sqlmock.NewRows([]string{
			"id", "username", "email", "first_name", "last_name",
			"birth_date", "phone_number", "created_at", "updated_at",
		}).AddRow(
			userID, username, email, newFirstName, username,
			time.Now(), time.Now(), time.Now(), time.Now(),
		)

		mock.ExpectQuery("UPDATE users SET").
			WithArgs(&newFirstName, nil, nil, nil, nil, userID).
			WillReturnRows(rows)

		mock.ExpectCommit()

		// Создаем запрос только с первым именем
		req := &pb.UpdateProfileRequest{
			Token:     tokenString,
			FirstName: newFirstName,
		}

		// Выполняем запрос
		resp, err := server.UpdateProfile(context.Background(), req)

		// Проверяем результаты
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.True(t, resp.Success)
		require.Equal(t, userID, resp.User.Id)
		require.Equal(t, username, resp.User.Username)
		require.Equal(t, email, resp.User.Email)
		require.Equal(t, newFirstName, resp.User.FirstName)
		require.Equal(t, username, resp.User.LastName)
		// Проверяем, что временные поля заполнены, но не сравниваем конкретные значения
		require.NotNil(t, resp.User.CreatedAt)
		require.NotNil(t, resp.User.UpdatedAt)
		require.NotNil(t, resp.User.BirthDate)

		// Проверяем, что все ожидания были выполнены
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Тест 3: Ошибка при обновлении
	t.Run("Ошибка при обновлении", func(t *testing.T) {
		// Сбрасываем ожидания
		mock.ExpectationsWereMet()

		// Настраиваем значение аргумента
		firstName := "TestUpdateError"

		// Настраиваем ожидания для запроса обновления с ошибкой
		mock.ExpectBegin()
		mock.ExpectQuery("UPDATE users SET").
			WithArgs(&firstName, nil, nil, nil, nil, userID).
			WillReturnError(fmt.Errorf("database error"))
		mock.ExpectRollback()

		// Создаем запрос
		req := &pb.UpdateProfileRequest{
			Token:     tokenString,
			FirstName: firstName,
		}

		// Выполняем запрос
		_, err := server.UpdateProfile(context.Background(), req)

		// Проверяем результаты - должен быть ошибка
		require.Error(t, err)
		require.Equal(t, codes.Internal, status.Code(err))
		require.Contains(t, status.Convert(err).Message(), "Failed to update profile")

		// Проверяем, что все ожидания были выполнены
		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Тест 4: Невалидный токен
	t.Run("Невалидный токен", func(t *testing.T) {
		// Сбрасываем ожидания
		mock.ExpectationsWereMet()

		// Настраиваем новый мок для токена с ошибкой
		invalidToken := "invalid_token"
		tokenService.On("VerifyToken", invalidToken).Return(nil, errors.New("invalid token"))

		// Создаем запрос с невалидным токеном
		req := &pb.UpdateProfileRequest{
			Token:     invalidToken,
			FirstName: username,
		}

		// Выполняем запрос
		_, err := server.UpdateProfile(context.Background(), req)

		// Проверяем результаты - должна быть ошибка аутентификации
		require.Error(t, err)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		require.Equal(t, "Invalid token", status.Convert(err).Message())
	})
}
