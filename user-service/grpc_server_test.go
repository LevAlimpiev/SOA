package main

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
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

	// Создаем сервер
	server := &userServiceServer{}

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	createdAt := time.Now()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, "testuser", "test@example.com", createdAt))

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
	assert.Equal(t, "user_token_1", resp.Token)
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

	// Создаем сервер
	server := &userServiceServer{}

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

	// Создаем сервер
	server := &userServiceServer{}

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
	assert.Equal(t, "user_token_1", resp.Token)
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

	// Создаем сервер
	server := &userServiceServer{}

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

	// Создаем сервер
	server := &userServiceServer{}

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

	// Создаем сервер
	server := &userServiceServer{}

	// Мокаем запросы к БД
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("testuser", "test@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	createdAt := time.Now()
	mock.ExpectQuery("INSERT INTO users").
		WithArgs("testuser", "test@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "username", "email", "created_at"}).
			AddRow(1, "testuser", "test@example.com", createdAt))

	// Создаем запрос
	req := &pb.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
	}

	// Инициализируем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Вызываем RPC
	resp, err := server.Register(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.Equal(t, "user_token_1", resp.Token)
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

	// Создаем сервер
	server := &userServiceServer{}

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

	// Инициализируем сервис токенов для тестов
	tokenService = token.NewSimpleTokenService(24)

	// Вызываем RPC
	resp, err := server.Login(context.Background(), req)

	// Проверяем отсутствие ошибок
	assert.NoError(t, err)

	// Проверяем ответ
	assert.NotNil(t, resp)
	assert.Equal(t, "user_token_1", resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}
