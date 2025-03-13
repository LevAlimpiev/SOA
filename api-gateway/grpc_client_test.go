package main

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
)

// Создаем структуру для тестового gRPC-сервера
type mockUserServer struct {
	pb.UnimplementedUserServiceServer
}

// Реализуем метод Register для тестового сервера
func (s *mockUserServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	// Проверяем входные данные и возвращаем соответствующий ответ
	if req.Username == "testuser" && req.Email == "test@example.com" && req.Password == "password123" {
		return &pb.AuthResponse{
			Token: "test_token",
			User: &pb.User{
				Id:        1,
				Username:  req.Username,
				Email:     req.Email,
				CreatedAt: timestamppb.Now(),
			},
		}, nil
	} else if req.Username == "existinguser" {
		return nil, status.Error(codes.AlreadyExists, "User with this username or email already exists")
	}
	return nil, status.Error(codes.InvalidArgument, "Invalid request")
}

// Реализуем метод Login для тестового сервера
func (s *mockUserServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	// Проверяем входные данные и возвращаем соответствующий ответ
	if req.Username == "testuser" && req.Password == "password123" {
		return &pb.AuthResponse{
			Token: "test_token",
			User: &pb.User{
				Id:        1,
				Username:  "testuser",
				Email:     "test@example.com",
				CreatedAt: timestamppb.Now(),
			},
		}, nil
	}
	return nil, status.Error(codes.Unauthenticated, "Invalid username or password")
}

// Вспомогательная функция для настройки подключения через буфер вместо сети
func setupGRPCConnection(t *testing.T) (*grpc.ClientConn, func()) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterUserServiceServer(server, &mockUserServer{})

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Fatalf("Failed to start mock gRPC server: %v", err)
		}
	}()

	// Функция для диалекта через буфер
	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}

	// Устанавливаем соединение
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	// Возвращаем соединение и функцию для закрытия
	return conn, func() {
		conn.Close()
		server.Stop()
	}
}

func TestRegisterUser(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewUserServiceClient(conn)
	userClient = client // Заменяем глобальную переменную

	// Вызываем функцию RegisterUser
	ctx := context.Background()
	resp, err := RegisterUser(ctx, "testuser", "test@example.com", "password123")

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test_token", resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)
}

func TestRegisterUser_AlreadyExists(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewUserServiceClient(conn)
	userClient = client // Заменяем глобальную переменную

	// Вызываем функцию RegisterUser с существующим пользователем
	ctx := context.Background()
	resp, err := RegisterUser(ctx, "existinguser", "existing@example.com", "password123")

	// Проверяем результат
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Проверяем статус ошибки
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
	assert.Contains(t, st.Message(), "User with this username or email already exists")
}

func TestLoginUser(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewUserServiceClient(conn)
	userClient = client // Заменяем глобальную переменную

	// Вызываем функцию LoginUser
	ctx := context.Background()
	resp, err := LoginUser(ctx, "testuser", "password123")

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test_token", resp.Token)
	assert.Equal(t, int32(1), resp.User.Id)
	assert.Equal(t, "testuser", resp.User.Username)
	assert.Equal(t, "test@example.com", resp.User.Email)
}

func TestLoginUser_InvalidCredentials(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewUserServiceClient(conn)
	userClient = client // Заменяем глобальную переменную

	// Вызываем функцию LoginUser с неверными учетными данными
	ctx := context.Background()
	resp, err := LoginUser(ctx, "testuser", "wrong_password")

	// Проверяем результат
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Проверяем статус ошибки
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid username or password")
}
