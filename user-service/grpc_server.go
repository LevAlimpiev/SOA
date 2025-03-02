package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
)

type userServiceServer struct {
	pb.UnimplementedUserServiceServer
	db           *sql.DB
	tokenService token.TokenService
}

// NewUserServiceServer создает новый экземпляр сервера с указанными зависимостями
func NewUserServiceServer(db *sql.DB, tokenService token.TokenService) *userServiceServer {
	return &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}
}

// Register creates a new user
func (s *userServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.AuthResponse, error) {
	// Validation
	if req.Username == "" || req.Email == "" || req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "All fields are required")
	}

	// Check if user exists
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
		req.Username, req.Email).Scan(&exists)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to check user existence")
	}

	if exists {
		return nil, status.Errorf(codes.AlreadyExists, "User with this username or email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to process password")
	}

	// Преобразование времени из protobuf в формат для базы данных
	now := time.Now()
	var birthDate *time.Time
	if req.BirthDate != nil {
		bd := req.BirthDate.AsTime()
		birthDate = &bd
	}

	// Create user
	var userID int
	var username, email, firstName, lastName, phoneNumber string
	var createdAt, updatedAt time.Time
	var birthDateResult sql.NullTime

	// Подготовка SQL-запроса с новыми полями
	query := `
		INSERT INTO users (
			username, email, password, first_name, last_name,
			birth_date, phone_number, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		) RETURNING
			id, username, email, first_name, last_name,
			birth_date, phone_number, created_at, updated_at
	`

	err = s.db.QueryRow(
		query,
		req.Username, req.Email, hashedPassword,
		req.FirstName, req.LastName,
		birthDate, req.PhoneNumber,
		now, now,
	).Scan(
		&userID, &username, &email,
		&firstName, &lastName,
		&birthDateResult, &phoneNumber,
		&createdAt, &updatedAt,
	)

	if err != nil {
		log.Printf("Error saving user: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to create user")
	}

	// Generate token
	token, err := s.tokenService.GenerateToken(userID, username, email)
	if err != nil {
		log.Printf("Ошибка при создании токена: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to generate token")
	}

	// Create response
	return &pb.AuthResponse{
		Token: token,
		User: &pb.User{
			Id:        int32(userID),
			Username:  username,
			Email:     email,
			CreatedAt: timestamppb.New(createdAt),
		},
	}, nil
}

// Login authenticates a user
func (s *userServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.AuthResponse, error) {
	// Validation
	if req.Username == "" || req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Username and password are required")
	}

	// Find user
	var userID int
	var username, email, hashedPassword string
	var createdAt time.Time

	err := s.db.QueryRow(
		"SELECT id, username, email, password, created_at FROM users WHERE username = $1",
		req.Username,
	).Scan(&userID, &username, &email, &hashedPassword, &createdAt)

	if err != nil {
		log.Printf("Error finding user: %v", err)
		return nil, status.Errorf(codes.NotFound, "Invalid username or password")
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		log.Printf("Invalid password for user %s: %v", req.Username, err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid username or password")
	}

	// Generate token
	token, err := s.tokenService.GenerateToken(userID, username, email)
	if err != nil {
		log.Printf("Ошибка при создании токена: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to generate token")
	}

	// Create response
	return &pb.AuthResponse{
		Token: token,
		User: &pb.User{
			Id:        int32(userID),
			Username:  username,
			Email:     email,
			CreatedAt: timestamppb.New(createdAt),
		},
	}, nil
}

// GetProfile returns all user profile data
func (s *userServiceServer) GetProfile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileResponse, error) {
	// Проверяем наличие токена (теперь он обязательный)
	if req.Token == "" {
		return &pb.ProfileResponse{
			Success: false,
			Error:   "Authorization token is required",
		}, status.Errorf(codes.Unauthenticated, "Authorization token is required")
	}

	var userID int32
	var username, email string
	var firstName, lastName, phoneNumber string
	var createdAt, updatedAt, birthDate time.Time
	var birthDateResult sql.NullTime

	// Проверяем токен и получаем id пользователя
	claims, err := s.tokenService.VerifyToken(req.Token)
	if err != nil {
		log.Printf("Error verifying token: %v", err)
		return &pb.ProfileResponse{
			Success: false,
			Error:   "Invalid token",
		}, status.Errorf(codes.Unauthenticated, "Invalid token")
	}
	userID = int32(claims.UserID)

	// Запрос всех данных профиля из базы данных
	query := `
		SELECT id, username, email, first_name, last_name,
		       birth_date, phone_number, created_at, updated_at
		FROM users WHERE id = $1
	`

	err = s.db.QueryRow(query, userID).Scan(
		&userID, &username, &email, &firstName, &lastName,
		&birthDateResult, &phoneNumber, &createdAt, &updatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return &pb.ProfileResponse{
				Success: false,
				Error:   "User not found",
			}, status.Errorf(codes.NotFound, "User not found")
		}
		log.Printf("Error fetching user profile: %v", err)
		return &pb.ProfileResponse{
			Success: false,
			Error:   "Failed to fetch user profile",
		}, status.Errorf(codes.Internal, "Failed to fetch user profile")
	}

	// Формируем ответ с данными пользователя
	user := &pb.User{
		Id:          userID,
		Username:    username,
		Email:       email,
		FirstName:   firstName,
		LastName:    lastName,
		PhoneNumber: phoneNumber,
		CreatedAt:   timestamppb.New(createdAt),
		UpdatedAt:   timestamppb.New(updatedAt),
	}

	// Преобразуем дату рождения, если она не NULL
	if birthDateResult.Valid {
		birthDate = birthDateResult.Time
		user.BirthDate = timestamppb.New(birthDate)
	}

	return &pb.ProfileResponse{
		User:    user,
		Success: true,
	}, nil
}

// Start GRPC server
func startGRPCServer(port string, db *sql.DB, tokenService token.TokenService) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	server := &userServiceServer{
		db:           db,
		tokenService: tokenService,
	}

	grpcServer := grpc.NewServer()
	pb.RegisterUserServiceServer(grpcServer, server)

	log.Printf("gRPC server started on port %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
