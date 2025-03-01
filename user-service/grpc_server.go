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

	// Create user
	var userID int
	var username, email string
	var createdAt time.Time

	err = s.db.QueryRow(
		"INSERT INTO users (username, email, password, created_at) VALUES ($1, $2, $3, $4) RETURNING id, username, email, created_at",
		req.Username, req.Email, hashedPassword, time.Now(),
	).Scan(&userID, &username, &email, &createdAt)

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
