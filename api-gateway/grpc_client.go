package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/user"
)

var (
	userClient pb.UserServiceClient
	conn       *grpc.ClientConn
)

// InitGRPCClient initializes the gRPC client connection
func InitGRPCClient(address string) error {
	var err error

	// Set up a connection to the server with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err = grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Printf("Failed to connect to gRPC server: %v", err)
		return err
	}

	userClient = pb.NewUserServiceClient(conn)
	log.Printf("Connected to gRPC server at %s", address)
	return nil
}

// CloseGRPCClient closes the gRPC client connection
func CloseGRPCClient() {
	if conn != nil {
		conn.Close()
	}
}

// RegisterUser calls the Register RPC
func RegisterUser(ctx context.Context, username, email, password string) (*pb.AuthResponse, error) {
	req := &pb.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
	return userClient.Register(ctx, req)
}

// LoginUser calls the Login RPC
func LoginUser(ctx context.Context, username, password string) (*pb.AuthResponse, error) {
	req := &pb.LoginRequest{
		Username: username,
		Password: password,
	}
	return userClient.Login(ctx, req)
}

// GetUserProfile calls the GetProfile RPC
func GetUserProfile(ctx context.Context, token string, userID int32) (*pb.ProfileResponse, error) {
	req := &pb.ProfileRequest{
		Token: token,
	}
	return userClient.GetProfile(ctx, req)
}
