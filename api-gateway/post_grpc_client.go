package main

import (
	"context"
	"log"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	postClient pb.PostServiceClient
	postConn   *grpc.ClientConn
)

// InitPostGRPCClient инициализирует gRPC клиент для сервиса постов
func InitPostGRPCClient(address string) error {
	var err error

	// Устанавливаем соединение с сервером
	postConn, err = grpc.Dial(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Printf("Failed to connect to post gRPC server: %v", err)
		return err
	}

	postClient = pb.NewPostServiceClient(postConn)
	log.Printf("Connected to post gRPC server at %s", address)
	return nil
}

// ClosePostGRPCClient закрывает gRPC клиент для сервиса постов
func ClosePostGRPCClient() {
	if postConn != nil {
		postConn.Close()
	}
}

// CreatePost создает новый пост через gRPC
func CreatePost(ctx context.Context, req CreatePostRequest) (*pb.PostResponse, error) {
	return postClient.CreatePost(ctx, &pb.CreatePostRequest{
		CreatorId:   req.CreatorID,
		Title:       req.Title,
		Description: req.Description,
		IsPrivate:   req.IsPrivate,
		Tags:        req.Tags,
	})
}

// GetPostByID получает пост по ID через gRPC
func GetPostByID(ctx context.Context, postID, userID int32) (*pb.PostResponse, error) {
	return postClient.GetPostById(ctx, &pb.PostIdRequest{
		PostId: postID,
		UserId: userID,
	})
}

// UpdatePost обновляет пост через gRPC
func UpdatePost(ctx context.Context, req UpdatePostRequest) (*pb.PostResponse, error) {
	// Создаем gRPC запрос
	grpcReq := &pb.UpdatePostRequest{
		PostId:    req.PostID,
		CreatorId: req.CreatorID,
		Tags:      req.Tags,
	}

	// Добавляем опциональные поля, если они предоставлены
	if req.Title != nil {
		titleStr := *req.Title
		grpcReq.Title = &titleStr
	}

	if req.Description != nil {
		descStr := *req.Description
		grpcReq.Description = &descStr
	}

	if req.IsPrivate != nil {
		isPrivateBool := *req.IsPrivate
		grpcReq.IsPrivate = &isPrivateBool
	}

	return postClient.UpdatePost(ctx, grpcReq)
}

// DeletePost удаляет пост через gRPC
func DeletePost(ctx context.Context, postID, userID int32) (*pb.DeletePostResponse, error) {
	return postClient.DeletePost(ctx, &pb.PostIdRequest{
		PostId: postID,
		UserId: userID,
	})
}

// ListPosts получает список постов с пагинацией через gRPC
func ListPosts(ctx context.Context, req ListPostsRequest) (*pb.ListPostsResponse, error) {
	// Создаем gRPC запрос
	grpcReq := &pb.ListPostsRequest{
		UserId:   req.UserID,
		Page:     req.Page,
		PageSize: req.PageSize,
		Tags:     req.Tags,
	}

	// Добавляем фильтр по создателю, если он предоставлен
	if req.CreatorID != nil {
		creatorIDInt32 := *req.CreatorID
		grpcReq.CreatorId = &creatorIDInt32
	}

	return postClient.ListPosts(ctx, grpcReq)
} 