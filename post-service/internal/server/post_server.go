package server

import (
	"context"
	"strings"

	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/kafka"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/service"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Глобальный экземпляр Kafka Producer
var kafkaProducer *kafka.KafkaProducer

// SetKafkaProducer устанавливает глобальный экземпляр Kafka Producer
func SetKafkaProducer(producer *kafka.KafkaProducer) {
	kafkaProducer = producer
}

// PostServer реализует gRPC-сервер для работы с постами
type PostServer struct {
	pb.UnimplementedPostServiceServer
	service service.PostService
}

// NewPostServer создает новый экземпляр сервера
func NewPostServer(service service.PostService) *PostServer {
	return &PostServer{
		service: service,
	}
}

// CreatePost создает новый пост
func (s *PostServer) CreatePost(ctx context.Context, req *pb.CreatePostRequest) (*pb.PostResponse, error) {
	// Проверка входных данных
	if req.CreatorId == 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID создателя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID создателя не может быть пустым")
	}

	if strings.TrimSpace(req.Title) == "" {
		return &pb.PostResponse{
			Success: false,
			Error:   "название поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "название поста не может быть пустым")
	}

	// Создаем пост через сервисный слой
	post, err := s.service.CreatePost(req.CreatorId, req.Title, req.Description, req.IsPrivate, req.Tags)
	if err != nil {
		return &pb.PostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(codes.InvalidArgument, err.Error())
	}

	return &pb.PostResponse{
		Post:    post,
		Success: true,
	}, nil
}

// GetPostById получает пост по ID
func (s *PostServer) GetPostById(ctx context.Context, req *pb.PostIdRequest) (*pb.PostResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	// Получаем пост через сервисный слой
	post, err := s.service.GetPostByID(req.PostId, req.UserId)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		} else if err.Error() == "доступ запрещен" {
			errCode = codes.PermissionDenied
		}

		return &pb.PostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	return &pb.PostResponse{
		Post:    post,
		Success: true,
	}, nil
}

// UpdatePost обновляет данные поста
func (s *PostServer) UpdatePost(ctx context.Context, req *pb.UpdatePostRequest) (*pb.PostResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.CreatorId == 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID создателя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID создателя не может быть пустым")
	}

	// Преобразуем опциональные поля
	var title, description *string
	var isPrivate *bool

	if req.Title != nil {
		title = req.Title
	}

	if req.Description != nil {
		description = req.Description
	}

	if req.IsPrivate != nil {
		isPrivate = req.IsPrivate
	}

	// Обновляем пост через сервисный слой
	post, err := s.service.UpdatePost(req.PostId, req.CreatorId, title, description, isPrivate, req.Tags)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		} else if err.Error() == "доступ запрещен" {
			errCode = codes.PermissionDenied
		}

		return &pb.PostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	return &pb.PostResponse{
		Post:    post,
		Success: true,
	}, nil
}

// DeletePost удаляет пост
func (s *PostServer) DeletePost(ctx context.Context, req *pb.PostIdRequest) (*pb.DeletePostResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.DeletePostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	// Удаляем пост через сервисный слой
	err := s.service.DeletePost(req.PostId, req.UserId)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		} else if err.Error() == "доступ запрещен" {
			errCode = codes.PermissionDenied
		}

		return &pb.DeletePostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	return &pb.DeletePostResponse{
		Success: true,
	}, nil
}

// ListPosts возвращает список постов с пагинацией и фильтрацией
func (s *PostServer) ListPosts(ctx context.Context, req *pb.ListPostsRequest) (*pb.ListPostsResponse, error) {
	// Преобразуем опциональные поля
	var creatorID *int32
	if req.CreatorId != nil {
		creatorVal := *req.CreatorId
		creatorID = &creatorVal
	}

	// Устанавливаем значения пагинации по умолчанию, если они не указаны
	page := req.Page
	if page < 1 {
		page = 1
	}

	pageSize := req.PageSize
	if pageSize < 1 {
		pageSize = 10
	}

	// Получаем список постов через сервисный слой
	posts, totalCount, err := s.service.ListPosts(req.UserId, page, pageSize, creatorID, req.Tags)
	if err != nil {
		return &pb.ListPostsResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(codes.Internal, "ошибка при получении списка постов")
	}

	return &pb.ListPostsResponse{
		Posts:      posts,
		TotalCount: totalCount,
		Success:    true,
	}, nil
}

// ViewPost регистрирует просмотр поста
func (s *PostServer) ViewPost(ctx context.Context, req *pb.ViewPostRequest) (*pb.ViewPostResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.ViewPostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	// Регистрируем просмотр через сервисный слой
	err := s.service.ViewPost(req.PostId, req.UserId)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		}

		return &pb.ViewPostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	// Отправляем событие просмотра в Kafka
	if kafkaProducer != nil {
		if err := kafkaProducer.SendPostView(req.PostId, req.UserId); err != nil {
			// Логируем ошибку, но не прерываем выполнение
			// так как это некритичная ошибка для основной функциональности
			status.Errorf(codes.Internal, "ошибка отправки события в Kafka: %v", err)
		}
	}

	return &pb.ViewPostResponse{
		Success: true,
	}, nil
}

// LikePost добавляет или удаляет лайк поста
func (s *PostServer) LikePost(ctx context.Context, req *pb.LikePostRequest) (*pb.LikePostResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.LikePostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.UserId == 0 {
		return &pb.LikePostResponse{
			Success: false,
			Error:   "ID пользователя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID пользователя не может быть пустым")
	}

	// Обрабатываем лайк через сервисный слой
	err := s.service.LikePost(req.PostId, req.UserId)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		} else if err.Error() == "доступ запрещен" {
			errCode = codes.PermissionDenied
		}

		return &pb.LikePostResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	// Отправляем событие лайка в Kafka
	if kafkaProducer != nil {
		if err := kafkaProducer.SendPostLike(req.PostId, req.UserId); err != nil {
			// Логируем ошибку, но не прерываем выполнение
			status.Errorf(codes.Internal, "ошибка отправки события в Kafka: %v", err)
		}
	}

	return &pb.LikePostResponse{
		Success: true,
	}, nil
}

// AddComment добавляет комментарий к посту
func (s *PostServer) AddComment(ctx context.Context, req *pb.AddCommentRequest) (*pb.AddCommentResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.UserId == 0 {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "ID пользователя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID пользователя не может быть пустым")
	}

	if strings.TrimSpace(req.Text) == "" {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "текст комментария не может быть пустым",
		}, status.Error(codes.InvalidArgument, "текст комментария не может быть пустым")
	}

	// Добавляем комментарий через сервисный слой
	comment, err := s.service.AddComment(req.PostId, req.UserId, req.Text)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		}

		return &pb.AddCommentResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	// Отправляем событие комментария в Kafka
	if kafkaProducer != nil {
		if err := kafkaProducer.SendPostComment(req.PostId, req.UserId, comment.Id); err != nil {
			// Логируем ошибку, но не прерываем выполнение
			status.Errorf(codes.Internal, "ошибка отправки события в Kafka: %v", err)
		}
	}

	return &pb.AddCommentResponse{
		Success: true,
		Comment: comment,
	}, nil
}

// GetComments возвращает список комментариев к посту
func (s *PostServer) GetComments(ctx context.Context, req *pb.GetCommentsRequest) (*pb.GetCommentsResponse, error) {
	// Проверка входных данных
	if req.PostId == 0 {
		return &pb.GetCommentsResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	// Устанавливаем значения пагинации по умолчанию, если они не указаны
	page := req.Page
	if page < 1 {
		page = 1
	}

	pageSize := req.PageSize
	if pageSize < 1 {
		pageSize = 10
	}

	// Получаем комментарии через сервисный слой
	comments, totalCount, err := s.service.GetComments(req.PostId, page, pageSize)
	if err != nil {
		errCode := codes.Internal
		if err.Error() == "пост не найден" {
			errCode = codes.NotFound
		}

		return &pb.GetCommentsResponse{
			Success: false,
			Error:   err.Error(),
		}, status.Error(errCode, err.Error())
	}

	return &pb.GetCommentsResponse{
		Comments:   comments,
		TotalCount: totalCount,
		Success:    true,
	}, nil
}
