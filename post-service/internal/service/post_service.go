package service

import (
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/db"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
)

// PostService интерфейс сервиса для работы с постами
type PostService interface {
	CreatePost(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error)
	GetPostByID(postID, userID int32) (*pb.Post, error)
	UpdatePost(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error)
	DeletePost(postID, userID int32) error
	ListPosts(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error)
}

// postService реализация сервиса для работы с постами
type postService struct {
	repo db.PostRepository
}

// NewPostService создает новый экземпляр сервиса
func NewPostService(repo db.PostRepository) PostService {
	return &postService{
		repo: repo,
	}
}

// CreatePost создает новый пост
func (s *postService) CreatePost(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error) {
	return s.repo.Create(creatorID, title, description, isPrivate, tags)
}

// GetPostByID получает пост по ID
func (s *postService) GetPostByID(postID, userID int32) (*pb.Post, error) {
	return s.repo.GetByID(postID, userID)
}

// UpdatePost обновляет данные поста
func (s *postService) UpdatePost(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error) {
	return s.repo.Update(postID, creatorID, title, description, isPrivate, tags)
}

// DeletePost удаляет пост
func (s *postService) DeletePost(postID, userID int32) error {
	return s.repo.Delete(postID, userID)
}

// ListPosts возвращает список постов с пагинацией и фильтрацией
func (s *postService) ListPosts(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error) {
	return s.repo.List(userID, page, pageSize, creatorID, tags)
} 