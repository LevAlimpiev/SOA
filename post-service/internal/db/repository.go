package db

import (
	"database/sql"
	"log"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
)

// PostRepository интерфейс для работы с хранилищем постов
type PostRepository interface {
	Create(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error)
	GetByID(postID, userID int32) (*pb.Post, error)
	Update(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error)
	Delete(postID, userID int32) error
	List(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error)
}

// NewPostRepository создает новый репозиторий постов
// Если передан nil, возвращает ошибку
func NewPostRepository(db *sql.DB) PostRepository {
	if db == nil {
		// Для обратной совместимости вернем пустую реализацию, которая всегда будет выдавать ошибку
		log.Println("ВНИМАНИЕ: Создание репозитория без подключения к базе данных не поддерживается")
		return nil
	}
	return NewPostgresPostRepository(db)
}
