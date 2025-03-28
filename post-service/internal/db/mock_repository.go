package db

import (
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MockPostRepository - мок-реализация PostRepository для тестов
type MockPostRepository struct {
	mutex         sync.RWMutex
	posts         map[int32]*pb.Post
	postIdCounter atomic.Int32
}

// NewMockPostRepository создает новый мок репозиторий постов для тестов
func NewMockPostRepository() PostRepository {
	repo := &MockPostRepository{
		posts: make(map[int32]*pb.Post),
	}
	repo.postIdCounter.Store(1) // Начинаем с ID = 1
	return repo
}

// Create создает новый пост в моке
func (r *MockPostRepository) Create(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	postID := r.postIdCounter.Add(1) - 1
	now := time.Now()

	post := &pb.Post{
		Id:          postID,
		CreatorId:   creatorID,
		Title:       title,
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        tags,
		CreatedAt:   timestamppb.New(now),
		UpdatedAt:   timestamppb.New(now),
	}

	r.posts[postID] = post
	return post, nil
}

// GetByID получает пост по ID
func (r *MockPostRepository) GetByID(postID, userID int32) (*pb.Post, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	post, exists := r.posts[postID]
	if !exists {
		return nil, ErrNotFound
	}

	// Проверка прав доступа: приватный пост может просматривать только создатель
	if post.IsPrivate && post.CreatorId != userID {
		return nil, ErrForbidden
	}

	return post, nil
}

// Update обновляет пост
func (r *MockPostRepository) Update(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	post, exists := r.posts[postID]
	if !exists {
		return nil, ErrNotFound
	}

	// Только создатель может обновлять пост
	if post.CreatorId != creatorID {
		return nil, ErrForbidden
	}

	// Обновляем поля, если они переданы
	if title != nil {
		post.Title = *title
	}

	if description != nil {
		post.Description = *description
	}

	if isPrivate != nil {
		post.IsPrivate = *isPrivate
	}

	// Обновляем теги, если они переданы
	if tags != nil {
		post.Tags = tags
	}

	// Обновляем дату изменения
	post.UpdatedAt = timestamppb.New(time.Now())

	return post, nil
}

// Delete удаляет пост
func (r *MockPostRepository) Delete(postID, userID int32) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	post, exists := r.posts[postID]
	if !exists {
		return ErrNotFound
	}

	// Только создатель может удалять пост
	if post.CreatorId != userID {
		return ErrForbidden
	}

	// Удаляем пост
	delete(r.posts, postID)
	return nil
}

// List возвращает список постов с фильтрацией
func (r *MockPostRepository) List(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Фильтруем посты согласно условиям
	var filteredPosts []*pb.Post

	for _, post := range r.posts {
		// Пропускаем приватные посты других пользователей
		if post.IsPrivate && post.CreatorId != userID {
			continue
		}

		// Если задан фильтр по создателю и он не совпадает, пропускаем
		if creatorID != nil && post.CreatorId != *creatorID {
			continue
		}

		// Если заданы теги, проверяем соответствие
		if len(tags) > 0 {
			hasAllTags := true
			for _, requiredTag := range tags {
				found := false
				for _, postTag := range post.Tags {
					if postTag == requiredTag {
						found = true
						break
					}
				}
				if !found {
					hasAllTags = false
					break
				}
			}
			if !hasAllTags {
				continue
			}
		}

		// Пост прошел все фильтры, добавляем его
		filteredPosts = append(filteredPosts, post)
	}

	// Общее количество постов после фильтрации
	totalCount := int32(len(filteredPosts))

	// Вычисляем начальный и конечный индексы для пагинации
	startIndex := (page - 1) * pageSize
	endIndex := startIndex + pageSize

	// Проверяем границы
	if startIndex > totalCount {
		return []*pb.Post{}, totalCount, nil
	}

	if endIndex > totalCount {
		endIndex = totalCount
	}

	// Возвращаем часть списка согласно пагинации
	result := make([]*pb.Post, 0, endIndex-startIndex)
	for i := startIndex; i < endIndex && i < totalCount; i++ {
		result = append(result, filteredPosts[i])
	}

	return result, totalCount, nil
}
