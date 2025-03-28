package main

import (
	"time"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
)

// CreatePostRequest представляет запрос на создание поста
type CreatePostRequest struct {
	CreatorID   int32    `json:"creator_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	IsPrivate   bool     `json:"is_private"`
	Tags        []string `json:"tags"`
}

// UpdatePostRequest представляет запрос на обновление поста
type UpdatePostRequest struct {
	PostID      int32     `json:"post_id"`
	CreatorID   int32     `json:"creator_id"`
	Title       *string   `json:"title,omitempty"`
	Description *string   `json:"description,omitempty"`
	IsPrivate   *bool     `json:"is_private,omitempty"`
	Tags        []string  `json:"tags"`
}

// ListPostsRequest представляет запрос на получение списка постов
type ListPostsRequest struct {
	UserID    int32    `json:"user_id"`
	Page      int32    `json:"page"`
	PageSize  int32    `json:"page_size"`
	CreatorID *int32   `json:"creator_id,omitempty"`
	Tags      []string `json:"tags"`
}

// Post представляет модель поста для REST API
type Post struct {
	ID          int32     `json:"id"`
	CreatorID   int32     `json:"creator_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsPrivate   bool      `json:"is_private"`
	Tags        []string  `json:"tags"`
}

// PostResponse представляет ответ с информацией о посте
type PostResponse struct {
	Post    *Post  `json:"post,omitempty"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// DeletePostResponse представляет ответ на запрос удаления поста
type DeletePostResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ListPostsResponse представляет ответ со списком постов
type ListPostsResponse struct {
	Posts      []Post `json:"posts"`
	TotalCount int32  `json:"total_count"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// ConvertProtoPostToRESTPost преобразует пост из protobuf в REST модель
func ConvertProtoPostToRESTPost(protoPost *pb.Post) *Post {
	if protoPost == nil {
		return nil
	}

	return &Post{
		ID:          protoPost.Id,
		CreatorID:   protoPost.CreatorId,
		Title:       protoPost.Title,
		Description: protoPost.Description,
		CreatedAt:   protoPost.CreatedAt.AsTime(),
		UpdatedAt:   protoPost.UpdatedAt.AsTime(),
		IsPrivate:   protoPost.IsPrivate,
		Tags:        protoPost.Tags,
	}
}

// ConvertProtoPostResponseToRESTResponse преобразует ответ с постом из protobuf в REST формат
func ConvertProtoPostResponseToRESTResponse(protoResponse *pb.PostResponse) *PostResponse {
	if protoResponse == nil {
		return &PostResponse{
			Success: false,
			Error:   "Пустой ответ от сервера",
		}
	}

	return &PostResponse{
		Post:    ConvertProtoPostToRESTPost(protoResponse.Post),
		Success: protoResponse.Success,
		Error:   protoResponse.Error,
	}
}

// ConvertProtoDeleteResponseToRESTResponse преобразует ответ на удаление из protobuf в REST формат
func ConvertProtoDeleteResponseToRESTResponse(protoResponse *pb.DeletePostResponse) *DeletePostResponse {
	if protoResponse == nil {
		return &DeletePostResponse{
			Success: false,
			Error:   "Пустой ответ от сервера",
		}
	}

	return &DeletePostResponse{
		Success: protoResponse.Success,
		Error:   protoResponse.Error,
	}
}

// ConvertProtoListResponseToRESTResponse преобразует ответ со списком постов из protobuf в REST формат
func ConvertProtoListResponseToRESTResponse(protoResponse *pb.ListPostsResponse) *ListPostsResponse {
	if protoResponse == nil {
		return &ListPostsResponse{
			Success: false,
			Error:   "Пустой ответ от сервера",
		}
	}

	posts := make([]Post, 0, len(protoResponse.Posts))
	for _, protoPost := range protoResponse.Posts {
		if post := ConvertProtoPostToRESTPost(protoPost); post != nil {
			posts = append(posts, *post)
		}
	}

	return &ListPostsResponse{
		Posts:      posts,
		TotalCount: protoResponse.TotalCount,
		Success:    protoResponse.Success,
		Error:      protoResponse.Error,
	}
} 