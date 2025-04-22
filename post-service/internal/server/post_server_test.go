package server

import (
	"context"
	"errors"
	"testing"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MockPostService реализует интерфейс service.PostService для тестирования
type MockPostService struct {
	mock.Mock
}

func (m *MockPostService) CreatePost(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error) {
	args := m.Called(creatorID, title, description, isPrivate, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.Post), args.Error(1)
}

func (m *MockPostService) GetPostByID(postID, userID int32) (*pb.Post, error) {
	args := m.Called(postID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.Post), args.Error(1)
}

func (m *MockPostService) UpdatePost(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error) {
	args := m.Called(postID, creatorID, title, description, isPrivate, tags)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.Post), args.Error(1)
}

func (m *MockPostService) DeletePost(postID, userID int32) error {
	args := m.Called(postID, userID)
	return args.Error(0)
}

func (m *MockPostService) ListPosts(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error) {
	args := m.Called(userID, page, pageSize, creatorID, tags)
	if args.Get(0) == nil {
		return nil, int32(args.Int(1)), args.Error(2)
	}
	return args.Get(0).([]*pb.Post), int32(args.Int(1)), args.Error(2)
}

// ViewPost реализация мока для просмотра поста
func (m *MockPostService) ViewPost(postID, userID int32) error {
	args := m.Called(postID, userID)
	return args.Error(0)
}

// LikePost реализация мока для лайка поста
func (m *MockPostService) LikePost(postID, userID int32) error {
	args := m.Called(postID, userID)
	return args.Error(0)
}

// AddComment реализация мока для добавления комментария
func (m *MockPostService) AddComment(postID, userID int32, text string) (*pb.Comment, error) {
	args := m.Called(postID, userID, text)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.Comment), args.Error(1)
}

// GetComments реализация мока для получения комментариев
func (m *MockPostService) GetComments(postID int32, page, pageSize int32) ([]*pb.Comment, int32, error) {
	args := m.Called(postID, page, pageSize)
	if args.Get(0) == nil {
		return nil, int32(args.Int(1)), args.Error(2)
	}
	return args.Get(0).([]*pb.Comment), int32(args.Int(1)), args.Error(2)
}

func createTestPost(id, creatorID int32, title, description string, isPrivate bool, tags []string) *pb.Post {
	return &pb.Post{
		Id:          id,
		CreatorId:   creatorID,
		Title:       title,
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        tags,
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
	}
}

func TestPostServer_CreatePost(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	creatorID := int32(1)
	title := "Тестовый пост"
	description := "Описание тестового поста"
	isPrivate := false
	tags := []string{"тест", "пост"}

	// Создаем ожидаемый пост
	expectedPost := createTestPost(1, creatorID, title, description, isPrivate, tags)

	// Настраиваем поведение мока сервиса
	mockService.On("CreatePost", creatorID, title, description, isPrivate, tags).Return(expectedPost, nil)

	// Создаем запрос
	req := &pb.CreatePostRequest{
		CreatorId:   creatorID,
		Title:       title,
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        tags,
	}

	// Вызываем метод сервера
	resp, err := server.CreatePost(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, expectedPost, resp.Post)
	mockService.AssertExpectations(t)

	// Тест с пустым названием
	invalidReq := &pb.CreatePostRequest{
		CreatorId:   creatorID,
		Title:       "", // Пустое название
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        tags,
	}

	resp, err = server.CreatePost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "название поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой создания
	mockError := errors.New("ошибка при создании поста")
	mockService.On("CreatePost", int32(0), "Название", description, isPrivate, tags).Return(nil, mockError)

	errorReq := &pb.CreatePostRequest{
		CreatorId:   0, // Неверный ID создателя
		Title:       "Название",
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        tags,
	}

	resp, err = server.CreatePost(ctx, errorReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())
}

func TestPostServer_GetPostById(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Создаем ожидаемый пост
	expectedPost := createTestPost(postID, userID, "Тестовый пост", "Описание", false, []string{"тег"})

	// Настраиваем поведение мока сервиса
	mockService.On("GetPostByID", postID, userID).Return(expectedPost, nil)

	// Создаем запрос
	req := &pb.PostIdRequest{
		PostId: postID,
		UserId: userID,
	}

	// Вызываем метод сервера
	resp, err := server.GetPostById(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, expectedPost, resp.Post)
	mockService.AssertExpectations(t)

	// Тест с несуществующим ID поста
	invalidReq := &pb.PostIdRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
	}

	resp, err = server.GetPostById(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой "пост не найден"
	mockService.On("GetPostByID", int32(999), userID).Return(nil, errors.New("пост не найден"))

	notFoundReq := &pb.PostIdRequest{
		PostId: 999,
		UserId: userID,
	}

	resp, err = server.GetPostById(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())

	// Тест с ошибкой "доступ запрещен"
	mockService.On("GetPostByID", postID, int32(3)).Return(nil, errors.New("доступ запрещен"))

	forbiddenReq := &pb.PostIdRequest{
		PostId: postID,
		UserId: 3,
	}

	resp, err = server.GetPostById(ctx, forbiddenReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "доступ запрещен", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, statusErr.Code())
}

func TestPostServer_UpdatePost(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	creatorID := int32(2)

	// Создаем тестовые данные
	titleValue := "Обновленный пост"
	descValue := "Обновленное описание"
	isPrivateValue := true
	tags := []string{"обновлено", "тест"}

	// Создаем ожидаемый обновленный пост
	expectedPost := createTestPost(postID, creatorID, titleValue, descValue, isPrivateValue, tags)

	// Настраиваем поведение мока сервиса с использованием mock.Anything() для строгого контроля типов
	mockService.On("UpdatePost", postID, creatorID, mock.Anything, mock.Anything, mock.Anything, tags).Return(expectedPost, nil)

	// Создаем запрос
	req := &pb.UpdatePostRequest{
		PostId:      postID,
		CreatorId:   creatorID,
		Title:       &titleValue,
		Description: &descValue,
		IsPrivate:   &isPrivateValue,
		Tags:        tags,
	}

	// Вызываем метод сервера
	resp, err := server.UpdatePost(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, expectedPost, resp.Post)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidReq := &pb.UpdatePostRequest{
		PostId:    0, // Неверный ID поста
		CreatorId: creatorID,
	}

	resp, err = server.UpdatePost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с неверным ID создателя
	invalidCreatorReq := &pb.UpdatePostRequest{
		PostId:    postID,
		CreatorId: 0, // Неверный ID создателя
	}

	resp, err = server.UpdatePost(ctx, invalidCreatorReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID создателя не может быть пустым", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с частичным обновлением
	partialTitle := "Частично обновлено"

	partialUpdatedPost := createTestPost(postID, creatorID, partialTitle, descValue, isPrivateValue, tags)
	mockService.On("UpdatePost", postID, creatorID, mock.Anything, mock.Anything, mock.Anything, []string{}).Return(partialUpdatedPost, nil)

	partialReq := &pb.UpdatePostRequest{
		PostId:    postID,
		CreatorId: creatorID,
		Title:     &partialTitle,
		Tags:      []string{}, // Пустой слайс тегов (удаление всех тегов)
	}

	resp, err = server.UpdatePost(ctx, partialReq)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, partialUpdatedPost, resp.Post)
}

func TestPostServer_DeletePost(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Настраиваем поведение мока сервиса
	mockService.On("DeletePost", postID, userID).Return(nil)

	// Создаем запрос
	req := &pb.PostIdRequest{
		PostId: postID,
		UserId: userID,
	}

	// Вызываем метод сервера
	resp, err := server.DeletePost(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidReq := &pb.PostIdRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
	}

	resp, err = server.DeletePost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой "пост не найден"
	mockService.On("DeletePost", int32(999), userID).Return(errors.New("пост не найден"))

	notFoundReq := &pb.PostIdRequest{
		PostId: 999,
		UserId: userID,
	}

	resp, err = server.DeletePost(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())

	// Тест с ошибкой "доступ запрещен"
	mockService.On("DeletePost", postID, int32(3)).Return(errors.New("доступ запрещен"))

	forbiddenReq := &pb.PostIdRequest{
		PostId: postID,
		UserId: 3,
	}

	resp, err = server.DeletePost(ctx, forbiddenReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "доступ запрещен", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, statusErr.Code())
}

func TestPostServer_ListPosts(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	userID := int32(1)
	page := int32(1)
	pageSize := int32(10)
	var creatorIDPtr *int32 = nil
	tags := []string{}

	// Создаем тестовые данные
	posts := []*pb.Post{
		createTestPost(1, 1, "Пост 1", "Описание 1", false, []string{"тег1"}),
		createTestPost(2, 1, "Пост 2", "Описание 2", false, []string{"тег2"}),
	}
	totalCount := int32(2)

	// Настраиваем поведение мока сервиса
	mockService.On("ListPosts", userID, page, pageSize, creatorIDPtr, tags).Return(posts, totalCount, nil)

	// Создаем запрос
	req := &pb.ListPostsRequest{
		UserId:   userID,
		Page:     page,
		PageSize: pageSize,
		Tags:     tags,
	}

	// Вызываем метод сервера
	resp, err := server.ListPosts(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, posts, resp.Posts)
	assert.Equal(t, totalCount, resp.TotalCount)
	mockService.AssertExpectations(t)

	// Тест с фильтрацией по создателю
	creatorID := int32(2)
	creatorIDPtr = &creatorID
	filteredPosts := []*pb.Post{
		createTestPost(3, 2, "Пост от создателя 2", "Описание", false, []string{"тег3"}),
	}
	filteredCount := int32(1)

	mockService.On("ListPosts", userID, page, pageSize, creatorIDPtr, tags).Return(filteredPosts, filteredCount, nil)

	filteredReq := &pb.ListPostsRequest{
		UserId:    userID,
		Page:      page,
		PageSize:  pageSize,
		CreatorId: &creatorID,
		Tags:      tags,
	}

	resp, err = server.ListPosts(ctx, filteredReq)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, filteredPosts, resp.Posts)
	assert.Equal(t, filteredCount, resp.TotalCount)

	// Тест с установкой значений пагинации по умолчанию
	defaultPagePosts := []*pb.Post{
		createTestPost(1, 1, "Default Page Post", "Description", false, []string{"tag"}),
	}
	defaultPageCount := int32(1)

	// Значения page = 0 и pageSize = 0 должны быть заменены на значения по умолчанию (1 и 10)
	mockService.On("ListPosts", userID, int32(1), int32(10), nil, tags).Return(defaultPagePosts, defaultPageCount, nil)

	defaultPageReq := &pb.ListPostsRequest{
		UserId:   userID,
		Page:     0,
		PageSize: 0,
		Tags:     tags,
	}

	resp, err = server.ListPosts(ctx, defaultPageReq)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, defaultPagePosts, resp.Posts)
	assert.Equal(t, defaultPageCount, resp.TotalCount)

	// Тест с ошибкой
	mockService.On("ListPosts", int32(0), int32(1), int32(10), nil, tags).Return(nil, int32(0), errors.New("ошибка при получении списка постов"))

	errorReq := &pb.ListPostsRequest{
		UserId: 0,
		Tags:   tags,
	}

	resp, err = server.ListPosts(ctx, errorReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ошибка при получении списка постов", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, statusErr.Code())
}

func TestPostServer_ViewPost(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Настраиваем поведение мока сервиса - успешный просмотр
	mockService.On("ViewPost", postID, userID).Return(nil)

	// Создаем запрос
	req := &pb.ViewPostRequest{
		PostId: postID,
		UserId: userID,
	}

	// Вызываем метод сервера
	resp, err := server.ViewPost(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidReq := &pb.ViewPostRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
	}

	resp, err = server.ViewPost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой "пост не найден"
	mockService.On("ViewPost", int32(999), userID).Return(errors.New("пост не найден"))

	notFoundReq := &pb.ViewPostRequest{
		PostId: 999,
		UserId: userID,
	}

	resp, err = server.ViewPost(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}

func TestPostServer_LikePost(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Настраиваем поведение мока сервиса - успешный лайк
	mockService.On("LikePost", postID, userID).Return(nil)

	// Создаем запрос
	req := &pb.LikePostRequest{
		PostId: postID,
		UserId: userID,
	}

	// Вызываем метод сервера
	resp, err := server.LikePost(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidPostIdReq := &pb.LikePostRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
	}

	resp, err = server.LikePost(ctx, invalidPostIdReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с неверным ID пользователя
	invalidUserIdReq := &pb.LikePostRequest{
		PostId: postID,
		UserId: 0, // Неверный ID пользователя
	}

	resp, err = server.LikePost(ctx, invalidUserIdReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID пользователя не может быть пустым", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой "пост не найден"
	mockService.On("LikePost", int32(999), userID).Return(errors.New("пост не найден"))

	notFoundReq := &pb.LikePostRequest{
		PostId: 999,
		UserId: userID,
	}

	resp, err = server.LikePost(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}

func TestPostServer_AddComment(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)
	text := "Тестовый комментарий"

	// Создаем ожидаемый комментарий
	expectedComment := &pb.Comment{
		Id:        1,
		PostId:    postID,
		UserId:    userID,
		Text:      text,
		Username:  "test_user",
		CreatedAt: timestamppb.Now(),
	}

	// Настраиваем поведение мока сервиса - успешное добавление комментария
	mockService.On("AddComment", postID, userID, text).Return(expectedComment, nil)

	// Создаем запрос
	req := &pb.AddCommentRequest{
		PostId: postID,
		UserId: userID,
		Text:   text,
	}

	// Вызываем метод сервера
	resp, err := server.AddComment(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, expectedComment, resp.Comment)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidPostIdReq := &pb.AddCommentRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
		Text:   text,
	}

	resp, err = server.AddComment(ctx, invalidPostIdReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с неверным ID пользователя
	invalidUserIdReq := &pb.AddCommentRequest{
		PostId: postID,
		UserId: 0, // Неверный ID пользователя
		Text:   text,
	}

	resp, err = server.AddComment(ctx, invalidUserIdReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID пользователя не может быть пустым", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с пустым текстом комментария
	emptyTextReq := &pb.AddCommentRequest{
		PostId: postID,
		UserId: userID,
		Text:   "", // Пустой текст
	}

	resp, err = server.AddComment(ctx, emptyTextReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "текст комментария не может быть пустым", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой "пост не найден"
	mockService.On("AddComment", int32(999), userID, text).Return(nil, errors.New("пост не найден"))

	notFoundReq := &pb.AddCommentRequest{
		PostId: 999,
		UserId: userID,
		Text:   text,
	}

	resp, err = server.AddComment(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}

func TestPostServer_GetComments(t *testing.T) {
	mockService := new(MockPostService)
	server := NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	page := int32(1)
	pageSize := int32(10)
	totalCount := int32(20)

	// Создаем ожидаемые комментарии
	expectedComments := []*pb.Comment{
		{
			Id:        1,
			PostId:    postID,
			UserId:    2,
			Text:      "Комментарий 1",
			Username:  "user1",
			CreatedAt: timestamppb.Now(),
		},
		{
			Id:        2,
			PostId:    postID,
			UserId:    3,
			Text:      "Комментарий 2",
			Username:  "user2",
			CreatedAt: timestamppb.Now(),
		},
	}

	// Настраиваем поведение мока сервиса - успешное получение комментариев
	mockService.On("GetComments", postID, page, pageSize).Return(expectedComments, totalCount, nil)

	// Создаем запрос
	req := &pb.GetCommentsRequest{
		PostId:   postID,
		Page:     page,
		PageSize: pageSize,
	}

	// Вызываем метод сервера
	resp, err := server.GetComments(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, expectedComments, resp.Comments)
	assert.Equal(t, totalCount, resp.TotalCount)
	mockService.AssertExpectations(t)

	// Тест с неверным ID поста
	invalidPostIdReq := &pb.GetCommentsRequest{
		PostId:   0, // Неверный ID поста
		Page:     page,
		PageSize: pageSize,
	}

	resp, err = server.GetComments(ctx, invalidPostIdReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "ID поста не может быть пустым", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с нулевыми значениями пагинации (должны быть установлены значения по умолчанию)
	mockService.On("GetComments", postID, int32(1), int32(10)).Return(expectedComments, totalCount, nil)

	zeroPaginationReq := &pb.GetCommentsRequest{
		PostId:   postID,
		Page:     0, // Неверное значение страницы
		PageSize: 0, // Неверное значение размера страницы
	}

	resp, err = server.GetComments(ctx, zeroPaginationReq)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	mockService.AssertExpectations(t)

	// Тест с ошибкой "пост не найден"
	mockService.On("GetComments", int32(999), int32(1), int32(10)).Return(nil, int32(0), errors.New("пост не найден"))

	notFoundReq := &pb.GetCommentsRequest{
		PostId:   999,
		Page:     1,
		PageSize: 10,
	}

	resp, err = server.GetComments(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "пост не найден", resp.Error)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}
