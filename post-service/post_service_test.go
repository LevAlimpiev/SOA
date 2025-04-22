package main

import (
	"context"
	"errors"
	"log"
	"testing"

	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/db"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/server"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/service"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PostServiceSuite содержит все интеграционные тесты для сервиса постов
type PostServiceSuite struct {
	suite.Suite
	repo    db.PostRepository
	service service.PostService
	server  *server.PostServer
	ctx     context.Context
}

// SetupSuite инициализирует все зависимости перед запуском тестов
func (s *PostServiceSuite) SetupSuite() {
	s.ctx = context.Background()

	// Создаем мок-репозиторий вместо подключения к базе данных
	s.repo = db.NewMockPostRepository()
	if s.repo == nil {
		log.Fatalf("Не удалось создать мок-репозиторий")
	}

	// Создаём сервисный слой и gRPC сервер
	s.service = service.NewPostService(s.repo)
	s.server = server.NewPostServer(s.service)
}

// SetupTest выполняется перед каждым тестом
func (s *PostServiceSuite) SetupTest() {
	// При использовании мока нет необходимости очищать таблицы
	// Каждый тест будет работать с новым инстансом мок-репозитория
}

// TearDownSuite закрывает соединение с базой данных после выполнения всех тестов
func (s *PostServiceSuite) TearDownSuite() {
	// При использовании мока нет необходимости закрывать соединение
}

// TestCreateAndGetPost проверяет создание и получение поста
func (s *PostServiceSuite) TestCreateAndGetPost() {
	t := s.T()

	// Создаем пост
	createReq := &pb.CreatePostRequest{
		CreatorId:   1,
		Title:       "Тестовый пост",
		Description: "Описание тестового поста",
		IsPrivate:   false,
		Tags:        []string{"тест", "интеграция"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)
	assert.NotNil(t, createResp.Post)

	// Получаем созданный пост
	getReq := &pb.PostIdRequest{
		PostId: createResp.Post.Id,
		UserId: createReq.CreatorId,
	}

	getResp, err := s.server.GetPostById(s.ctx, getReq)
	assert.NoError(t, err)
	assert.True(t, getResp.Success)
	assert.Equal(t, createResp.Post.Id, getResp.Post.Id)
	assert.Equal(t, createReq.Title, getResp.Post.Title)
	assert.Equal(t, createReq.Description, getResp.Post.Description)
	assert.Equal(t, createReq.IsPrivate, getResp.Post.IsPrivate)
	assert.ElementsMatch(t, createReq.Tags, getResp.Post.Tags)
}

// TestUpdatePost проверяет обновление поста
func (s *PostServiceSuite) TestUpdatePost() {
	t := s.T()

	// Создаем пост
	createReq := &pb.CreatePostRequest{
		CreatorId:   1,
		Title:       "Пост для обновления",
		Description: "Исходное описание",
		IsPrivate:   false,
		Tags:        []string{"исходный", "тег"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Обновляем пост
	newTitle := "Обновленный заголовок"
	newPrivate := true
	updateReq := &pb.UpdatePostRequest{
		PostId:    createResp.Post.Id,
		CreatorId: createReq.CreatorId,
		Title:     &newTitle,
		IsPrivate: &newPrivate,
		Tags:      []string{"обновленный", "тег"},
	}

	updateResp, err := s.server.UpdatePost(s.ctx, updateReq)
	assert.NoError(t, err)
	assert.True(t, updateResp.Success)
	assert.Equal(t, newTitle, updateResp.Post.Title)
	assert.Equal(t, createReq.Description, updateResp.Post.Description) // Описание не менялось
	assert.Equal(t, newPrivate, updateResp.Post.IsPrivate)
	assert.Equal(t, updateReq.Tags, updateResp.Post.Tags)
}

// TestDeletePost проверяет удаление поста
func (s *PostServiceSuite) TestDeletePost() {
	t := s.T()

	// Создаем пост
	createReq := &pb.CreatePostRequest{
		CreatorId:   1,
		Title:       "Пост для удаления",
		Description: "Описание поста для удаления",
		IsPrivate:   false,
		Tags:        []string{"удалить"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Удаляем пост
	deleteReq := &pb.PostIdRequest{
		PostId: createResp.Post.Id,
		UserId: createReq.CreatorId,
	}

	deleteResp, err := s.server.DeletePost(s.ctx, deleteReq)
	assert.NoError(t, err)
	assert.True(t, deleteResp.Success)

	// Проверяем, что пост удален
	getReq := &pb.PostIdRequest{
		PostId: createResp.Post.Id,
		UserId: createReq.CreatorId,
	}

	getResp, err := s.server.GetPostById(s.ctx, getReq)
	assert.Error(t, err) // Должна быть ошибка
	assert.False(t, getResp.Success)
}

// TestPrivatePostAccess проверяет доступ к приватному посту
func (s *PostServiceSuite) TestPrivatePostAccess() {
	t := s.T()

	// Создаем приватный пост
	ownerID := int32(1)
	createReq := &pb.CreatePostRequest{
		CreatorId:   ownerID,
		Title:       "Приватный пост",
		Description: "Описание приватного поста",
		IsPrivate:   true,
		Tags:        []string{"приватный"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Владелец должен иметь доступ к посту
	ownerGetReq := &pb.PostIdRequest{
		PostId: createResp.Post.Id,
		UserId: ownerID,
	}

	ownerGetResp, err := s.server.GetPostById(s.ctx, ownerGetReq)
	assert.NoError(t, err)
	assert.True(t, ownerGetResp.Success)

	// Другой пользователь не должен иметь доступ к посту
	otherUserID := int32(2)
	otherUserGetReq := &pb.PostIdRequest{
		PostId: createResp.Post.Id,
		UserId: otherUserID,
	}

	otherUserGetResp, err := s.server.GetPostById(s.ctx, otherUserGetReq)
	assert.Error(t, err)
	assert.False(t, otherUserGetResp.Success)
	assert.Contains(t, otherUserGetResp.Error, "доступ запрещен")
}

// TestListPosts проверяет получение списка постов
func (s *PostServiceSuite) TestListPosts() {
	t := s.T()

	// Создаем несколько постов от разных пользователей
	userID1 := int32(1)
	userID2 := int32(2)

	// Пост от первого пользователя
	createReq1 := &pb.CreatePostRequest{
		CreatorId:   userID1,
		Title:       "Пост пользователя 1",
		Description: "Описание поста пользователя 1",
		IsPrivate:   false,
		Tags:        []string{"пользователь1", "общий"},
	}

	_, _ = s.server.CreatePost(s.ctx, createReq1)

	// Пост от второго пользователя
	createReq2 := &pb.CreatePostRequest{
		CreatorId:   userID2,
		Title:       "Пост пользователя 2",
		Description: "Описание поста пользователя 2",
		IsPrivate:   false,
		Tags:        []string{"пользователь2", "общий"},
	}

	createResp2, _ := s.server.CreatePost(s.ctx, createReq2)

	// Получаем все посты
	listReq := &pb.ListPostsRequest{
		UserId:   userID1,
		Page:     1,
		PageSize: 10,
	}

	listResp, err := s.server.ListPosts(s.ctx, listReq)
	assert.NoError(t, err)
	assert.True(t, listResp.Success)
	assert.GreaterOrEqual(t, listResp.TotalCount, int32(2)) // Должно быть как минимум 2 поста

	// Фильтрация по пользователю
	user2FilterReq := &pb.ListPostsRequest{
		UserId:    userID1,
		Page:      1,
		PageSize:  10,
		CreatorId: &userID2,
	}

	user2FilterResp, err := s.server.ListPosts(s.ctx, user2FilterReq)
	assert.NoError(t, err)
	assert.True(t, user2FilterResp.Success)

	// Проверяем, что все посты принадлежат пользователю 2
	foundUser2Post := false
	for _, post := range user2FilterResp.Posts {
		assert.Equal(t, userID2, post.CreatorId)
		if post.Id == createResp2.Post.Id {
			foundUser2Post = true
		}
	}
	assert.True(t, foundUser2Post, "Должен быть найден пост пользователя 2")

	// Фильтрация по тегу
	tagFilterReq := &pb.ListPostsRequest{
		UserId:   userID1,
		Page:     1,
		PageSize: 10,
		Tags:     []string{"общий"},
	}

	tagFilterResp, err := s.server.ListPosts(s.ctx, tagFilterReq)
	assert.NoError(t, err)
	assert.True(t, tagFilterResp.Success)
	assert.GreaterOrEqual(t, tagFilterResp.TotalCount, int32(2)) // Должно быть как минимум 2 поста с тегом "общий"
}

// TestViewPost проверяет регистрацию просмотра поста
func (s *PostServiceSuite) TestViewPost() {
	t := s.T()

	// Создаем пост
	createReq := &pb.CreatePostRequest{
		CreatorId:   1,
		Title:       "Пост для просмотра",
		Description: "Описание поста для просмотра",
		IsPrivate:   false,
		Tags:        []string{"просмотр"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Регистрируем просмотр поста
	viewerID := int32(2)
	viewReq := &pb.ViewPostRequest{
		PostId: createResp.Post.Id,
		UserId: viewerID,
	}

	viewResp, err := s.server.ViewPost(s.ctx, viewReq)
	assert.NoError(t, err)
	assert.True(t, viewResp.Success)

	// Проверяем повторный просмотр от того же пользователя
	// (повторный просмотр не должен вызывать ошибку)
	repeatViewResp, err := s.server.ViewPost(s.ctx, viewReq)
	assert.NoError(t, err)
	assert.True(t, repeatViewResp.Success)
}

// TestLikePost проверяет лайк и снятие лайка поста
func (s *PostServiceSuite) TestLikePost() {
	t := s.T()

	// Создаем пост
	creatorID := int32(1)
	createReq := &pb.CreatePostRequest{
		CreatorId:   creatorID,
		Title:       "Пост для лайка",
		Description: "Описание поста для лайка",
		IsPrivate:   false,
		Tags:        []string{"лайк"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Ставим лайк посту от другого пользователя
	likerID := int32(2)
	likeReq := &pb.LikePostRequest{
		PostId: createResp.Post.Id,
		UserId: likerID,
	}

	likeResp, err := s.server.LikePost(s.ctx, likeReq)
	assert.NoError(t, err)
	assert.True(t, likeResp.Success)

	// Снимаем лайк (повторный вызов метода должен снять лайк)
	unlikeResp, err := s.server.LikePost(s.ctx, likeReq)
	assert.NoError(t, err)
	assert.True(t, unlikeResp.Success)

	// Собственный лайк поста
	selfLikeReq := &pb.LikePostRequest{
		PostId: createResp.Post.Id,
		UserId: creatorID,
	}

	selfLikeResp, err := s.server.LikePost(s.ctx, selfLikeReq)
	assert.NoError(t, err)
	assert.True(t, selfLikeResp.Success)
}

// TestAddAndGetComments проверяет добавление и получение комментариев
func (s *PostServiceSuite) TestAddAndGetComments() {
	t := s.T()

	// Создаем пост
	createReq := &pb.CreatePostRequest{
		CreatorId:   1,
		Title:       "Пост для комментариев",
		Description: "Описание поста для комментариев",
		IsPrivate:   false,
		Tags:        []string{"комментарий"},
	}

	createResp, err := s.server.CreatePost(s.ctx, createReq)
	assert.NoError(t, err)
	assert.True(t, createResp.Success)

	// Добавляем первый комментарий
	commenterID1 := int32(2)
	comment1 := "Это первый комментарий"
	addCommentReq1 := &pb.AddCommentRequest{
		PostId: createResp.Post.Id,
		UserId: commenterID1,
		Text:   comment1,
	}

	addCommentResp1, err := s.server.AddComment(s.ctx, addCommentReq1)
	assert.NoError(t, err)
	assert.True(t, addCommentResp1.Success)
	assert.Equal(t, comment1, addCommentResp1.Comment.Text)
	assert.Equal(t, commenterID1, addCommentResp1.Comment.UserId)

	// Добавляем второй комментарий от другого пользователя
	commenterID2 := int32(3)
	comment2 := "Это второй комментарий"
	addCommentReq2 := &pb.AddCommentRequest{
		PostId: createResp.Post.Id,
		UserId: commenterID2,
		Text:   comment2,
	}

	addCommentResp2, err := s.server.AddComment(s.ctx, addCommentReq2)
	assert.NoError(t, err)
	assert.True(t, addCommentResp2.Success)

	// Получаем комментарии
	getCommentsReq := &pb.GetCommentsRequest{
		PostId:   createResp.Post.Id,
		Page:     1,
		PageSize: 10,
	}

	getCommentsResp, err := s.server.GetComments(s.ctx, getCommentsReq)
	assert.NoError(t, err)
	assert.True(t, getCommentsResp.Success)
	assert.GreaterOrEqual(t, len(getCommentsResp.Comments), 2)

	// Проверяем, что комментарии в порядке от новых к старым
	assert.Equal(t, comment2, getCommentsResp.Comments[0].Text)
	assert.Equal(t, comment1, getCommentsResp.Comments[1].Text)
}

// Запуск интеграционных тестов
func TestPostService(t *testing.T) {
	suite.Run(t, new(PostServiceSuite))
}

// --------- Модульные тесты для PostServer ---------

// MockPostService для модульного тестирования сервера
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
		return nil, int32(0), args.Error(2)
	}
	return args.Get(0).([]*pb.Post), args.Get(1).(int32), args.Error(2)
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
		return nil, args.Get(1).(int32), args.Error(2)
	}
	return args.Get(0).([]*pb.Comment), args.Get(1).(int32), args.Error(2)
}

// Вспомогательная функция для создания тестовых постов
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

// Модульные тесты сервера

func TestPostServer_CreatePostUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

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

func TestPostServer_GetPostByIdUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

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

func TestPostServer_UpdatePostUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

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

	// Настраиваем поведение мока сервиса
	mockService.On("UpdatePost", postID, creatorID, mock.Anything, mock.Anything, mock.Anything, tags).
		Return(expectedPost, nil)

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

	// Тест с пустым ID поста
	invalidReq := &pb.UpdatePostRequest{
		PostId:    0, // Неверный ID поста
		CreatorId: creatorID,
		Tags:      tags,
	}

	resp, err = server.UpdatePost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой обновления - пост не найден
	mockService.On("UpdatePost", int32(999), creatorID, mock.Anything, mock.Anything, mock.Anything, tags).
		Return(nil, errors.New("пост не найден"))

	notFoundReq := &pb.UpdatePostRequest{
		PostId:    999,
		CreatorId: creatorID,
		Tags:      tags,
	}

	resp, err = server.UpdatePost(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}

func TestPostServer_DeletePostUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

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

	// Тест с пустым ID поста
	invalidReq := &pb.PostIdRequest{
		PostId: 0, // Неверный ID поста
		UserId: userID,
	}

	resp, err = server.DeletePost(ctx, invalidReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, statusErr.Code())

	// Тест с ошибкой - пост не найден
	mockService.On("DeletePost", int32(999), userID).Return(errors.New("пост не найден"))

	notFoundReq := &pb.PostIdRequest{
		PostId: 999,
		UserId: userID,
	}

	resp, err = server.DeletePost(ctx, notFoundReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())

	// Тест с ошибкой - доступ запрещен
	mockService.On("DeletePost", postID, int32(3)).Return(errors.New("доступ запрещен"))

	forbiddenReq := &pb.PostIdRequest{
		PostId: postID,
		UserId: 3,
	}

	resp, err = server.DeletePost(ctx, forbiddenReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	statusErr, _ = status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, statusErr.Code())
}

func TestPostServer_ListPostsUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

	ctx := context.Background()
	userID := int32(1)
	page := int32(1)
	pageSize := int32(10)
	creatorID := int32(2)
	tags := []string{"тест"}

	// Создаем тестовые посты
	posts := []*pb.Post{
		createTestPost(1, creatorID, "Пост 1", "Описание 1", false, tags),
		createTestPost(2, creatorID, "Пост 2", "Описание 2", false, tags),
	}
	totalCount := int32(2)

	// Настраиваем поведение мока сервиса
	mockService.On("ListPosts", userID, page, pageSize, (*int32)(nil), []string(nil)).
		Return(posts, totalCount, nil)

	// Создаем запрос
	req := &pb.ListPostsRequest{
		UserId:   userID,
		Page:     page,
		PageSize: pageSize,
	}

	// Вызываем метод сервера
	resp, err := server.ListPosts(ctx, req)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, totalCount, resp.TotalCount)
	assert.Equal(t, posts, resp.Posts)
	mockService.AssertExpectations(t)

	// Тест с фильтрацией по создателю
	filteredCreatorID := creatorID
	filteredPosts := []*pb.Post{
		createTestPost(3, creatorID, "Пост от создателя", "Описание", false, tags),
	}
	filteredCount := int32(1)

	mockService.On("ListPosts", userID, page, pageSize, &filteredCreatorID, []string(nil)).
		Return(filteredPosts, filteredCount, nil)

	// Создаем запрос с фильтром по создателю
	reqWithCreator := &pb.ListPostsRequest{
		UserId:    userID,
		Page:      page,
		PageSize:  pageSize,
		CreatorId: &filteredCreatorID,
	}

	// Вызываем метод сервера
	respWithCreator, err := server.ListPosts(ctx, reqWithCreator)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, respWithCreator.Success)
	assert.Equal(t, filteredCount, respWithCreator.TotalCount)
	assert.Equal(t, filteredPosts, respWithCreator.Posts)
	mockService.AssertExpectations(t)

	// Тест с фильтрацией по тегам
	tagFilteredPosts := []*pb.Post{
		createTestPost(4, creatorID, "Пост с тегом", "Описание", false, tags),
	}
	tagFilteredCount := int32(1)

	mockService.On("ListPosts", userID, page, pageSize, (*int32)(nil), tags).
		Return(tagFilteredPosts, tagFilteredCount, nil)

	// Создаем запрос с фильтром по тегам
	reqWithTags := &pb.ListPostsRequest{
		UserId:   userID,
		Page:     page,
		PageSize: pageSize,
		Tags:     tags,
	}

	// Вызываем метод сервера
	respWithTags, err := server.ListPosts(ctx, reqWithTags)

	// Проверяем результаты
	assert.NoError(t, err)
	assert.True(t, respWithTags.Success)
	assert.Equal(t, tagFilteredCount, respWithTags.TotalCount)
	assert.Equal(t, tagFilteredPosts, respWithTags.Posts)
	mockService.AssertExpectations(t)
}

// TestPostServer_ViewPostUnit тестирует функцию ViewPost unit-тестами
func TestPostServer_ViewPostUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Настраиваем поведение мока сервиса
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
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, statusErr.Code())
}

// TestPostServer_LikePostUnit тестирует функцию LikePost unit-тестами
func TestPostServer_LikePostUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	userID := int32(2)

	// Настраиваем поведение мока сервиса
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

	// Тест с ошибкой доступа
	mockService.On("LikePost", postID, int32(999)).Return(errors.New("доступ запрещен"))

	accessErrorReq := &pb.LikePostRequest{
		PostId: postID,
		UserId: 999,
	}

	resp, err = server.LikePost(ctx, accessErrorReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "доступ запрещен", resp.Error)
	statusErr, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, statusErr.Code())
}

// TestPostServer_AddCommentUnit тестирует функцию AddComment unit-тестами
func TestPostServer_AddCommentUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

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

	// Настраиваем поведение мока сервиса
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

	// Тест с пустым текстом комментария
	emptyTextReq := &pb.AddCommentRequest{
		PostId: postID,
		UserId: userID,
		Text:   "",
	}

	resp, err = server.AddComment(ctx, emptyTextReq)
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "текст комментария не может быть пустым", resp.Error)
}

// TestPostServer_GetCommentsUnit тестирует функцию GetComments unit-тестами
func TestPostServer_GetCommentsUnit(t *testing.T) {
	mockService := new(MockPostService)
	server := server.NewPostServer(mockService)

	ctx := context.Background()
	postID := int32(1)
	page := int32(1)
	pageSize := int32(10)
	totalCount := int32(2)

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

	// Настраиваем поведение мока сервиса
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

	// Тест с нулевыми значениями пагинации (должны быть установлены значения по умолчанию)
	mockService.On("GetComments", postID, int32(1), int32(10)).Return(expectedComments, totalCount, nil)

	zeroPaginationReq := &pb.GetCommentsRequest{
		PostId:   postID,
		Page:     0,
		PageSize: 0,
	}

	resp, err = server.GetComments(ctx, zeroPaginationReq)
	assert.NoError(t, err)
	assert.True(t, resp.Success)
}
