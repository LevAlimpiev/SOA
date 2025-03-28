package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/db"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/server"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/service"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	_ "github.com/lib/pq"
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
	dbConn  *sql.DB
}

// Инициализация подключения к базе данных для тестов
func initTestDB() (*sql.DB, error) {
	// Получаем параметры соединения из переменных окружения или используем значения по умолчанию для тестов
	dbHost := getTestEnv("TEST_DB_HOST", "localhost")
	dbPort := getTestEnv("TEST_DB_PORT", "5432")
	dbUser := getTestEnv("TEST_DB_USER", "postgres")
	dbPassword := getTestEnv("TEST_DB_PASSWORD", "postgres")
	dbName := getTestEnv("TEST_DB_NAME", "post_service_test")

	// Формируем строку подключения к PostgreSQL
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// Открываем соединение
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("ошибка при открытии соединения с БД для тестов: %w", err)
	}

	// Устанавливаем параметры соединения
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Проверяем соединение
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ошибка при проверке соединения с БД для тестов: %w", err)
	}

	return db, nil
}

// getTestEnv получает значение переменной окружения или возвращает значение по умолчанию
func getTestEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Инициализация схемы базы данных для тестов
func initTestSchema(database *sql.DB) error {
	// SQL для создания таблицы posts
	createPostsTable := `
    CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        creator_id INTEGER NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        is_private BOOLEAN DEFAULT FALSE
    );
    `

	// SQL для создания таблицы post_tags
	createPostTagsTable := `
    CREATE TABLE IF NOT EXISTS post_tags (
        post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
        tag VARCHAR(50) NOT NULL,
        PRIMARY KEY (post_id, tag)
    );
    `

	// Выполняем SQL запросы
	_, err := database.Exec(createPostsTable)
	if err != nil {
		return fmt.Errorf("ошибка при создании таблицы posts: %w", err)
	}

	_, err = database.Exec(createPostTagsTable)
	if err != nil {
		return fmt.Errorf("ошибка при создании таблицы post_tags: %w", err)
	}

	// Создаем индексы
	_, err = database.Exec("CREATE INDEX IF NOT EXISTS posts_creator_id_idx ON posts(creator_id);")
	if err != nil {
		return fmt.Errorf("ошибка при создании индекса posts_creator_id_idx: %w", err)
	}

	_, err = database.Exec("CREATE INDEX IF NOT EXISTS post_tags_tag_idx ON post_tags(tag);")
	if err != nil {
		return fmt.Errorf("ошибка при создании индекса post_tags_tag_idx: %w", err)
	}

	return nil
}

// Очистка таблиц перед каждым тестом
func cleanupTables(database *sql.DB) error {
	// Удаляем все данные из таблиц
	_, err := database.Exec("DELETE FROM post_tags;")
	if err != nil {
		return fmt.Errorf("ошибка при очистке таблицы post_tags: %w", err)
	}

	_, err = database.Exec("DELETE FROM posts;")
	if err != nil {
		return fmt.Errorf("ошибка при очистке таблицы posts: %w", err)
	}

	// Сбрасываем sequence для ID
	_, err = database.Exec("ALTER SEQUENCE posts_id_seq RESTART WITH 1;")
	if err != nil {
		return fmt.Errorf("ошибка при сбросе sequence posts_id_seq: %w", err)
	}

	return nil
}

// SetupSuite инициализирует все зависимости перед запуском тестов
func (s *PostServiceSuite) SetupSuite() {
	s.ctx = context.Background()

	// Создаем мок-репозиторий вместо подключения к базе данных
	s.repo = db.NewMockPostRepository()

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
