package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
)

// Создаем структуру для тестового gRPC-сервера постов
type mockPostServer struct {
	pb.UnimplementedPostServiceServer
}

// Реализуем метод CreatePost для тестового сервера
func (s *mockPostServer) CreatePost(ctx context.Context, req *pb.CreatePostRequest) (*pb.PostResponse, error) {
	if req.Title == "" {
		return &pb.PostResponse{
			Success: false,
			Error:   "название поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "название поста не может быть пустым")
	}

	if req.CreatorId <= 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID создателя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID создателя не может быть пустым")
	}

	// Успешное создание поста
	post := &pb.Post{
		Id:          1,
		CreatorId:   req.CreatorId,
		Title:       req.Title,
		Description: req.Description,
		IsPrivate:   req.IsPrivate,
		Tags:        req.Tags,
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
	}

	return &pb.PostResponse{
		Success: true,
		Post:    post,
	}, nil
}

// Реализуем метод GetPostById для тестового сервера
func (s *mockPostServer) GetPostById(ctx context.Context, req *pb.PostIdRequest) (*pb.PostResponse, error) {
	if req.PostId <= 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.PostId == 999 {
		return &pb.PostResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	// Успешное получение поста
	post := &pb.Post{
		Id:          req.PostId,
		CreatorId:   1,
		Title:       "Тестовый пост",
		Description: "Описание тестового поста",
		IsPrivate:   false,
		Tags:        []string{"тест"},
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
	}

	return &pb.PostResponse{
		Success: true,
		Post:    post,
	}, nil
}

// Реализуем метод UpdatePost для тестового сервера
func (s *mockPostServer) UpdatePost(ctx context.Context, req *pb.UpdatePostRequest) (*pb.PostResponse, error) {
	if req.PostId <= 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.CreatorId <= 0 {
		return &pb.PostResponse{
			Success: false,
			Error:   "ID создателя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID создателя не может быть пустым")
	}

	// Формируем значения для обновленного поста
	title := "Тестовый пост"
	description := "Описание тестового поста"
	isPrivate := false

	if req.Title != nil {
		title = *req.Title
	}
	if req.Description != nil {
		description = *req.Description
	}
	if req.IsPrivate != nil {
		isPrivate = *req.IsPrivate
	}

	// Успешное обновление поста
	post := &pb.Post{
		Id:          req.PostId,
		CreatorId:   req.CreatorId,
		Title:       title,
		Description: description,
		IsPrivate:   isPrivate,
		Tags:        req.Tags,
		CreatedAt:   timestamppb.Now(),
		UpdatedAt:   timestamppb.Now(),
	}

	return &pb.PostResponse{
		Success: true,
		Post:    post,
	}, nil
}

// Реализуем метод DeletePost для тестового сервера
func (s *mockPostServer) DeletePost(ctx context.Context, req *pb.PostIdRequest) (*pb.DeletePostResponse, error) {
	if req.PostId <= 0 {
		return &pb.DeletePostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.PostId == 999 {
		return &pb.DeletePostResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	if req.PostId == 998 {
		return &pb.DeletePostResponse{
			Success: false,
			Error:   "доступ запрещен",
		}, status.Error(codes.PermissionDenied, "доступ запрещен")
	}

	// Успешное удаление поста
	return &pb.DeletePostResponse{
		Success: true,
	}, nil
}

// Реализуем метод ListPosts для тестового сервера
func (s *mockPostServer) ListPosts(ctx context.Context, req *pb.ListPostsRequest) (*pb.ListPostsResponse, error) {
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	if req.UserId <= 0 {
		return &pb.ListPostsResponse{
			Success: false,
			Error:   "ID пользователя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID пользователя не может быть пустым")
	}

	// Создаем тестовые посты
	posts := []*pb.Post{
		{
			Id:          1,
			CreatorId:   1,
			Title:       "Пост 1",
			Description: "Описание поста 1",
			IsPrivate:   false,
			Tags:        []string{"тег1"},
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
		{
			Id:          2,
			CreatorId:   2,
			Title:       "Пост 2",
			Description: "Описание поста 2",
			IsPrivate:   false,
			Tags:        []string{"тег2"},
			CreatedAt:   timestamppb.Now(),
			UpdatedAt:   timestamppb.Now(),
		},
	}

	// Фильтрация по создателю, если указан
	if req.CreatorId != nil && *req.CreatorId > 0 {
		filteredPosts := []*pb.Post{}
		for _, post := range posts {
			if post.CreatorId == *req.CreatorId {
				filteredPosts = append(filteredPosts, post)
			}
		}
		posts = filteredPosts
	}

	// Фильтрация по тегам, если указаны
	if len(req.Tags) > 0 {
		tagFilteredPosts := []*pb.Post{}
		for _, post := range posts {
			for _, postTag := range post.Tags {
				for _, reqTag := range req.Tags {
					if postTag == reqTag {
						tagFilteredPosts = append(tagFilteredPosts, post)
						break
					}
				}
			}
		}
		posts = tagFilteredPosts
	}

	// Успешное получение списка постов
	return &pb.ListPostsResponse{
		Success:    true,
		Posts:      posts,
		TotalCount: int32(len(posts)),
	}, nil
}

// Реализуем метод ViewPost для тестового сервера
func (s *mockPostServer) ViewPost(ctx context.Context, req *pb.ViewPostRequest) (*pb.ViewPostResponse, error) {
	if req.PostId <= 0 {
		return &pb.ViewPostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.PostId == 999 {
		return &pb.ViewPostResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	// Успешная регистрация просмотра
	return &pb.ViewPostResponse{
		Success: true,
	}, nil
}

// Реализуем метод LikePost для тестового сервера
func (s *mockPostServer) LikePost(ctx context.Context, req *pb.LikePostRequest) (*pb.LikePostResponse, error) {
	if req.PostId <= 0 {
		return &pb.LikePostResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.UserId <= 0 {
		return &pb.LikePostResponse{
			Success: false,
			Error:   "ID пользователя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID пользователя не может быть пустым")
	}

	if req.PostId == 999 {
		return &pb.LikePostResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	// Успешная установка лайка
	return &pb.LikePostResponse{
		Success: true,
	}, nil
}

// Реализуем метод AddComment для тестового сервера
func (s *mockPostServer) AddComment(ctx context.Context, req *pb.AddCommentRequest) (*pb.AddCommentResponse, error) {
	if req.PostId <= 0 {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.UserId <= 0 {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "ID пользователя не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID пользователя не может быть пустым")
	}

	if req.Text == "" {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "текст комментария не может быть пустым",
		}, status.Error(codes.InvalidArgument, "текст комментария не может быть пустым")
	}

	if req.PostId == 999 {
		return &pb.AddCommentResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	// Успешное создание комментария
	comment := &pb.Comment{
		Id:        1,
		PostId:    req.PostId,
		UserId:    req.UserId,
		Text:      req.Text,
		Username:  "test_user",
		CreatedAt: timestamppb.Now(),
	}

	return &pb.AddCommentResponse{
		Success: true,
		Comment: comment,
	}, nil
}

// Реализуем метод GetComments для тестового сервера
func (s *mockPostServer) GetComments(ctx context.Context, req *pb.GetCommentsRequest) (*pb.GetCommentsResponse, error) {
	if req.PostId <= 0 {
		return &pb.GetCommentsResponse{
			Success: false,
			Error:   "ID поста не может быть пустым",
		}, status.Error(codes.InvalidArgument, "ID поста не может быть пустым")
	}

	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 10
	}

	if req.PostId == 999 {
		return &pb.GetCommentsResponse{
			Success: false,
			Error:   "пост не найден",
		}, status.Error(codes.NotFound, "пост не найден")
	}

	// Создаем тестовые комментарии
	comments := []*pb.Comment{
		{
			Id:        2,
			PostId:    req.PostId,
			UserId:    3,
			Text:      "Второй комментарий",
			Username:  "user3",
			CreatedAt: timestamppb.New(time.Now()), // Более новый комментарий
		},
		{
			Id:        1,
			PostId:    req.PostId,
			UserId:    2,
			Text:      "Первый комментарий",
			Username:  "user2",
			CreatedAt: timestamppb.New(time.Now().Add(-1 * time.Hour)), // Более старый комментарий
		},
	}

	// Успешное получение комментариев
	return &pb.GetCommentsResponse{
		Success:    true,
		Comments:   comments,
		TotalCount: int32(len(comments)),
	}, nil
}

// Вспомогательная функция для настройки подключения через буфер вместо сети
func setupPostGRPCConnection(t *testing.T) (*grpc.ClientConn, func()) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterPostServiceServer(server, &mockPostServer{})

	go func() {
		if err := server.Serve(listener); err != nil {
			t.Fatalf("Failed to start mock gRPC server: %v", err)
		}
	}()

	// Функция для диалекта через буфер
	dialer := func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}

	// Устанавливаем соединение
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}

	// Возвращаем соединение и функцию для закрытия
	return conn, func() {
		conn.Close()
		server.Stop()
	}
}

func TestCreatePost(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию CreatePost
	ctx := context.Background()
	req := CreatePostRequest{
		CreatorID:   1,
		Title:       "Тестовый пост",
		Description: "Описание тестового поста",
		IsPrivate:   false,
		Tags:        []string{"тест", "api-gateway"},
	}

	resp, err := CreatePost(ctx, req)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), resp.Post.Id)
	assert.Equal(t, req.Title, resp.Post.Title)
	assert.Equal(t, req.Description, resp.Post.Description)
	assert.Equal(t, req.IsPrivate, resp.Post.IsPrivate)
	assert.Equal(t, req.Tags, resp.Post.Tags)
}

func TestGetPostByID(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию GetPostByID
	ctx := context.Background()
	postID := int32(1)
	userID := int32(1)

	resp, err := GetPostByID(ctx, postID, userID)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, postID, resp.Post.Id)
	assert.Equal(t, "Тестовый пост", resp.Post.Title)

	// Тестируем получение несуществующего поста
	nonExistentPostID := int32(999)
	resp, err = GetPostByID(ctx, nonExistentPostID, userID)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")
}

func TestUpdatePost(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию UpdatePost
	ctx := context.Background()
	title := "Обновленный пост"
	description := "Обновленное описание"
	isPrivate := true

	req := UpdatePostRequest{
		PostID:      1,
		CreatorID:   1,
		Title:       &title,
		Description: &description,
		IsPrivate:   &isPrivate,
		Tags:        []string{"обновлено", "тест"},
	}

	resp, err := UpdatePost(ctx, req)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, req.PostID, resp.Post.Id)
	assert.Equal(t, title, resp.Post.Title)
	assert.Equal(t, description, resp.Post.Description)
	assert.Equal(t, isPrivate, resp.Post.IsPrivate)
	assert.Equal(t, req.Tags, resp.Post.Tags)

	// Тестируем частичное обновление
	partialTitle := "Частично обновленный пост"
	partialReq := UpdatePostRequest{
		PostID:    1,
		CreatorID: 1,
		Title:     &partialTitle,
		Tags:      []string{"частично"},
	}

	resp, err = UpdatePost(ctx, partialReq)

	// Проверяем результат частичного обновления
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, partialTitle, resp.Post.Title)
}

func TestDeletePost(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию DeletePost
	ctx := context.Background()
	postID := int32(1)
	userID := int32(1)

	resp, err := DeletePost(ctx, postID, userID)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Тестируем удаление несуществующего поста
	nonExistentPostID := int32(999)
	resp, err = DeletePost(ctx, nonExistentPostID, userID)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")

	// Тестируем удаление с запрещенным доступом
	forbiddenPostID := int32(998)
	resp, err = DeletePost(ctx, forbiddenPostID, userID)

	// Проверяем ошибку доступа
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok = status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "доступ запрещен")
}

func TestListPosts(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию ListPosts
	ctx := context.Background()
	creatorID := int32(1)

	req := ListPostsRequest{
		UserID:    1,
		Page:      1,
		PageSize:  10,
		CreatorID: &creatorID,
		Tags:      []string{},
	}

	resp, err := ListPosts(ctx, req)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Posts)

	// Проверяем правильность фильтрации по создателю
	for _, post := range resp.Posts {
		assert.Equal(t, creatorID, post.CreatorId)
	}

	// Тестируем фильтрацию по тегам
	tagReq := ListPostsRequest{
		UserID:   1,
		Page:     1,
		PageSize: 10,
		Tags:     []string{"тег1"},
	}

	tagResp, err := ListPosts(ctx, tagReq)

	// Проверяем фильтрацию по тегам
	assert.NoError(t, err)
	assert.NotNil(t, tagResp)
	assert.True(t, tagResp.Success)
}

func TestViewPost(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию ViewPost
	ctx := context.Background()
	postID := int32(1)
	userID := int32(1)

	resp, err := ViewPost(ctx, postID, userID)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Тестируем просмотр несуществующего поста
	nonExistentPostID := int32(999)
	resp, err = ViewPost(ctx, nonExistentPostID, userID)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")
}

func TestLikePost(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию LikePost
	ctx := context.Background()
	postID := int32(1)
	userID := int32(1)

	resp, err := LikePost(ctx, postID, userID)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)

	// Тестируем лайк несуществующего поста
	nonExistentPostID := int32(999)
	resp, err = LikePost(ctx, nonExistentPostID, userID)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")
}

func TestAddComment(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию AddComment
	ctx := context.Background()
	postID := int32(1)
	userID := int32(1)
	text := "Тестовый комментарий"

	resp, err := AddComment(ctx, postID, userID, text)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Equal(t, text, resp.Comment.Text)
	assert.Equal(t, userID, resp.Comment.UserId)
	assert.Equal(t, postID, resp.Comment.PostId)

	// Тестируем добавление комментария к несуществующему посту
	nonExistentPostID := int32(999)
	resp, err = AddComment(ctx, nonExistentPostID, userID, text)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")

	// Тестируем добавление пустого комментария
	resp, err = AddComment(ctx, postID, userID, "")

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok = status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "текст комментария не может быть пустым")
}

func TestGetComments(t *testing.T) {
	// Настраиваем соединение
	conn, cleanup := setupPostGRPCConnection(t)
	defer cleanup()

	// Создаем клиента
	client := pb.NewPostServiceClient(conn)
	postClient = client // Заменяем глобальную переменную

	// Вызываем функцию GetComments
	ctx := context.Background()
	postID := int32(1)
	page := int32(1)
	pageSize := int32(10)

	resp, err := GetComments(ctx, postID, page, pageSize)

	// Проверяем результат
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Comments)
	assert.Equal(t, int32(2), resp.TotalCount)

	// Проверяем порядок комментариев (от новых к старым)
	assert.Equal(t, int32(2), resp.Comments[0].Id)
	assert.Equal(t, "Второй комментарий", resp.Comments[0].Text)
	assert.Equal(t, int32(1), resp.Comments[1].Id)
	assert.Equal(t, "Первый комментарий", resp.Comments[1].Text)

	// Тестируем получение комментариев несуществующего поста
	nonExistentPostID := int32(999)
	resp, err = GetComments(ctx, nonExistentPostID, page, pageSize)

	// Проверяем ошибку
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "пост не найден")

	// Тестируем получение комментариев с нулевыми значениями пагинации
	resp, err = GetComments(ctx, postID, 0, 0)

	// Проверяем, что значения пагинации были заменены на значения по умолчанию
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.Comments)
}
