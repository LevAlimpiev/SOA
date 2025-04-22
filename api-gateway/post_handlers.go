package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// RegisterPostHandlers регистрирует обработчики для постов в маршрутизаторе
func RegisterPostHandlers(router *mux.Router) {
	// Публичные маршруты
	router.HandleFunc("/api/posts", GetPostsHandler).Methods("GET")
	router.HandleFunc("/api/posts/{id:[0-9]+}", GetPostHandler).Methods("GET")

	// Защищенные маршруты (требуют авторизации)
	router.Handle("/api/posts", authMiddleware(http.HandlerFunc(CreatePostHandler))).Methods("POST")
	router.Handle("/api/posts/{id:[0-9]+}", authMiddleware(http.HandlerFunc(UpdatePostHandler))).Methods("PUT")
	router.Handle("/api/posts/{id:[0-9]+}", authMiddleware(http.HandlerFunc(DeletePostHandler))).Methods("DELETE")

	// Новые маршруты для просмотров, лайков и комментариев
	router.Handle("/api/posts/{id:[0-9]+}/view", authMiddleware(http.HandlerFunc(viewPostHandler))).Methods("POST")
	router.Handle("/api/posts/{id:[0-9]+}/like", authMiddleware(http.HandlerFunc(likePostHandler))).Methods("POST")
	router.Handle("/api/posts/{id:[0-9]+}/comments", authMiddleware(http.HandlerFunc(addCommentHandler))).Methods("POST")
	router.Handle("/api/posts/{id:[0-9]+}/comments", authMiddleware(http.HandlerFunc(getCommentsHandler))).Methods("GET")
}

// CreatePostHandler обрабатывает запрос на создание поста
func CreatePostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем информацию о пользователе из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Декодируем запрос
	var req CreatePostRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Неверный формат запроса: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Устанавливаем ID создателя из токена для безопасности
	req.CreatorID = userID

	// Проверяем, что обязательные поля заполнены
	if req.Title == "" {
		http.Error(w, "Название поста обязательно", http.StatusBadRequest)
		return
	}

	// Вызываем gRPC метод
	resp, err := CreatePost(r.Context(), req)
	if err != nil {
		http.Error(w, "Ошибка при создании поста: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразуем ответ в REST формат
	restResp := ConvertProtoPostResponseToRESTResponse(resp)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	if !restResp.Success {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	json.NewEncoder(w).Encode(restResp)
}

// GetPostHandler обрабатывает запрос на получение поста по ID
func GetPostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID поста из URL
	params := mux.Vars(r)
	postID, err := strconv.ParseInt(params["id"], 10, 32)
	if err != nil {
		http.Error(w, "Неверный ID поста", http.StatusBadRequest)
		return
	}

	// Получаем ID пользователя (0, если не аутентифицирован)
	userID, _ := getUserIDFromContext(r.Context())

	// Вызываем gRPC метод
	resp, err := GetPostByID(r.Context(), int32(postID), userID)
	if err != nil {
		http.Error(w, "Ошибка при получении поста: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразуем ответ в REST формат
	restResp := ConvertProtoPostResponseToRESTResponse(resp)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	if !restResp.Success {
		if restResp.Error == "пост не найден" {
			w.WriteHeader(http.StatusNotFound)
		} else if restResp.Error == "доступ запрещен" {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
	json.NewEncoder(w).Encode(restResp)
}

// UpdatePostHandler обрабатывает запрос на обновление поста
func UpdatePostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем информацию о пользователе из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Получаем ID поста из URL
	params := mux.Vars(r)
	postID, err := strconv.ParseInt(params["id"], 10, 32)
	if err != nil {
		http.Error(w, "Неверный ID поста", http.StatusBadRequest)
		return
	}

	// Декодируем запрос
	var req UpdatePostRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Неверный формат запроса: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Устанавливаем ID создателя и ID поста из параметров
	req.CreatorID = userID
	req.PostID = int32(postID)

	// Вызываем gRPC метод
	resp, err := UpdatePost(r.Context(), req)
	if err != nil {
		http.Error(w, "Ошибка при обновлении поста: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразуем ответ в REST формат
	restResp := ConvertProtoPostResponseToRESTResponse(resp)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	if !restResp.Success {
		if restResp.Error == "пост не найден" {
			w.WriteHeader(http.StatusNotFound)
		} else if restResp.Error == "доступ запрещен" {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}
	json.NewEncoder(w).Encode(restResp)
}

// DeletePostHandler обрабатывает запрос на удаление поста
func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем информацию о пользователе из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Получаем ID поста из URL
	params := mux.Vars(r)
	postID, err := strconv.ParseInt(params["id"], 10, 32)
	if err != nil {
		http.Error(w, "Неверный ID поста", http.StatusBadRequest)
		return
	}

	// Вызываем gRPC метод
	resp, err := DeletePost(r.Context(), int32(postID), userID)
	if err != nil {
		http.Error(w, "Ошибка при удалении поста: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразуем ответ в REST формат
	restResp := ConvertProtoDeleteResponseToRESTResponse(resp)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	if !restResp.Success {
		if restResp.Error == "пост не найден" {
			w.WriteHeader(http.StatusNotFound)
		} else if restResp.Error == "доступ запрещен" {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetPostsHandler обрабатывает запрос на получение списка постов
func GetPostsHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID пользователя (0, если не аутентифицирован)
	userID, authenticated := getUserIDFromContext(r.Context())
	if !authenticated {
		userID = 0 // Для неаутентифицированных пользователей будут видны только публичные посты
	}

	// Получаем параметры пагинации из query параметров
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize <= 0 {
		pageSize = 10
	}

	// Получаем фильтр по создателю, если указан
	var creatorID *int32
	if creatorIDStr := r.URL.Query().Get("creator_id"); creatorIDStr != "" {
		if id, err := strconv.ParseInt(creatorIDStr, 10, 32); err == nil {
			creatorIDInt32 := int32(id)
			creatorID = &creatorIDInt32
		}
	}

	// Получаем фильтр по тегам, если указаны
	var tags []string
	if tagsParam := r.URL.Query().Get("tags"); tagsParam != "" {
		tags = extractTags(tagsParam)
	}

	// Формируем запрос
	req := ListPostsRequest{
		UserID:    userID,
		Page:      int32(page),
		PageSize:  int32(pageSize),
		CreatorID: creatorID,
		Tags:      tags,
	}

	// Вызываем gRPC метод
	resp, err := ListPosts(r.Context(), req)
	if err != nil {
		http.Error(w, "Ошибка при получении списка постов: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Преобразуем ответ в REST формат
	restResp := ConvertProtoListResponseToRESTResponse(resp)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	if !restResp.Success {
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(restResp)
}

// extractTags разбирает строку тегов, разделенных запятыми, в массив
func extractTags(tagsParam string) []string {
	// Здесь можно добавить более сложную логику разбора тегов, если нужно
	// В простейшем случае просто разделяем по запятой
	return splitAndTrim(tagsParam, ",")
}

// Константы для контекста
type contextKey string

const userIDKey contextKey = "user_id"

// viewPostHandler обрабатывает запрос на просмотр поста
func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID поста из URL
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "некорректный ID поста", http.StatusBadRequest)
		return
	}

	// Получаем ID пользователя из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Вызываем gRPC метод
	resp, err := ViewPost(r.Context(), int32(postID), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Проверяем результат
	if !resp.Success {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ActionResponse{
			Success: false,
			Error:   resp.Error,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ActionResponse{
		Success: true,
	})
}

// likePostHandler обрабатывает запрос на лайк/анлайк поста
func likePostHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID поста из URL
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "некорректный ID поста", http.StatusBadRequest)
		return
	}

	// Получаем ID пользователя из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Вызываем gRPC метод
	resp, err := LikePost(r.Context(), int32(postID), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Проверяем результат
	if !resp.Success {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ActionResponse{
			Success: false,
			Error:   resp.Error,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ActionResponse{
		Success: true,
	})
}

// addCommentHandler обрабатывает запрос на добавление комментария к посту
func addCommentHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID поста из URL
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "некорректный ID поста", http.StatusBadRequest)
		return
	}

	// Получаем ID пользователя из контекста
	userID, ok := getUserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "требуется аутентификация", http.StatusUnauthorized)
		return
	}

	// Парсим JSON запрос
	var req AddCommentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Вызываем gRPC метод
	resp, err := AddComment(r.Context(), int32(postID), userID, req.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Проверяем результат
	if !resp.Success {
		http.Error(w, resp.Error, http.StatusBadRequest)
		return
	}

	// Преобразуем комментарий из proto в REST формат
	comment := CommentResponse{
		ID:        resp.Comment.Id,
		PostID:    resp.Comment.PostId,
		UserID:    resp.Comment.UserId,
		Username:  resp.Comment.Username,
		Text:      resp.Comment.Text,
		CreatedAt: resp.Comment.CreatedAt.AsTime(),
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(comment)
}

// getCommentsHandler обрабатывает запрос на получение комментариев к посту
func getCommentsHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID поста из URL
	vars := mux.Vars(r)
	postID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "некорректный ID поста", http.StatusBadRequest)
		return
	}

	// Получаем параметры пагинации из query-строки
	query := r.URL.Query()
	pageStr := query.Get("page")
	page := 1
	if pageStr != "" {
		pageVal, err := strconv.Atoi(pageStr)
		if err == nil && pageVal > 0 {
			page = pageVal
		}
	}

	pageSizeStr := query.Get("page_size")
	pageSize := 10
	if pageSizeStr != "" {
		pageSizeVal, err := strconv.Atoi(pageSizeStr)
		if err == nil && pageSizeVal > 0 {
			pageSize = pageSizeVal
		}
	}

	// Вызываем gRPC метод
	resp, err := GetComments(r.Context(), int32(postID), int32(page), int32(pageSize))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Проверяем результат
	if !resp.Success {
		http.Error(w, resp.Error, http.StatusBadRequest)
		return
	}

	// Преобразуем комментарии из proto в REST формат
	comments := make([]CommentResponse, 0, len(resp.Comments))
	for _, protoComment := range resp.Comments {
		comment := CommentResponse{
			ID:        protoComment.Id,
			PostID:    protoComment.PostId,
			UserID:    protoComment.UserId,
			Username:  protoComment.Username,
			Text:      protoComment.Text,
			CreatedAt: protoComment.CreatedAt.AsTime(),
		}
		comments = append(comments, comment)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(CommentListResponse{
		Comments:   comments,
		TotalCount: resp.TotalCount,
	})
}
