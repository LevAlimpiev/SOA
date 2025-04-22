package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PostgresPostRepository реализация хранилища постов в PostgreSQL
type PostgresPostRepository struct {
	db *sql.DB
}

// NewPostgresPostRepository создает новый репозиторий постов в PostgreSQL
func NewPostgresPostRepository(db *sql.DB) PostRepository {
	return &PostgresPostRepository{
		db: db,
	}
}

// Create создает новый пост
func (r *PostgresPostRepository) Create(creatorID int32, title, description string, isPrivate bool, tags []string) (*pb.Post, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("ошибка при начале транзакции: %w", err)
	}
	defer tx.Rollback()

	// Вставляем пост
	var postID int32
	var createdAt, updatedAt time.Time
	err = tx.QueryRow(
		`INSERT INTO posts (creator_id, title, description, is_private) 
         VALUES ($1, $2, $3, $4) 
         RETURNING id, created_at, updated_at`,
		creatorID, title, description, isPrivate,
	).Scan(&postID, &createdAt, &updatedAt)

	if err != nil {
		return nil, fmt.Errorf("ошибка при создании поста: %w", err)
	}

	// Если есть теги, вставляем их
	if len(tags) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO post_tags (post_id, tag) VALUES ($1, $2)`)
		if err != nil {
			return nil, fmt.Errorf("ошибка при подготовке запроса для тегов: %w", err)
		}
		defer stmt.Close()

		for _, tag := range tags {
			_, err = stmt.Exec(postID, tag)
			if err != nil {
				return nil, fmt.Errorf("ошибка при добавлении тега: %w", err)
			}
		}
	}

	// Подтверждаем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("ошибка при подтверждении транзакции: %w", err)
	}

	return &pb.Post{
		Id:          postID,
		CreatorId:   creatorID,
		Title:       title,
		Description: description,
		CreatedAt:   timestamppb.New(createdAt),
		UpdatedAt:   timestamppb.New(updatedAt),
		IsPrivate:   isPrivate,
		Tags:        tags,
	}, nil
}

// GetByID получает пост по ID
func (r *PostgresPostRepository) GetByID(postID, userID int32) (*pb.Post, error) {
	// Получаем пост
	var post pb.Post
	var createdAt, updatedAt time.Time
	err := r.db.QueryRow(
		`SELECT id, creator_id, title, description, created_at, updated_at, is_private
         FROM posts
         WHERE id = $1`,
		postID,
	).Scan(
		&post.Id,
		&post.CreatorId,
		&post.Title,
		&post.Description,
		&createdAt,
		&updatedAt,
		&post.IsPrivate,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пост не найден")
		}
		return nil, fmt.Errorf("ошибка при получении поста: %w", err)
	}

	// Проверяем права доступа: видеть приватный пост может только его создатель
	if post.IsPrivate && post.CreatorId != userID {
		return nil, errors.New("доступ запрещен")
	}

	post.CreatedAt = timestamppb.New(createdAt)
	post.UpdatedAt = timestamppb.New(updatedAt)

	// Получаем теги поста
	rows, err := r.db.Query("SELECT tag FROM post_tags WHERE post_id = $1", postID)
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении тегов: %w", err)
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fmt.Errorf("ошибка при сканировании тега: %w", err)
		}
		tags = append(tags, tag)
	}

	post.Tags = tags
	return &post, nil
}

// Update обновляет данные поста
func (r *PostgresPostRepository) Update(postID, creatorID int32, title, description *string, isPrivate *bool, tags []string) (*pb.Post, error) {
	// Проверяем существование поста и права доступа
	var existingCreatorID int32
	err := r.db.QueryRow(
		"SELECT creator_id FROM posts WHERE id = $1",
		postID,
	).Scan(&existingCreatorID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("пост не найден")
		}
		return nil, fmt.Errorf("ошибка при проверке поста: %w", err)
	}

	// Только создатель может обновлять пост
	if existingCreatorID != creatorID {
		return nil, errors.New("доступ запрещен")
	}

	// Начинаем транзакцию
	tx, err := r.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("ошибка при начале транзакции: %w", err)
	}
	defer tx.Rollback()

	// Подготавливаем SQL запрос для обновления
	setStatements := []string{"updated_at = NOW()"}
	args := []interface{}{}
	argIndex := 1

	if title != nil {
		setStatements = append(setStatements, fmt.Sprintf("title = $%d", argIndex))
		args = append(args, *title)
		argIndex++
	}

	if description != nil {
		setStatements = append(setStatements, fmt.Sprintf("description = $%d", argIndex))
		args = append(args, *description)
		argIndex++
	}

	if isPrivate != nil {
		setStatements = append(setStatements, fmt.Sprintf("is_private = $%d", argIndex))
		args = append(args, *isPrivate)
		argIndex++
	}

	// Добавляем ID поста как последний аргумент
	args = append(args, postID)

	// Выполняем обновление
	query := fmt.Sprintf(
		"UPDATE posts SET %s WHERE id = $%d RETURNING id, creator_id, title, description, created_at, updated_at, is_private",
		strings.Join(setStatements, ", "),
		argIndex,
	)

	// Выполняем запрос и получаем обновленные данные
	var post pb.Post
	var createdAt, updatedAt time.Time
	err = tx.QueryRow(query, args...).Scan(
		&post.Id,
		&post.CreatorId,
		&post.Title,
		&post.Description,
		&createdAt,
		&updatedAt,
		&post.IsPrivate,
	)

	if err != nil {
		return nil, fmt.Errorf("ошибка при обновлении поста: %w", err)
	}

	post.CreatedAt = timestamppb.New(createdAt)
	post.UpdatedAt = timestamppb.New(updatedAt)

	// Если указаны теги, обновляем их
	if tags != nil {
		// Сначала удаляем все существующие теги
		_, err = tx.Exec("DELETE FROM post_tags WHERE post_id = $1", postID)
		if err != nil {
			return nil, fmt.Errorf("ошибка при удалении старых тегов: %w", err)
		}

		// Затем добавляем новые теги
		if len(tags) > 0 {
			stmt, err := tx.Prepare("INSERT INTO post_tags (post_id, tag) VALUES ($1, $2)")
			if err != nil {
				return nil, fmt.Errorf("ошибка при подготовке запроса для тегов: %w", err)
			}
			defer stmt.Close()

			for _, tag := range tags {
				_, err = stmt.Exec(postID, tag)
				if err != nil {
					return nil, fmt.Errorf("ошибка при добавлении тега: %w", err)
				}
			}
		}

		// Получаем обновленные теги
		post.Tags = tags
	} else {
		// Если теги не указаны, получаем существующие
		rows, err := tx.Query("SELECT tag FROM post_tags WHERE post_id = $1", postID)
		if err != nil {
			return nil, fmt.Errorf("ошибка при получении тегов: %w", err)
		}
		defer rows.Close()

		var existingTags []string
		for rows.Next() {
			var tag string
			if err := rows.Scan(&tag); err != nil {
				return nil, fmt.Errorf("ошибка при сканировании тега: %w", err)
			}
			existingTags = append(existingTags, tag)
		}

		post.Tags = existingTags
	}

	// Подтверждаем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("ошибка при подтверждении транзакции: %w", err)
	}

	return &post, nil
}

// Delete удаляет пост
func (r *PostgresPostRepository) Delete(postID, userID int32) error {
	// Проверяем существование поста и права доступа
	var creatorID int32
	err := r.db.QueryRow(
		"SELECT creator_id FROM posts WHERE id = $1",
		postID,
	).Scan(&creatorID)

	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("пост не найден")
		}
		return fmt.Errorf("ошибка при проверке поста: %w", err)
	}

	// Только создатель может удалить пост
	if creatorID != userID {
		return errors.New("доступ запрещен")
	}

	// Удаление поста. Теги будут удалены автоматически благодаря ON DELETE CASCADE
	_, err = r.db.Exec("DELETE FROM posts WHERE id = $1", postID)
	if err != nil {
		return fmt.Errorf("ошибка при удалении поста: %w", err)
	}

	return nil
}

// List возвращает список постов с пагинацией и фильтрацией
func (r *PostgresPostRepository) List(userID int32, page, pageSize int32, creatorID *int32, tags []string) ([]*pb.Post, int32, error) {
	// Базовый запрос для подсчета общего количества постов
	countQuery := `
		SELECT COUNT(DISTINCT p.id) 
		FROM posts p
		LEFT JOIN post_tags pt ON p.id = pt.post_id
		WHERE (NOT p.is_private OR p.creator_id = $1)
	`

	// Базовый запрос для получения постов
	query := `
		SELECT DISTINCT p.id, p.creator_id, p.title, p.description, p.created_at, p.updated_at, p.is_private
		FROM posts p
		LEFT JOIN post_tags pt ON p.id = pt.post_id
		WHERE (NOT p.is_private OR p.creator_id = $1)
	`

	args := []interface{}{userID}
	argIndex := 2

	// Добавляем фильтр по создателю
	if creatorID != nil {
		countQuery += fmt.Sprintf(" AND p.creator_id = $%d", argIndex)
		query += fmt.Sprintf(" AND p.creator_id = $%d", argIndex)
		args = append(args, *creatorID)
		argIndex++
	}

	// Добавляем фильтр по тегам
	if len(tags) > 0 {
		placeholders := make([]string, len(tags))
		for i, tag := range tags {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, tag)
			argIndex++
		}
		countQuery += fmt.Sprintf(" AND pt.tag IN (%s)", strings.Join(placeholders, ", "))
		query += fmt.Sprintf(" AND pt.tag IN (%s)", strings.Join(placeholders, ", "))
	}

	// Добавляем сортировку и пагинацию
	query += " ORDER BY p.created_at DESC"
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, pageSize, (page-1)*pageSize)

	// Получаем общее количество постов
	var totalCount int32
	err := r.db.QueryRow(countQuery, args[:argIndex-2]...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при подсчете постов: %w", err)
	}

	// Если нет постов, возвращаем пустой массив
	if totalCount == 0 {
		return []*pb.Post{}, totalCount, nil
	}

	// Получаем посты
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при получении постов: %w", err)
	}
	defer rows.Close()

	// Мапа для хранения постов по ID
	postsMap := make(map[int32]*pb.Post)
	var postIDs []int32

	// Сканируем результаты запроса
	for rows.Next() {
		var post pb.Post
		var createdAt, updatedAt time.Time
		err := rows.Scan(
			&post.Id,
			&post.CreatorId,
			&post.Title,
			&post.Description,
			&createdAt,
			&updatedAt,
			&post.IsPrivate,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("ошибка при сканировании поста: %w", err)
		}

		post.CreatedAt = timestamppb.New(createdAt)
		post.UpdatedAt = timestamppb.New(updatedAt)
		post.Tags = []string{}

		if _, exists := postsMap[post.Id]; !exists {
			postsMap[post.Id] = &post
			postIDs = append(postIDs, post.Id)
		}
	}

	// Если получено 0 постов, возвращаем пустой массив
	if len(postIDs) == 0 {
		return []*pb.Post{}, totalCount, nil
	}

	// Получаем теги для этих постов
	placeholders := make([]string, len(postIDs))
	tagsArgs := make([]interface{}, len(postIDs))
	for i, id := range postIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		tagsArgs[i] = id
	}

	// Запрос для получения тегов
	tagsQuery := fmt.Sprintf(
		"SELECT post_id, tag FROM post_tags WHERE post_id IN (%s)",
		strings.Join(placeholders, ", "),
	)

	// Выполняем запрос
	tagsRows, err := r.db.Query(tagsQuery, tagsArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при получении тегов: %w", err)
	}
	defer tagsRows.Close()

	// Сканируем теги
	for tagsRows.Next() {
		var postID int32
		var tag string
		if err := tagsRows.Scan(&postID, &tag); err != nil {
			return nil, 0, fmt.Errorf("ошибка при сканировании тега: %w", err)
		}

		if post, exists := postsMap[postID]; exists {
			post.Tags = append(post.Tags, tag)
		}
	}

	// Создаем результирующий массив в том же порядке, что и postIDs
	result := make([]*pb.Post, len(postIDs))
	for i, id := range postIDs {
		result[i] = postsMap[id]
	}

	return result, totalCount, nil
}

// ViewPost регистрирует просмотр поста
func (r *PostgresPostRepository) ViewPost(postID, userID int32) error {
	// Проверяем существование поста
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)", postID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования поста: %w", err)
	}
	if !exists {
		return errors.New("пост не найден")
	}

	// Добавляем запись о просмотре
	_, err = r.db.Exec(
		`INSERT INTO post_views (post_id, user_id, viewed_at) 
         VALUES ($1, $2, NOW())`,
		postID, userID,
	)
	if err != nil {
		return fmt.Errorf("ошибка при регистрации просмотра: %w", err)
	}

	return nil
}

// LikePost добавляет или удаляет лайк поста
func (r *PostgresPostRepository) LikePost(postID, userID int32) error {
	// Проверяем существование поста
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)", postID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования поста: %w", err)
	}
	if !exists {
		return errors.New("пост не найден")
	}

	// Начинаем транзакцию
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("ошибка при начале транзакции: %w", err)
	}
	defer tx.Rollback()

	// Проверяем, ставил ли пользователь уже лайк этому посту
	var likeExists bool
	err = tx.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM post_likes WHERE post_id = $1 AND user_id = $2)",
		postID, userID,
	).Scan(&likeExists)
	if err != nil {
		return fmt.Errorf("ошибка при проверке существования лайка: %w", err)
	}

	if likeExists {
		// Если лайк уже существует, удаляем его (toggle)
		_, err = tx.Exec(
			"DELETE FROM post_likes WHERE post_id = $1 AND user_id = $2",
			postID, userID,
		)
		if err != nil {
			return fmt.Errorf("ошибка при удалении лайка: %w", err)
		}
	} else {
		// Если лайка нет, добавляем его
		_, err = tx.Exec(
			`INSERT INTO post_likes (post_id, user_id, created_at) 
             VALUES ($1, $2, NOW())`,
			postID, userID,
		)
		if err != nil {
			return fmt.Errorf("ошибка при добавлении лайка: %w", err)
		}
	}

	// Фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("ошибка при фиксации транзакции: %w", err)
	}

	return nil
}

// AddComment добавляет комментарий к посту
func (r *PostgresPostRepository) AddComment(postID, userID int32, text string) (*pb.Comment, error) {
	// Проверяем существование поста
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)", postID).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("ошибка при проверке существования поста: %w", err)
	}
	if !exists {
		return nil, errors.New("пост не найден")
	}

	// Получаем имя пользователя
	var username string
	err = r.db.QueryRow(
		`SELECT username FROM users WHERE id = $1`,
		userID,
	).Scan(&username)
	if err != nil {
		// Если не находим пользователя, используем ID в качестве имени
		username = fmt.Sprintf("user_%d", userID)
	}

	// Добавляем комментарий
	var commentID int32
	var createdAt time.Time
	err = r.db.QueryRow(
		`INSERT INTO post_comments (post_id, user_id, text, created_at) 
         VALUES ($1, $2, $3, NOW()) 
         RETURNING id, created_at`,
		postID, userID, text,
	).Scan(&commentID, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("ошибка при добавлении комментария: %w", err)
	}

	return &pb.Comment{
		Id:        commentID,
		PostId:    postID,
		UserId:    userID,
		Text:      text,
		CreatedAt: timestamppb.New(createdAt),
		Username:  username,
	}, nil
}

// GetComments возвращает комментарии к посту с пагинацией
func (r *PostgresPostRepository) GetComments(postID int32, page, pageSize int32) ([]*pb.Comment, int32, error) {
	// Проверяем существование поста
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)", postID).Scan(&exists)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при проверке существования поста: %w", err)
	}
	if !exists {
		return nil, 0, errors.New("пост не найден")
	}

	// Получаем общее количество комментариев
	var totalCount int32
	err = r.db.QueryRow(
		"SELECT COUNT(*) FROM post_comments WHERE post_id = $1",
		postID,
	).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при получении количества комментариев: %w", err)
	}

	// Проверяем и корректируем параметры пагинации
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	// Вычисляем смещение
	offset := (page - 1) * pageSize

	// Запрашиваем комментарии
	rows, err := r.db.Query(
		`SELECT c.id, c.post_id, c.user_id, c.text, c.created_at, 
                COALESCE(u.username, 'user_' || c.user_id) as username
         FROM post_comments c
         LEFT JOIN users u ON c.user_id = u.id
         WHERE c.post_id = $1
         ORDER BY c.created_at DESC
         LIMIT $2 OFFSET $3`,
		postID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("ошибка при получении комментариев: %w", err)
	}
	defer rows.Close()

	// Обрабатываем результаты
	var comments []*pb.Comment
	for rows.Next() {
		var comment pb.Comment
		var createdAt time.Time
		err := rows.Scan(
			&comment.Id,
			&comment.PostId,
			&comment.UserId,
			&comment.Text,
			&createdAt,
			&comment.Username,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("ошибка при обработке комментария: %w", err)
		}
		comment.CreatedAt = timestamppb.New(createdAt)
		comments = append(comments, &comment)
	}

	return comments, totalCount, nil
}
