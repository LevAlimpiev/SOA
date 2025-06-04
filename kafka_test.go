package main

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UserRegistrationEvent представляет событие регистрации пользователя из Kafka
type UserRegistrationEvent struct {
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// PostViewEvent представляет событие просмотра поста из Kafka
type PostViewEvent struct {
	PostID     int32     `json:"post_id"`
	UserID     int32     `json:"user_id"`
	ViewedAt   time.Time `json:"viewed_at"`
	EntityType string    `json:"entity_type"`
}

// PostLikeEvent представляет событие лайка поста из Kafka
type PostLikeEvent struct {
	PostID     int32     `json:"post_id"`
	UserID     int32     `json:"user_id"`
	LikedAt    time.Time `json:"liked_at"`
	EntityType string    `json:"entity_type"`
}

// TestKafkaUserRegistrationConsumer тестирует чтение событий регистрации пользователей из Kafka
// и сохранение статистики в БД
func TestKafkaUserRegistrationConsumer(t *testing.T) {
	// Создаем мок базы данных
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Создаем тестовое событие с фиксированным временем
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	event := UserRegistrationEvent{
		UserID:    123,
		Username:  "testuser",
		Email:     "test@example.com",
		CreatedAt: fixedTime,
	}

	// Сериализуем событие в JSON
	eventData, err := json.Marshal(event)
	require.NoError(t, err)

	// Настраиваем ожидания для БД - используем Exec вместо Query
	mock.ExpectExec("INSERT INTO user_activity").
		WithArgs(event.UserID, 1, 0, 0, 0, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Настраиваем ожидания для БД - обновление дневных метрик
	mock.ExpectExec("INSERT INTO daily_metrics").
		WithArgs(sqlmock.AnyArg(), "user_registrations", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Симулируем обработку сообщения из Kafka
	err = processUserRegistrationEvent(db, eventData)
	assert.NoError(t, err)

	// Проверяем, что все ожидаемые SQL-запросы были выполнены
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestKafkaPostEventsConsumer тестирует чтение событий активности с постами из Kafka
// и обновление счетчиков в БД
func TestKafkaPostEventsConsumer(t *testing.T) {
	t.Run("PostViewEvent", func(t *testing.T) {
		// Создаем мок базы данных для каждого подтеста
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer db.Close()

		// Создаем событие просмотра с фиксированным временем
		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		viewEvent := PostViewEvent{
			PostID:     1,
			UserID:     123,
			ViewedAt:   fixedTime,
			EntityType: "post",
		}

		// Сериализуем событие в JSON
		eventData, err := json.Marshal(viewEvent)
		require.NoError(t, err)

		// Настраиваем ожидания для БД - обновление статистики поста
		mock.ExpectExec("INSERT INTO post_statistics").
			WithArgs(viewEvent.PostID, 1, 0, 0, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Настраиваем ожидания для БД - запись события просмотра
		mock.ExpectExec("INSERT INTO view_events").
			WithArgs(viewEvent.PostID, "post", viewEvent.UserID, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Симулируем обработку сообщения из Kafka
		err = processPostViewEvent(db, eventData)
		assert.NoError(t, err)

		// Проверяем, что все ожидаемые SQL-запросы были выполнены
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("PostLikeEvent", func(t *testing.T) {
		// Создаем мок базы данных для каждого подтеста
		db, mock, err := sqlmock.New()
		require.NoError(t, err)
		defer db.Close()

		// Создаем событие лайка с фиксированным временем
		fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		likeEvent := PostLikeEvent{
			PostID:     1,
			UserID:     123,
			LikedAt:    fixedTime,
			EntityType: "post",
		}

		// Сериализуем событие в JSON
		eventData, err := json.Marshal(likeEvent)
		require.NoError(t, err)

		// Настраиваем ожидания для БД - обновление статистики поста
		mock.ExpectExec("UPDATE post_statistics SET likes_count = likes_count \\+ 1").
			WithArgs(likeEvent.PostID).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Настраиваем ожидания для БД - обновление активности пользователя
		mock.ExpectExec("UPDATE user_activity SET likes_given = likes_given \\+ 1").
			WithArgs(likeEvent.UserID).
			WillReturnResult(sqlmock.NewResult(1, 1))

		// Симулируем обработку сообщения из Kafka
		err = processPostLikeEvent(db, eventData)
		assert.NoError(t, err)

		// Проверяем, что все ожидаемые SQL-запросы были выполнены
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

// Вспомогательные функции для симуляции обработки событий

func processUserRegistrationEvent(db *sql.DB, eventData []byte) error {
	var event UserRegistrationEvent
	if err := json.Unmarshal(eventData, &event); err != nil {
		return err
	}

	// Обновляем статистику пользователя - используем Exec вместо Query
	_, err := db.Exec(
		"INSERT INTO user_activity (user_id, posts_count, comments_count, likes_given, likes_received, last_activity) VALUES ($1, $2, $3, $4, $5, $6)",
		event.UserID, 1, 0, 0, 0, event.CreatedAt,
	)
	if err != nil {
		return err
	}

	// Обновляем дневные метрики - используем Exec вместо Query
	_, err = db.Exec(
		"INSERT INTO daily_metrics (date, metric_type, value) VALUES ($1, $2, $3)",
		event.CreatedAt.Format("2006-01-02"), "user_registrations", 1,
	)
	return err
}

func processPostViewEvent(db *sql.DB, eventData []byte) error {
	var event PostViewEvent
	if err := json.Unmarshal(eventData, &event); err != nil {
		return err
	}

	// Обновляем статистику поста
	_, err := db.Exec(
		"INSERT INTO post_statistics (post_id, views_count, likes_count, comments_count, last_viewed_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (post_id) DO UPDATE SET views_count = post_statistics.views_count + 1, last_viewed_at = $5",
		event.PostID, 1, 0, 0, event.ViewedAt,
	)
	if err != nil {
		return err
	}

	// Записываем событие просмотра
	_, err = db.Exec(
		"INSERT INTO view_events (target_id, target_type, user_id, viewed_at) VALUES ($1, $2, $3, $4)",
		event.PostID, event.EntityType, event.UserID, event.ViewedAt,
	)
	return err
}

func processPostLikeEvent(db *sql.DB, eventData []byte) error {
	var event PostLikeEvent
	if err := json.Unmarshal(eventData, &event); err != nil {
		return err
	}

	// Обновляем счетчик лайков поста
	_, err := db.Exec(
		"UPDATE post_statistics SET likes_count = likes_count + 1 WHERE post_id = $1",
		event.PostID,
	)
	if err != nil {
		return err
	}

	// Обновляем активность пользователя
	_, err = db.Exec(
		"UPDATE user_activity SET likes_given = likes_given + 1 WHERE user_id = $1",
		event.UserID,
	)
	return err
}
