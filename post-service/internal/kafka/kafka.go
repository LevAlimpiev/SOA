package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaProducer представляет обертку для отправки сообщений
type KafkaProducer struct {
	kafkaEnabled bool
	kafkaBrokers string
}

// NewKafkaProducer создает новый экземпляр KafkaProducer
func NewKafkaProducer() (*KafkaProducer, error) {
	// Проверяем, включен ли Kafka
	kafkaEnabled := os.Getenv("KAFKA_ENABLED")
	if kafkaEnabled != "true" {
		log.Println("Kafka отключена, события не будут отправляться")
		return &KafkaProducer{kafkaEnabled: false}, nil
	}

	// Адреса брокеров Kafka
	kafkaBrokers := os.Getenv("KAFKA_BROKERS")
	if kafkaBrokers == "" {
		kafkaBrokers = "kafka:9092" // По умолчанию
	}

	log.Printf("Инициализация Kafka Producer с брокером: %s", kafkaBrokers)

	return &KafkaProducer{
		kafkaEnabled: true,
		kafkaBrokers: kafkaBrokers,
	}, nil
}

// PostViewEvent представляет событие о просмотре поста
type PostViewEvent struct {
	PostID     int32     `json:"post_id"`
	UserID     int32     `json:"user_id"`
	ViewedAt   time.Time `json:"viewed_at"`
	EntityType string    `json:"entity_type"` // "post" или "promo"
}

// PostLikeEvent представляет событие о лайке поста
type PostLikeEvent struct {
	PostID     int32     `json:"post_id"`
	UserID     int32     `json:"user_id"`
	LikedAt    time.Time `json:"liked_at"`
	EntityType string    `json:"entity_type"` // "post" или "promo"
}

// PostCommentEvent представляет событие о комментарии к посту
type PostCommentEvent struct {
	PostID      int32     `json:"post_id"`
	UserID      int32     `json:"user_id"`
	CommentID   int32     `json:"comment_id"`
	CommentedAt time.Time `json:"commented_at"`
	EntityType  string    `json:"entity_type"` // "post" или "promo"
}

// SendPostView отправляет событие о просмотре поста
func (kp *KafkaProducer) SendPostView(postID, userID int32) error {
	if !kp.kafkaEnabled {
		// Симуляция отправки сообщения для тестирования
		log.Printf("Симуляция отправки события о просмотре поста: postID=%d, userID=%d", postID, userID)
		return nil
	}

	event := PostViewEvent{
		PostID:     postID,
		UserID:     userID,
		ViewedAt:   time.Now(),
		EntityType: "post",
	}

	err := kp.sendMessage("post_view", event)
	if err != nil {
		return err
	}

	log.Printf("Событие о просмотре поста ID=%d успешно отправлено в Kafka", postID)
	return nil
}

// SendPostLike отправляет событие о лайке поста
func (kp *KafkaProducer) SendPostLike(postID, userID int32) error {
	if !kp.kafkaEnabled {
		// Симуляция отправки сообщения для тестирования
		log.Printf("Симуляция отправки события о лайке поста: postID=%d, userID=%d", postID, userID)
		return nil
	}

	event := PostLikeEvent{
		PostID:     postID,
		UserID:     userID,
		LikedAt:    time.Now(),
		EntityType: "post",
	}

	err := kp.sendMessage("post_like", event)
	if err != nil {
		return err
	}

	log.Printf("Событие о лайке поста ID=%d успешно отправлено в Kafka", postID)
	return nil
}

// SendPostComment отправляет событие о комментарии к посту
func (kp *KafkaProducer) SendPostComment(postID, userID, commentID int32) error {
	if !kp.kafkaEnabled {
		// Симуляция отправки сообщения для тестирования
		log.Printf("Симуляция отправки события о комментарии к посту: postID=%d, userID=%d, commentID=%d", postID, userID, commentID)
		return nil
	}

	event := PostCommentEvent{
		PostID:      postID,
		UserID:      userID,
		CommentID:   commentID,
		CommentedAt: time.Now(),
		EntityType:  "post",
	}

	err := kp.sendMessage("post_comment", event)
	if err != nil {
		return err
	}

	log.Printf("Событие о комментарии к посту ID=%d успешно отправлено в Kafka", postID)
	return nil
}

// sendMessage отправляет сообщение в указанный топик
func (kp *KafkaProducer) sendMessage(topic string, value interface{}) error {
	// Сериализуем значение в JSON
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("ошибка сериализации сообщения: %w", err)
	}

	// Логирование для отладки
	log.Printf("Отправка события в топик %s: %s", topic, string(data))

	// Создаем writer для данного топика
	writer := &kafka.Writer{
		Addr:     kafka.TCP(kp.kafkaBrokers),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
	defer writer.Close()

	// Отправляем сообщение
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = writer.WriteMessages(ctx,
		kafka.Message{
			Value: data,
		},
	)

	if err != nil {
		return fmt.Errorf("ошибка отправки сообщения в Kafka: %w", err)
	}

	log.Printf("Сообщение успешно отправлено в топик %s", topic)
	return nil
}

// Close закрывает соединение
func (kp *KafkaProducer) Close() {
	log.Println("Закрытие Kafka Producer")
}
