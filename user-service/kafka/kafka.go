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
	writer       *kafka.Writer
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

// UserRegistrationEvent представляет событие регистрации пользователя
type UserRegistrationEvent struct {
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// SendUserRegistration отправляет событие о регистрации пользователя
func (kp *KafkaProducer) SendUserRegistration(userID int, username, email string, createdAt time.Time) error {
	if !kp.kafkaEnabled {
		// Симуляция отправки сообщения для тестирования
		log.Printf("Симуляция отправки события о регистрации пользователя: ID=%d, username=%s", userID, username)
		return nil
	}

	event := UserRegistrationEvent{
		UserID:    userID,
		Username:  username,
		Email:     email,
		CreatedAt: createdAt,
	}

	err := kp.sendMessage("user_registration", event)
	if err != nil {
		return err
	}

	log.Printf("Событие о регистрации пользователя ID=%d успешно отправлено в Kafka", userID)
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
