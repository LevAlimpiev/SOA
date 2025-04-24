package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"

	"github.com/levalimpiev/service_oriented_architectures/user-service/kafka"
	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
)

// User struct for user data
type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	Password    string    `json:"-"`
	FirstName   string    `json:"first_name,omitempty"`
	LastName    string    `json:"last_name,omitempty"`
	BirthDate   time.Time `json:"birth_date,omitempty"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// Глобальная переменная для доступа к Kafka Producer
var kafkaProducer *kafka.KafkaProducer

// App структура для хранения зависимостей приложения
type App struct {
	db            *sql.DB
	tokenService  token.TokenService
	kafkaProducer *kafka.KafkaProducer
}

// NewApp создает и инициализирует новое приложение
func NewApp() (*App, error) {
	app := &App{}

	// Инициализация базы данных
	db, err := app.initDB()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации базы данных: %v", err)
	}
	app.db = db

	// Инициализация сервиса токенов
	app.tokenService = app.initTokenService()

	// Инициализация Kafka Producer
	app.kafkaProducer, err = kafka.NewKafkaProducer()
	if err != nil {
		log.Printf("Ошибка инициализации Kafka Producer: %v", err)
		log.Println("Сервис продолжит работу без отправки событий в Kafka")
	} else {
		log.Println("Kafka Producer успешно инициализирован")
	}

	// Сохраняем глобальные ссылки
	kafkaProducer = app.kafkaProducer

	return app, nil
}

// initDB инициализирует соединение с базой данных
func (a *App) initDB() (*sql.DB, error) {
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "userdb")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	log.Println("Database connection established successfully")
	return db, nil
}

// initTokenService инициализирует сервис токенов на основе переменной окружения
func (a *App) initTokenService() token.TokenService {
	// Получение типа токена из переменных окружения (по умолчанию "simple")
	tokenType := getEnv("TOKEN_TYPE", "simple")

	// Время жизни токена (по умолчанию 24 часа)
	expirationHoursStr := getEnv("TOKEN_EXPIRATION_HOURS", "24")
	expirationHours, err := strconv.Atoi(expirationHoursStr)
	if err != nil {
		log.Printf("Неверный формат TOKEN_EXPIRATION_HOURS: %v, используется значение по умолчанию 24", err)
		expirationHours = 24
	}

	// Создание сервиса токенов в зависимости от типа
	if tokenType == "jwt" {
		jwtSecret := getEnv("JWT_SECRET", "default-secret-key")
		log.Printf("Инициализация JWT Token Service с временем жизни %d часов", expirationHours)
		return token.NewJWTTokenService(jwtSecret, expirationHours)
	}

	log.Printf("Инициализация Simple Token Service с временем жизни %d часов", expirationHours)
	return token.NewSimpleTokenService(expirationHours)
}

// Run запускает gRPC сервер
func (a *App) Run() {
	// Запуск gRPC сервера
	grpcPort := getEnv("GRPC_PORT", "50051")
	startGRPCServer(grpcPort, a.db, a.tokenService)
}

// getEnv возвращает значение переменной окружения или значение по умолчанию
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// main функция инициализирует и запускает приложение
func main() {
	// Создание приложения
	app, err := NewApp()
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	// Важно: закрыть Kafka Producer перед завершением
	if app.kafkaProducer != nil {
		defer app.kafkaProducer.Close()
	}

	// Запуск приложения
	app.Run()
}

// GetKafkaProducer возвращает инициализированный экземпляр Kafka Producer
func GetKafkaProducer() *kafka.KafkaProducer {
	return kafkaProducer
}
