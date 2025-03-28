package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/db"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/server"
	"github.com/levalimpiev/service_oriented_architectures/post-service/internal/service"
	pb "github.com/levalimpiev/service_oriented_architectures/proto/post"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Определяем порт из переменной окружения или используем значение по умолчанию
	port := os.Getenv("PORT")
	if port == "" {
		port = "50052"
	}

	// Устанавливаем соединение с базой данных
	database, err := initDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Создаем репозиторий для работы с данными постов
	postRepo := db.NewPostgresPostRepository(database)

	// Создаем сервис, использующий репозиторий
	postService := service.NewPostService(postRepo)

	// Инициализируем gRPC сервер
	grpcServer := grpc.NewServer()

	// Регистрируем имплементацию сервиса
	pb.RegisterPostServiceServer(grpcServer, server.NewPostServer(postService))

	// Включаем reflection для удобства отладки
	reflection.Register(grpcServer)

	// Слушаем указанный порт
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Post service is running on port %s", port)

	// Запускаем gRPC сервер в горутине
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Настраиваем graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down post service...")
	grpcServer.GracefulStop()
	log.Println("Post service stopped")
}

// initDB устанавливает соединение с базой данных PostgreSQL
func initDB() (*sql.DB, error) {
	// Получаем параметры соединения из переменных окружения
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "postgres")
	dbName := getEnv("DB_NAME", "post_service")

	// Формируем строку подключения к PostgreSQL
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// Открываем соединение
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("ошибка при открытии соединения с БД: %w", err)
	}

	// Устанавливаем параметры соединения
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Проверяем соединение
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ошибка при проверке соединения с БД: %w", err)
	}

	log.Println("Соединение с базой данных установлено успешно")
	return db, nil
}

// getEnv получает значение переменной окружения или возвращает значение по умолчанию
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
