package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/levalimpiev/service_oriented_architectures/user-service/token"
)

// User struct for user data
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// Auth response structure
type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// Error response
type ErrorResponse struct {
	Error string `json:"error"`
}

// App структура для хранения зависимостей приложения
type App struct {
	db           *sql.DB
	tokenService token.TokenService
	router       *mux.Router
}

// NewApp создает и инициализирует новое приложение
func NewApp() (*App, error) {
	app := &App{
		router: mux.NewRouter(),
	}

	// Инициализация базы данных
	db, err := app.initDB()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации базы данных: %v", err)
	}
	app.db = db

	// Инициализация сервиса токенов
	app.tokenService = app.initTokenService()

	// Настройка маршрутов
	app.setupRoutes()

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

// setupRoutes настраивает HTTP маршруты
func (a *App) setupRoutes() {
	// Публичные маршруты
	a.router.HandleFunc("/register", a.registerHandler).Methods("POST")
	a.router.HandleFunc("/login", a.loginHandler).Methods("POST")
}

// registerHandler обрабатывает регистрацию пользователя
func (a *App) registerHandler(w http.ResponseWriter, r *http.Request) {
	// Парсинг JSON из тела запроса
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	// Валидация входных данных
	if user.Username == "" || user.Email == "" || user.Password == "" {
		respondWithError(w, http.StatusBadRequest, "All fields are required")
		return
	}

	// Проверка, существует ли пользователь
	var exists bool
	err = a.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
		user.Username, user.Email).Scan(&exists)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to check user existence")
		return
	}

	if exists {
		respondWithError(w, http.StatusConflict, "User with this username or email already exists")
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to process password")
		return
	}

	// Создание пользователя
	var userID int
	var username, email string
	var createdAt time.Time

	err = a.db.QueryRow(
		"INSERT INTO users (username, email, password, created_at) VALUES ($1, $2, $3, $4) RETURNING id, username, email, created_at",
		user.Username, user.Email, string(hashedPassword), time.Now(),
	).Scan(&userID, &username, &email, &createdAt)

	if err != nil {
		log.Printf("Error saving user: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	// Генерация токена
	tokenString, err := a.tokenService.GenerateToken(userID, username, email)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Формирование и отправка ответа
	response := AuthResponse{
		Token: tokenString,
		User: User{
			ID:        userID,
			Username:  username,
			Email:     email,
			CreatedAt: createdAt,
		},
	}

	respondWithJSON(w, http.StatusCreated, response)
}

// loginHandler обрабатывает авторизацию пользователя
func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	// Парсинг JSON из тела запроса
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	// Валидация входных данных
	if credentials.Username == "" || credentials.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	// Поиск пользователя
	var user User
	err = a.db.QueryRow(
		"SELECT id, username, email, password, created_at FROM users WHERE username = $1",
		credentials.Username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.CreatedAt)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Проверка пароля
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Генерация токена
	tokenString, err := a.tokenService.GenerateToken(user.ID, user.Username, user.Email)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Формирование и отправка ответа
	response := AuthResponse{
		Token: tokenString,
		User: User{
			ID:        user.ID,
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		},
	}

	respondWithJSON(w, http.StatusOK, response)
}

// Run запускает HTTP и gRPC серверы
func (a *App) Run() {
	// Запуск gRPC сервера в отдельной горутине
	go startGRPCServer(getEnv("GRPC_PORT", "50051"), a.db, a.tokenService)

	// Запуск HTTP сервера
	httpPort := getEnv("HTTP_PORT", "8081")
	log.Printf("HTTP server started on port %s", httpPort)
	log.Fatal(http.ListenAndServe(":"+httpPort, a.router))
}

// respondWithError отправляет JSON-ответ с ошибкой
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, ErrorResponse{Error: message})
}

// respondWithJSON отправляет JSON-ответ
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
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

	// Запуск приложения
	app.Run()
}
