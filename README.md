# Микросервисная архитектура на Golang с gRPC

## Обзор проекта

Проект демонстрирует взаимодействие микросервисов с использованием gRPC:

1. **api-gateway** - API-шлюз, предоставляющий REST API для клиентов
2. **user-service** - Сервис пользователей с аутентификацией на JWT токенах
3. **post-service** - Сервис для работы с постами, использующий PostgreSQL для хранения данных
4. **statistics-service** - Сервис для сбора и обработки статистики активности пользователей

```
Клиент --> API Gateway (REST, 8080) --> User Service (gRPC, 50051) --> PostgreSQL
                                     --> Post Service (gRPC, 50052) --> PostgreSQL
                                     --> Statistics Service ----------> PostgreSQL
```

## Быстрый старт

### Запуск с JWT-токенами (рекомендуется)

```bash
# Делаем скрипты исполняемыми
chmod +x *.sh

# Запускаем сервисы с JWT токенами
./docker_run_jwt.sh

# Для просмотра логов
./docker_logs.sh
```

## Демонстрация работы

### 1. Регистрация пользователя

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","email":"test@example.com","password":"password123"}'
```

Пример успешного ответа:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "test_user",
    "email": "test@example.com",
    "created_at": "2023-06-12T15:30:45Z"
  }
}
```

### 2. Авторизация пользователя

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"password123"}'
```

Пример успешного ответа (c JWT токеном):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "test_user",
    "email": "test@example.com",
    "created_at": "2023-06-12T15:30:45Z"
  }
}
```

### 3. Работа с профилем пользователя

Сохраните токен для использования в запросах:
```bash
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Получение профиля пользователя:
```bash
curl -X GET http://localhost:8080/profile \
  -H "Authorization: Bearer $TOKEN"
```

Обновление профиля пользователя:
```bash
curl -X PUT http://localhost:8080/profile \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"first_name": "Иван", "last_name": "Петров", "phone_number": "+7 900 123-45-67"}'
```

### 4. Работа с постами

Создание нового поста:
```bash
curl -X POST http://localhost:8080/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "Мой первый пост",
    "description": "Это тестовый пост в нашей системе",
    "is_private": false,
    "tags": ["тест", "первый_пост"]
  }'
```

Получение поста по ID:
```bash
curl -X GET http://localhost:8080/posts/1 \
  -H "Authorization: Bearer $TOKEN"
```

Обновление поста:
```bash
curl -X PUT http://localhost:8080/posts/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "title": "Обновленный заголовок",
    "description": "Обновленное описание",
    "is_private": true,
    "tags": ["обновлено", "тест"]
  }'
```

Удаление поста:
```bash
curl -X DELETE http://localhost:8080/posts/1 \
  -H "Authorization: Bearer $TOKEN"
```

Получение списка постов:
```bash
curl -X GET http://localhost:8080/posts?page=1&page_size=10 \
  -H "Authorization: Bearer $TOKEN"
```

Фильтрация постов по тегам:
```bash
curl -X GET "http://localhost:8080/posts?tags=тест,важное&page=1&page_size=10" \
  -H "Authorization: Bearer $TOKEN"
```

## Остановка сервисов

```bash
docker-compose down
```

## О JWT токенах

Сервис использует JWT токены для аутентификации, что обеспечивает:
- Безопасное хранение данных пользователя в токене
- Проверка токена без обращения к базе данных
- Стандартизированная технология аутентификации

JWT токен содержит:
- Информацию о пользователе (ID, имя, email)
- Время жизни токена
- Цифровую подпись для проверки целостности

## Технические детали

### API Endpoints

#### Аутентификация и профиль
- **POST /auth/register** - Регистрация нового пользователя
- **POST /auth/login** - Аутентификация пользователя
- **GET /profile** - Получение профиля пользователя
- **PUT /profile** - Обновление профиля пользователя

#### Посты
- **POST /posts** - Создание нового поста
- **GET /posts/{id}** - Получение поста по ID
- **PUT /posts/{id}** - Обновление поста
- **DELETE /posts/{id}** - Удаление поста
- **GET /posts** - Получение списка постов с пагинацией и фильтрацией

### Архитектура

- **API Gateway**: REST API на порту 8080
- **User Service**: gRPC API на порту 50051, PostgreSQL для хранения пользователей
- **Post Service**: gRPC API на порту 50052, PostgreSQL для хранения постов
- **Statistics Service**: Сервис сбора и анализа статистики:
  - Сбор данных о просмотрах, лайках, комментариях
  - Аналитика пользовательской активности
  - Генерация отчетов и метрик
  - Хранение исторических данных

### Запуск тестов

```bash
# Интеграционные тесты через docker-compose
./docker_compose_test.sh

# Юнит-тесты для post-service
cd post-service && go test -v

# Запуск всех тестов
./run_tests.sh
```

### Дополнительные сведения

Проект использует:
- **gRPC** для межсервисного взаимодействия
- **JWT** для аутентификации
- **PostgreSQL** для хранения данных
- **Docker Compose** для запуска и оркестрации сервисов
- **Swagger UI** для просмотра документации API (доступно по URL: http://localhost:8080/swagger/ при запущенном проекте)
