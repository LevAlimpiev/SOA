# Микросервисная архитектура на Golang с gRPC

## Обзор проекта

Проект демонстрирует взаимодействие двух микросервисов с использованием gRPC:

1. **api-gateway** - API-шлюз, предоставляющий REST API для клиентов
2. **user-service** - Сервис пользователей с аутентификацией на JWT токенах

```
Клиент --> API Gateway (REST, 8080) --> User Service (gRPC, 50051) --> PostgreSQL
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
curl -X POST http://localhost:8080/api/register \
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
curl -X POST http://localhost:8080/api/login \
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

## Остановка сервиса

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

- **POST /api/register** - Регистрация нового пользователя
- **POST /api/login** - Аутентификация пользователя

### Архитектура

- **API Gateway**: REST API на порту 8080
- **User Service**: gRPC API на порту 50051, внутренний REST API на порту 8081
- **База данных**: PostgreSQL

### Запуск тестов

```bash
# Через docker-compose
./docker_compose_test.sh
```