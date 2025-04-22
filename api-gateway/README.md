# API Gateway

http://localhost:8090


docker stop $(docker ps -q --filter ancestor=swaggerapi/swagger-ui)


docker run -p 8090:8080 -e SWAGGER_URL=/openapi.yml -v $(pwd)/openapi.yml:/usr/share/nginx/html/openapi.yml swaggerapi/swagger-ui

API-шлюз предоставляет единую точку входа для клиентских приложений и перенаправляет запросы на соответствующие микросервисы.

## Зоны ответственности
- Предоставление единой точки входа для клиентских приложений
- Проксирование запросов на соответствующие микросервисы
- Возможность расширения для дополнительных сервисов в будущем

## API Endpoints

- **POST /api/register** - Регистрация нового пользователя (проксируется на user-service)
- **POST /api/login** - Аутентификация пользователя (проксируется на user-service)

## Структура запросов и ответов

### Регистрация (POST /api/register)

**Запрос:**
```json
{
  "username": "example_user",
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Ответ:**
```json
{
  "token": "user_token_1",
  "user": {
    "id": 1,
    "username": "example_user",
    "email": "user@example.com",
    "created_at": "2023-08-01T15:30:45Z"
  }
}
```

### Аутентификация (POST /api/login)

**Запрос:**
```json
{
  "username": "example_user",
  "password": "secure_password"
}
```

**Ответ:**
```json
{
  "token": "user_token_1",
  "user": {
    "id": 1,
    "username": "example_user",
    "email": "user@example.com",
    "created_at": "2023-08-01T15:30:45Z"
  }
}
```

## Запуск сервиса

### С помощью Docker
```bash
docker build -t api-gateway .
docker run -p 8080:8080 -e USER_SERVICE_URL=http://user-service:8081 api-gateway
```

### Локальная разработка
```bash
go mod download
go run main.go
```

## Границы сервиса
- Не хранит бизнес-данные
- Не реализует бизнес-логику
- Не выполняет сложную обработку данных
- Не управляет состоянием пользователей
- Не обрабатывает файлы напрямую
