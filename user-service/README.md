# User Service

Сервис для управления пользователями, обеспечивающий регистрацию и аутентификацию.

## Зоны ответственности
- Регистрация и аутентификация пользователей
- Управление профилями пользователей
- Управление ролями и правами доступа
- Управление сессиями пользователей
- Валидация токенов доступа

## API Endpoints

- **POST /api/users/register** - Регистрация нового пользователя
- **POST /api/users/login** - Аутентификация пользователя по логину и паролю

## Структура запросов и ответов

### Регистрация (POST /api/users/register)

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

### Аутентификация (POST /api/users/login)

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

## Аутентификация и токены

Сервис использует интерфейс `TokenService` для аутентификации пользователей. Интерфейс включает два метода:
- `GenerateToken` - создание нового токена
- `VerifyToken` - проверка токена и получение информации о пользователе

Доступны две реализации:
1. **SimpleTokenService** (по умолчанию) - хранит токены в памяти
2. **JWTTokenService** - использует JSON Web Tokens для создания и проверки токенов

### Выбор реализации токенов

Реализация выбирается через переменную окружения `TOKEN_TYPE`:
- `TOKEN_TYPE=simple` - использование SimpleTokenService (по умолчанию)
- `TOKEN_TYPE=jwt` - использование JWTTokenService

При использовании JWT необходимо также задать секретный ключ с помощью переменной `JWT_SECRET`.

### Запуск с JWT токенами

```bash
# Через Docker Compose с переменными окружения
TOKEN_TYPE=jwt JWT_SECRET=your-secret-key docker-compose up -d

# Или с помощью специального скрипта
./docker_run_jwt.sh
```

### Защищенные эндпоинты

Для доступа к защищенным эндпоинтам необходимо передать токен в заголовке `Authorization`:

```
GET /protected/profile
Authorization: <token>
```

## База данных

Сервис использует PostgreSQL для хранения данных пользователей.

### Таблица users

| Колонка     | Тип         | Описание                     |
|-------------|-------------|------------------------------|
| id          | SERIAL      | Уникальный идентификатор     |
| username    | VARCHAR(50) | Имя пользователя (уникальное)|
| email       | VARCHAR(100)| Email пользователя (уникальный)  |
| password    | VARCHAR(255)| Хешированный пароль         |
| created_at  | TIMESTAMP   | Дата создания записи        |

## Запуск сервиса

### С помощью Docker
```bash
docker build -t user-service .
docker run -p 8081:8081 -e DB_HOST=postgres -e DB_PORT=5432 -e DB_USER=postgres -e DB_PASSWORD=postgres -e DB_NAME=user_service user-service
```

### Локальная разработка
```bash
go mod download
go run main.go
```

## Границы сервиса
- Не хранит данные постов и комментариев
- Не обрабатывает статистику активности
- Не управляет файлами пользователей
- Не реализует бизнес-логику других сервисов