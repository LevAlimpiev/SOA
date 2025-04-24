# Примеры работы с API постов

В этом документе представлены примеры использования API для работы с постами в проекте.
Для всех запросов требуется JWT-токен аутентификации.

## Подготовка

### 1. Запуск сервисов

Убедитесь, что все сервисы запущены:

```bash
./docker_run_jwt.sh
```

### 2. Получение токена аутентификации

Для работы с API постов необходимо сначала зарегистрироваться или авторизоваться
и получить JWT-токен.

Регистрация нового пользователя:
```bash
curl -X POST http://localhost:8080/api/register -H "Content-Type: application/json" -d '{"username":"test_user", "password":"testpassword", "email":"test@example.com"}'
```

Авторизация существующего пользователя:
```bash
curl -X POST http://localhost:8080/api/login -H "Content-Type: application/json" -d '{"username":"test_user", "password":"testpassword"}'
```

Сохраните полученный токен:
```bash
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Примеры API запросов

### 1. Создание нового поста

```bash
curl -X POST http://localhost:8080/api/posts -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title": "Мой первый пост", "description": "Это тестовый пост с подробным описанием", "is_private": false, "tags": ["тест", "первый_пост", "golang"]}'
```

Пример успешного ответа:
```json
{
  "success": true,
  "post": {
    "id": 1,
    "creator_id": 1,
    "title": "Мой первый пост",
    "description": "Это тестовый пост с подробным описанием",
    "created_at": "2023-06-12T15:30:45Z",
    "updated_at": "2023-06-12T15:30:45Z",
    "is_private": false,
    "tags": ["тест", "первый_пост", "golang"]
  }
}
```

### 2. Получение поста по ID

```bash
curl -X GET http://localhost:8080/api/posts/3 -H "Authorization: Bearer $TOKEN"
```

Пример успешного ответа:
```json
{
  "success": true,
  "post": {
    "id": 1,
    "creator_id": 1,
    "title": "Мой первый пост",
    "description": "Это тестовый пост с подробным описанием",
    "created_at": "2023-06-12T15:30:45Z",
    "updated_at": "2023-06-12T15:30:45Z",
    "is_private": false,
    "tags": ["тест", "первый_пост", "golang"]
  }
}
```

### 3. Обновление существующего поста

```bash
curl -X PUT http://localhost:8080/api/posts/4 -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title": "Обновленный заголовок", "description": "ABACAVA", "is_private": false, "tags": ["обновлено", "тест", "приватный_пост"]}'
```

Пример успешного ответа:
```json
{
  "success": true,
  "post": {
    "id": 1,
    "creator_id": 1,
    "title": "Обновленный заголовок",
    "description": "Это обновленное описание поста",
    "created_at": "2023-06-12T15:30:45Z",
    "updated_at": "2023-06-12T15:35:12Z",
    "is_private": true,
    "tags": ["обновлено", "тест", "приватный_пост"]
  }
}
```

### 4. Удаление поста

```bash
curl -X DELETE http://localhost:8080/api/posts/1 -H "Authorization: Bearer $TOKEN"
```

Пример успешного ответа:
```json
{
  "success": true
}
```

5.

curl -X GET "http://localhost:8080/api/posts?page=1&page_size=10" -H "Authorization: Bearer $TOKEN"

#### Фильтрация по тегам:

```bash
curl -X GET "http://localhost:8080/api/posts?tags=тест,golang&page=1&page_size=10" -H "Authorization: Bearer $TOKEN"
```

#### Фильтрация по создателю:

```bash
curl -X GET "http://localhost:8080/api/posts?creator_id=2&page=1&page_size=10" -H "Authorization: Bearer $TOKEN"
```

## Дополнительные примеры

### Частичное обновление поста

Можно обновлять только нужные поля поста, не указывая остальные:

```bash
curl -X PUT http://localhost:8080/api/posts/1 -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title": "Только обновили заголовок"}'
```

### Создание приватного поста

Приватные посты видны только их создателю:

```bash
curl -X POST http://localhost:8080/api/posts -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title": "Приватный пост", "description": "Этот пост будет виден только мне", "is_private": true, "tags": ["приватный", "личное"]}'
```

### Обработка ошибок

При попытке получить несуществующий пост:

```bash
curl -X GET http://localhost:8080/api/posts/999 -H "Authorization: Bearer $TOKEN"
```

Пример ответа с ошибкой:
```json
{
  "success": false,
  "error": "пост не найден"
}
```

При попытке доступа к приватному посту другого пользователя:

```bash
curl -X GET http://localhost:8080/api/posts/5 -H "Authorization: Bearer $TOKEN"
```

Пример ответа с ошибкой доступа:
```json
{
  "success": false,
  "error": "доступ запрещен"
}