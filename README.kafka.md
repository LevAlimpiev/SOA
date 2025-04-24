# Реализация отправки событий в Kafka

В рамках данного задания реализована отправка событий в Apache Kafka для следующих действий:

1. **Регистрация клиента** - отправка события в топик `user_registration`
2. **Лайк поста** - отправка события в топик `post_like`
3. **Просмотр поста** - отправка события в топик `post_view`
4. **Комментарий к посту** - отправка события в топик `post_comment`

## Структура событий

### Событие регистрации пользователя
```json
{
  "user_id": 123,
  "username": "test_user",
  "email": "test@example.com",
  "created_at": "2023-06-12T15:30:45Z"
}
```

### Событие просмотра поста
```json
{
  "post_id": 42,
  "user_id": 123,
  "viewed_at": "2023-06-12T16:30:45Z",
  "entity_type": "post"
}
```

### Событие лайка поста
```json
{
  "post_id": 42,
  "user_id": 123,
  "liked_at": "2023-06-12T16:35:45Z",
  "entity_type": "post"
}
```

### Событие комментария к посту
```json
{
  "post_id": 42,
  "user_id": 123,
  "comment_id": 789,
  "commented_at": "2023-06-12T16:40:45Z",
  "entity_type": "post"
}
```

## Инструкция по проверке

1. Запустите сервисы с помощью Docker Compose:
   ```bash
   ./docker_run_jwt.sh
   ```

2. Откройте Kafka UI для просмотра топиков и сообщений:
   ```
   http://localhost:8090
   ```

3. Создайте нового пользователя (событие регистрации):
   ```bash
   curl -X POST http://localhost:8080/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username":"test_user","email":"test@example.com","password":"password123"}'
   ```

4. Создайте новый пост:
   ```bash
   curl -X POST http://localhost:8080/posts \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <token>" \
     -d '{
       "title": "Тестовый пост для Kafka",
       "description": "Это тестовый пост для проверки отправки событий в Kafka",
       "is_private": false,
       "tags": ["kafka", "тест"]
     }'
   ```

5. Просмотрите пост (событие просмотра):
   ```bash
   curl -X GET http://localhost:8080/posts/1 \
     -H "Authorization: Bearer <token>"
   ```

6. Поставьте лайк посту (событие лайка):
   ```bash
   curl -X POST http://localhost:8080/posts/1/like \
     -H "Authorization: Bearer <token>"
   ```

7. Добавьте комментарий (событие комментария):
   ```bash
   curl -X POST http://localhost:8080/posts/1/comments \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <token>" \
     -d '{"text": "Тестовый комментарий для проверки Kafka"}'
   ```

8. В Kafka UI вы должны увидеть соответствующие сообщения в топиках:
   - `user_registration` - событие регистрации пользователя
   - `post_view` - событие просмотра поста 
   - `post_like` - событие лайка поста
   - `post_comment` - событие комментария к посту

## Архитектура решения

1. В docker-compose добавлены сервисы:
   - Zookeeper
   - Kafka
   - Kafka UI (для удобной проверки)

2. Добавлены пакеты для работы с Kafka:
   - `user-service/kafka` - отправка событий регистрации
   - `post-service/internal/kafka` - отправка событий просмотра, лайка и комментирования

3. Интеграция событий:
   - При регистрации пользователя в `user-service/grpc_server.go`
   - При просмотре поста в `post-service/internal/server/post_server.go` (метод ViewPost)
   - При лайке поста в `post-service/internal/server/post_server.go` (метод LikePost)
   - При комментировании поста в `post-service/internal/server/post_server.go` (метод AddComment)

## Примечания

- При ошибке отправки события в Kafka работа основной функциональности не прерывается
- Все события содержат timestamp и идентификаторы для корректного отслеживания
- Kafka UI доступен по адресу http://localhost:8090 