# TODO: Statistics Service

## Минимальные требования для завершения домашнего задания

### 1. Создать proto файл для Statistics Service

**Файл:** `proto/statistics/statistics.proto`

```proto
syntax = "proto3";
package statistics;
option go_package = "github.com/levalimpiev/service_oriented_architectures/proto/statistics";

service StatisticsService {
  rpc GetPostStatistics(PostStatsRequest) returns (PostStatsResponse);
  rpc GetUserActivity(UserActivityRequest) returns (UserActivityResponse);  
  rpc GetTopPosts(TopPostsRequest) returns (TopPostsResponse);
}

// Добавить соответствующие message типы
```

### 2. Создать основной файл сервиса

**Файл:** `statistics-service/main.go`
- Инициализация gRPC сервера на порту 50053
- Подключение к БД PostgreSQL
- Регистрация StatisticsService

### 3. Создать тесты

**Файл:** `statistics-service/statistics_service_test.go`

Необходимо создать 3 теста:
```go
func TestGetPostStatistics(t *testing.T) {
    // Тест получения статистики по посту
}

func TestGetUserActivity(t *testing.T) {
    // Тест получения активности пользователя
}

func TestGetTopPosts(t *testing.T) {
    // Тест получения топ постов
}
```

### 4. Минимальная реализация gRPC методов

Методы могут возвращать моки данных для прохождения тестов:

```go
func (s *StatsServer) GetPostStatistics(ctx context.Context, req *pb.PostStatsRequest) (*pb.PostStatsResponse, error) {
    return &pb.PostStatsResponse{
        Success: true,
        Stats: &pb.PostStats{
            PostId: req.PostId,
            ViewCount: 100,
            LikeCount: 10,
            CommentCount: 5,
        },
    }, nil
}
```

### 5. Обновить docker-compose.yml

Добавить сервис statistics-service:
```yaml
statistics-service:
  build:
    context: .
    dockerfile: statistics-service/Dockerfile
  container_name: statistics-service
  ports:
    - "50053:50053"
  environment:
    PORT: 50053
    DB_HOST: postgres
    # ... другие переменные
```

## Быстрый старт

1. **Создать минимальный proto файл**
2. **Создать main.go с заглушками**  
3. **Создать 3 теста с моками**
4. **Запустить тесты:** `cd statistics-service && go test -v`

Это минимум для прохождения требований домашнего задания. Полную реализацию можно доделать позже. 