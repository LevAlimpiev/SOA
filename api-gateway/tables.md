# API Gateway - Таблицы

## ApiKeys
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| key_hash | string | Хеш API ключа |
| client_name | string | Название клиента |
| permissions | json | Права доступа |
| created_at | timestamp | Время создания |
| expires_at | timestamp | Время истечения |
| is_active | boolean | Активен ли ключ |

## RequestLogs
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| api_key_id | UUID | Внешний ключ на ApiKeys |
| endpoint | string | URL эндпоинта |
| method | string | HTTP метод |
| status_code | int | HTTP статус |
| response_time | int | Время ответа (мс) |
| created_at | timestamp | Время запроса |
| ip_address | string | IP адрес |
| user_agent | string | User-Agent |

## RouteCache
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| path_pattern | string | Паттерн URL маршрута |
| service_name | string | Имя целевого сервиса |
| method | string | HTTP метод |
| is_active | boolean | Активен ли маршрут |
| timeout_ms | int | Таймаут запроса в мс |
| created_at | timestamp | Время создания |
| updated_at | timestamp | Время обновления |