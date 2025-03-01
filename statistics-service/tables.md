# Statistics Service - Таблицы

## PostStatistics
| Колонка | Тип | Описание |
|---------|-----|----------|
| post_id | UUID | ID поста |
| views_count | int | Количество просмотров |
| likes_count | int | Количество лайков |
| comments_count | int | Количество комментариев |
| shares_count | int | Количество репостов |
| last_viewed_at | timestamp | Последний просмотр |
| last_updated | timestamp | Последнее обновление |

## UserActivity
| Колонка | Тип | Описание |
|---------|-----|----------|
| user_id | UUID | ID пользователя |
| posts_count | int | Количество постов |
| comments_count | int | Количество комментариев |
| likes_given | int | Поставлено лайков |
| likes_received | int | Получено лайков |
| last_activity | timestamp | Последняя активность |
| activity_history | json | История активности |

## ViewEvents
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| target_id | UUID | ID просмотренного объекта |
| target_type | string | Тип объекта |
| user_id | UUID | ID пользователя |
| viewed_at | timestamp | Время просмотра |
| user_agent | string | User-Agent |
| ip_address | string | IP адрес |
| referrer | string | Источник перехода |

## DailyMetrics
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| date | date | Дата метрики |
| metric_type | string | Тип метрики |
| value | int | Значение |
| breakdown | json | Детализация |
| calculated_at | timestamp | Время расчета |