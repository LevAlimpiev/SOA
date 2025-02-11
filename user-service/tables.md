# User Service - Таблицы

## Users
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| username | string | Имя пользователя |
| email | string | Email пользователя |
| password_hash | string | Хеш пароля |
| first_name | string | Имя |
| last_name | string | Фамилия |
| avatar_url | string | URL аватара |
| created_at | timestamp | Время создания |
| updated_at | timestamp | Время обновления |
| is_active | boolean | Активен ли пользователь |

## Roles
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| name | string | Название роли |
| description | string | Описание роли |
| priority | int | Приоритет роли |
| created_at | timestamp | Время создания |
| is_system | boolean | Системная ли роль |

## UserRoles
| Колонка | Тип | Описание |
|---------|-----|----------|
| user_id | UUID | Внешний ключ на Users |
| role_id | UUID | Внешний ключ на Roles |
| assigned_at | timestamp | Время назначения |

## Sessions
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| user_id | UUID | Внешний ключ на Users |
| token | string | Токен сессии |
| expires_at | timestamp | Время истечения |
| ip_address | string | IP адрес |
| user_agent | string | User-Agent |