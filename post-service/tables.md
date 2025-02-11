# Post Service - Таблицы

## Posts
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| author_id | UUID | ID автора |
| title | string | Заголовок поста |
| content | text | Содержание поста |
| tags | string[] | Теги поста |
| view_count | int | Количество просмотров |
| created_at | timestamp | Время создания |
| updated_at | timestamp | Время обновления |
| is_deleted | boolean | Удален ли пост |

## Comments
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| post_id | UUID | ID поста |
| author_id | UUID | ID автора |
| parent_comment_id | UUID | ID родительского комментария |
| content | text | Текст комментария |
| likes_count | int | Количество лайков |
| created_at | timestamp | Время создания |
| is_deleted | boolean | Удален ли комментарий |

## Likes
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| target_id | UUID | ID целевого объекта |
| target_type | string | Тип целевого объекта |
| user_id | UUID | ID пользователя |
| created_at | timestamp | Время создания |

## Attachments
| Колонка | Тип | Описание |
|---------|-----|----------|
| id | UUID | Первичный ключ |
| post_id | UUID | ID поста |
| file_url | string | URL файла |
| file_type | string | Тип файла |
| file_size | int | Размер файла |
| original_name | string | Оригинальное имя |
| uploaded_at | timestamp | Время загрузки |