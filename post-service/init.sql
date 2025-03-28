-- Создание таблицы posts
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    creator_id INTEGER NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_private BOOLEAN DEFAULT FALSE
);

-- Создание таблицы для хранения тегов постов
CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    tag VARCHAR(50) NOT NULL,
    PRIMARY KEY (post_id, tag)
);

-- Добавление индексов для ускорения запросов
CREATE INDEX IF NOT EXISTS posts_creator_id_idx ON posts(creator_id);
CREATE INDEX IF NOT EXISTS post_tags_tag_idx ON post_tags(tag);

-- Комментарий к базе данных
COMMENT ON TABLE posts IS 'Таблица для хранения постов пользователей';
COMMENT ON TABLE post_tags IS 'Таблица для хранения тегов постов'; 