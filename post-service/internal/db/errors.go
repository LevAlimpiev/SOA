package db

import "errors"

// Определения ошибок репозитория
var (
	ErrNotFound                   = errors.New("пост не найден")
	ErrForbidden                  = errors.New("доступ запрещен")
	ErrDatabaseConnectionRequired = errors.New("требуется соединение с базой данных")
)
