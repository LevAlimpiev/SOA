package service

import "errors"

// Определения ошибок сервисного слоя
var (
	ErrNotFound  = errors.New("пост не найден")
	ErrForbidden = errors.New("доступ запрещен")
) 