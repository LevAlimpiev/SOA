#!/bin/bash

echo "Запуск сервисов с JWT-токенами..."

# Остановка всех контейнеров
docker-compose down

# Экспорт переменных окружения для JWT
export TOKEN_TYPE=jwt
export JWT_SECRET=my-super-secure-jwt-secret-key

# Запуск с новыми переменными окружения и принудительной пересборкой образов
docker-compose up --build -d

echo "Сервисы запущены с использованием JWT-токенов!"
echo "Для проверки логов используйте: ./docker_logs.sh"
echo "Для остановки сервисов: docker-compose down"