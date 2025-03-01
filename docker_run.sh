#!/bin/bash

echo "Building and starting services with Docker Compose..."

# Останавливаем и удаляем существующие контейнеры
docker-compose down

# Собираем и запускаем сервисы (без тестового профиля)
docker-compose up --build -d

echo "Сервисы запущены! Используйте 'docker-compose logs -f' для просмотра логов"
echo "Для остановки сервисов используйте 'docker-compose down'"