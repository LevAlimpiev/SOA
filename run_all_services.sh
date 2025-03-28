#!/bin/bash

# Скрипт для запуска всех сервисов через docker-compose

# Делаем скрипты исполняемыми
chmod +x *.sh

# Устанавливаем переменные окружения для JWT
export TOKEN_TYPE=jwt
export JWT_SECRET=your-super-secret-key-for-jwt-tokens

# Запускаем сервисы через docker-compose
docker-compose up -d

# Выводим информацию о запущенных сервисах
echo "Сервисы запущены!"
echo "API Gateway: http://localhost:8080"
echo "User Service (gRPC): localhost:50051"
echo "Post Service (gRPC): localhost:50052"
echo ""
echo "Для просмотра логов, выполните: ./docker_logs.sh"
echo "Для остановки сервисов, выполните: docker-compose down" 