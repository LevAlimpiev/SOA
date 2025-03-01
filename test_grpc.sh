#!/bin/bash

# Проверка наличия grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo "grpcurl не найден! Устанавливаем..."

    if command -v brew &> /dev/null; then
        # macOS с Homebrew
        brew install grpcurl
    elif command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update && apt-get install -y grpcurl
    elif command -v go &> /dev/null; then
        # Установка через Go
        go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
    else
        echo "Не удалось установить grpcurl. Пожалуйста, установите его вручную:"
        echo "https://github.com/fullstorydev/grpcurl#installation"
        exit 1
    fi
fi

echo "===== Проверка gRPC сервисов ====="

# Получаем адрес gRPC сервиса
GRPC_ADDR=${1:-"localhost:50051"}

echo "Подключение к gRPC серверу: $GRPC_ADDR"
echo ""

# Получаем список доступных сервисов
echo "Доступные сервисы:"
grpcurl -plaintext $GRPC_ADDR list

echo ""
echo "Методы сервиса user.UserService:"
grpcurl -plaintext $GRPC_ADDR list user.UserService

echo ""
echo "Тестируем метод Register (создание нового пользователя):"
grpcurl -d '{
  "username": "test_user",
  "email": "test@example.com",
  "password": "password123"
}' -plaintext $GRPC_ADDR user.UserService/Register

echo ""
echo "Тестируем метод Login (авторизация):"
grpcurl -d '{
  "username": "test_user",
  "password": "password123"
}' -plaintext $GRPC_ADDR user.UserService/Login