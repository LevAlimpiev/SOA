#!/bin/bash

echo "🧪 Запуск тестов для микросервисной архитектуры"
echo "=============================================="

# Проверка наличия необходимых пакетов
echo -e "\n📦 Проверяем зависимости..."
go mod download

# Установка библиотек для тестирования, если их нет
if ! go list -m github.com/stretchr/testify &> /dev/null; then
    echo "Установка github.com/stretchr/testify..."
    go get github.com/stretchr/testify
fi

if ! go list -m github.com/DATA-DOG/go-sqlmock &> /dev/null; then
    echo "Установка github.com/DATA-DOG/go-sqlmock..."
    go get github.com/DATA-DOG/go-sqlmock
fi

# Запуск тестов для user-service
echo -e "\n📋 Запуск тестов для user-service..."
cd user-service && go test -v ./... && cd ..

# Запуск тестов для api-gateway
echo -e "\n📋 Запуск тестов для api-gateway..."
cd api-gateway && go test -v ./... && cd ..

# Запуск интеграционных тестов
echo -e "\n📋 Запуск интеграционных тестов..."
go test -v ./...

echo -e "\n✅ Тестирование завершено!"