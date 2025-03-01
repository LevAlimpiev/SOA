#!/bin/bash

echo "✨ Подготовка проекта к запуску ✨"
echo "=================================="

# Шаг 1: Проверка наличия необходимых инструментов
echo -e "\n📦 Проверяем необходимые инструменты..."

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker не найден! Пожалуйста, установите Docker: https://docs.docker.com/get-docker/"
    exit 1
fi
echo "✓ Docker найден: $(docker --version)"

# Проверка Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose не найден! Пожалуйста, установите Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
echo "✓ Docker Compose найден: $(docker-compose --version)"

# Проверка Go
if ! command -v go &> /dev/null; then
    echo "❌ Go не найден! Пожалуйста, установите Go: https://golang.org/doc/install"
    exit 1
fi
echo "✓ Go найден: $(go version)"

# Проверка Protoc (может отсутствовать, но предупредим пользователя)
if ! command -v protoc &> /dev/null; then
    echo "⚠️ Protoc не найден! Некоторые функции могут быть недоступны."
    echo "  Для установки Protoc выполните:"
    echo "  - MacOS: brew install protobuf"
    echo "  - Linux: apt-get install protobuf-compiler"
else
    echo "✓ Protoc найден: $(protoc --version)"
fi

# Шаг 2: Установка зависимостей и генерация кода
echo -e "\n📦 Устанавливаем зависимости и генерируем код..."
chmod +x proto/install_deps.sh proto/generate.sh
./proto/install_deps.sh

# Если protoc доступен, генерируем код из .proto файлов
if command -v protoc &> /dev/null; then
    ./proto/generate.sh
else
    echo "⚠️ Пропускаем генерацию кода из .proto файлов (protoc не установлен)"
fi

# Шаг 3: Делаем скрипты исполняемыми
echo -e "\n📦 Настраиваем скрипты запуска..."
chmod +x run_user_service.sh run_api_gateway.sh run_all.sh docker_run.sh

# Шаг 4: Предложение дальнейших действий
echo -e "\n✅ Настройка завершена!"
echo "Теперь вы можете:"
echo "1. Локальная разработка: ./run_all.sh"
echo "2. Запуск в Docker: ./docker_run.sh"
echo "3. Тестировать API: curl -X POST http://localhost:8080/api/register -d '{\"username\":\"test\",\"email\":\"test@example.com\",\"password\":\"password\"}'"