#!/bin/bash

# Скрипт для демонстрации всех тестов домашнего задания #6

echo "🧪 ДОМАШНЕЕ ЗАДАНИЕ #6 - ТЕСТИРОВАНИЕ МИКРОСЕРВИСНОЙ АРХИТЕКТУРЫ"
echo "=================================================================="
echo ""

# Переменные для подсчета тестов
TOTAL_TESTS=0
PASSED_TESTS=0

# Функция для запуска тестов
run_test() {
    local test_name="$1"
    local test_command="$2"
    local test_description="$3"
    
    echo "📋 $test_name: $test_description"
    echo "   Команда: $test_command"
    echo -n "   Результат: "
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo "✅ ПРОШЕЛ"
        ((PASSED_TESTS++))
    else
        echo "❌ НЕ ПРОШЕЛ"
        echo "   Подробности:"
        eval "$test_command" 2>&1 | sed 's/^/     /'
    fi
    ((TOTAL_TESTS++))
    echo ""
}

echo "1️⃣ ТЕСТЫ СЕРВИСНОГО СЛОЯ ДЛЯ gRPC МЕТОДОВ"
echo "==========================================="

# User Service gRPC тесты
echo "👤 User Service gRPC тесты:"
run_test "User Service - Register" \
    "cd user-service && go test -run TestRegisterRPC -v" \
    "Тест регистрации пользователя через gRPC"

run_test "User Service - Login" \
    "cd user-service && go test -run TestLoginRPC -v" \
    "Тест авторизации пользователя через gRPC"

run_test "User Service - GetProfile" \
    "cd user-service && go test -run TestGetProfileRPC -v" \
    "Тест получения профиля пользователя через gRPC"

# Post Service gRPC тесты
echo "📝 Post Service gRPC тесты:"
run_test "Post Service - CreateAndGet" \
    "cd post-service && go test -run TestCreateAndGetPost -v" \
    "Тест создания и получения поста через gRPC"

run_test "Post Service - Update" \
    "cd post-service && go test -run TestUpdatePost -v" \
    "Тест обновления поста через gRPC"

run_test "Post Service - Delete" \
    "cd post-service && go test -run TestDeletePost -v" \
    "Тест удаления поста через gRPC"

echo "2️⃣ ТЕСТЫ СЕРВИСНОГО СЛОЯ ДЛЯ REST МЕТОДОВ"
echo "=========================================="

echo "🌐 REST API тесты:"
run_test "REST - Register" \
    "go test -run TestIntegration_Register -v" \
    "Тест регистрации пользователя через REST API"

run_test "REST - Login" \
    "go test -run TestIntegration_Login -v" \
    "Тест авторизации пользователя через REST API"

run_test "REST - UpdateProfile" \
    "go test -run TestIntegration_UpdateProfile -v" \
    "Тест обновления профиля пользователя через REST API"

echo "3️⃣ ТЕСТЫ KAFKA ТОПИКОВ"
echo "======================"

echo "📨 Kafka тесты:"
run_test "Kafka - UserRegistration" \
    "go test -run TestKafkaUserRegistrationConsumer -v" \
    "Тест чтения событий регистрации пользователей из Kafka"

run_test "Kafka - PostEvents" \
    "go test -run TestKafkaPostEventsConsumer -v" \
    "Тест чтения событий активности с постами из Kafka"

echo "4️⃣ СКВОЗНЫЕ E2E ТЕСТЫ"
echo "===================="

echo "🔄 E2E тесты:"
run_test "E2E - Posts" \
    "go test -run TestIntegration_Posts -v" \
    "Сквозной тест работы с постами от создания до просмотра"

run_test "E2E - Likes" \
    "go test -run TestIntegration_Likes -v" \
    "Сквозной тест системы лайков"

run_test "E2E - Complete Flow" \
    "go test -run TestIntegration_Register.*TestIntegration_Posts -v" \
    "Полный пользовательский сценарий от регистрации до работы с постами"

echo "5️⃣ ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ"
echo "======================="

echo "🧪 Дополнительные тесты:"
run_test "API Gateway - gRPC Client" \
    "cd api-gateway && go test -run TestGRPCClient -v" \
    "Тесты gRPC клиента API Gateway"

run_test "Post Service - Unit Tests" \
    "cd post-service && go test -run TestPostServer.*Unit -v" \
    "Юнит-тесты сервера постов"

echo ""
echo "📊 ИТОГОВЫЙ ОТЧЕТ"
echo "================="
echo "Всего тестов: $TOTAL_TESTS"
echo "Прошло тестов: $PASSED_TESTS"
echo "Не прошло тестов: $((TOTAL_TESTS - PASSED_TESTS))"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo "🎉 ВСЕ ТЕСТЫ ПРОШЛИ УСПЕШНО!"
    exit 0
else
    echo "⚠️  НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОШЛИ"
    echo ""
    echo "📋 КРИТЕРИИ ДОМАШНЕГО ЗАДАНИЯ:"
    echo "- [✅] 3 теста на сервисном слое для gRPC методов сервиса пользователей"
    echo "- [✅] 3 теста на сервисном слое для gRPC методов сервиса постов"
    echo "- [❌] 3 теста на сервисном слое для gRPC методов сервиса статистики (ТРЕБУЕТСЯ РЕАЛИЗАЦИЯ)"
    echo "- [✅] 3 теста на сервисном слое для REST методов"
    echo "- [✅] 2 теста на Kafka топик для проверки чтения и сохранения в БД"
    echo "- [✅] 3 сквозных e2e теста на всю систему"
    echo ""
    echo "🔧 ДЛЯ ЗАВЕРШЕНИЯ ЗАДАНИЯ НЕОБХОДИМО:"
    echo "1. Реализовать Statistics Service (см. README_homework_6.md)"
    echo "2. Добавить 3 gRPC теста для Statistics Service"
    echo "3. Обновить docker-compose.yml для включения Statistics Service"
    exit 1
fi 