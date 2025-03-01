#!/bin/bash

echo "Starting all services..."

# Запускаем сервисы в фоновом режиме
./run_user_service.sh &
USER_SERVICE_PID=$!

# Даем пользовательскому сервису немного времени для запуска
sleep 2

./run_api_gateway.sh &
API_GATEWAY_PID=$!

echo "Services started!"
echo "User Service PID: $USER_SERVICE_PID"
echo "API Gateway PID: $API_GATEWAY_PID"
echo "Press Ctrl+C to stop all services"

# Ожидаем сигнал прерывания
trap "kill $USER_SERVICE_PID $API_GATEWAY_PID; echo 'Services stopped'; exit 0" INT
wait