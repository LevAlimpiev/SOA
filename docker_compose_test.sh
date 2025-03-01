#!/bin/bash

echo "Запуск тестов через docker-compose..."
docker-compose --profile test run --rm test