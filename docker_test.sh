#!/bin/bash

echo "Сборка Docker-образа для тестирования..."
docker build -t service-oriented-arch-tests -f Dockerfile.test .

echo "Запуск тестов в Docker-контейнере..."
docker run --rm service-oriented-arch-tests