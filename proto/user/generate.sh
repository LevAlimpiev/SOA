#!/bin/bash

echo "Генерация Go кода из Proto файлов..."

# Проверяем наличие GOPATH и добавляем его в PATH
export GOPATH=$(go env GOPATH)
export PATH=$PATH:$GOPATH/bin

# Проверяем наличие protoc-gen-go
if ! command -v protoc-gen-go &> /dev/null; then
    echo "Установка protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
fi

# Запускаем протогенератор из текущей директории
# Выходные файлы будут помещены в текущую директорию (.)
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative user.proto

echo "Генерация кода завершена!"