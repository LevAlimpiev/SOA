#!/bin/bash

echo "Генерация Go кода из Proto файлов..."

# Проверяем наличие GOPATH и добавляем его в PATH
export GOPATH=$(go env GOPATH)
export PATH=$PATH:$GOPATH/bin

# Устанавливаем конкретные версии инструментов, совместимые с gRPC v1.59.0
echo "Установка protoc-gen-go и protoc-gen-go-grpc..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

# Запускаем протогенератор из текущей директории
# Выходные файлы будут помещены в текущую директорию (.)
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative post.proto

echo "Генерация кода завершена!" 