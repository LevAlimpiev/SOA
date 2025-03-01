#!/bin/bash

echo "Starting User Service..."
go run user-service/main.go user-service/grpc_server.go