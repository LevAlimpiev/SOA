module github.com/levalimpiev/service_oriented_architectures

go 1.21

toolchain go1.24.0

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/gorilla/mux v1.8.0
	github.com/levalimpiev/service_oriented_architectures/proto/post v0.0.0
	github.com/levalimpiev/service_oriented_architectures/proto/user v0.0.0
	github.com/segmentio/kafka-go v0.4.47
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.12.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.14.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/levalimpiev/service_oriented_architectures/proto/user => ./proto/user

replace github.com/levalimpiev/service_oriented_architectures/proto/post => ./proto/post

replace github.com/levalimpiev/service_oriented_architectures/user-service => ./user-service

replace github.com/levalimpiev/service_oriented_architectures/api-gateway => ./api-gateway
