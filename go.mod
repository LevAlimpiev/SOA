module github.com/levalimpiev/service_oriented_architectures

go 1.20

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/gorilla/mux v1.8.0
	github.com/levalimpiev/service_oriented_architectures/api-gateway v0.0.0-00010101000000-000000000000
	github.com/levalimpiev/service_oriented_architectures/proto/user v0.0.0
	github.com/levalimpiev/service_oriented_architectures/user-service v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.12.0
	google.golang.org/grpc v1.59.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.14.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/levalimpiev/service_oriented_architectures/proto/user => ./proto/user

replace github.com/levalimpiev/service_oriented_architectures/user-service => ./user-service

replace github.com/levalimpiev/service_oriented_architectures/api-gateway => ./api-gateway
