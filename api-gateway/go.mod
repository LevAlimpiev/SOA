module github.com/levalimpiev/service_oriented_architectures/api-gateway

go 1.21

toolchain go1.24.0

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/levalimpiev/service_oriented_architectures/proto/post v0.0.0
	github.com/levalimpiev/service_oriented_architectures/proto/user v0.0.0
	github.com/stretchr/testify v1.8.4
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	golang.org/x/net v0.14.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230822172742-b8732ec3820d // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/levalimpiev/service_oriented_architectures/proto/user => ../proto/user

replace github.com/levalimpiev/service_oriented_architectures/proto/post => ../proto/post
