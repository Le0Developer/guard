.PHONY: build test generate check
build:
	go build -mod=readonly ./cmd/guard
test:
	go test -race ./...
generate:
	sqlc generate
check:
	test -z "$$(gofmt -l cmd internal)"
	sqlc vet
	go vet ./...
	go test -race ./...
