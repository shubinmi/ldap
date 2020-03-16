all: dep lint test

dep:
	go mod tidy

lint:
	golangci-lint run

test:
	go test ./...