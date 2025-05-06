# Production-grade Makefile for Go Fiber SaaS Backend

APP_NAME=subinc-cost-microservice
GOFILES=$(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build run lint test fmt tidy migrate docker

all: build

build:
	go build -o bin/$(APP_NAME) ./cmd/main.go

run:
	go run ./cmd/main.go

lint:
	golangci-lint run --timeout=5m

test:
	go test -v ./...

fmt:
	gofmt -s -w $(GOFILES)

# Ensure go.mod/go.sum are tidy

tidy:
	go mod tidy

# Run DB migrations (if using golang-migrate)
migrate:
	migrate -path migrations -database "$(shell yq e '.database.url' config/config.yaml)" up

# Build and run Docker image
docker:
	docker build -t $(APP_NAME):latest . 