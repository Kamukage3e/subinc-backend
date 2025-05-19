# Production-grade Makefile for Go Fiber SaaS Backend

APP_NAME=subinc-cost-microservice
GOFILES=$(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: all build run lint test fmt tidy migrate docker run test build clean db-reset db-migrate run-test test-setup

all: deps build

build:
	@echo "Building binary..."
	go build -o bin/$(APP_NAME) ./cmd/main.go

run:
	@echo "Starting server..."
	go run ./cmd/main.go

lint:
	@echo "Running linter..."
	golangci-lint run --timeout=5m

test:
	@echo "Running tests..."
	go test -v ./...

fmt:
	gofmt -s -w $(GOFILES)

# Ensure go.mod/go.sum are tidy

tidy:
	go mod tidy

# Run DB migrations (if using golang-migrate)
migrate:
	migrate -path migrations -database "$$OWNER_DB_DSN" up

# Build and run Docker image
docker:
	docker build -t $(APP_NAME):latest .

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@go clean

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download

# Reset database
db-reset:
	@echo "Resetting database..."
	@psql -h localhost -p 5432 -U postgres -c "DROP DATABASE IF EXISTS subinc;"
	@psql -h localhost -p 5432 -U postgres -c "CREATE DATABASE subinc;"
	@go run cmd/admin-tools/db-setup.go

# Run migrations
db-migrate:
	@echo "Running migrations..."
	@go run cmd/admin-tools/db-migrate.go

# Run the automated test script
run-test:
	@echo "Running tests with automated server management..."
	@chmod +x run_and_test.sh
	@./run_and_test.sh

# Make the test scripts executable
test-setup:
	@echo "Making test scripts executable..."
	@chmod +x test_org_endpoints.sh
	@chmod +x test_project_endpoints.sh
	@chmod +x run_and_test.sh 