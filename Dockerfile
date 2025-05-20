# Build Stage
FROM golang:1.21-alpine AS builder

# Install required packages
RUN apk --no-cache add ca-certificates git tzdata

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source from the current directory to the working directory
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X 'main.Version=$(git describe --tags --always --dirty)' -X 'main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" \
    -o /app/bin/subinc-backend \
    ./cmd/main.go

# Build the migration tool
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/migrate \
    ./cmd/migrate/main.go

# Final Stage
FROM alpine:latest

# Install required packages
RUN apk --no-cache add ca-certificates tzdata curl

# Set working directory
WORKDIR /app

# Install Atlas migration tool
RUN curl -sSf https://atlasgo.sh | sh

# Copy the binaries from builder stage
COPY --from=builder /app/bin/subinc-backend /app/bin/subinc-backend
COPY --from=builder /app/bin/migrate /app/bin/migrate

# Copy schema and migrations
COPY --from=builder /app/schema.hcl /app/schema.hcl
COPY --from=builder /app/migrations /app/migrations

# Copy swagger docs if present
COPY --from=builder /app/swagger.json /app/swagger.json
COPY --from=builder /app/swagger.yaml /app/swagger.yaml
COPY --from=builder /app/swagger-ui /app/swagger-ui

# Copy entrypoint script
COPY --from=builder /app/scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create non-root user and set permissions
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app
USER appuser

# Set environment variables with defaults
ENV APP_ENV=prod \
    SERVICE_NAME=subinc-backend \
    PORT=8080 \
    LOG_LEVEL=info \
    LOG_FORMAT=json \
    LOG_COLOR=false

# Expose port
EXPOSE 8080

# Set the entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (runs the main app)
CMD ["/app/bin/subinc-backend"] 