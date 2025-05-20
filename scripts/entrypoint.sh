#!/bin/sh
set -e

# Function to wait for postgres to be ready
wait_for_postgres() {
    echo "Waiting for PostgreSQL to be ready..."
    
    # Extract values from DATABASE_URL or use environment variables
    DB_HOST=${DB_HOST:-localhost}
    DB_PORT=${DB_PORT:-5432}
    
    # Wait for PostgreSQL to be ready
    until nc -z -v -w30 $DB_HOST $DB_PORT; do
      echo "Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
      sleep 2
    done
    
    echo "PostgreSQL is ready!"
}

# Function to wait for redis to be ready
wait_for_redis() {
    echo "Waiting for Redis to be ready..."
    
    # Extract values from REDIS_ADDR or use environment variables
    REDIS_HOST=$(echo ${REDIS_ADDR:-localhost:6379} | cut -d':' -f1)
    REDIS_PORT=$(echo ${REDIS_ADDR:-localhost:6379} | cut -d':' -f2)
    
    # Wait for Redis to be ready
    until nc -z -v -w30 $REDIS_HOST $REDIS_PORT; do
      echo "Waiting for Redis at $REDIS_HOST:$REDIS_PORT..."
      sleep 2
    done
    
    echo "Redis is ready!"
}

# Run migrations if RUN_MIGRATIONS is set to true
run_migrations() {
    if [ "$RUN_MIGRATIONS" = "true" ]; then
        echo "Running database migrations..."
        
        # Create migrations directory if it doesn't exist
        mkdir -p /app/migrations
        
        # Run the migrate command
        /app/bin/migrate -action=init -schema=/app/schema.hcl -migrations-dir=/app/migrations
        /app/bin/migrate -action=apply -schema=/app/schema.hcl -migrations-dir=/app/migrations
        
        echo "Migrations completed!"
    else
        echo "Skipping migrations as RUN_MIGRATIONS is not set to true"
    fi
}

# Main execution
main() {
    # Wait for dependencies if enabled
    if [ "$WAIT_FOR_DEPS" = "true" ]; then
        wait_for_postgres
        wait_for_redis
    fi
    
    # Run migrations if requested
    run_migrations
    
    # Execute the passed command
    echo "Starting application..."
    exec "$@"
}

# Run the main function
main "$@" 