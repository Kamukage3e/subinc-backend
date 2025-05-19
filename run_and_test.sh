#!/bin/bash

# Stop any existing server processes
echo "Stopping any existing server processes..."
pkill -f "go run cmd/main.go" || true

# Find an available port (default to 8080)
PORT=8080
while netstat -tuln | grep -q ":$PORT "; do
  echo "Port $PORT is already in use, trying next port..."
  PORT=$((PORT+1))
done

echo "Starting server on port $PORT..."
DB_PORT=5432 HTTP_PORT=$PORT go run cmd/main.go &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
for i in {1..30}; do
  if curl -s "http://localhost:$PORT/api/v1/health" > /dev/null 2>&1; then
    echo "Server is ready!"
    break
  fi
  
  # Check if server process is still running
  if ! ps -p $SERVER_PID > /dev/null; then
    echo "Server failed to start. Please check the logs."
    exit 1
  fi
  
  echo "Waiting... ($i/30)"
  sleep 1
done

# Set API URL for test scripts
export API_URL="http://localhost:$PORT/api/v1"

# Run tests
echo -e "\n========== RUNNING ORGANIZATION TESTS ==========\n"
./test_org_endpoints.sh

echo -e "\n========== RUNNING PROJECT TESTS ==========\n"
./test_project_endpoints.sh

# Kill the server
echo -e "\n========== TESTS COMPLETED, SHUTTING DOWN SERVER ==========\n"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null

echo "All done!" 