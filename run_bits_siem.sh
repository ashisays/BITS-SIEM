#!/bin/bash
# filepath: run_bits_siem.sh

set -e

echo "=== BITS-SIEM Automated Setup ==="

# 1. Build and start all services using Docker Compose
echo "-> Starting Docker Compose services..."
docker-compose up --build -d

# 2. Wait for API and DB to be ready
echo "-> Waiting for API and DB to be ready..."
MAX_TRIES=30
TRIES=0
until curl -s http://localhost:8000/docs > /dev/null; do
  sleep 3
  TRIES=$((TRIES+1))
  if [ $TRIES -ge $MAX_TRIES ]; then
    echo "API did not start in time. Check docker-compose logs."
    exit 1
  fi
done
echo "API is up!"

# 3. Get or set JWT token (for demo, use a default or fetch from API if implemented)
TENANT_ID="default-tenant"
JWT_TOKEN="demo-token" # Replace with actual token logic if needed

# 4. Initialize detection rules for your tenant
echo "-> Initializing detection rules for tenant: $TENANT_ID"
curl -s -X POST "http://localhost:8000/api/detection/rules/initialize-defaults?tenant_id=$TENANT_ID" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  || echo "Detection rule initialization skipped (check token/API)."

# 5. Seed test data (if script exists)
if [ -f "api/seed_test_data.py" ]; then
  echo "-> Seeding test data..."
  python3 api/seed_test_data.py || echo "Test data seeding failed (check Python and DB connection)."
else
  echo "-> No seed_test_data.py found, skipping data seeding."
fi

# 6. Launch the dashboard in the default browser
echo "-> Opening dashboard in browser..."
if command -v xdg-open &> /dev/null; then
  xdg-open http://localhost:3000
elif command -v gnome-open &> /dev/null; then
  gnome-open http://localhost:3000
else
  echo "Please open http://localhost:3000 in your browser."
fi

echo "=== Setup Complete! ==="
echo "Check logs with: docker-compose logs -f"
