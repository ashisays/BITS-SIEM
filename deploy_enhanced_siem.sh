#!/bin/bash

# BITS-SIEM Enhanced Deployment Script
# ===================================
# This script deploys the complete enhanced SIEM system including:
# - Enhanced notification service
# - Real-time WebSocket notifications
# - Email and webhook integrations
# - Dashboard with real-time monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="bits-siem-enhanced"
COMPOSE_FILE="docker-compose.enhanced.yml"

echo -e "${BLUE}🚀 BITS-SIEM Enhanced Deployment${NC}"
echo "======================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed. Please install it and try again.${NC}"
    exit 1
fi

# Create enhanced docker-compose file
echo -e "${YELLOW}📝 Creating enhanced docker-compose configuration...${NC}"

cat > ${COMPOSE_FILE} << 'EOF'
version: '3.8'

services:
  # Redis for caching and message queuing
  redis:
    image: redis:7-alpine
    container_name: bits-siem-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # PostgreSQL database
  postgres:
    image: postgres:15-alpine
    container_name: bits-siem-postgres
    environment:
      POSTGRES_DB: siem
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: siem123
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U siem -d siem"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Enhanced Notification Service
  notification:
    build: ./notification
    container_name: bits-siem-notification
    ports:
      - "8001:8001"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - SMTP_SERVER=localhost
      - SMTP_PORT=587
      - EMAIL_FROM=siem@company.com
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  # API Service
  api:
    build: ./api
    container_name: bits-siem-api
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://siem:siem123@postgres:5432/siem
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - NOTIFICATION_SERVICE_URL=http://notification:8001
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      notification:
        condition: service_healthy
    volumes:
      - ./api:/app
    restart: unless-stopped

  # Ingestion Service
  ingestion:
    build: ./ingestion
    container_name: bits-siem-ingestion
    ports:
      - "514:514/udp"
      - "601:601/tcp"
      - "6514:6514/tcp"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - DATABASE_URL=postgresql://siem:siem123@postgres:5432/siem
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./ingestion:/app
    restart: unless-stopped

  # Processing Service
  processing:
    build: ./processing
    container_name: bits-siem-processing
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_DB=0
      - DATABASE_URL=postgresql://siem:siem123@postgres:5432/siem
      - NOTIFICATION_SERVICE_URL=http://notification:8001
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      notification:
        condition: service_healthy
    volumes:
      - ./processing:/app
    restart: unless-stopped

  # Dashboard (Vue.js frontend)
  dashboard:
    build: ./dashboard
    container_name: bits-siem-dashboard
    ports:
      - "3000:80"
    environment:
      - VITE_API_BASE_URL=http://localhost:8000
      - VITE_NOTIFICATION_WS_URL=ws://localhost:8001
    depends_on:
      api:
        condition: service_started
      notification:
        condition: service_healthy
    volumes:
      - ./dashboard:/app
      - /app/node_modules
    restart: unless-stopped

  # Nginx reverse proxy
  nginx:
    image: nginx:alpine
    container_name: bits-siem-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - api
      - dashboard
      - notification
    restart: unless-stopped

volumes:
  redis_data:
  postgres_data:
EOF

# Create nginx configuration
echo -e "${YELLOW}📝 Creating nginx configuration...${NC}"

cat > nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream api_backend {
        server api:8000;
    }
    
    upstream dashboard_backend {
        server dashboard:80;
    }
    
    upstream notification_backend {
        server notification:8001;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=web:10m rate=30r/s;

    server {
        listen 80;
        server_name localhost;

        # Dashboard
        location / {
            limit_req zone=web burst=20 nodelay;
            proxy_pass http://dashboard_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # API
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://api_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Notification service
        location /notifications/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://notification_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket proxy for notifications
        location /ws/ {
            proxy_pass http://notification_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health checks
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOF

# Create SSL directory
mkdir -p ssl

# Create environment file
echo -e "${YELLOW}📝 Creating environment configuration...${NC}"

cat > .env << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://siem:siem123@localhost:5432/siem
POSTGRES_DB=siem
POSTGRES_USER=siem
POSTGRES_PASSWORD=siem123

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# Notification Service Configuration
NOTIFICATION_SERVICE_URL=http://localhost:8001
SMTP_SERVER=localhost
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
EMAIL_FROM=siem@company.com
EMAIL_FROM_NAME=BITS-SIEM Security

# WebSocket Configuration
WEBSOCKET_URL=ws://localhost:8001

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
ENCRYPTION_KEY=your-32-character-encryption-key

# Logging
LOG_LEVEL=INFO
METRICS_ENABLED=true
METRICS_PORT=9090

# Threat Detection
BRUTE_FORCE_THRESHOLD=5
BRUTE_FORCE_WINDOW=300
PORT_SCAN_THRESHOLD=10
PORT_SCAN_WINDOW=600
ANOMALY_DETECTION_ENABLED=true
EOF

# Build and start services
echo -e "${YELLOW}🔨 Building and starting services...${NC}"

# Stop existing containers
docker-compose -f ${COMPOSE_FILE} down --remove-orphans

# Build images
docker-compose -f ${COMPOSE_FILE} build --no-cache

# Start services
docker-compose -f ${COMPOSE_FILE} up -d

# Wait for services to be healthy
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"

# Wait for database
echo "Waiting for PostgreSQL..."
until docker exec bits-siem-postgres pg_isready -U siem -d siem > /dev/null 2>&1; do
    sleep 2
done

# Wait for Redis
echo "Waiting for Redis..."
until docker exec bits-siem-redis redis-cli ping > /dev/null 2>&1; do
    sleep 2
done

# Wait for notification service
echo "Waiting for Notification Service..."
until curl -f http://localhost:8001/health > /dev/null 2>&1; do
    sleep 2
done

# Wait for API service
echo "Waiting for API Service..."
until curl -f http://localhost:8000/health > /dev/null 2>&1; do
    sleep 2
done

# Initialize database
echo -e "${YELLOW}🗄️  Initializing database...${NC}"
docker exec bits-siem-api python init_database.py

# Seed test data
echo -e "${YELLOW}🌱 Seeding test data...${NC}"
docker exec bits-siem-api python seed_test_data.py

# Show service status
echo -e "${YELLOW}📊 Service Status:${NC}"
docker-compose -f ${COMPOSE_FILE} ps

# Show logs
echo -e "${YELLOW}📋 Recent logs:${NC}"
docker-compose -f ${COMPOSE_FILE} logs --tail=20

# Show access information
echo -e "${GREEN}🎉 BITS-SIEM Enhanced System Deployed Successfully!${NC}"
echo "=================================================="
echo ""
echo "🌐 Access URLs:"
echo "   Dashboard:     http://localhost"
echo "   API:          http://localhost:8000"
echo "   Notifications: http://localhost:8001"
echo ""
echo "🔌 Service Ports:"
echo "   Dashboard:     80"
echo "   API:          8000"
echo "   Notifications: 8001"
echo "   PostgreSQL:   5432"
echo "   Redis:        6379"
echo "   Syslog UDP:   514"
echo "   Syslog TCP:   601"
echo "   Syslog TLS:   6514"
echo ""
echo "🧪 Test the system:"
echo "   python test_enhanced_notifications.py"
echo ""
echo "📁 Configuration files:"
echo "   Docker Compose: ${COMPOSE_FILE}"
echo "   Nginx Config:   nginx.conf"
echo "   Environment:    .env"
echo ""
echo "🔄 Management commands:"
echo "   Start:  docker-compose -f ${COMPOSE_FILE} up -d"
echo "   Stop:   docker-compose -f ${COMPOSE_FILE} down"
echo "   Logs:   docker-compose -f ${COMPOSE_FILE} logs -f"
echo "   Restart: docker-compose -f ${COMPOSE_FILE} restart"
echo ""
echo -e "${BLUE}🚀 The enhanced SIEM system is ready for testing!${NC}"
