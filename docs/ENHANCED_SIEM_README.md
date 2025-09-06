# BITS-SIEM Enhanced System

## Overview

The BITS-SIEM Enhanced System is a comprehensive Security Information and Event Management (SIEM) solution that provides real-time threat detection, advanced notification systems, and an intuitive dashboard for security monitoring. This enhanced version includes sophisticated brute force attack detection, real-time notifications, and multi-channel alerting capabilities.

## 🚀 Key Features

### Enhanced Threat Detection
- **Brute Force Attack Detection**: Advanced algorithms to detect and prevent brute force attacks
- **Port Scanning Detection**: Identifies port scanning activities and network reconnaissance
- **Anomaly Detection**: Machine learning-based anomaly detection for unusual behavior patterns
- **Real-time Correlation**: Intelligent alert correlation to reduce false positives

### Advanced Notification System
- **Real-time WebSocket Notifications**: Instant alerts delivered to the dashboard
- **Email Notifications**: Professional HTML email templates with actionable information
- **Webhook Integrations**: REST API webhooks for external system integration
- **Multi-channel Delivery**: Simultaneous delivery across multiple notification channels
- **Notification Preferences**: User-configurable notification settings and escalation rules

### Enhanced Dashboard
- **Real-time Monitoring**: Live updates without page refresh
- **Interactive Alerts**: Click-to-action alert management
- **Visual Analytics**: Charts and graphs for threat analysis
- **Responsive Design**: Mobile-friendly interface for on-the-go monitoring

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Dashboard     │    │   API Service   │    │  Notification   │
│   (Vue.js)     │◄──►│   (FastAPI)     │◄──►│   Service       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ingestion     │    │   Processing    │    │     Redis       │
│   Service       │    │   Service       │    │   (Message      │
│                 │    │                 │    │    Queue)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │   Threat        │
│   Database      │    │   Detection     │
│                 │    │   Engines       │
└─────────────────┘    └─────────────────┘
```

## 🛠️ Technology Stack

### Backend Services
- **Python 3.11+**: Core application logic
- **FastAPI**: High-performance API framework
- **SQLAlchemy**: Database ORM
- **PostgreSQL**: Primary database
- **Redis**: Caching and message queuing
- **Structlog**: Structured logging

### Frontend
- **Vue.js 3**: Progressive JavaScript framework
- **Vite**: Build tool and dev server
- **WebSocket**: Real-time communication
- **CSS3**: Modern styling with animations

### Infrastructure
- **Docker**: Containerization
- **Docker Compose**: Multi-service orchestration
- **Nginx**: Reverse proxy and load balancing

## 📦 Installation & Deployment

### Prerequisites
- Docker and Docker Compose
- Python 3.11+
- 4GB+ RAM available
- Ports 80, 8000, 8001, 5432, 6379 available

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd BITS-SIEM
   ```

2. **Deploy the enhanced system**
   ```bash
   chmod +x deploy_enhanced_siem.sh
   ./deploy_enhanced_siem.sh
   ```

3. **Access the system**
   - Dashboard: http://localhost
   - API: http://localhost:8000
   - Notifications: http://localhost:8001

### Manual Deployment

1. **Build and start services**
   ```bash
   docker-compose -f docker-compose.enhanced.yml up -d
   ```

2. **Initialize database**
   ```bash
   docker exec bits-siem-api python init_database.py
   docker exec bits-siem-api python seed_test_data.py
   ```

3. **Verify services**
   ```bash
   docker-compose -f docker-compose.enhanced.yml ps
   ```

## 🧪 Testing the System

### Run Comprehensive Tests
```bash
python test_enhanced_notifications.py
```

### Test Individual Components

1. **Test Notification Service**
   ```bash
   curl http://localhost:8001/health
   ```

2. **Test API Endpoints**
   ```bash
   curl http://localhost:8000/api/detection/health
   ```

3. **Test WebSocket Connection**
   ```bash
   # Use a WebSocket client to connect to ws://localhost:8001/ws/notifications/{tenant_id}
   ```

### Simulate Attacks

1. **Brute Force Attack**
   ```bash
   # Send multiple failed login attempts
   for i in {1..10}; do
     curl -X POST "http://localhost:8000/api/detection/events/ingest?tenant_id=demo-org" \
       -H "Content-Type: application/json" \
       -d '{"username":"testuser","event_type":"login_failure","source_ip":"192.168.1.100"}'
     sleep 0.1
   done
   ```

2. **Port Scan Detection**
   ```bash
   # Send network connection events to different ports
   for port in 22 80 443 3389; do
     curl -X POST "http://localhost:8000/api/detection/events/ingest?tenant_id=demo-org" \
       -H "Content-Type: application/json" \
       -d "{\"event_type\":\"network_connection\",\"source_ip\":\"10.0.0.50\",\"metadata\":{\"port\":$port}}"
     sleep 0.1
   done
   ```

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following configuration:

```env
# Database
DATABASE_URL=postgresql://siem:siem123@localhost:5432/siem

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=siem@company.com

# Security
JWT_SECRET=your-super-secret-jwt-key
ENCRYPTION_KEY=your-32-character-encryption-key

# Threat Detection
BRUTE_FORCE_THRESHOLD=5
BRUTE_FORCE_WINDOW=300
PORT_SCAN_THRESHOLD=10
PORT_SCAN_WINDOW=600
```

### Notification Templates

The system includes pre-built email templates for:
- Brute Force Attacks
- Port Scanning
- Anomaly Detection
- General Security Alerts

Customize templates in `notification/main.py`.

## 📊 Dashboard Features

### Real-time Monitoring
- Live threat detection updates
- WebSocket-based notifications
- Auto-refresh capabilities
- Connection status indicators

### Alert Management
- Severity-based filtering
- Status updates (Open, Investigating, Resolved)
- Alert correlation display
- Bulk operations

### Analytics
- 24-hour event statistics
- Threat trend analysis
- Source IP analysis
- Detection accuracy metrics

## 🔔 Notification System

### Email Notifications
- HTML and plain text formats
- Professional templates
- Configurable delivery schedules
- Quiet hours support

### Webhook Integrations
- REST API endpoints
- Retry mechanisms
- Rate limiting
- Custom payload formats

### Real-time Updates
- WebSocket connections
- Tenant isolation
- Connection management
- Automatic reconnection

## 🚨 Threat Detection Engines

### Brute Force Detection
- Configurable thresholds
- Time-window analysis
- IP-based tracking
- Username correlation

### Port Scan Detection
- Port diversity analysis
- Scan pattern recognition
- Severity classification
- Service identification

### Anomaly Detection
- Behavioral baselines
- Statistical analysis
- Feature extraction
- Machine learning models

## 📈 Performance & Scaling

### Optimization Features
- Batch processing
- Redis caching
- Database indexing
- Async operations

### Monitoring
- Prometheus metrics
- Health checks
- Performance logging
- Resource utilization

### Scaling Considerations
- Horizontal scaling support
- Load balancing
- Database sharding
- Microservice architecture

## 🔒 Security Features

### Authentication & Authorization
- JWT-based authentication
- Role-based access control
- Tenant isolation
- Session management

### Data Protection
- Encrypted storage
- Secure communication
- Audit logging
- Data retention policies

### Network Security
- Rate limiting
- Input validation
- SQL injection prevention
- XSS protection

## 🐛 Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**
   - Check notification service status
   - Verify tenant ID
   - Check firewall settings

2. **Notifications Not Delivered**
   - Verify SMTP configuration
   - Check Redis connectivity
   - Review notification preferences

3. **Alerts Not Generated**
   - Check processing service logs
   - Verify event ingestion
   - Review detection rules

### Debug Commands

```bash
# Check service logs
docker-compose -f docker-compose.enhanced.yml logs -f [service-name]

# Check service status
docker-compose -f docker-compose.enhanced.yml ps

# Restart specific service
docker-compose -f docker-compose.enhanced.yml restart [service-name]

# Check Redis
docker exec bits-siem-redis redis-cli ping

# Check database
docker exec bits-siem-postgres pg_isready -U siem -d siem
```

## 📚 API Documentation

### Detection API Endpoints

- `POST /api/detection/events/ingest` - Ingest security events
- `GET /api/detection/alerts` - Retrieve security alerts
- `PUT /api/detection/alerts/{id}/status` - Update alert status
- `GET /api/detection/stats` - Get detection statistics

### Notification API Endpoints

- `GET /health` - Service health check
- `POST /notifications/send` - Send notification directly
- `WS /ws/notifications/{tenant_id}` - WebSocket endpoint

## 🤝 Contributing

### Development Setup

1. **Clone and setup**
   ```bash
   git clone <repository-url>
   cd BITS-SIEM
   pip install -r requirements.txt
   ```

2. **Run tests**
   ```bash
   python -m pytest tests/
   python test_enhanced_notifications.py
   ```

3. **Code style**
   - Follow PEP 8
   - Use type hints
   - Add docstrings
   - Write tests

### Testing Guidelines

- Unit tests for all functions
- Integration tests for services
- End-to-end tests for workflows
- Performance testing for scaling

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI community for the excellent web framework
- Vue.js team for the progressive frontend framework
- Redis team for the high-performance caching solution
- PostgreSQL team for the reliable database system

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the API documentation
- Contact the development team

---

**BITS-SIEM Enhanced System** - Advanced Security Information and Event Management with Real-time Notifications

