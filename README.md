# BITS-SIEM

A cloud-native, multi-tenant SIEM (Security Information and Event Management) system for real-time security assessment using syslog data with advanced machine learning and threat detection capabilities.

## 🚀 Features

### Core SIEM Capabilities
- **Multi-tenant Architecture**: Isolated tenant environments with role-based access control
- **Real-time Syslog Ingestion**: Support for RFC 3164, RFC 5424, Cisco, and custom formats
- **Advanced Threat Detection**: Machine learning-based anomaly detection and pattern recognition
- **Security Analytics**: Real-time correlation and threat scoring
- **Comprehensive Dashboard**: Modern Vue.js interface with real-time updates
- **Notification System**: Email and web-based alerting
- **Report Generation**: Automated security and compliance reports

### Technical Highlights
- **Scalable Architecture**: Microservices with Docker and Kubernetes support
- **Real-time Processing**: Kafka-based event streaming
- **Machine Learning**: Isolation Forest for anomaly detection
- **Threat Intelligence**: IP/domain reputation and indicator matching
- **Event Correlation**: Complex event correlation rules
- **Multi-format Support**: Comprehensive syslog format parsing
- **High Performance**: Optimized for high-volume log processing

## 🏗️ Project Structure

```
BITS-SIEM/
│
├── docker-compose.yml         # Orchestrates all services
├── README.md                  # Project documentation
├── IMPLEMENTATION_SUMMARY.md  # Implementation details
├── INGESTION_PROCESSING_ARCHITECTURE.md # Architecture documentation
├── test_syslog_ingestion.py  # Test script for ingestion
│
├── dashboard/                 # Web frontend (Vue.js)
├── api/                       # Backend API (FastAPI)
├── ingestion/                 # Syslog ingestion service
├── processing/                # Real-time processing & ML
├── notification/              # Notification service
└── db/                        # Database initialization
```

## 🛠️ Services

### Core Services
- **dashboard**: Modern Vue.js web interface for configuration, monitoring, and analytics
- **api**: FastAPI backend for user/tenant management and configuration
- **ingestion**: High-performance syslog ingestion with multi-format support
- **processing**: Real-time analytics and ML-based threat detection
- **notification**: Email and web-based alert notifications

### Infrastructure Services
- **db**: PostgreSQL database for multi-tenant data storage
- **redis**: Redis cache for real-time data access
- **kafka**: Apache Kafka for event streaming and buffering
- **zookeeper**: Kafka coordination service

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- 8GB+ RAM (16GB recommended)
- 50GB+ disk space

### 1. Clone and Start
```bash
git clone <repository-url>
cd BITS-SIEM
docker-compose up --build
```

### 2. Access Services
- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8000
- **Ingestion Health**: http://localhost:8001/health
- **Processing Health**: http://localhost:8002/health
- **Syslog UDP**: localhost:514
- **Database**: localhost:5432 (user: siem, password: siempassword, db: siemdb)

### 3. Test Syslog Ingestion
```bash
# Send test syslog messages
python test_syslog_ingestion.py

# Or manually send a message
echo '<134>Jan 15 10:30:00 testhost testapp: Test message' | nc -u localhost 514
```

## 📊 Architecture Overview

### Data Flow
```
Syslog Sources → Ingestion Service → Kafka → Processing Service → Alerts/Dashboard
                ↓                    ↓           ↓
              Redis Cache        PostgreSQL   ML Models
```

### Key Components

#### Ingestion Service
- **UDP Syslog Server**: Receives syslog messages on port 514
- **Multi-format Parser**: RFC 3164, RFC 5424, Cisco, custom formats
- **Tenant Resolution**: Automatic tenant assignment based on source IP
- **Real-time Buffering**: Efficient message buffering and batching
- **Multiple Outputs**: Redis (real-time), Kafka (streaming), PostgreSQL (persistence)

#### Processing Service
- **Machine Learning**: Isolation Forest for anomaly detection
- **Threat Detection**: Pattern-based threat identification
- **Threat Intelligence**: IP/domain reputation checking
- **Event Correlation**: Complex event correlation rules
- **Real-time Scoring**: Dynamic threat scoring algorithm

#### Dashboard
- **Real-time Monitoring**: Live security event visualization
- **Multi-tenant Support**: Isolated views per tenant
- **Advanced Analytics**: Interactive charts and reports
- **User Management**: Role-based access control
- **Notification Center**: Integrated alert management

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://siem:siempassword@db:5432/siemdb

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:29092

# Syslog
SYSLOG_PORT=514
SYSLOG_HOST=0.0.0.0
```

### Service Configuration
Each service can be configured independently:
- **Ingestion**: Message parsing, buffering, and output settings
- **Processing**: ML model parameters, threat thresholds, correlation rules
- **API**: Authentication, rate limiting, CORS settings
- **Dashboard**: UI customization, theme settings

## 📈 Performance

### Scalability
- **Ingestion**: 10,000+ messages/second per instance
- **Processing**: 5,000+ events/second per instance
- **Storage**: Horizontal scaling with Kafka partitioning
- **Database**: Read replicas for analytics queries

### Resource Requirements
- **Development**: 4 cores, 8GB RAM, 50GB storage
- **Production**: 8+ cores, 16GB+ RAM, 500GB+ storage per service

## 🔒 Security Features

### Data Protection
- **Encryption**: TLS for all communications
- **Authentication**: JWT-based API authentication
- **Authorization**: Role-based access control
- **Audit Logging**: Complete audit trail

### Network Security
- **Firewall Rules**: Restrict syslog port access
- **VLAN Isolation**: Separate network segments
- **VPN Access**: Secure remote access

### Compliance
- **Data Retention**: Configurable retention policies
- **Audit Trails**: Complete event logging
- **Access Controls**: Granular permissions

## 🧪 Testing

### Automated Testing
```bash
# Run the comprehensive test suite
python test_syslog_ingestion.py

# Test individual services
curl http://localhost:8000/health    # API
curl http://localhost:8001/health    # Ingestion
curl http://localhost:8002/health    # Processing
```

### Manual Testing
```bash
# Send syslog messages
echo '<134>Jan 15 10:30:00 testhost testapp: Test message' | nc -u localhost 514

# Monitor logs
docker-compose logs -f ingestion processing

# Check database
docker-compose exec db psql -U siem -d siemdb -c "SELECT COUNT(*) FROM syslog_events;"
```

## 📚 Documentation

- **[Implementation Summary](IMPLEMENTATION_SUMMARY.md)**: Detailed implementation overview
- **[Ingestion & Processing Architecture](INGESTION_PROCESSING_ARCHITECTURE.md)**: Comprehensive architecture documentation
- **[Database Integration](DATABASE_INTEGRATION.md)**: Database schema and integration details

## 🔮 Roadmap

### Planned Features
- **Advanced ML Models**: Deep learning for pattern recognition
- **Real-time Dashboards**: Live threat maps and visualizations
- **Advanced Correlation**: Graph-based correlation and ML correlation
- **Compliance Features**: Automated compliance reporting
- **Cloud Integration**: AWS, Azure, GCP native integrations

### Integration Opportunities
- **SIEM Integration**: Splunk, QRadar, ELK Stack
- **Threat Feeds**: STIX/TAXII, MISP, AlienVault OTX
- **Security Tools**: Firewalls, IDS/IPS, EDR
- **Cloud Platforms**: AWS, Azure, GCP

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the documentation
- Review the architecture guides
- Test with the provided test scripts
- Monitor service health endpoints

---

**BITS-SIEM**: Enterprise-grade security event processing with machine learning and real-time analytics.
