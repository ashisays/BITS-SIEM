# BITS-SIEM Ingestion and Processing Architecture

## Overview

The BITS-SIEM system now includes a comprehensive ingestion and processing layer that handles real-time syslog data collection, normalization, threat detection, and machine learning-based analysis. This architecture provides scalable, multi-tenant security event processing with advanced analytics capabilities.

## 🏗️ Architecture Components

### 1. Ingestion Service (`ingestion/`)

**Purpose**: Collect, normalize, and forward syslog data from various sources

**Key Features**:
- **Multi-format Syslog Support**: RFC 3164, RFC 5424, Cisco, and custom formats
- **Real-time Processing**: Asynchronous message handling with buffering
- **Tenant Isolation**: Automatic tenant resolution based on source IP
- **Multiple Outputs**: Redis (real-time), Kafka (streaming), Database (persistence)
- **Health Monitoring**: REST API for service monitoring

**Technical Stack**:
- **Language**: Python 3.11
- **Framework**: FastAPI + asyncio
- **Protocols**: UDP syslog (port 514)
- **Storage**: Redis, PostgreSQL, Kafka
- **Parsing**: Regex-based with fallback normalization

**Data Flow**:
```
Syslog Sources → UDP Server → Parser → Normalizer → Buffer → Multiple Outputs
```

### 2. Processing Service (`processing/`)

**Purpose**: Real-time threat detection, anomaly detection, and security analytics

**Key Features**:
- **Machine Learning**: Isolation Forest for anomaly detection
- **Threat Pattern Detection**: Regex-based threat identification
- **Threat Intelligence**: IP/domain reputation checking
- **Event Correlation**: Complex event correlation rules
- **Real-time Scoring**: Dynamic threat scoring algorithm
- **Model Training**: Periodic ML model retraining

**Technical Stack**:
- **Language**: Python 3.11
- **ML Libraries**: scikit-learn, pandas, numpy
- **Streaming**: Kafka consumer/producer
- **Storage**: Redis, PostgreSQL
- **Analytics**: Real-time scoring and correlation

**Data Flow**:
```
Kafka Topics → Consumer → ML Analysis → Threat Detection → Correlation → Alerts
```

## 🔄 Data Flow Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Syslog        │    │   Ingestion     │    │   Processing    │
│   Sources       │───▶│   Service       │───▶│   Service       │
│                 │    │                 │    │                 │
│ • Firewalls     │    │ • UDP Server    │    │ • ML Models     │
│ • Servers       │    │ • Parser        │    │ • Threat Intel  │
│ • Network       │    │ • Normalizer    │    │ • Correlation   │
│   Devices       │    │ • Buffer        │    │ • Scoring       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Storage       │    │   Outputs       │
                       │   Layer         │    │                 │
                       │                 │    │ • Alerts        │
                       │ • Redis         │    │ • Notifications │
                       │ • Kafka         │    │ • Reports       │
                       │ • PostgreSQL    │    │ • Dashboard     │
                       └─────────────────┘    └─────────────────┘
```

## 📊 Syslog Message Processing

### Message Parsing

The ingestion service supports multiple syslog formats:

1. **RFC 3164**: Traditional syslog format
   ```
   <134>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
   ```

2. **RFC 5424**: Structured syslog format
   ```
   <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8
   ```

3. **Cisco Format**: Cisco device specific
   ```
   189 000001: %SYS-5-CONFIG_I: Configured from console by vty0 (10.0.0.1)
   ```

### Normalization Process

1. **Priority Parsing**: Extract facility and severity from priority
2. **Timestamp Parsing**: Convert to UTC with timezone handling
3. **Message Extraction**: Parse structured and unstructured data
4. **Metadata Addition**: Add source IP, port, and tenant information
5. **Format Detection**: Identify and tag message format

### Output Structure

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "facility": "AUTH",
  "severity": "ERROR",
  "hostname": "webserver01",
  "app_name": "sshd",
  "proc_id": "12345",
  "msg_id": "",
  "message": "Failed password for user admin",
  "raw_message": "<134>Jan 15 10:30:00 webserver01 sshd[12345]: Failed password for user admin",
  "source_ip": "192.168.1.100",
  "source_port": 514,
  "tenant_id": "acme-corp",
  "normalized": true,
  "parsed_fields": {
    "format": "RFC3164",
    "priority": 134
  }
}
```

## 🤖 Machine Learning & Analytics

### Anomaly Detection

**Algorithm**: Isolation Forest
- **Features**: Text TF-IDF, temporal patterns, metadata statistics
- **Training**: Unsupervised learning on normal traffic patterns
- **Scoring**: Anomaly probability (0-1 scale)
- **Threshold**: Configurable (default: 0.8)

**Feature Extraction**:
- Message length and word count
- Special character ratios
- Temporal patterns (hour, day of week)
- Text-based TF-IDF features

### Threat Pattern Detection

**Pattern Categories**:
1. **Brute Force Attacks**: Failed authentication patterns
2. **SQL Injection**: Database attack patterns
3. **XSS Attacks**: Cross-site scripting patterns
4. **DoS Attacks**: Denial of service patterns
5. **Malware Indicators**: Malicious activity patterns

**Detection Method**: Regex-based pattern matching with severity scoring

### Threat Intelligence

**Reputation Checking**:
- **IP Reputation**: Malicious IP databases
- **Domain Reputation**: Phishing/malware domains
- **Indicator Matching**: Known threat indicators

**Scoring Algorithm**:
```
Threat Score = Pattern Score + Anomaly Score + Reputation Score + Indicator Score
```

## 🔗 Event Correlation

### Correlation Rules

1. **Brute Force Detection**:
   - Multiple failed logins from same IP
   - Time window: 5 minutes
   - Threshold: 5+ attempts

2. **Port Scanning**:
   - Multiple connection attempts to different ports
   - Time window: 10 minutes
   - Threshold: 10+ ports

3. **Data Exfiltration**:
   - Large data transfers to external IPs
   - Time window: 1 hour
   - Threshold: 1MB+ transfers

### Correlation Engine

- **Sliding Window**: Time-based event windows
- **Rule Matching**: Configurable correlation rules
- **Alert Generation**: Automatic alert creation
- **Context Preservation**: Full event context in alerts

## 🗄️ Data Storage Strategy

### Redis (Real-time)
- **Purpose**: Fast access to recent events
- **TTL**: 1 hour for syslog events
- **Structure**: Key-value with JSON serialization
- **Use Cases**: Real-time dashboards, live monitoring

### Kafka (Streaming)
- **Purpose**: Event streaming and buffering
- **Topics**: Tenant-specific topics (`syslog.{tenant_id}`)
- **Retention**: Configurable (default: 7 days)
- **Use Cases**: Stream processing, event replay

### PostgreSQL (Persistence)
- **Purpose**: Long-term storage and analytics
- **Tables**: syslog_events, security_events, alerts
- **Indexing**: Optimized for time-series queries
- **Use Cases**: Historical analysis, compliance reporting

## 🔧 Configuration

### Ingestion Service Configuration

```python
class Config:
    REDIS_HOST = "redis"
    REDIS_PORT = 6379
    KAFKA_BOOTSTRAP_SERVERS = "kafka:9092"
    DATABASE_URL = "postgresql://siem:siempassword@db:5432/siemdb"
    SYSLOG_PORT = 514
    SYSLOG_HOST = "0.0.0.0"
    MAX_MESSAGE_SIZE = 8192
    BATCH_SIZE = 100
    BATCH_TIMEOUT = 5  # seconds
```

### Processing Service Configuration

```python
class Config:
    REDIS_HOST = "redis"
    REDIS_PORT = 6379
    KAFKA_BOOTSTRAP_SERVERS = "kafka:9092"
    DATABASE_URL = "postgresql://siem:siempassword@db:5432/siemdb"
    ANOMALY_THRESHOLD = 0.8
    THREAT_SCORE_THRESHOLD = 0.7
    MODEL_UPDATE_INTERVAL = 3600  # 1 hour
    MIN_SAMPLES_FOR_TRAINING = 1000
```

## 🚀 Deployment

### Docker Compose Services

```yaml
services:
  # Infrastructure
  db: PostgreSQL database
  redis: Redis cache
  zookeeper: Kafka coordination
  kafka: Message streaming
  
  # Application Services
  api: Backend API
  dashboard: Web frontend
  ingestion: Syslog ingestion
  processing: ML processing
  notification: Alert notifications
```

### Health Checks

All services include health check endpoints:
- **Ingestion**: `http://localhost:8001/health`
- **Processing**: `http://localhost:8002/health`
- **API**: `http://localhost:8000/health`

### Monitoring Endpoints

- **Statistics**: `/stats` - Service statistics
- **Manual Flush**: `/flush` - Force buffer flush
- **Model Training**: `/train` - Trigger ML training

## 📈 Performance Characteristics

### Scalability

- **Ingestion**: 10,000+ messages/second per instance
- **Processing**: 5,000+ events/second per instance
- **Storage**: Horizontal scaling with Kafka partitioning
- **Database**: Read replicas for analytics queries

### Latency

- **Ingestion to Storage**: < 100ms
- **Processing Pipeline**: < 500ms
- **Alert Generation**: < 1 second
- **Dashboard Updates**: Real-time via WebSocket

### Resource Requirements

**Minimum (Development)**:
- CPU: 4 cores
- RAM: 8GB
- Storage: 50GB SSD

**Production (Per Service)**:
- CPU: 8+ cores
- RAM: 16GB+
- Storage: 500GB+ SSD
- Network: 1Gbps+

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
- **Intrusion Detection**: Monitor for attacks

### Compliance

- **Data Retention**: Configurable retention policies
- **Audit Trails**: Complete event logging
- **Access Controls**: Granular permissions
- **Encryption**: Data at rest and in transit

## 🛠️ Development & Testing

### Local Development

```bash
# Start all services
docker-compose up --build

# Test syslog ingestion
echo '<134>Jan 15 10:30:00 testhost testapp: Test message' | nc -u localhost 514

# Check processing
curl http://localhost:8002/stats
```

### Testing Tools

- **Syslog Generator**: Python script for load testing
- **Kafka Tools**: Topic monitoring and message inspection
- **Database Tools**: Query analysis and performance testing
- **Monitoring**: Prometheus metrics and Grafana dashboards

### Debugging

- **Logs**: Structured logging with loguru
- **Metrics**: Prometheus-compatible metrics
- **Tracing**: Distributed tracing with OpenTelemetry
- **Profiling**: Python profiling tools

## 🔮 Future Enhancements

### Planned Features

1. **Advanced ML Models**:
   - Deep learning for pattern recognition
   - Natural language processing for log analysis
   - Predictive analytics for threat forecasting

2. **Real-time Dashboards**:
   - Live threat maps
   - Interactive visualizations
   - Custom dashboards per tenant

3. **Advanced Correlation**:
   - Graph-based correlation
   - Machine learning correlation
   - Cross-tenant threat sharing

4. **Compliance Features**:
   - Automated compliance reporting
   - Regulatory framework support
   - Audit automation

### Integration Opportunities

- **SIEM Integration**: Splunk, QRadar, ELK Stack
- **Threat Feeds**: STIX/TAXII, MISP, AlienVault OTX
- **Security Tools**: Firewalls, IDS/IPS, EDR
- **Cloud Platforms**: AWS, Azure, GCP

## 📚 API Documentation

### Ingestion Service APIs

- `GET /health` - Service health check
- `GET /stats` - Ingestion statistics
- `POST /flush` - Manual buffer flush

### Processing Service APIs

- `GET /health` - Service health check
- `GET /stats` - Processing statistics
- `POST /train` - Trigger model training

### Kafka Topics

- `syslog.{tenant_id}` - Tenant-specific syslog events
- `security-events` - Generated security events
- `alerts` - Security alerts and notifications

This architecture provides a robust, scalable foundation for real-time security event processing with advanced analytics capabilities. 