# BITS-SIEM Brute-Force Detection System Documentation

## Overview

The BITS-SIEM Brute-Force Detection System implements behavioral correlation and baseline analysis with multi-factor source correlation to detect brute-force login attacks with minimal false positives.

### Key Features

- **Behavioral Analytics**: Adaptive user behavior baselines with statistical deviation detection
- **Multi-Source Correlation**: Cross-service attack detection (web, SSH, RDP, VPN, API)
- **Tenant Isolation**: All detection analysis performed within tenant boundaries
- **Dynamic Thresholds**: Statistical baselines that adapt to user behavior patterns
- **Real-time Processing**: Event ingestion with immediate analysis and alerting
- **Confidence Scoring**: All alerts include confidence scores and explainable context

## Baseline Management System

### Overview
The baseline management system creates **adaptive behavioral profiles** for each user by analyzing their historical authentication patterns. Unlike static rules, these baselines evolve with user behavior to minimize false positives.

### Baseline Components

#### 1. Temporal Patterns
The system analyzes when users typically authenticate:

```python
# Example baseline data:
temporal_baseline = {
    "typical_login_hours": [8, 9, 10, 17, 18],  # User logs in 8-10 AM, 5-6 PM
    "typical_days": [1, 2, 3, 4, 5],            # Monday-Friday worker
    "avg_session_duration": 240.5,              # Average 4 hours per session
    "time_deviation_threshold": 0.7              # 70% confidence for time anomalies
}
```

**Detection Logic**: Alerts when login occurs outside typical hours with high confidence deviation.

#### 2. Geographic Patterns
Location-based behavioral analysis:

```python
# Geographic baseline:
geographic_baseline = {
    "typical_countries": ["United States", "Canada"],  # Normal work locations
    "typical_ips": ["192.168.1.100", "10.0.0.50"],   # Office and home IPs
    "location_deviation_threshold": 0.8,               # 80% confidence for new locations
    "geographic_strict_mode": False                    # Tenant configurable
}
```

**Detection Logic**: Flags logins from new countries or IPs with statistical analysis of travel feasibility.

#### 3. Device & Technology Patterns
Device fingerprinting and browser analysis:

```python
# Device baseline:
device_baseline = {
    "typical_user_agents": ["Chrome/91.0.4472.124", "Firefox/89.0"],
    "typical_devices": ["device_hash_abc123", "device_hash_def456"],
    "device_change_sensitivity": 0.8,  # Alert on new devices
    "browser_consistency_check": True
}
```

**Detection Logic**: Identifies suspicious new devices, unusual browsers, or automated tools.

#### 4. Frequency & Failure Patterns
Behavioral metrics for login patterns:

```python
# Frequency baseline:
frequency_baseline = {
    "avg_daily_logins": 3.2,                    # Typically logs in 3 times per day
    "login_frequency_threshold": 8.4,           # Alert if >8 logins/day (statistical outlier)
    "avg_failed_attempts": 0.1,                 # Rarely fails login
    "failure_rate_threshold": 0.2,              # Alert if >20% failure rate
    "max_failed_attempts": 2                    # Historical maximum failures
}
```

**Detection Logic**: Uses statistical analysis to detect unusual login frequency or failure patterns.

### Dynamic Threshold Calculation

The system uses **statistical analysis** rather than fixed rules:

```python
# Adaptive threshold calculation:
def calculate_dynamic_thresholds(historical_data):
    # Login frequency threshold (mean + 2 standard deviations)
    login_frequency_threshold = mean(daily_logins) + (2 * stdev(daily_logins))
    
    # Failure rate threshold (adaptive with cap)
    failure_rate_threshold = min(0.3, avg_failed_attempts + 0.1)
    
    # Geographic confidence (based on historical locations)
    location_confidence = 1.0 - (new_locations / total_locations)
    
    return thresholds
```

This ensures thresholds adapt to each user's normal behavior patterns, reducing false positives.

### Baseline Learning Process

1. **Initial Learning Period**: 30 days of historical data (minimum 10 events)
2. **Continuous Updates**: Baselines updated weekly with new legitimate activity
3. **Seasonal Adjustments**: Accounts for vacation patterns, schedule changes
4. **Feedback Integration**: Analyst validation improves baseline accuracy

## Detection Rules System

### Rule Types

#### 1. Behavioral Rules
Monitor deviations from user baselines:

```json
{
  "rule_name": "Temporal Anomaly Detection",
  "rule_type": "behavioral",
  "severity": "medium",
  "confidence_threshold": 0.7,
  "parameters": {
    "check_temporal_anomaly": true,
    "check_geographic_anomaly": true,
    "check_device_anomaly": true,
    "check_frequency_anomaly": true,
    "baseline_lookback_days": 30,
    "minimum_baseline_events": 10
  }
}
```

#### 2. Correlation Rules
Detect multi-source attack patterns:

```json
{
  "rule_name": "Multi-Source Brute Force",
  "rule_type": "correlation",
  "severity": "high",
  "confidence_threshold": 0.8,
  "parameters": {
    "correlation_window": 300,      // 5 minutes
    "min_sources": 2,               // At least 2 different services
    "pattern_types": ["sequential", "parallel", "distributed"],
    "cross_service_threshold": 5,   // Failed attempts across services
    "ip_correlation_enabled": true,
    "user_correlation_enabled": true
  }
}
```

#### 3. Threshold Rules
Hard limits for obvious attacks:

```json
{
  "rule_name": "High Volume Attack",
  "rule_type": "threshold",
  "severity": "critical",
  "confidence_threshold": 0.9,
  "parameters": {
    "max_failed_attempts": 10,      // Per user per hour
    "max_login_rate": 20,           // Per IP per minute
    "suspicious_countries": ["Country1", "Country2"],
    "blocked_user_agents": ["sqlmap", "nikto"],
    "rapid_fire_threshold": 5       // Attempts per minute
  }
}
```

### Tenant-Specific Rule Configuration

Each tenant can customize detection sensitivity:

```python
# Example: High-security banking tenant
banking_rules = {
    "rule_name": "Banking High Security",
    "confidence_threshold": 0.9,     # Very strict
    "severity": "critical",
    "parameters": {
        "geographic_strict_mode": True,
        "device_change_alert": True,
        "after_hours_sensitivity": 0.95,
        "international_login_block": True,
        "mfa_bypass_detection": True
    }
}

# Example: Development environment
dev_rules = {
    "rule_name": "Development Relaxed",
    "confidence_threshold": 0.6,     # More lenient
    "severity": "low",
    "parameters": {
        "geographic_strict_mode": False,
        "device_change_alert": False,
        "after_hours_sensitivity": 0.3,
        "test_account_exclusions": ["test_*", "dev_*"]
    }
}
```

## Brute-Force Attack Detection Process

### Step 1: Event Analysis
When a login event occurs:

1. **Baseline Comparison**: Compare against user's behavioral baseline
2. **Anomaly Scoring**: Calculate deviation scores for each pattern type
3. **Rule Evaluation**: Apply tenant-specific detection rules
4. **Context Enrichment**: Add geographic, device, and timing context

### Step 2: Multi-Factor Correlation

The system looks for attack patterns across multiple dimensions:

#### Sequential Attacks (Same user, different services)
```python
# Pattern: Attacker tries user@web → user@ssh → user@rdp
correlation_pattern = {
    "type": "sequential",
    "user": "john.doe",
    "sources": ["web_login", "ssh_login", "rdp_login"],
    "time_window": "5 minutes",
    "failure_escalation": True,
    "confidence": 0.85,
    "explanation": "User attempted across multiple services in rapid succession"
}
```

#### Parallel Attacks (Same IP, multiple users)
```python
# Pattern: Multiple users from same IP simultaneously
correlation_pattern = {
    "type": "parallel",
    "source_ip": "203.0.113.1",
    "users": ["user1", "user2", "user3"],
    "simultaneous_attempts": True,
    "dictionary_attack_indicators": True,
    "confidence": 0.92,
    "explanation": "Multiple user accounts targeted from single IP"
}
```

#### Distributed Attacks (Same user, multiple IPs)
```python
# Pattern: Same user from multiple IPs (botnet)
correlation_pattern = {
    "type": "distributed",
    "user": "admin",
    "source_ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
    "geographic_spread": True,
    "botnet_indicators": True,
    "confidence": 0.88,
    "explanation": "Single user targeted from geographically distributed IPs"
}
```

### Step 3: Alert Generation

Alerts are generated only when:

1. **Behavioral deviation** exceeds baseline thresholds
2. **Correlation patterns** match known attack signatures  
3. **Combined confidence score** exceeds rule threshold
4. **Multiple factors** align (not single-point failures)

### Example Detection Scenario

```python
# Real attack detection example:
user_baseline = {
    "typical_hours": [8, 9, 17, 18],
    "typical_countries": ["US"],
    "avg_daily_logins": 3,
    "failure_rate_threshold": 0.1
}

suspicious_event = {
    "timestamp": "03:00 AM",           # ❌ Outside typical hours
    "country": "Romania",              # ❌ New country  
    "failed_attempts": 15,             # ❌ High failure rate
    "user_agent": "Unknown Bot",       # ❌ Suspicious agent
    "source_ip": "203.0.113.1"
}

# Correlation analysis finds:
correlation_data = {
    "same_ip_multiple_users": True,    # ❌ IP attacking multiple accounts
    "rapid_service_switching": True,   # ❌ Web→SSH→RDP attempts
    "geographic_impossibility": True,  # ❌ Login from US then Romania in 5 min
    "pattern_type": "parallel_distributed"
}

# Result: HIGH CONFIDENCE ALERT
alert = {
    "severity": "critical",
    "confidence": 0.94,
    "alert_type": "brute_force_attack",
    "explanation": "Multiple behavioral anomalies + correlation patterns indicate coordinated brute-force attack",
    "evidence": {
        "temporal_anomaly": 0.9,
        "geographic_anomaly": 0.95,
        "correlation_strength": 0.92,
        "failure_rate_anomaly": 0.88
    },
    "recommended_actions": [
        "Block source IP immediately",
        "Force password reset for affected user",
        "Enable additional MFA requirements",
        "Monitor for lateral movement"
    ]
}
```

## Key Benefits

### 1. Low False Positives
- **Adaptive baselines** learn normal user behavior
- **Multi-factor validation** prevents single-point alerts
- **Statistical thresholds** account for natural behavior variation
- **Tenant customization** allows industry-specific tuning

### 2. High Detection Accuracy
- **Correlation analysis** catches sophisticated attacks
- **Cross-service detection** identifies distributed campaigns
- **Behavioral analytics** spot subtle anomalies
- **Pattern recognition** identifies attack methodologies

### 3. Explainable Alerts
Every alert includes:
- **Specific deviations** from baseline with confidence scores
- **Correlation evidence** supporting the alert
- **Attack pattern classification** (sequential, parallel, distributed)
- **Contextual information** for investigation
- **Recommended response actions**

### 4. Continuous Learning
- **Baseline adaptation** improves over time
- **Feedback integration** from analyst validation
- **Seasonal adjustments** for changing user patterns
- **False positive reduction** through machine learning

## Architecture

### High-Level Flow

```
Authentication Sources → Event Ingestion → Detection Engine → Alerts → Dashboard
                                     ↓
                              Database Storage
                                     ↓
                            Behavioral Baselines
```

### Core Components

1. **BehavioralAnalyzer**: Builds adaptive user baselines and detects deviations
2. **CorrelationEngine**: Multi-source attack detection across services
3. **AlertEngine**: Intelligent alert generation with severity classification
4. **BruteForceDetectionEngine**: Main orchestrator for event processing

## Database Schema

### Key Tables

- **authentication_events**: All authentication attempts with context
- **user_behavior_baselines**: Adaptive behavioral patterns per user
- **security_alerts**: Generated alerts with correlation data
- **detection_rules**: Configurable detection rules per tenant
- **correlation_events**: Cross-source event correlation

## API Endpoints

### Event Ingestion
- `POST /api/detection/events/ingest` - Single event ingestion
- `POST /api/detection/events/batch-ingest` - Batch event processing

### Alert Management
- `GET /api/detection/alerts` - Retrieve alerts with filtering
- `PUT /api/detection/alerts/{id}/status` - Update alert status

### Baseline Management
- `GET /api/detection/baselines` - View user baselines
- `POST /api/detection/baselines/rebuild` - Rebuild baselines

### Detection Rules
- `GET /api/detection/rules` - List detection rules
- `POST /api/detection/rules` - Create new rule
- `POST /api/detection/rules/initialize-defaults` - Setup default rules

### Monitoring
- `GET /api/detection/stats` - System statistics
- `GET /api/detection/health` - Health check

## Detection Workflow

### 1. Event Processing
1. Authentication event received via API
2. Event stored in database with full context
3. Active detection rules retrieved for tenant
4. Behavioral analysis performed (if baseline exists)
5. Correlation analysis across recent events
6. Alerts generated based on risk scores
7. Results returned to caller

### 2. Behavioral Analysis
1. Check if user baseline exists
2. If no baseline, attempt to build from historical data
3. Calculate deviations across multiple dimensions:
   - Temporal patterns (login hours, days)
   - Geographic patterns (countries, IPs)
   - Device patterns (user agents, fingerprints)
   - Frequency patterns (login rates, failure rates)
4. Generate risk score from weighted deviations
5. Create alert if risk exceeds threshold

### 3. Correlation Analysis
1. Retrieve recent events within time window
2. Group events by IP address and username
3. Analyze patterns:
   - Multi-source attacks from same IP
   - Cross-service attacks on same user
   - Distributed attacks across IPs
4. Calculate correlation confidence and risk scores
5. Generate correlation alerts for significant patterns

## Frontend Dashboard

### Features
- Real-time statistics (active alerts, 24h metrics, accuracy)
- Filterable alerts table with status management
- Alert detail modal with correlation data
- Auto-refresh every 30 seconds
- Professional UI with severity indicators

### Usage
```vue
<DetectionDashboard />
```

## Configuration

### Default Detection Rules
1. **Behavioral Anomaly Detection** (medium severity, 60% threshold)
2. **Multi-Source Correlation** (high severity, 70% threshold)
3. **High-Frequency Threshold** (high severity, 80% threshold)

### Environment Variables
```bash
DATABASE_URL=postgresql+psycopg2://siem:siempassword@db:5432/siemdb
DETECTION_ENABLED=true
BASELINE_LOOKBACK_DAYS=30
CORRELATION_TIME_WINDOW=15
```

## Usage Examples

### Python Event Ingestion
```python
import requests

def ingest_auth_event(tenant_id, event_data, token):
    url = f"http://localhost:8000/api/detection/events/ingest?tenant_id={tenant_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=event_data)
    return response.json()

# Example usage
event = {
    "username": "user@example.com",
    "event_type": "login_failure",
    "source_type": "web",
    "source_ip": "192.168.1.100",
    "failed_attempts_count": 3
}

result = ingest_auth_event("tenant-123", event, "your-jwt-token")
print(f"Alerts generated: {result['alerts_generated']}")
```

### JavaScript Alert Management
```javascript
async function getActiveAlerts(tenantId, token) {
    const response = await fetch(`/api/detection/alerts?tenant_id=${tenantId}&status=open`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    return await response.json();
}

async function updateAlertStatus(alertId, tenantId, status, token) {
    const response = await fetch(`/api/detection/alerts/${alertId}/status?tenant_id=${tenantId}&status=${status}`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    return await response.json();
}
```

## Deployment

### Docker Setup
```yaml
services:
  api:
    build: ./api
    environment:
      - DATABASE_URL=postgresql+psycopg2://siem:siempassword@db:5432/siemdb
      - DETECTION_ENABLED=true
    depends_on:
      - db
  
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=siemdb
      - POSTGRES_USER=siem
      - POSTGRES_PASSWORD=siempassword
```

### Initialization
```bash
# Start services
docker-compose up -d

# Initialize detection rules for tenant
curl -X POST "http://localhost:8000/api/detection/rules/initialize-defaults?tenant_id=your-tenant-id" \
  -H "Authorization: Bearer your-jwt-token"
```

## Monitoring & Maintenance

### Health Monitoring
```python
def check_system_health():
    response = requests.get("http://localhost:8000/api/detection/health")
    health = response.json()
    return health['status'] == 'healthy'
```

### Performance Queries
```sql
-- Monitor alert generation
SELECT 
    DATE_TRUNC('hour', created_at) as hour,
    COUNT(*) as alerts_generated,
    AVG(confidence_score) as avg_confidence
FROM security_alerts 
WHERE created_at >= NOW() - INTERVAL '24 hours'
GROUP BY hour;

-- Check baseline quality
SELECT 
    tenant_id,
    COUNT(*) as total_baselines,
    AVG(confidence_score) as avg_confidence
FROM user_behavior_baselines
GROUP BY tenant_id;
```

### Maintenance Tasks
```python
# Daily baseline updates
def update_baselines(tenant_id):
    requests.post(f"/api/detection/baselines/rebuild?tenant_id={tenant_id}")

# Cleanup old events (90 days)
def cleanup_old_events():
    query = "DELETE FROM authentication_events WHERE timestamp < NOW() - INTERVAL '90 days'"
    execute_query(query)
```

## Troubleshooting

### Common Issues

**No Alerts Generated**:
- Check if detection rules are initialized
- Verify baseline confidence scores
- Review event ingestion logs

**High False Positives**:
- Increase confidence thresholds
- Improve baseline quality with more training data
- Adjust rule parameters

**Performance Issues**:
- Add database indexes
- Optimize correlation time windows
- Monitor query performance

### Debug Tools
```python
# Trace event processing
def debug_event(event_data):
    event_data['metadata'] = {'debug': True, 'trace_id': str(uuid.uuid4())}
    result = ingest_auth_event(tenant_id, event_data, token)
    return result

# Analyze baseline quality
def check_baseline_quality(tenant_id):
    baselines = get_user_baselines(tenant_id)
    low_confidence = [b for b in baselines if b['confidence_score'] < 0.3]
    return len(low_confidence)
```

## Security Considerations

- All API endpoints require JWT authentication
- Tenant isolation enforced at database level
- Sensitive data encrypted in transit and at rest
- Audit logging for all detection activities
- Rate limiting on API endpoints

## Performance Optimization

- Database connection pooling
- Optimized indexes for time-series queries
- Background processing for baseline updates
- Caching for frequently accessed data
- Horizontal scaling support

This documentation provides a comprehensive guide to understanding, deploying, and maintaining the BITS-SIEM Brute-Force Detection System.
