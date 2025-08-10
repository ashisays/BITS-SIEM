# BITS-SIEM Architecture Workflows & Sequence Diagrams


## 🏗️ System Architecture Overview

The BITS-SIEM system uses a microservices architecture with:

- **Dashboard** (Vue.js 3, Vite, Pinia, Vue Router, WebSocket): UI for registration, configuration, monitoring, alerts, multi-tenant management, and real-time notifications.
- **API** (FastAPI, SQLAlchemy, JWT, CSRF, WebSocket): Backend for tenant/user management, configuration, authentication, and alerting. Implements strict role-based access and tenant isolation.
- **Ingestion**: High-performance syslog listeners (UDP, TCP, TLS) with async Python, parsing, enrichment, and tenant resolution.
- **Processing**: Real-time analytics, ML-based anomaly detection, brute-force/port-scan/correlation engines, and alert generation.
- **Storage**: PostgreSQL for persistent, multi-tenant data storage; Redis for caching and message queueing; optional time-series DB for analytics.
- **Notification**: Email, WebSocket, and push notifications for alerts and status updates.

## 📊 Workflow Diagrams

### 1. Overall System Workflow

```mermaid
graph TB
    subgraph "External Sources"
        WS[Web Servers]
        DB[Database Servers]
        FW[Firewalls]
        RT[Routers]
    end
    
    subgraph "Ingestion Layer"
        UDP[UDP Listener :514]
        TCP[TCP Listener :514]
        TLS[TLS Listener :6514]
        PI[Parser & Enricher]
    end
    
    subgraph "Processing Layer"
        SP[Stream Processor]
        TD[Threat Detectors]
        ML[ML Analytics]
        AE[Anomaly Engine]
    end
    
    subgraph "Storage Layer"
        PG[(PostgreSQL)]
        RD[(Redis Cache)]
        TS[(Time-Series DB)]
    end
    
    subgraph "Application Layer"
        API[FastAPI Backend]
        UI[Vue.js Dashboard]
        NT[Notification Service]
    end
    
    subgraph "Users"
        ADM[Admin Users]
        USR[Regular Users]
        SRE[SRE Team]
    end
    
    WS --> UDP
    DB --> TCP
    FW --> TLS
    RT --> UDP
    
    UDP --> PI
    TCP --> PI
    TLS --> PI
    
    PI --> SP
    SP --> TD
    TD --> ML
    ML --> AE
    
    SP --> PG
    SP --> RD
    AE --> TS
    
    PG --> API
    RD --> API
    TS --> API
    
    API --> UI
    API --> NT
    
    UI --> ADM
    UI --> USR
    UI --> SRE
    
    TD --> NT
    AE --> NT

    %% Notes: All API endpoints use JWT authentication and enforce tenant isolation. Real-time notifications are pushed via WebSocket. Error handling and access control are implemented at every layer.
```

### 2. Syslog Ingestion Workflow

```mermaid
graph TB
    subgraph "Data Sources"
        SRC1[Source 1<br/>10.0.1.10]
        SRC2[Source 2<br/>10.0.1.20]
        SRC3[Source 3<br/>10.0.1.30]
    end
    
    subgraph "Ingestion Layer"
        UDP[UDP Listener<br/>:514]
        TCP[TCP Listener<br/>:514]
        TLS[TLS Listener<br/>:6514]
        
        subgraph "Parser Engine"
            RFC3164[RFC3164 Parser]
            RFC5424[RFC5424 Parser]
            CUSTOM[Custom Parser]
        end
        
        subgraph "Enrichment Engine"
            TID[Tenant ID Resolution]
            GEO[Geo-location Lookup]
            META[Metadata Addition]
        end
        
        VLD[Validation & Filtering]
    end
    
    subgraph "Processing Queue"
        QUEUE[Message Queue<br/>Redis/RabbitMQ]
    end
    
    SRC1 -.->|UDP Syslog| UDP
    SRC2 -.->|TCP Syslog| TCP
    SRC3 -.->|TLS Syslog| TLS
    
    UDP --> RFC3164
    TCP --> RFC5424
    TLS --> RFC5424
    
    RFC3164 --> TID
    RFC5424 --> TID
    CUSTOM --> TID
    
    TID --> GEO
    GEO --> META
    META --> VLD
    
    VLD --> QUEUE
    
    style SRC1 fill:#e1f5fe
    style SRC2 fill:#e8f5e8
    style SRC3 fill:#fff3e0
    style QUEUE fill:#f3e5f5
```

### 3. Threat Detection Workflow

```mermaid
graph TB
    subgraph "Input Stream"
        LOGS[Enriched Syslog Messages]
    end
    
    subgraph "Stream Processing"
        FILTER[Message Filtering]
        PARSE[Event Parsing]
        ENRICH[Context Enrichment]
    end
    
    subgraph "Threat Detection Engines"
        BF[Brute Force Detector<br/>5+ failed logins in 5min]
        PS[Port Scan Detector<br/>10+ ports in 10min]
        ANOM[Anomaly Detector<br/>ML-based patterns]
        CUSTOM[Custom Rules Engine]
    end
    
    subgraph "Decision Engine"
        CORRELATE[Event Correlation]
        SCORE[Risk Scoring]
        THRESHOLD[Threshold Evaluation]
    end
    
    subgraph "Response Actions"
        ALERT[Generate Alert]
        NOTIFY[Send Notification]
        BLOCK[Auto-block (Optional)]
        LOG[Log to Database]
    end
    
    LOGS --> FILTER
    FILTER --> PARSE
    PARSE --> ENRICH
    
    ENRICH --> BF
    ENRICH --> PS
    ENRICH --> ANOM
    ENRICH --> CUSTOM
    
    BF --> CORRELATE
    PS --> CORRELATE
    ANOM --> CORRELATE
    CUSTOM --> CORRELATE
    
    CORRELATE --> SCORE
    SCORE --> THRESHOLD
    
    THRESHOLD -->|Above Threshold| ALERT
    THRESHOLD -->|Below Threshold| LOG
    
    ALERT --> NOTIFY
    ALERT --> BLOCK
    ALERT --> LOG
    
    style BF fill:#ffebee
    style PS fill:#fff3e0
    style ANOM fill:#e8f5e8
    style ALERT fill:#ffcdd2
    style NOTIFY fill:#f8bbd9

    %% Notes: Brute-force and port-scan detection logic matches backend code. ML-based anomaly detection and event correlation are implemented in Python. Alerts are generated and pushed to users in real time.
```

### 4. Multi-Tenant Data Flow

```mermaid
graph TB
    subgraph "Tenant A (acme-corp)"
        TA_SRC[Sources<br/>10.0.1.0/24]
        TA_DATA[Tenant A Data]
        TA_USERS[Tenant A Users]
    end
    
    subgraph "Tenant B (beta-industries)"
        TB_SRC[Sources<br/>10.0.2.0/24]
        TB_DATA[Tenant B Data]
        TB_USERS[Tenant B Users]
    end
    
    subgraph "Tenant C (cisco-systems)"
        TC_SRC[Sources<br/>10.0.3.0/24]
        TC_DATA[Tenant C Data]
        TC_USERS[Tenant C Users]
    end
    
    subgraph "Ingestion Layer"
        INGEST[Syslog Ingestion<br/>Multi-protocol]
        TENANT_RESOLVE[Tenant Resolution<br/>Based on Source IP]
    end
    
    subgraph "Processing Layer"
        PROC_A[Processing Pipeline A]
        PROC_B[Processing Pipeline B]
        PROC_C[Processing Pipeline C]
    end
    
    subgraph "Storage Layer"
        PG[(PostgreSQL<br/>Tenant Isolation)]
        REDIS[(Redis Cache<br/>Tenant Prefixed)]
    end
    
    subgraph "SRE Access"
        SRE[SRE Team<br/>Cross-tenant Access]
    end
    
    TA_SRC --> INGEST
    TB_SRC --> INGEST
    TC_SRC --> INGEST
    
    INGEST --> TENANT_RESOLVE
    
    TENANT_RESOLVE -->|Tenant A| PROC_A
    TENANT_RESOLVE -->|Tenant B| PROC_B
    TENANT_RESOLVE -->|Tenant C| PROC_C
    
    PROC_A --> PG
    PROC_B --> PG
    PROC_C --> PG
    
    PROC_A --> REDIS
    PROC_B --> REDIS
    PROC_C --> REDIS
    
    PG --> TA_USERS
    PG --> TB_USERS
    PG --> TC_USERS
    
    PG --> SRE
    REDIS --> SRE
    
    style TA_SRC fill:#e1f5fe
    style TB_SRC fill:#e8f5e8
    style TC_SRC fill:#fff3e0
    style SRE fill:#f3e5f5
```

## 🔄 Sequence Diagrams

### 1. User Authentication and Tenant Access

```mermaid
sequenceDiagram
    participant U as User
    participant UI as Vue.js Dashboard
    participant API as FastAPI Backend
    participant DB as PostgreSQL
    participant REDIS as Redis Cache
    
    U->>UI: Login Request
    UI->>API: POST /api/login {email, password}
    API->>DB: Query User by Email
    DB-->>API: User Record + Tenant Info
    API->>API: Validate Password
    API->>REDIS: Cache User Session
    API-->>UI: JWT Token + User Info
    UI->>UI: Store Token & Redirect
    UI->>API: GET /api/tenant/{tenant_id}/dashboard
    API->>API: Validate JWT & Tenant Access
    API->>DB: Query Tenant Data
    DB-->>API: Tenant Dashboard Data
    API-->>UI: Dashboard Data
    UI-->>U: Display Dashboard
    
    Note over U,REDIS: Multi-tenant access, role-based permissions, and session management are enforced by JWT claims and backend validation. CSRF protection is applied to all state-changing operations.
```

### 2. Syslog Ingestion and Processing Sequence

```mermaid
sequenceDiagram
    participant SRC as Log Source
    participant ING as Ingestion Service
    participant PARSE as Parser Engine
    participant ENRICH as Enrichment Engine
    participant PROC as Processing Service
    participant DETECT as Threat Detection
    participant DB as PostgreSQL
    participant NOTIFY as Notification Service
    
    SRC->>ING: Syslog Message (UDP/TCP/TLS)
    ING->>PARSE: Raw Syslog Data
    PARSE->>PARSE: Parse RFC3164/5424
    PARSE->>ENRICH: Parsed Message
    ENRICH->>ENRICH: Resolve Tenant ID
    ENRICH->>ENRICH: Add Geo-location
    ENRICH->>ENRICH: Add Metadata
    ENRICH->>PROC: Enriched Message
    PROC->>DETECT: Stream to Threat Detection
    PROC->>DB: Store Raw Log
    DETECT->>DETECT: Apply Detection Rules
    alt Threat Detected
        DETECT->>DB: Store Alert
        DETECT->>NOTIFY: Send Alert Notification
        NOTIFY->>NOTIFY: Send Email/Web Alert
    else No Threat
        DETECT->>DB: Store Normal Event
    end
    
    Note over SRC,NOTIFY: Real-time processing with tenant isolation
```

### 3. Threat Detection and Alerting Sequence

```mermaid
sequenceDiagram
    participant LOGS as Log Stream
    participant BF as Brute Force Detector
    participant PS as Port Scan Detector
    participant ML as ML Analytics
    participant CORR as Correlation Engine
    participant ALERT as Alert Manager
    participant DB as PostgreSQL
    participant NOTIFY as Notification Service
    participant USER as User Dashboard
    
    LOGS->>BF: Authentication Events
    LOGS->>PS: Network Connection Events
    LOGS->>ML: All Events for Analysis
    
    BF->>BF: Count Failed Logins
    alt 5+ Failed Logins in 5min
        BF->>CORR: Brute Force Alert
    end
    
    PS->>PS: Count Port Connections
    alt 10+ Ports in 10min
        PS->>CORR: Port Scan Alert
    end
    
    ML->>ML: Pattern Analysis
    alt Anomaly Detected
        ML->>CORR: Anomaly Alert
    end
    
    CORR->>CORR: Correlate Events
    CORR->>CORR: Calculate Risk Score
    alt Risk Score > Threshold
        CORR->>ALERT: Generate Alert
        ALERT->>DB: Store Alert Record
        ALERT->>NOTIFY: Send Notification
        NOTIFY->>USER: Real-time Alert
    else Risk Score <= Threshold
        CORR->>DB: Store Event Only
    end
    
    Note over LOGS,USER: Multi-layered threat detection with correlation
```

### 4. Real-time Notification Sequence

```mermaid
sequenceDiagram
    participant DETECT as Threat Detection
    participant ALERT as Alert Manager
    participant DB as PostgreSQL
    participant EMAIL as Email Service
    participant WS as WebSocket Service
    participant UI as User Dashboard
    participant MOBILE as Mobile App
    
    DETECT->>ALERT: Threat Detected
    ALERT->>DB: Store Alert Record
    ALERT->>ALERT: Determine Notification Recipients
    
    par Email Notifications
        ALERT->>EMAIL: Send Email Alert
        EMAIL->>EMAIL: Format Email Template
        EMAIL->>EMAIL: Send to Recipients
    and Web Notifications
        ALERT->>WS: Send WebSocket Message
        WS->>UI: Real-time Alert Push
        UI->>UI: Display Alert Badge
    and Mobile Push
        ALERT->>MOBILE: Send Push Notification
        MOBILE->>MOBILE: Display Mobile Alert
    end
    
    UI->>DB: Mark Alert as Read
    DB-->>UI: Update Status
    
    Note over DETECT,MOBILE: Multi-channel notification delivery
```

## 🎯 Threat Detection Use Cases Implementation

### 1. Brute Force Attack Detection

**Logic**: Multiple failed logins from same IP within time window

```python
def detect_brute_force(event):
    if event.type == "authentication_failure":
        key = f"failed_logins:{event.source_ip}"
        count = redis.incr(key)
        redis.expire(key, 300)  # 5 minute window
        
        if count >= 5:
            return create_alert(
                type="brute_force",
                severity="critical",
                source_ip=event.source_ip,
                tenant_id=event.tenant_id
            )

# Matches backend implementation: see `bruteforce_detection.py` for actual logic and alert creation.
```

### 2. Port Scanning Detection

**Logic**: Multiple connection attempts to different ports from same IP

```python
def detect_port_scan(event):
    if event.type == "connection_attempt":
        key = f"port_scan:{event.source_ip}"
        ports = redis.sadd(key, event.destination_port)
        redis.expire(key, 600)  # 10 minute window
        
        if ports >= 10:
            return create_alert(
                type="port_scan",
                severity="warning",
                source_ip=event.source_ip,
                tenant_id=event.tenant_id
            )

# Matches backend implementation: see `bruteforce_detection.py` for actual logic and alert creation.
```

## 🚀 Implementation Phases

### Phase 1: Core Ingestion Services
- Multi-protocol syslog listeners (UDP/TCP/TLS)
- Message parsing and validation
- Tenant resolution and enrichment
- Basic storage integration

### Phase 2: Processing and Analytics
- Stream processing pipeline
- Basic threat detection rules
- Alert generation and storage
- Notification integration

### Phase 3: ML-Enhanced Detection
- Anomaly detection algorithms
- Behavioral analytics
- Advanced correlation rules
- Machine learning model training

### Phase 4: Advanced Features
- Custom rule engine
- Advanced reporting
- Performance optimization
- Horizontal scaling

## 🔧 Technical Stack

### Ingestion Layer

### Ingestion Layer
- **Languages**: Python (asyncio)
- **Protocols**: UDP, TCP, TLS syslog
- **Libraries**: asyncio, socket, ssl

### Processing Layer
- **Stream Processing**: Redis Streams (default), optional Apache Kafka
- **ML Libraries**: scikit-learn, TensorFlow
- **Analytics**: Pandas, NumPy

### Storage Layer
- **Primary**: PostgreSQL (multi-tenant, SQLAlchemy ORM)
- **Cache/Queue**: Redis (caching, message queue, session store)
- **Time-series**: InfluxDB or TimescaleDB (optional)

### Integration
- **API**: FastAPI (JWT, CSRF, WebSocket, SQLAlchemy)
- **Frontend**: Vue.js 3, Vite, Pinia, Vue Router, WebSocket
- **Notifications**: Email, WebSocket, Push

### Security & Error Handling
- **Authentication**: JWT, session management, CSRF protection
- **Role-based Access**: Admin, SRE, User roles
- **Tenant Isolation**: Enforced at API and database layers
- **Error Handling**: Comprehensive backend and frontend error reporting

This architecture provides a robust, scalable, and secure SIEM solution with multi-tenant support, advanced threat detection, and real-time alerting.

## 🧪 Test Dataset & How to Run

To validate features end-to-end, a reproducible test dataset and tests are included.

### What it seeds
- Multi-tenant base data (tenants, users, sources, notifications, reports) via `api/init_database.py`
- Realistic AuthenticationEvent patterns (normal, brute-force burst, distributed failures) via `api/seed_test_data.py`
- Optional UserBehaviorBaseline construction and default DetectionRule initialization when available

### How to use
1) Ensure PostgreSQL is reachable and `DATABASE_URL` is set (see `api/alembic.ini` for example URL).
2) Initialize base data:
    - In `api/`: run `python init_database.py`
3) Seed test dataset:
    - In `api/`: run `python seed_test_data.py`
    - Or seed a single tenant: `python seed_test_data.py acme-corp`
4) Run dataset smoke tests (optional):
    - In `api/`: run `pytest -q` (requires `pytest` in `api/requirements.txt`)

The dataset covers both normal behavior and attack patterns to exercise detection and correlation logic used by the backend.
