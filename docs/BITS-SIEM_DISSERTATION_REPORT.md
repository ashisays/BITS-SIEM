# BITS-SIEM: A Modern, Modular Security Information and Event Management System for Intelligent Brute-Force Attack Detection

**Candidate:** [Your Name]
**Supervisor:** [Supervisor's Name]
**Date:** [Date of Submission]

---

## Abstract
This dissertation presents BITS-SIEM, a modular, scalable Security Information and Event Management (SIEM) system designed to address the challenge of detecting brute-force attacks in high-volume environments. Traditional SIEMs often suffer from alert fatigue due to excessive false positives, overwhelming security teams and reducing operational effectiveness. BITS-SIEM aims to solve this by combining real-time event ingestion, intelligent detection logic, and behavioral analysis to accurately identify brute-force attacks while minimizing false alarms. The system leverages a microservices architecture (Ingestion, Processing, API, Notification, Dashboard) built with Python, FastAPI, PostgreSQL, Redis, and Vue.js. Core detection is based on configurable thresholds, time windows, and user baselining. Results from seeded datasets and automated tests demonstrate the system's ability to distinguish genuine user activity from attacks, providing actionable alerts and a responsive dashboard. This work contributes a practical, extensible solution for modern security monitoring.

---

## Table of Contents
1. Abstract ............................................. [Page]
2. List of Figures & Tables ............................. [Page]
3. Chapter 1: Introduction .............................. [Page]
4. Chapter 2: Literature Review ......................... [Page]
5. Chapter 3: System Design and Architecture ............ [Page]
6. Chapter 4: Implementation ............................ [Page]
7. Chapter 5: Testing and Evaluation .................... [Page]
8. Chapter 6: Conclusion and Future Work ................ [Page]
9. References ........................................... [Page]
10. Appendices .......................................... [Page]

---

## List of Figures & Tables
- Figure 1: Architecture Diagram ......................... [Page]
- Figure 2: Sequence Diagram ............................ [Page]
- Figure 3: Module Diagram .............................. [Page]
- Table 1: Test Results Table ........................... [Page]

---

# Chapter 1: Introduction
## 1.1 Background and Motivation
Cybersecurity is increasingly critical for organizations, with threats evolving in complexity and frequency. SIEM systems aggregate, normalize, and analyze security events to provide visibility and enable rapid response. However, traditional SIEMs often generate excessive alerts, many of which are false positives, leading to alert fatigue and missed genuine threats.

## 1.2 Problem Statement
Organizations need a reliable way to detect authentication-based threats, especially brute-force attacks, without overwhelming analysts with alerts triggered by normal user mistakes or benign activity.

## 1.3 Project Aims and Objectives
The primary aim is to design, build, and validate BITS-SIEM—a modern SIEM platform capable of accurately detecting brute-force attacks in real time. Objectives include:
- Implementing a scalable, microservices-based architecture for event ingestion, processing, and alerting.
- Developing robust detection for both single-source and distributed brute-force attacks.
- Reducing false positives by modeling user behavior and analyzing event context.
- Providing real-time notifications and a user-friendly dashboard for threat analysis.

## 1.4 Scope and Delimitations
This project focuses on authentication-based brute-force attack detection using structured syslog events (RFC3164/5424). Validation is performed with seeded datasets and automated tests. Other attack types and unstructured logs are outside the current scope.

## 1.5 Dissertation Structure
The dissertation is organized into six chapters: Introduction, Literature Review, System Design and Architecture, Implementation, Testing and Evaluation, and Conclusion/Future Work.

---

# Chapter 2: Literature Review
## 2.1 Fundamentals of SIEM Systems
SIEM systems have evolved from basic log management to sophisticated platforms integrating correlation, reporting, and real-time analytics. Key functions include log aggregation, normalization, correlation, and alerting. Prominent solutions include open-source (Wazuh, ELK Stack) and commercial (Splunk, QRadar) offerings.

## 2.2 Anatomy of Brute-Force Attacks
Brute-force attacks involve repeated attempts to guess credentials. Types include simple brute-force, dictionary attacks, and credential stuffing. Attacks may originate from a single IP or be distributed across many sources.

## 2.3 Techniques for Threat Detection
Detection methods include:
- Signature-based: Matching known patterns.
- Threshold-based: Counting events over time (e.g., 5 failures in 5 minutes).
- Behavioral/Anomaly: Establishing baselines and flagging deviations.
- Machine Learning: Advanced anomaly detection and classification.
BITS-SIEM primarily uses threshold and behavioral methods for accuracy and simplicity.

## 2.4 The Challenge of False Positives in Security Monitoring
False positives arise from password typos, misconfigurations, or benign user behavior. Excessive alerts cause fatigue and reduce response effectiveness. Strategies for reduction include baselining, contextual analysis, and adaptive thresholds—all incorporated in BITS-SIEM.

---

# Chapter 3: System Design and Architecture
## 3.1 High-Level Architectural Overview
BITS-SIEM uses a microservices architecture for scalability and maintainability. Components include:
- Syslog Sources: Devices sending authentication events.
- Ingestion Service: Receives, parses, enriches, and stores events.
- Processing Service: Analyzes events for threats and generates alerts.
- API Service: REST/WebSocket endpoints for data and notifications.
- Notification Service: Streams alerts to users.
- Dashboard: Vue.js SPA for monitoring and analysis.
- PostgreSQL: Central data store.
- Redis: Caching and streaming.

### Architecture Diagram
```
Syslog Sources --> Ingestion Service --> Processing Service --> API Service --> Dashboard
         |               |                    |                |
         v               v                    v                v
      PostgreSQL <---- Redis <------------ Notification Service
```

## 3.2 Component Breakdown
- **Ingestion Service:** Handles UDP/TCP/TLS syslog, parsing (RFC3164/5424), enrichment (GeoIP, tenant resolution), batching.
- **Processing Service:** Analyzes events, applies detection logic, generates alerts.
- **API Service:** REST/WebSocket for data access and notifications.
- **Notification Service:** Real-time alert streaming.
- **Data Storage:** PostgreSQL (events, users, alerts), Redis (caching, enrichment, streaming).
- **Dashboard:** Vue.js SPA for visualization and interaction.

### Modules Diagram
```
api/
  ├── app.py (main API entrypoint)
  ├── database.py (models, DB logic)
  ├── bruteforce_detection.py (detection rules)
  ├── detection_api.py (detection endpoints)
  ├── config.py (settings)
  ├── models/ (ORM models)
  ├── seed_test_data.py (test data seeder)
  ├── test_seed_data.py (pytest tests)
ingestion/
  ├── main.py (service entrypoint)
  ├── config.py (settings)
  ├── database.py (raw event storage)
  ├── enrichment.py (geo, tenant, metadata)
  ├── listeners.py (UDP/TCP/TLS listeners)
  ├── parsers.py (RFC3164/5424 parsing)
  ├── test_integration.py (integration tests)
processing/
  ├── main.py (service entrypoint)
  ├── alert_manager.py (alert logic)
  ├── stream_processor.py (event streaming)
  ├── threat_detection.py (ML/anomaly detection)
  ├── test_integration.py (tests)
dashboard/
  ├── src/
      ├── App.vue (root component)
      ├── components/ (UI widgets)
      ├── views/ (pages)
      ├── services/ (API/WebSocket)
      ├── store/ (state management)
      ├── router/ (navigation)
```

## 3.3 Data Flow and Sequence of Operations
### Sequence Diagram
```
Device --> Ingestion --> PostgreSQL
Ingestion --> Redis (enrichment)
Processing --> PostgreSQL (fetch events)
Processing --> Notification (send alert)
API --> Dashboard (stream alert)
```

## 3.4 Technology Stack
- Python 3.12+, FastAPI, SQLAlchemy, Alembic, python-jose, psycopg2-binary, pydantic, websockets, uvloop, redis, geoip2, structlog, prometheus-client, pytest, pytest-asyncio, pytest-mock, black, flake8, mypy
- Vue 3, Vite, Pinia, Vue Router, Axios
- Docker, PostgreSQL, Redis

---

# Chapter 4: Implementation
## 4.1 Core Detection Logic: Brute-Force Attacks

The BITS-SIEM Brute-Force Detection System integrates behavioral analytics, adaptive baselines, multi-source correlation, and dynamic rule management to detect brute-force login attacks with minimal false positives.

### Key Features
- **Behavioral Analytics**: Adaptive user behavior baselines with statistical deviation detection.
- **Multi-Source Correlation**: Cross-service attack detection (web, SSH, RDP, VPN, API).
- **Tenant Isolation**: All detection analysis performed within tenant boundaries.
- **Dynamic Thresholds**: Statistical baselines that adapt to user behavior patterns.
- **Real-time Processing**: Event ingestion with immediate analysis and alerting.
- **Confidence Scoring**: All alerts include confidence scores and explainable context.

### Baseline Management System
The baseline management system creates adaptive behavioral profiles for each user by analyzing historical authentication patterns. Baselines evolve with user behavior, minimizing false positives.

#### Baseline Components
- **Temporal Patterns**: Tracks typical login hours, days, and session durations. Alerts are triggered when logins occur outside normal hours with high confidence deviation.
- **Geographic Patterns**: Analyzes usual countries and IPs. Flags logins from new locations, considering travel feasibility.
- **Device & Technology Patterns**: Fingerprints devices and browsers. Detects suspicious new devices or automated tools.
- **Frequency & Failure Patterns**: Monitors login frequency and failure rates, using statistical analysis to detect anomalies.

#### Dynamic Threshold Calculation
Thresholds are calculated using statistical analysis (e.g., mean + 2 standard deviations for login frequency), adapting to each user's normal behavior and reducing false positives.

#### Baseline Learning Process
1. Initial learning period: 30 days of historical data (minimum 10 events).
2. Continuous updates: Baselines updated weekly.
3. Seasonal adjustments: Accounts for vacation and schedule changes.
4. Feedback integration: Analyst validation improves accuracy.

### Detection Rules System
Detection rules are categorized as:
- **Behavioral Rules**: Monitor deviations from user baselines (temporal, geographic, device, frequency).
- **Correlation Rules**: Detect multi-source attack patterns (sequential, parallel, distributed).
- **Threshold Rules**: Hard limits for obvious attacks (e.g., max failed attempts per hour).

Rules are tenant-specific and configurable for sensitivity, allowing industry-specific tuning (e.g., strict for banking, lenient for development).

### Brute-Force Attack Detection Process
1. **Event Analysis**: Each login event is compared against user baselines, scored for anomalies, and evaluated against tenant rules.
2. **Multi-Factor Correlation**: Detects attack patterns across services, users, and IPs (sequential, parallel, distributed).
3. **Alert Generation**: Alerts are generated only when behavioral deviation, correlation patterns, and confidence scores exceed thresholds.

#### Example Detection Scenario
An alert is generated when multiple behavioral anomalies (e.g., login at odd hours, from a new country, high failure rate, suspicious user agent) and correlation patterns (e.g., same IP attacking multiple users, rapid service switching) are detected, with recommended actions such as blocking IP, forcing password reset, and enabling MFA.

### Key Benefits
- **Low False Positives**: Adaptive baselines and multi-factor validation.
- **High Detection Accuracy**: Correlation analysis and cross-service detection.
- **Explainable Alerts**: Each alert includes deviations, evidence, pattern classification, and recommended actions.
- **Continuous Learning**: Baselines adapt over time, integrating analyst feedback and seasonal changes.

### Architecture and Workflow
High-level flow:

Authentication Sources → Event Ingestion → Detection Engine → Alerts → Dashboard
             ↓
           Database Storage
             ↓
         Behavioral Baselines

Core components:
1. **BehavioralAnalyzer**: Builds baselines and detects deviations.
2. **CorrelationEngine**: Detects multi-source attacks.
3. **AlertEngine**: Generates alerts with severity classification.
4. **BruteForceDetectionEngine**: Orchestrates event processing.

### Database Schema
- **authentication_events**: Stores authentication attempts with context.
- **user_behavior_baselines**: Stores adaptive behavioral patterns per user.
- **security_alerts**: Stores generated alerts with correlation data.
- **detection_rules**: Configurable detection rules per tenant.
- **correlation_events**: Stores cross-source event correlation.

### API Endpoints
- `POST /api/detection/events/ingest`: Single event ingestion.
- `POST /api/detection/events/batch-ingest`: Batch event processing.
- `GET /api/detection/alerts`: Retrieve alerts with filtering.
- `PUT /api/detection/alerts/{id}/status`: Update alert status.
- `GET /api/detection/baselines`: View user baselines.
- `POST /api/detection/baselines/rebuild`: Rebuild baselines.
- `GET /api/detection/rules`: List detection rules.
- `POST /api/detection/rules`: Create new rule.
- `POST /api/detection/rules/initialize-defaults`: Setup default rules.
- `GET /api/detection/stats`: System statistics.
- `GET /api/detection/health`: Health check.

### Detection Workflow
1. Authentication event received via API.
2. Event stored in database with full context.
3. Active detection rules retrieved for tenant.
4. Behavioral analysis performed (if baseline exists).
5. Correlation analysis across recent events.
6. Alerts generated based on risk scores.
7. Results returned to caller.

### Troubleshooting and Maintenance
- **No Alerts Generated**: Check detection rule initialization, baseline confidence, and event ingestion logs.
- **High False Positives**: Increase confidence thresholds, improve baseline quality, adjust rule parameters.
- **Performance Issues**: Add DB indexes, optimize correlation windows, monitor query performance.
- **Debug Tools**: Trace event processing, analyze baseline quality.

### Security and Performance Considerations
- All API endpoints require JWT authentication.
- Tenant isolation enforced at database level.
- Sensitive data encrypted in transit and at rest.
- Audit logging for all detection activities.
- Rate limiting on API endpoints.
- Database connection pooling, optimized indexes, background processing, caching, and horizontal scaling support.

This expanded section integrates all technical, operational, and architectural details from the brute-force detection documentation, ensuring the dissertation provides a complete and authoritative reference for the BITS-SIEM brute-force detection system.

## 4.2 Intelligent False Positive Reduction
Strategies include:
- Behavioral Baselining: Learning normal login patterns for each user.
- Sensible Thresholds: Ignoring isolated or low-frequency failures.
- Success-After-Failure Logic: Suppressing alerts after a successful login.
- Contextual Trust: Differentiating between known and unknown source IPs.

## 4.3 Implementation of System Modules
- **Ingestion Service:** Listeners, parsers, enrichment pipeline.
- **API Service:** REST endpoints, JWT authentication, WebSocket notifications.
- **Dashboard:** Vue.js SPA, components, services, Pinia state management.

## 4.4 Database Schema
- **AuthenticationEvent:** Stores login attempts, event type, user, IP, timestamp.
- **SecurityAlert:** Stores detected threats, user, IP(s), type, time window.
- **Users, Tenants:** User and organization metadata.

---

# Chapter 5: Testing and Evaluation
## 5.1 Testing Strategy
Testing combines unit, integration, and end-to-end tests. Docker Compose is used for consistent environments.

## 5.2 Test Data Generation
The seed_test_data.py script creates realistic datasets with normal activity, brute-force bursts, and distributed attack patterns.

## 5.3 Test Scenarios and Results
- **Test Case 1:** test_bruteforce_pattern_present
  - Validates detection of clear brute-force attacks.
- **Test Case 2:** False Positive Avoidance
  - Ensures normal user mistakes do not trigger alerts.
- **Test Case 3:** Distributed Attack Detection
  - Confirms aggregation of failures from multiple IPs.

## 5.4 Evaluation Summary
Results confirm accurate detection and effective false-positive reduction. Configurable thresholds allow tuning for different environments.

---

# Chapter 6: Conclusion and Future Work
## 6.1 Conclusion
BITS-SIEM achieves its goal of accurate, real-time brute-force attack detection with minimal false positives. The modular architecture supports scalability and adaptability.

## 6.2 Limitations
Current limitations include focus on brute-force attacks, reliance on structured logs, and performance not benchmarked at massive scale.

## 6.3 Future Work
- Expand detection to other attack types (port scanning, SQL injection).
- Implement advanced anomaly detection (ML models).
- Enhance dashboard with analytics and incident response features.
- Benchmark and optimize for large-scale deployments.
- Support broader log formats and sources.

---

# References
[List all academic papers, books, technical documentation, and online resources.]

# Appendices (Optional)
- Appendix A: Full source code for key modules.
- Appendix B: docker-compose.yml and configuration files.
- Appendix C: Full list of Python and Node.js dependencies.
