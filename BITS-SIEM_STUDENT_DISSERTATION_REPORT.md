# BITS-SIEM: A Modern, Modular Security Information and Event Management System for Intelligent Brute-Force Attack Detection

**Candidate:** [Your Name]
**Supervisor:** [Supervisor's Name]
**Date:** [Date of Submission]

---

## Abstract
This dissertation explores the design and implementation of BITS-SIEM, a student-built, modular SIEM platform focused on detecting brute-force attacks in real time. The project addresses the challenge of alert fatigue in traditional security systems by combining smart event analysis, behavioral baselining, and configurable detection logic. Using Python, FastAPI, PostgreSQL, Redis, and Vue.js, BITS-SIEM demonstrates how a microservices approach can deliver accurate threat detection and reduce false positives, making security monitoring more effective and less overwhelming for teams.

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
As cyber threats keep growing, organizations need better ways to spot attacks fast. SIEM systems help by collecting and analyzing security events, but they often flood teams with too many alerts—most of which aren’t real threats. This project aims to build a SIEM that’s smarter about what really matters.

## 1.2 Problem Statement
How can we detect brute-force attacks (lots of failed logins) without overwhelming security teams with alerts every time someone forgets their password?

## 1.3 Project Aims and Objectives
- Build a scalable SIEM using microservices.
- Detect both single-source and distributed brute-force attacks.
- Cut down on false positives by learning normal user behavior.
- Give users a dashboard with real-time alerts and easy navigation.

## 1.4 Scope and Delimitations
This project focuses on authentication-based brute-force attacks using structured syslog events. Other attack types and unstructured logs are outside the current scope.

## 1.5 Dissertation Structure
The report covers background, related work, system design, implementation, testing, and future improvements.

---

# Chapter 2: Literature Review
## 2.1 Fundamentals of SIEM Systems
SIEMs started as simple log managers and now do real-time analytics, correlation, and reporting. Popular tools include Wazuh, ELK Stack, Splunk, and QRadar.

## 2.2 Anatomy of Brute-Force Attacks
Brute-force attacks mean lots of login attempts, hoping to guess a password. They can come from one IP or many (distributed attacks).

## 2.3 Techniques for Threat Detection
- Signature-based: Look for known patterns.
- Threshold-based: Count events (e.g., 5 failures in 5 minutes).
- Behavioral: Learn what’s normal and flag weird stuff.
- Machine Learning: Use models to spot anomalies.
BITS-SIEM uses threshold and behavioral methods for simplicity and accuracy.

## 2.4 The Challenge of False Positives
False positives happen when normal mistakes (like typos) trigger alerts. Too many alerts mean real threats get missed. BITS-SIEM uses baselining and context to keep alerts meaningful.

---

# Chapter 3: System Design and Architecture
## 3.1 High-Level Architectural Overview
BITS-SIEM is built with microservices for flexibility and scale. Main parts:
- Syslog Sources: Devices sending events.
- Ingestion Service: Listens, parses, enriches, and stores events.
- Processing Service: Analyzes events and creates alerts.
- API Service: REST/WebSocket for data and notifications.
- Notification Service: Sends alerts to users.
- Dashboard: Vue.js SPA for monitoring.
- PostgreSQL: Stores all data.
- Redis: Caching and streaming.

### Architecture Diagram
```
Syslog Sources --> Ingestion Service --> Processing Service --> API Service --> Dashboard
         |               |                    |                |
         v               v                    v                v
      PostgreSQL <---- Redis <------------ Notification Service
```

## 3.2 Component Breakdown
- **Ingestion Service:** Handles syslog (UDP/TCP/TLS), parses RFC3164/5424, enriches with tenant/geo info, batches events.
- **Processing Service:** Runs detection logic, generates alerts.
- **API Service:** REST/WebSocket endpoints, authentication.
- **Notification Service:** Real-time alert streaming.
- **Data Storage:** PostgreSQL (events, users, alerts), Redis (cache, enrichment, streaming).
- **Dashboard:** Vue.js SPA for visualization.

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
The detection algorithm collects login events in a time window (like 5 minutes), counts failed logins by user and IP, and checks if the count passes a threshold (like 5 failures). If lots of IPs hit the same user, it’s flagged as distributed. Alerts are sent to the dashboard. Example pseudocode:
```python
for user in users:
    failures = get_auth_events(user_id=user.id, event_type='login_failure', window=BRUTE_FORCE_WINDOW)
    ip_counts = count_failures_by_ip(failures)
    for ip, count in ip_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            create_security_alert(user_id=user.id, source_ip=ip, count=count, type='brute_force')
```

## 4.2 Intelligent False Positive Reduction
- Learn normal login patterns for each user.
- Ignore isolated or low-frequency failures.
- Suppress alerts if a user logs in successfully after a few mistakes.
- Trust known IPs and flag weird ones.

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
Unit, integration, and end-to-end tests. Docker Compose for environment.

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
BITS-SIEM meets its goal of accurate, real-time brute-force attack detection with minimal false positives. The modular design makes it easy to scale and adapt.

## 6.2 Limitations
Focuses on brute-force attacks and structured logs. Performance at massive scale not benchmarked yet.

## 6.3 Future Work
- Add detection for other attacks (port scanning, SQL injection).
- Implement advanced anomaly detection (ML models).
- Enhance dashboard with analytics and incident response features.
- Benchmark and optimize for large-scale deployments.
- Support more log formats and sources.

---

# References
[List all academic papers, books, technical documentation, and online resources.]

# Appendices (Optional)
- Appendix A: Full source code for key modules.
- Appendix B: docker-compose.yml and configuration files.
- Appendix C: Full list of Python and Node.js dependencies.
