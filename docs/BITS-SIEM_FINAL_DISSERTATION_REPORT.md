# BITS-SIEM_FINAL_DISSERTATION_REPORT.md

Cover Page
- Title: BITS-SIEM: A Cloud-Native Multi-Tenant SIEM for Real-Time Threat Detection and Alerting
- Student Name: [Your Name]
- Student ID: [Your ID]
- Program: Cloud Computing
- Department: [Department Name]
- Institution: Birla Institute of Technology and Science (BITS)
- Supervisor: [Supervisor Name]
- Date of Submission: [Month DD, YYYY]

Title page (inner cover)
BITS-SIEM: A Cloud-Native Multi-Tenant SIEM for Real-Time Threat Detection and Alerting
A Final Year Dissertation submitted in partial fulfillment of the requirements for the degree of [Degree Name]
by [Your Name], [Your ID]
Under the supervision of [Supervisor Name]
Department of [Dept], Birla Institute of Technology and Science (BITS)
[Month, Year]

Certificate from the supervisor
This is to certify that the dissertation titled “BITS-SIEM: A Cloud-Native Multi-Tenant SIEM for Real-Time Threat Detection and Alerting” is a bonafide work carried out by [Your Name], [Your ID], under my supervision in the Department of [Dept], BITS. The work has not been submitted to any other Institution for any other degree/diploma.
Supervisor: [Supervisor Name]
Signature: ___________
Date: [Date]

Acknowledgements
I would like to express my gratitude to my supervisor, [Supervisor Name], for continuous guidance and encouragement. I also thank the faculty and peers in the [Dept], BITS for their valuable feedback. Finally, thanks to my family and friends for their unwavering support.

Abstract
Security Information and Event Management (SIEM) systems centralize log ingestion, correlation, and alerting across diverse sources. This dissertation presents BITS-SIEM, a cloud-native, multi-tenant SIEM built with Python (FastAPI/async) and Vue.js that ingests syslog data, enriches and processes events in real time, detects threats (brute-force, port scans), and notifies users via WebSocket, email, and webhooks. The architecture comprises modular microservices (api, ingestion, processing, notification, dashboard) using Redis for streaming/caching and PostgreSQL for persistence, with tenant isolation enforced across layers. Extensive tests validate correctness and pipeline behavior. The result is an extensible, observable, and scalable SIEM foundation appropriate for education and research.

Table of contents
1. Introduction
2. Background and Literature Review
3. Problem Statement and Objectives
4. System Architecture
5. Detailed Design and Implementation
6. Data Model and Database Schema
7. Threat Detection and False Positive Reduction
8. Stream Processing and Scalability
9. API Design and Security
10. Frontend (Dashboard) Architecture
11. Notification System
12. Deployment and DevOps
13. Observability and Monitoring
14. Testing and Validation
15. Results and Discussion
16. Limitations
17. Conclusions
18. Recommendations / Future Work
19. Appendices
20. Bibliography / References
21. List of Publications / Presentations
22. Checklist of Items

List of Symbols & Abbreviations used
- SIEM: Security Information and Event Management
- API: Application Programming Interface
- JWT: JSON Web Token
- CSRF: Cross-Site Request Forgery
- RBAC: Role-Based Access Control
- ER: Entity-Relationship
- UDP/TCP/TLS: Transport Protocols
- AOF: Append-Only File (Redis persistence)
- KPI: Key Performance Indicator

List of Tables / Figures
Tables
- Table 1: Core Entities and Relationships (Tenants, Users, Sources, Reports)
- Table 2: Detection Rules and Parameters
- Table 3: Metrics and Health Endpoints
- Table 4: Test Suite Overview and Coverage

Figures
- Figure 1: High-Level System Architecture (Microservices)
- Figure 2: Event Processing Pipeline
- Figure 3: Deployment Topology (Docker Compose)
- Figure 4: Database ER Diagram (Core + Advanced Detection)
- Figure 5: Dashboard Component Structure

### Table 5: Key Environment Variables
| Variable | Service | Description |
| --- | --- | --- |
| `DATABASE_URL` | api, ingestion, processing | Full PostgreSQL connection string. |
| `REDIS_HOST` | api, ingestion, processing, notification | Hostname for the Redis server. |
| `REDIS_PORT` | api, ingestion, processing, notification | Port for the Redis server. |
| `POSTGRES_DB` | postgres | Name of the PostgreSQL database. |
| `POSTGRES_USER` | postgres | Username for the PostgreSQL database. |
| `POSTGRES_PASSWORD` | postgres | Password for the PostgreSQL database. |
| `JWT_SECRET_KEY` | api | Secret key for signing JWT tokens. |
| `VITE_API_BASE_URL` | dashboard | Base URL for the API service. |
| `VITE_NOTIFICATION_WS_URL` | dashboard | WebSocket URL for the notification service. |


1. Introduction
Enterprises rely on SIEM platforms for timely detection and response to security threats. BITS-SIEM explores the design and implementation of a cloud-native, multi-tenant SIEM focusing on real-time analytics, extensibility, and developer-friendly operations. The project aims to deliver an end-to-end pipeline—log ingestion to alert visualization—with clear separation of concerns and robust observability.

Scope
- Multi-tenant isolation across ingestion, processing, storage, and UI
- Real-time detection for brute-force and port-scan scenarios
- Flexible notifications (WebSocket, email, webhooks)
- Containerized deployment (Docker Compose)

Contributions
- Modular microservices architecture with Redis Streams-based messaging
- Pluggable detection engines and false positive reduction strategies
- Tenant-aware configuration and access control
- Comprehensive tests and documentation

2. Background and Literature Review
- SIEM Fundamentals: Collection, normalization, correlation, alerting.
- Multi-Tenancy: Logical isolation for tenants; implemented in DB models and service flows.
- Streaming Analytics: Redis Streams consumer groups enable horizontal scaling and at-least-once processing semantics suitable for real-time SIEM workflows.
- Behavior-based Detection: Baselines and adaptive thresholds reduce false positives relative to static rules.
- Technology Selection: Python FastAPI (rapid API development; async support), Vue.js (reactive UI), Redis (low-latency caching/streaming), PostgreSQL (robust RDBMS), Docker (reproducibility).

3. Problem Statement and Objectives
Problem: Build a cloud-native SIEM that ingests and analyzes syslog data in real time with tenant isolation, robust detection, and actionable notifications via a web dashboard.

Objectives
- Architectural modularity with independent scaling per service
- Pluggable detection algorithms (brute force, port scan, extensible hooks for ML)
- Tenant isolation: tenant_id propagated across events, models, and alerts
- Strong observability: structured logs, Prometheus metrics, health checks
- Documented workflows and tests to demonstrate correctness

4. System Architecture
Microservices (from repository structure)
- api/ (FastAPI): Authentication, tenant/config management, detection endpoints; CSRF/JWT security, fallback modes
- ingestion/: Multi-protocol syslog listeners, parsing, enrichment, Redis Streams publishing
- processing/: Stream processing, threat detection, false positive reduction, alert management
- notification/: WebSocket server, email/webhook delivery, preferences
- dashboard/: Vue.js frontend for monitoring, configuration, and visualization
- Data layer: PostgreSQL (persistence), Redis (cache/streaming)

Inter-service data flow
- Ingestion publishes to Redis stream siem:raw_messages
- Processing consumes batches, converts to ProcessedEvent, runs engines, and triggers alert_manager/notifications
- API exposes detection endpoints, reads/writes DB models (when available)

Key design principles
- Scalability: consumer groups, batch processing, independent service scaling
- Fault tolerance: API fallback without DB; mock Redis paths for tests in processing layer
- Extensibility: clear engine interfaces; enhanced detection and FP reduction layers are drop-in modules

5. Detailed Design and Implementation
5.1 Configuration Management (api/config.py)
- Environment-driven settings: DB URL, SIEM base IP/port, JWT/CSRF, API CORS, debug
- SIEM server config per tenant via generate_tenant_siem_config (protocol-derived port logic: UDP=514, TCP/TLS=601)
- Secure password generation with character-set policy
- Validation and .env generation via tests/generate_config.py

5.2 Ingestion Service (ingestion/)
- parsers.py: RFC3164/RFC5424 parsing; SyslogMessage dataclass; resilient timestamp parsing; structured-data handling
- enrichment.py: TenantResolver (IP range-to-tenant mapping with Redis caching), GeoLocationService (GeoIP2 optional), MetadataEnricher (classification, facility/severity mapping)
- main.py: MessageProcessor batches messages using config thresholds, persists to DB, and xadd to siem:raw_messages

5.3 Processing Service (processing/)
- stream_processor.py: RedisStreamBackend with consumer group siem-processing; ProcessedEvent dataclass fields (id, tenant_id, source_ip, timestamp, event_type, severity, message, raw_data, enriched_data, risk_score, tags)
- threat_detection.py: BruteForceDetectionEngine and PortScanDetectionEngine with Redis state; keys like brute_force:{tenant}:{ip} and brute_force_attempts:...
- enhanced_detection.py: Adaptive thresholds (adaptive_threshold:brute_force:{tenant}:{user}), time-based analysis, geographic intelligence, service-account detection
- false_positive_reduction.py: Static whitelist (static_whitelist:{tenant}:{entry_type}), dynamic whitelist (dynamic_whitelist:active:{tenant}), business hours, user behavior profiles
- alert_manager.py: ManagedAlert lifecycle; correlation engine with Redis; SQLAlchemy models AlertModel, AlertRuleModel
- main.py: Prometheus metrics (e.g., siem_events_processed_total, siem_threats_detected_total, siem_processing_duration_seconds), health checks, background tasks (cleanup, health, metrics)

5.4 API Service (api/)
- app.py: FastAPI app; CORS; JWT, CSRF middleware (X-CSRF-Token); includes routers detection_api.py and false_positive_api.py when available; fallback user data when DB unavailable
- detection_api.py: Endpoints /api/detection/events/ingest, /batch-ingest, /alerts, etc.; request/response models; DB interactions via database_working.py
- database_working.py: SQLAlchemy models (Tenant, TenantConfig, User, Source, Notification, Report); init_db bootstraps sample tenants/users; connection pooling and pre-ping

5.5 Notification Service (notification/)
- main.py: FastAPI-based WebSocket endpoint and email/webhook logic; NotificationMessage dataclass; rate limiting and templates

5.6 Dashboard (dashboard/)
- Vue 3 app with Vite; components for SIEM setup, sources, alerts, admin; composables (useAuth), router, Pinia (where used); WS integration

6. Data Model and Database Schema
The BITS-SIEM database is designed to support a multi-tenant architecture with detailed data logging for security events and threat detection. The schema is implemented using SQLAlchemy ORM and includes tables for core entities as well as advanced threat detection.

### Core Entities
These tables form the foundation of the SIEM, managing tenants, users, and basic security data.

- **`tenants`**: Stores information about each organization using the SIEM.
  - `id`, `name`, `description`, `user_count`, `sources_count`, `status`, `created_at`, `updated_at`
- **`users`**: Manages user accounts, roles, and tenant associations.
  - `id`, `email`, `name`, `password`, `role` (sre/admin/user), `tenant_id`, `tenants_access`, `is_active`, `created_at`, `updated_at`
- **`sources`**: Tracks data sources for each tenant.
  - `id`, `name`, `type`, `ip`, `port`, `protocol`, `status`, `tenant_id`, `notifications`, `last_activity`, `created_at`, `updated_at`
- **`notifications`**: Stores system and security notifications.
  - `id`, `message`, `severity`, `tenant_id`, `is_read`, `meta_data`, `created_at`
- **`reports`**: Contains generated security reports.
  - `id`, `title`, `summary`, `report_type`, `tenant_id`, `generated_by`, `data`, `created_at`

### Advanced Detection Schema
These tables support the advanced threat detection capabilities of the system.

- **`authentication_events`**: Logs all authentication attempts with rich context.
  - `id`, `tenant_id`, `user_id`, `username`, `event_type`, `source_type`, `source_ip`, `user_agent`, `country`, `device_fingerprint`, `timestamp`
- **`user_behavior_baselines`**: Stores adaptive behavioral baselines for each user.
  - `id`, `tenant_id`, `user_id`, `typical_login_hours`, `typical_countries`, `typical_devices`, `avg_daily_logins`, `last_updated`
- **`detection_rules`**: Manages configurable detection rules for each tenant.
  - `id`, `tenant_id`, `rule_name`, `rule_type`, `is_enabled`, `severity`, `parameters`, `created_at`
- **`security_alerts`**: Stores generated security alerts from the detection engine.
  - `id`, `tenant_id`, `alert_type`, `title`, `description`, `severity`, `confidence_score`, `status`, `created_at`
- **`correlation_events`**: Logs events that are correlated across multiple sources.
  - `id`, `tenant_id`, `correlation_id`, `event_type`, `username`, `source_ip`, `involved_sources`, `event_count`, `time_window`, `first_event_time`, `last_event_time`

7. Threat Detection and False Positive Reduction
The threat detection capabilities of BITS-SIEM are designed to identify common attack patterns in real time. The system employs several detection engines that analyze processed events and generate alerts when malicious activity is suspected.

### 7.1 Brute-Force Detection
The brute-force detection engine identifies repeated failed login attempts from a single IP address. It uses Redis to maintain a sliding window of failed authentication events.

- **State Management**: The engine uses the following Redis keys to track failed login attempts:
  - `brute_force:{tenant_id}:{ip}`: A counter for the number of failed logins from a specific IP address within the defined time window.
  - `brute_force_attempts:{tenant_id}:{ip}`: A list that stores details of recent failed attempts for evidence.
- **Detection Logic**: When the number of failed attempts from an IP exceeds the configured threshold (`config.threat_detection.brute_force_threshold`) within the time window (`config.threat_detection.brute_force_window`), an alert is generated.
- **Confidence and Severity**: The confidence score of the alert is calculated based on how much the attempt count exceeds the threshold. The severity is then determined based on this confidence score (e.g., `critical` for high confidence, `warning` for medium confidence).

### 7.2 Port Scan Detection
The port scan detection engine monitors for patterns of a single IP connecting to multiple ports on one or more hosts within a short time frame.

- **State Management**: The engine uses these Redis keys:
  - `port_scan:{tenant_id}:{ip}`: A set that stores the unique ports accessed by a specific IP address within the time window.
  - `port_scan_details:{tenant_id}:{ip}`: A list that stores details of the connections for evidence.
- **Detection Logic**: An alert is triggered when the number of unique ports accessed by an IP exceeds the configured threshold (`config.threat_detection.port_scan_threshold`) within the time window (`config.threat_detection.port_scan_window`).
- **Scan Classification**: The engine classifies the scan type (e.g., `comprehensive_scan`, `service_discovery`, `admin_service_scan`) based on the range and type of ports accessed, which helps in determining the alert's severity.

### 7.3 False Positive Reduction
To improve the accuracy of alerts and reduce noise, BITS-SIEM implements a multi-layered false positive reduction engine. This engine analyzes alerts in the context of known legitimate behavior and operational patterns before they are sent as notifications.

- **Static Whitelisting**: Administrators can define static whitelists for IP addresses, network ranges, and user agents that are known to be safe. These are stored in Redis under keys like `static_whitelist:{tenant_id}:{entry_type}`.

- **Dynamic Whitelisting**: The system can automatically whitelist IP addresses that have a consistent history of successful authentications. This is managed using Redis keys such as `dynamic_whitelist:active:{tenant_id}`.

- **Behavioral Analysis**: The engine builds behavioral profiles for users, learning their typical login hours, locations, and devices. Alerts that deviate from these profiles are given higher risk scores, while those that conform may be suppressed. Profiles are stored in Redis under keys like `behavior_profile:{tenant_id}:{user_identifier}`.

- **Business Hours Context**: The system allows for the configuration of business hours, holidays, and maintenance windows. Alerts generated outside of normal operating hours can be treated with a higher level of scrutiny. This configuration is stored in Redis under keys like `business_hours:{tenant_id}`.

8. Stream Processing and Scalability (processing/stream_processor.py)
- Redis Streams consumer groups (siem-processing) with batch size and block time from config.stream
- Backpressure via blocking reads and bounded maxlen on produced topics
- Alternative Kafka backend scaffold (KafkaStreamBackend) for higher scale

9. API Design and Security
The BITS-SIEM API is a RESTful service built with FastAPI that provides a comprehensive set of endpoints for managing the entire SIEM workflow, from event ingestion to alert management and system configuration. The API is designed with security and multi-tenancy as core principles.

### Authentication and Authorization
- **Authentication**: The API uses JSON Web Tokens (JWT) for authenticating requests. Clients must include a valid JWT in the `Authorization` header as a Bearer token.
- **Authorization**: Role-Based Access Control (RBAC) is implemented to restrict access to certain endpoints based on user roles (e.g., `sre`, `admin`, `user`).
- **CSRF Protection**: To prevent Cross-Site Request Forgery attacks, the API implements CSRF protection using the `X-CSRF-Token` header for all state-changing operations.

### API Endpoints
The API is organized into several logical groups of endpoints:

#### Detection API (`/api/detection`)
| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /events/ingest | Ingests a single authentication event. |
| POST | /events/batch-ingest | Ingests a batch of authentication events. |
| GET | /alerts | Retrieves a list of security alerts with filtering and sorting options. |
| GET | /alerts/stats | Retrieves statistics about security alerts. |
| PUT | /alerts/{alert_id}/status | Updates the status of a specific security alert. |
| GET | /baselines | Retrieves user behavior baselines. |
| POST | /baselines/rebuild | Initiates a rebuild of user behavior baselines. |
| GET | /rules | Retrieves detection rules. |
| POST | /rules | Creates a new detection rule. |
| GET | /stats | Retrieves overall detection statistics. |
| GET | /health | Checks the health of the detection service. |

#### False Positive API (`/api/false-positive`)
| Method | Endpoint | Description |
| --- | --- | --- |
| POST | /whitelist | Adds an entry to the whitelist. |
| DELETE | /whitelist | Removes an entry from the whitelist. |
| GET | /whitelist/check | Checks if a value is whitelisted. |
| POST | /business-hours | Sets the business hours configuration. |
| GET | /business-hours/check | Checks if a timestamp is within business hours. |
| GET | /user-profile | Retrieves a user's behavioral profile. |
| POST | /user-profile/rebuild | Initiates a rebuild of a user's behavioral profile. |
| GET | /stats | Retrieves statistics on false positive reduction. |
| GET | /health | Checks the health of the false positive reduction service. |

10. Frontend (Dashboard) Architecture
- Vue 3 + Vite; components: alerts, admin tenants/users, SIEM setup, notifications; composables (useAuth) manage session and tokens
- WebSocket connection to notification service (VITE_NOTIFICATION_WS_URL)
- Axios calls to API (VITE_API_BASE_URL)

11. Notification System (notification/main.py)
- WebSocket server for live alerts; email via SMTP; webhook integration via aiohttp
- Templates for security events (e.g., brute force) with contextual variables
- Preferences and rate limiting planned in code structure

12. Deployment and DevOps
The deployment of BITS-SIEM is managed through Docker Compose, allowing for a consistent and reproducible environment across different machines. The deployment process is automated using shell scripts that handle the configuration, startup, and initialization of the services.

- **`docker-compose.yml`**: This file defines the multi-container application, specifying the services, networks, and volumes required to run the SIEM. It includes services for the API, ingestion and processing engines, notification service, dashboard, Redis, PostgreSQL, and Nginx.

- **`run_bits_siem.sh`**: This script provides a simple way to start the basic SIEM system. It builds and starts all the services, waits for the API and database to be ready, initializes detection rules, and seeds the database with test data.

- **`deploy_enhanced_siem.sh`**: This script handles the deployment of the enhanced SIEM system. It dynamically generates an enhanced `docker-compose.enhanced.yml` file, creates the necessary Nginx configuration, and brings up the entire stack. It also includes health checks to ensure all services are running correctly before finishing.

- **Configuration Management**: The system's configuration is managed through a `.env` file, which is generated by the `tests/generate_config.py` script. This allows for easy customization of database connections, API keys, and other settings without modifying the core application code.

13. Observability and Monitoring
Observability is a key design principle of BITS-SIEM, enabling operators to monitor the system's health, performance, and behavior. This is achieved through a combination of metrics, logging, and health checks.

### Prometheus Metrics
The processing service exposes a wide range of metrics in the Prometheus format, allowing for detailed monitoring and alerting. The key metrics include:

- **`siem_events_processed_total`**: A counter for the total number of events processed, labeled by `tenant_id`, `event_type`, and `source`.
- **`siem_threats_detected_total`**: A counter for the total number of threats detected, labeled by `tenant_id`, `threat_type`, and `severity`.
- **`siem_alerts_created_total`**: A counter for the total number of alerts created, labeled by `tenant_id`, `alert_type`, and `severity`.
- **`siem_processing_duration_seconds`**: A histogram that measures the latency of event processing, labeled by `tenant_id` and `processing_stage`.
- **`siem_active_streams`**: A gauge that indicates the number of active processing streams, providing insight into the current load.
- **`siem_processing_errors_total`**: A counter for the total number of errors that occur during processing, labeled by `tenant_id` and `error_type`.

### Structured Logging
All microservices use the `structlog` library to produce structured logs in JSON format. This approach ensures that log entries are machine-readable and can be easily ingested, parsed, and queried by log management platforms. Each log entry includes a timestamp, log level, logger name, and a detailed message, along with contextual information relevant to the event being logged.

### Health Checks
Each microservice exposes a `/health` endpoint that can be used to monitor its status. These endpoints are used by Docker Compose for readiness checks, ensuring that dependent services are only started after their dependencies are healthy. This prevents cascading failures during startup and improves the overall resilience of the system.

14. Testing and Validation
Test Suites (tests/ and service test_integration.py)
- tests/test_bruteforce_detection_simple.py: core brute force scenarios
- tests/test_false_positive_reduction.py: FP heuristics coverage
- tests/test_enhanced_detection_scenarios.py: advanced patterns
- tests/test_container_notifications.py: WS and notification flows
- tests/test_siem_setup.py: configuration flows
- ingestion/test_integration.py and processing/test_integration.py: pipeline behavior
- tests/test_existing_functionality_validation.py: system validation

How to run
- pytest tests/test_bruteforce_detection_simple.py -v
- pytest tests/test_false_positive_reduction.py -v
- pytest tests/test_enhanced_detection_scenarios.py -v

15. Results and Discussion
- The event pipeline demonstrates low-latency processing from ingestion to alert creation, sustained by Redis Streams and async batching.
- Detection accuracy validated across curated tests; enhanced detection and FP reduction significantly reduce noise in common scenarios.
- Observability (metrics/logs/health) accelerates debugging and shows stable service operations.
- The dashboard delivers tenant-scoped visibility and administrative flows.

16. Limitations
- ML features are scaffolds; production-grade performance requires larger datasets and feature stores.
- Redis-centric streaming suitable for lab scale; for very high throughput, Kafka/NATS/managed queues are recommended.
- Secrets management (Vault), SSO (OIDC/SAML), and hardened TLS across all services are future work for production readiness.

17. Conclusions
BITS-SIEM delivers a cohesive, cloud-native SIEM with a complete pipeline from syslog ingestion to real-time alerting and visualization. The modular services, clear interfaces, and observability-first approach provide a strong foundation for research and future enhancements. The implementation meets the educational objectives and demonstrates modern SIEM design patterns.

18. Recommendations / Future Work
- Migrate to Kafka for durable, scalable event streaming; adopt schema registry
- Expand detection sets (lateral movement, exfiltration, privilege escalation)
- Production hardening: Vault for secrets, SSO integration, per-tenant quotas, rate limiting
- CI/CD pipeline with security scans and automated tests
- Advanced analytics: feature stores, online learning, explainability for alerts
- Kubernetes deployment (HPA, service mesh, multi-cloud strategies)

19. Appendices
A. Quick Start
- python tests/generate_config.py
- docker-compose up --build
- Dashboard: http://localhost:3000; API: http://localhost:8000; WS: ws://localhost:8001

B. Key Prometheus Metrics
- siem_events_processed_total, siem_threats_detected_total, siem_alerts_created_total
- siem_processing_duration_seconds, siem_processing_errors_total
- siem_ingestion_messages_received_total

C. Important Files and Directories
- api/app.py, api/config.py, api/database_working.py
- ingestion/main.py, ingestion/parsers.py, ingestion/enrichment.py
- processing/main.py, processing/stream_processor.py, processing/threat_detection.py, processing/enhanced_detection.py, processing/false_positive_reduction.py, processing/alert_manager.py
- notification/main.py
- dashboard/src/*
- docker-compose.yml; scripts: run_bits_siem.sh, deploy_enhanced_siem.sh
- tests/*

20. Bibliography / References
Project Documentation (in repo)
- README.md
- DISSERTATION_DETAILED_DESIGN_AND_IMPLEMENTATION.md
- DEPLOYMENT_ARCHITECTURE_DOCUMENTATION.md
- DATABASE_SCHEMA_DOCUMENTATION.md and docs/DATABASE_SCHEMA.md
- THREAT_DETECTION_ALGORITHMS_DOCUMENTATION.md
- API_ENDPOINTS_DOCUMENTATION.md
- docs/BRUTEFORCE_DETECTION_DOCUMENTATION.md
- docs/ENHANCED_SIEM_README.md, docs/ENHANCED_NOTIFICATIONS_README.md
- docs/SIEM_ARCHITECTURE_WORKFLOWS.md
- docs/TEST_SUMMARY.md

External References
- FastAPI: https://fastapi.tiangolo.com
- SQLAlchemy: https://docs.sqlalchemy.org
- PostgreSQL: https://www.postgresql.org/docs/
- Redis & Streams: https://redis.io/docs/
- Vue.js 3: https://vuejs.org
- Vite: https://vitejs.dev
- Prometheus Python Client: https://github.com/prometheus/client_python
- Docker & Compose: https://docs.docker.com
- JWT (RFC 7519): https://www.rfc-editor.org/rfc/rfc7519

21. List of Publications / Presentations
- [If applicable] [Title], [Conference/Journal], [Date]

22. Checklist of Items
- [ ] Cover and Title pages completed
- [ ] Supervisor Certificate signed
- [ ] Acknowledgements and Abstract included
- [ ] TOC, List of Symbols, Tables/Figures complete
- [ ] Chapters align with implemented code and tests
- [ ] Internal documentation and external references cited
- [ ] Appendices include quick start and metrics
- [ ] Proofread for clarity and completeness

