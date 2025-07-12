# BITS-SIEM

A cloud-native, multi-tenant SIEM (Security Information and Event Management) system for real-time security assessment using syslog data.

## Project Structure

```
BITS-SIEM/
│
├── docker-compose.yml         # Orchestrates all services
├── README.md                  # Project documentation
│
├── dashboard/                 # Web frontend (dashboard)
├── api/                       # Backend API (user/tenant/config management)
├── ingestion/                 # Syslog ingestion service
├── processing/                # Real-time processing (Flink, ML)
├── notification/              # Notification service (web/email)
└── db/                        # Database initialization scripts/configs
```

## Services
- **dashboard**: Tenant web dashboard for configuration, notifications, and reports.
- **api**: Backend for user/tenant management and configuration.
- **ingestion**: Receives syslog data, normalizes, and forwards for processing.
- **processing**: Real-time analytics and ML-based threat detection (e.g., Apache Flink).
- **notification**: Sends notifications via web/email.
- **db**: PostgreSQL database for multi-tenant configuration and event storage.

## Getting Started

1. **Clone the repository**
2. **Build and start all services**:
   ```sh
   docker-compose up --build
   ```
3. **Access the services**:
   - Dashboard: http://localhost:3000
   - API: http://localhost:8000
   - Syslog UDP: localhost:514
   - Database: localhost:5432 (user: siem, password: siempassword, db: siemdb)

## Development
- Each service has its own directory and Dockerfile.
- Replace the placeholder Dockerfiles and code with your implementation for each service.

---
