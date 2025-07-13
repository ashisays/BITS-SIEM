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
- **dashboard**: Tenant web dashboard for configuration, notifications, reports, and SIEM setup.
- **api**: Backend for user/tenant management, configuration, and SIEM setup.
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

4. **Configure SIEM Setup**:
    - Login to the dashboard
    - Navigate to "SIEM Setup" in the navigation
    - Configure your tenant-specific SIEM server settings
    - Follow the setup guide to configure your devices
    - Test connectivity and monitor for events

## Features

### Multi-tenant SIEM Configuration
- **Tenant-specific SIEM servers**: Each tenant gets unique IP and port configuration
- **Flexible syslog formats**: Support for RFC 3164, RFC 5424, and Cisco formats
- **Protocol options**: UDP, TCP, and TLS support
- **Setup guides**: Comprehensive step-by-step instructions for device configuration
- **Troubleshooting**: Built-in troubleshooting guides and connectivity testing

### Device Configuration Examples
- **Cisco IOS**: `logging 192.168.1.10`
- **Cisco ASA**: `logging host inside 192.168.1.10 udp`
- **Linux rsyslog**: `*.* @192.168.1.10:514`
- **Windows Event Log**: Windows Event Forwarding configuration
- **Firewalls**: Generic syslog output configuration

### Security Features
- **Tenant isolation**: Complete separation of configurations and data
- **Role-based access**: Admin users can only configure their own tenant
- **CSRF protection**: Secure state-changing operations
- **Audit logging**: Complete configuration change tracking

## Development
- Each service has its own directory and Dockerfile.
- Replace the placeholder Dockerfiles and code with your implementation for each service.
- Test SIEM setup functionality using `python test_siem_setup.py`

---
