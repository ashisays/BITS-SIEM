# Multi-Tenant SIEM Dashboard (Vue)

## Features
- JWT/session authentication for tenant admin
- Source IP/network configuration
- Real-time and historical notifications (WebSocket)
- Diagnosis/threat reports

## Project Structure
- `src/components/`: UI components (Login, Register, SourceConfig, Notifications, DiagnosisReports)
- `src/views/`: Dashboard layout
- `src/router/`: Vue Router setup
- `src/store/`: Pinia store for state management
- `src/services/`: API and WebSocket services

## Usage
1. Install dependencies:
   ```sh
   npm install
   ```
2. Run the development server:
   ```sh
   npm run dev
   ```
3. Build for production:
   ```sh
   npm run build
   ```
4. Use Docker for containerized deployment.

---
