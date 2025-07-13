-- BITS-SIEM Database Schema
-- Comprehensive database initialization for the SIEM system

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'active',
    user_count INTEGER DEFAULT 0,
    sources_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tenant SIEM Configuration table
CREATE TABLE IF NOT EXISTS tenant_configs (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    siem_server_ip VARCHAR(45) NOT NULL,
    siem_server_port INTEGER NOT NULL DEFAULT 514,
    siem_protocol VARCHAR(10) NOT NULL DEFAULT 'udp', -- udp, tcp, tls
    syslog_format VARCHAR(20) NOT NULL DEFAULT 'rfc3164', -- rfc3164, rfc5424, cisco
    facility VARCHAR(20) DEFAULT 'local0',
    severity VARCHAR(20) DEFAULT 'info',
    enabled BOOLEAN DEFAULT TRUE,
    setup_instructions TEXT,
    last_configured TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id)
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    tenants_access JSONB, -- Additional tenants user can access
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Sources table
CREATE TABLE IF NOT EXISTS sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    notifications JSONB DEFAULT '{"enabled": false, "emails": []}',
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    severity VARCHAR(20) DEFAULT 'info',
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    is_read BOOLEAN DEFAULT FALSE,
    meta_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    report_type VARCHAR(50) NOT NULL,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    generated_by VARCHAR(255) NOT NULL,
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_tenant_configs_tenant_id ON tenant_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sources_tenant_id ON sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sources_ip ON sources(ip);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_id ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_id ON reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);

-- Create functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sources_updated_at BEFORE UPDATE ON sources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_configs_updated_at BEFORE UPDATE ON tenant_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data
INSERT INTO tenants (id, name, description) VALUES
    ('acme-corp', 'Acme Corporation', 'Main corporate tenant'),
    ('beta-industries', 'Beta Industries', 'Beta testing environment'),
    ('cisco-systems', 'Cisco Systems', 'Cisco internal systems'),
    ('demo-org', 'Demo Organization', 'Demo and testing environment'),
    ('bits-internal', 'BITS Internal', 'BITS internal monitoring')
ON CONFLICT (id) DO NOTHING;

-- Insert sample tenant configurations
INSERT INTO tenant_configs (tenant_id, siem_server_ip, siem_server_port, siem_protocol, syslog_format, facility, severity, enabled, setup_instructions) VALUES
    ('acme-corp', '192.168.1.10', 514, 'udp', 'rfc3164', 'local0', 'info', true, 'Configure your devices to send syslog to 192.168.1.10:514 using UDP protocol with RFC3164 format.'),
    ('beta-industries', '10.0.1.10', 515, 'udp', 'rfc5424', 'local1', 'info', true, 'Configure your devices to send syslog to 10.0.1.10:515 using UDP protocol with RFC5424 format.'),
    ('cisco-systems', '172.16.1.10', 516, 'tcp', 'cisco', 'local2', 'info', true, 'Configure your Cisco devices to send syslog to 172.16.1.10:516 using TCP protocol with Cisco format.'),
    ('demo-org', '10.0.0.10', 517, 'udp', 'rfc3164', 'local3', 'info', true, 'Configure your devices to send syslog to 10.0.0.10:517 using UDP protocol with RFC3164 format.'),
    ('bits-internal', '192.168.0.10', 518, 'udp', 'rfc3164', 'local4', 'info', true, 'Configure your devices to send syslog to 192.168.0.10:518 using UDP protocol with RFC3164 format.')
ON CONFLICT (tenant_id) DO NOTHING;

-- Insert sample users
INSERT INTO users (id, email, password, name, tenant_id, role, tenants_access) VALUES
    ('admin@acme.com', 'admin123', 'Admin User', 'acme-corp', 'admin', '["acme-corp"]'),
    ('user@acme.com', 'user123', 'Regular User', 'acme-corp', 'user', '["acme-corp"]'),
    ('admin@beta.com', 'admin123', 'Beta Admin', 'beta-industries', 'admin', '["beta-industries"]'),
    ('aspundir@cisco.com', 'password123', 'Aspundir Singh', 'cisco-systems', 'admin', '["cisco-systems"]'),
    ('sre@bits.com', 'sre123', 'BITS SRE', 'bits-internal', 'sre', '["bits-internal", "acme-corp", "beta-industries", "cisco-systems", "demo-org"]')
ON CONFLICT (id) DO NOTHING;

-- Insert sample sources
INSERT INTO sources (name, type, ip, port, protocol, tenant_id, notifications) VALUES
    ('Web Server', 'web-server', '192.168.1.100', 80, 'http', 'acme-corp', '{"enabled": true, "emails": ["admin@acme.com", "security@acme.com"]}'),
    ('Database Server', 'database', '192.168.1.200', 3306, 'tcp', 'acme-corp', '{"enabled": true, "emails": ["dba@acme.com"]}'),
    ('Firewall', 'firewall', '10.0.1.1', 514, 'udp', 'beta-industries', '{"enabled": true, "emails": ["admin@beta.com"]}'),
    ('Cisco ASA Firewall', 'firewall', '172.16.1.1', 443, 'https', 'cisco-systems', '{"enabled": true, "emails": ["aspundir@cisco.com", "security@cisco.com"]}'),
    ('IOS Router', 'router', '172.16.1.2', 161, 'snmp', 'cisco-systems', '{"enabled": true, "emails": ["netops@cisco.com"]}'),
    ('Demo Web Server', 'web-server', '10.0.0.100', 80, 'http', 'demo-org', '{"enabled": true, "emails": ["admin@demo.com"]}')
ON CONFLICT DO NOTHING;

-- Insert sample notifications
INSERT INTO notifications (message, severity, tenant_id, meta_data) VALUES
    ('High CPU usage detected on Web Server', 'warning', 'acme-corp', '{"cpu_usage": "85%"}'),
    ('Suspicious login attempt blocked', 'critical', 'acme-corp', '{"ip": "192.168.1.50"}'),
    ('System backup completed successfully', 'info', 'acme-corp', '{"backup_size": "2.3GB"}'),
    ('Firewall rule updated', 'info', 'beta-industries', '{"rule_id": "FW-001"}'),
    ('Network intrusion detected', 'critical', 'cisco-systems', '{"source_ip": "172.16.1.50"}'),
    ('Router configuration backup', 'info', 'cisco-systems', '{"device": "IOS-Router-01"}'),
    ('Demo alert - System monitoring', 'info', 'demo-org', '{"status": "monitoring"}')
ON CONFLICT DO NOTHING;

-- Insert sample reports
INSERT INTO reports (title, summary, report_type, tenant_id, generated_by, data) VALUES
    ('Security Summary Report', 'Weekly security overview', 'security', 'acme-corp', 'system', '{"total_events": 1250, "threats_blocked": 15}'),
    ('Threat Analysis Report', 'Analysis of recent security threats', 'threat', 'acme-corp', 'admin', '{"threats_detected": 8, "false_positives": 2}'),
    ('Network Security Report', 'Network security assessment', 'network', 'beta-industries', 'system', '{"vulnerabilities": 3, "patches_needed": 5}'),
    ('Cisco Infrastructure Report', 'Cisco network infrastructure analysis', 'infrastructure', 'cisco-systems', 'admin', '{"devices_monitored": 25, "uptime": "99.9%"}'),
    ('Demo Security Report', 'Demo security overview', 'security', 'demo-org', 'system', '{"events": 100, "alerts": 5}')
ON CONFLICT DO NOTHING; 