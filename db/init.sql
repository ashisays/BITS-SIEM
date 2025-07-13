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

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
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

-- Syslog events table (for raw syslog data)
CREATE TABLE IF NOT EXISTS syslog_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    facility VARCHAR(50),
    severity VARCHAR(20),
    hostname VARCHAR(255),
    app_name VARCHAR(100),
    proc_id VARCHAR(50),
    msg_id VARCHAR(50),
    message TEXT,
    raw_message TEXT NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    parsed_fields JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Security events table (for processed security events)
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(100) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    event_type VARCHAR(100),
    severity VARCHAR(20),
    threat_level VARCHAR(20),
    threat_score DECIMAL(3,2),
    description TEXT,
    raw_data JSONB,
    indicators JSONB,
    tags JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Reports table
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    file_path VARCHAR(500),
    generated_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    event_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    meta_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(20) NOT NULL, -- ip, domain, hash, url
    indicator_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(50),
    confidence DECIMAL(3,2),
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    meta_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(indicator_type, indicator_value)
);

-- ML models table
CREATE TABLE IF NOT EXISTS ml_models (
    id SERIAL PRIMARY KEY,
    model_type VARCHAR(50) NOT NULL,
    model_name VARCHAR(100) NOT NULL,
    version VARCHAR(20),
    file_path VARCHAR(500),
    accuracy DECIMAL(5,4),
    training_samples INTEGER,
    last_trained TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    meta_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) REFERENCES tenants(id) ON DELETE CASCADE,
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_syslog_events_timestamp ON syslog_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_syslog_events_tenant_id ON syslog_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_syslog_events_source_ip ON syslog_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_syslog_events_severity ON syslog_events(severity);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_id ON security_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_threat_level ON security_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_id ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_is_active ON alerts(is_active);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant_id ON notifications(tenant_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);

CREATE INDEX IF NOT EXISTS idx_threat_intelligence_indicator ON threat_intelligence(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_is_active ON threat_intelligence(is_active);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Create full-text search indexes
CREATE INDEX IF NOT EXISTS idx_syslog_events_message_gin ON syslog_events USING gin(to_tsvector('english', message));
CREATE INDEX IF NOT EXISTS idx_security_events_description_gin ON security_events USING gin(to_tsvector('english', description));

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

-- Insert sample data
INSERT INTO tenants (id, name, description) VALUES
    ('acme-corp', 'Acme Corporation', 'Main corporate tenant'),
    ('beta-industries', 'Beta Industries', 'Beta testing environment'),
    ('cisco-systems', 'Cisco Systems', 'Cisco internal systems'),
    ('demo-org', 'Demo Organization', 'Demo and testing environment'),
    ('bits-internal', 'BITS Internal', 'BITS internal monitoring')
ON CONFLICT (id) DO NOTHING;

-- Insert sample users
INSERT INTO users (id, email, password, name, tenant_id, role) VALUES
    ('admin@acme.com', 'hashed_password_here', 'Admin User', 'acme-corp', 'admin'),
    ('user@acme.com', 'hashed_password_here', 'Regular User', 'acme-corp', 'user'),
    ('admin@beta.com', 'hashed_password_here', 'Beta Admin', 'beta-industries', 'admin'),
    ('aspundir@cisco.com', 'hashed_password_here', 'Aspundir Singh', 'cisco-systems', 'admin'),
    ('sre@bits.com', 'hashed_password_here', 'BITS SRE', 'bits-internal', 'sre')
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

-- Insert sample threat intelligence
INSERT INTO threat_intelligence (indicator_type, indicator_value, threat_type, confidence) VALUES
    ('ip', '192.168.1.100', 'malware', 0.9),
    ('ip', '10.0.0.50', 'botnet', 0.8),
    ('domain', 'malware.example.com', 'phishing', 0.95),
    ('domain', 'botnet.net', 'botnet', 0.85)
ON CONFLICT (indicator_type, indicator_value) DO NOTHING; 