-- Create test security alerts for demo-org
-- This script creates sample brute force and authentication alerts

-- Insert test security alerts
INSERT INTO security_alerts (
    id, tenant_id, alert_type, severity, title, description,
    source_ip, target_ip, risk_score, confidence, status,
    created_at, updated_at, event_metadata, correlation_data
) VALUES 
(
    'bf-alert-001', 'demo-org', 'brute_force_attack', 'critical',
    'Brute Force Attack Detected',
    'Multiple failed login attempts detected from 10.0.0.100',
    '10.0.0.100', NULL, 0.9, 0.85, 'open',
    NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes',
    '{"failed_attempts": 8, "target_users": ["admin", "user", "john.doe"], "attack_duration": "2 minutes", "detection_engine": "brute_force"}',
    '{"related_events": 8, "attack_pattern": "rapid_sequential", "source_reputation": "unknown"}'
),
(
    'bf-alert-002', 'demo-org', 'brute_force_attack', 'high',
    'Distributed Brute Force Attack',
    'Coordinated attack from multiple IPs targeting admin account',
    '10.0.0.101', NULL, 0.8, 0.75, 'investigating',
    NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '8 minutes',
    '{"failed_attempts": 6, "target_users": ["admin"], "attack_duration": "3 minutes", "detection_engine": "brute_force"}',
    '{"related_events": 6, "attack_pattern": "distributed", "source_reputation": "suspicious"}'
),
(
    'auth-alert-001', 'demo-org', 'authentication_anomaly', 'medium',
    'Unusual Authentication Pattern',
    'Login attempts outside normal business hours',
    '192.168.0.100', NULL, 0.6, 0.65, 'open',
    NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '15 minutes',
    '{"failed_attempts": 3, "target_users": ["jane.smith"], "time_anomaly": "after_hours", "detection_engine": "anomaly_detection"}',
    '{"related_events": 3, "attack_pattern": "time_based", "source_reputation": "clean"}'
);

-- Insert corresponding notifications
INSERT INTO notifications (
    id, tenant_id, type, title, message, severity, status,
    created_at, updated_at, event_metadata
) VALUES 
(
    'notif-bf-001', 'demo-org', 'security_alert',
    'Brute Force Attack Detected',
    'Multiple failed login attempts detected from 10.0.0.100',
    'critical', 'unread',
    NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '5 minutes',
    '{"failed_attempts": 8, "target_users": ["admin", "user", "john.doe"], "attack_duration": "2 minutes", "detection_engine": "brute_force"}'
),
(
    'notif-bf-002', 'demo-org', 'security_alert',
    'Distributed Brute Force Attack',
    'Coordinated attack from multiple IPs targeting admin account',
    'high', 'unread',
    NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '8 minutes',
    '{"failed_attempts": 6, "target_users": ["admin"], "attack_duration": "3 minutes", "detection_engine": "brute_force"}'
),
(
    'notif-auth-001', 'demo-org', 'security_alert',
    'Unusual Authentication Pattern',
    'Login attempts outside normal business hours',
    'medium', 'unread',
    NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '15 minutes',
    '{"failed_attempts": 3, "target_users": ["jane.smith"], "time_anomaly": "after_hours", "detection_engine": "anomaly_detection"}'
);

-- Display results
SELECT 'Security Alerts Created:' as result;
SELECT COUNT(*) as alert_count FROM security_alerts WHERE tenant_id = 'demo-org';

SELECT 'Notifications Created:' as result;
SELECT COUNT(*) as notification_count FROM notifications WHERE tenant_id = 'demo-org';

SELECT 'Sample Alert Details:' as result;
SELECT alert_type, severity, title, source_ip, created_at 
FROM security_alerts 
WHERE tenant_id = 'demo-org' 
ORDER BY created_at DESC 
LIMIT 3;

