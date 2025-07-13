"""
BITS-SIEM Configuration Management
Handles environment variables and generates tenant-specific configurations
"""

import os
import ipaddress
import secrets
import string
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str
    host: str
    port: int
    name: str
    user: str
    password: str

@dataclass
class SiemConfig:
    """SIEM server configuration"""
    base_ip: str
    base_port: int
    network_mask: int
    protocol_default: str
    format_default: str

@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret: str
    jwt_algorithm: str
    jwt_expiration_hours: int
    csrf_enabled: bool
    csrf_expiration_hours: int
    password_min_length: int
    password_require_special_chars: bool

@dataclass
class ApiConfig:
    """API configuration"""
    host: str
    port: int
    debug: bool
    cors_origins: List[str]

class ConfigManager:
    """Manages application configuration and tenant-specific settings"""
    
    def __init__(self):
        self._load_environment()
        self._tenant_configs = {}
    
    def _load_environment(self):
        """Load configuration from environment variables"""
        # Database Configuration
        self.database = DatabaseConfig(
            url=os.getenv('DATABASE_URL', 'postgresql+psycopg2://siem:siempassword@db:5432/siemdb'),
            host=os.getenv('DATABASE_HOST', 'db'),
            port=int(os.getenv('DATABASE_PORT', '5432')),
            name=os.getenv('DATABASE_NAME', 'siemdb'),
            user=os.getenv('DATABASE_USER', 'siem'),
            password=os.getenv('DATABASE_PASSWORD', 'siempassword')
        )
        
        # SIEM Configuration
        self.siem = SiemConfig(
            base_ip=os.getenv('SIEM_BASE_IP', '192.168.1.0'),
            base_port=int(os.getenv('SIEM_BASE_PORT', '514')),
            network_mask=int(os.getenv('SIEM_NETWORK_MASK', '24')),
            protocol_default=os.getenv('SIEM_PROTOCOL_DEFAULT', 'udp'),
            format_default=os.getenv('SIEM_FORMAT_DEFAULT', 'rfc3164')
        )
        
        # Security Configuration
        self.security = SecurityConfig(
            jwt_secret=os.getenv('JWT_SECRET_KEY', 'your-super-secret-jwt-key-change-this-in-production'),
            jwt_algorithm=os.getenv('JWT_ALGORITHM', 'HS256'),
            jwt_expiration_hours=int(os.getenv('JWT_EXPIRATION_HOURS', '24')),
            csrf_enabled=os.getenv('CSRF_ENABLED', 'true').lower() == 'true',
            csrf_expiration_hours=int(os.getenv('CSRF_EXPIRATION_HOURS', '24')),
            password_min_length=int(os.getenv('PASSWORD_MIN_LENGTH', '8')),
            password_require_special_chars=os.getenv('PASSWORD_REQUIRE_SPECIAL_CHARS', 'true').lower() == 'true'
        )
        
        # API Configuration
        self.api = ApiConfig(
            host=os.getenv('API_HOST', '0.0.0.0'),
            port=int(os.getenv('API_PORT', '8000')),
            debug=os.getenv('API_DEBUG', 'false').lower() == 'true',
            cors_origins=os.getenv('API_CORS_ORIGINS', 'http://localhost:3000,http://localhost:5173').split(',')
        )
        
        # Tenant Configuration
        self.default_tenant_password = os.getenv('DEFAULT_TENANT_PASSWORD', 'changeme123')
        self.admin_email_suffix = os.getenv('ADMIN_EMAIL_SUFFIX', '@admin.local')
        self.user_email_suffix = os.getenv('USER_EMAIL_SUFFIX', '@user.local')
        
        # Development Configuration
        self.debug = os.getenv('DEBUG', 'false').lower() == 'true'
        self.environment = os.getenv('ENVIRONMENT', 'production')
    
    def generate_tenant_siem_config(self, tenant_id: str, protocol: str = None, syslog_format: str = None) -> Dict:
        """
        Generate SIEM configuration for all tenants (same IP/port from env)
        Args:
            tenant_id: Unique tenant identifier
            protocol: Optional protocol override (udp, tcp, tls)
            syslog_format: Optional syslog format override
        Returns:
            Dictionary with SIEM configuration
        """
        # Use env values for all tenants
        siem_ip = self.siem.base_ip
        siem_protocol = protocol or self.siem.protocol_default
        siem_format = syslog_format or self.siem.format_default
        # Port logic: 514 for UDP, 601 for TCP/TLS (RFC standard)
        if siem_protocol == 'udp':
            siem_port = 514
        elif siem_protocol in ('tcp', 'tls'):
            siem_port = 601
        else:
            siem_port = self.siem.base_port
        config = {
            'siem_server_ip': siem_ip,
            'siem_server_port': siem_port,
            'siem_protocol': siem_protocol,
            'syslog_format': siem_format,
            'facility': 'local0',
            'severity': 'info',
            'enabled': True,
            'setup_instructions': self._generate_setup_instructions(siem_ip, siem_port, siem_protocol, siem_format)
        }
        return config
    
    def _generate_setup_instructions(self, ip: str, port: int, protocol: str, format_type: str) -> str:
        """Generate setup instructions for the tenant"""
        protocol_upper = protocol.upper()
        format_upper = format_type.upper()
        
        instructions = f"Configure your devices to send syslog to {ip}:{port} using {protocol_upper} protocol with {format_upper} format.\n\n"
        
        if format_type == 'cisco':
            instructions += f"Example Cisco commands:\n"
            instructions += f"  logging {ip}\n"
            instructions += f"  logging host inside {ip} {protocol}\n"
        elif format_type == 'rfc5424':
            instructions += f"Example rsyslog configuration:\n"
            instructions += f"  *.* @{ip}:{port}\n"
        else:  # rfc3164
            instructions += f"Example rsyslog configuration:\n"
            instructions += f"  *.* @{ip}:{port}\n"
        
        instructions += f"\nTest connectivity:\n"
        instructions += f"  telnet {ip} {port}\n"
        instructions += f"  nc -u {ip} {port}\n"
        
        return instructions
    
    def generate_secure_password(self, length: int = None) -> str:
        """
        Generate a secure password
        
        Args:
            length: Password length (uses config default if not specified)
            
        Returns:
            Secure password string
        """
        if length is None:
            length = self.security.password_min_length
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each required set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits)
        ]
        
        if self.security.password_require_special_chars:
            password.append(secrets.choice(special_chars))
        
        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits
        if self.security.password_require_special_chars:
            all_chars += special_chars
        
        remaining_length = length - len(password)
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)
    
    def get_tenant_passwords(self) -> Dict[str, str]:
        """
        Get or generate passwords for default tenants
        
        Returns:
            Dictionary mapping tenant IDs to passwords
        """
        default_tenants = [
            'acme-corp',
            'beta-industries', 
            'cisco-systems',
            'demo-org',
            'bits-internal'
        ]
        
        passwords = {}
        for tenant_id in default_tenants:
            # Generate deterministic but secure password based on tenant_id
            seed = hash(tenant_id) % 10000
            secrets.SystemRandom().seed(seed)
            passwords[tenant_id] = self.generate_secure_password(12)
            secrets.SystemRandom().seed()  # Reset seed
        
        return passwords
    
    def get_sample_tenant_configs(self) -> Dict[str, Dict]:
        """
        Get sample tenant configurations for database initialization
        
        Returns:
            Dictionary of tenant configurations
        """
        tenant_configs = {}
        tenant_passwords = self.get_tenant_passwords()
        
        # Define tenant metadata
        tenant_metadata = {
            'acme-corp': {'name': 'Acme Corporation', 'description': 'Main corporate tenant'},
            'beta-industries': {'name': 'Beta Industries', 'description': 'Beta testing environment'},
            'cisco-systems': {'name': 'Cisco Systems', 'description': 'Cisco internal systems'},
            'demo-org': {'name': 'Demo Organization', 'description': 'Demo and testing environment'},
            'bits-internal': {'name': 'BITS Internal', 'description': 'BITS internal monitoring'}
        }
        
        for i, (tenant_id, metadata) in enumerate(tenant_metadata.items()):
            siem_config = self.generate_tenant_siem_config(tenant_id, i)
            tenant_configs[tenant_id] = {
                'metadata': metadata,
                'siem_config': siem_config,
                'password': tenant_passwords[tenant_id]
            }
        
        return tenant_configs
    
    def validate_configuration(self) -> List[str]:
        """
        Validate the current configuration
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate SIEM base IP
        try:
            ipaddress.IPv4Address(self.siem.base_ip)
        except ipaddress.AddressValueError:
            errors.append(f"Invalid SIEM_BASE_IP: {self.siem.base_ip}")
        
        # Validate network mask
        if not (8 <= self.siem.network_mask <= 30):
            errors.append(f"Invalid SIEM_NETWORK_MASK: {self.siem.network_mask} (must be 8-30)")
        
        # Validate base port (allow standard syslog port 514)
        if not (514 <= self.siem.base_port <= 65535):
            errors.append(f"Invalid SIEM_BASE_PORT: {self.siem.base_port} (must be 514-65535)")
        
        # Validate protocol
        if self.siem.protocol_default not in ['udp', 'tcp', 'tls']:
            errors.append(f"Invalid SIEM_PROTOCOL_DEFAULT: {self.siem.protocol_default}")
        
        # Validate format
        if self.siem.format_default not in ['rfc3164', 'rfc5424', 'cisco']:
            errors.append(f"Invalid SIEM_FORMAT_DEFAULT: {self.siem.format_default}")
        
        # Validate JWT secret
        if len(self.security.jwt_secret) < 32:
            errors.append("JWT_SECRET_KEY must be at least 32 characters long")
        
        return errors

# Global configuration instance
config = ConfigManager() 