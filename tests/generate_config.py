#!/usr/bin/env python3
"""
BITS-SIEM Configuration Generator
Generates and displays system configurations based on environment variables
"""

import os
import sys
from datetime import datetime

# Add the api directory to the path so we can import the config module
sys.path.append(os.path.join(os.path.dirname(__file__), 'api'))

try:
    from config import config
except ImportError as e:
    print(f"Error importing config: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'-' * 40}")
    print(f" {title}")
    print(f"{'-' * 40}")

def display_environment_config():
    """Display current environment configuration"""
    print_header("BITS-SIEM Environment Configuration")
    
    print_section("Database Configuration")
    print(f"Host: {config.database.host}")
    print(f"Port: {config.database.port}")
    print(f"Database: {config.database.name}")
    print(f"User: {config.database.user}")
    print(f"Password: {'*' * len(config.database.password)}")
    print(f"URL: {config.database.url.replace(config.database.password, '***')}")
    
    print_section("SIEM Configuration")
    print(f"Base IP: {config.siem.base_ip}")
    print(f"Base Port: {config.siem.base_port}")
    print(f"Network Mask: /{config.siem.network_mask}")
    print(f"Default Protocol: {config.siem.protocol_default}")
    print(f"Default Format: {config.siem.format_default}")
    
    print_section("Security Configuration")
    print(f"JWT Algorithm: {config.security.jwt_algorithm}")
    print(f"JWT Expiration: {config.security.jwt_expiration_hours} hours")
    print(f"CSRF Enabled: {config.security.csrf_enabled}")
    print(f"CSRF Expiration: {config.security.csrf_expiration_hours} hours")
    print(f"Password Min Length: {config.security.password_min_length}")
    print(f"Require Special Chars: {config.security.password_require_special_chars}")
    
    print_section("API Configuration")
    print(f"Host: {config.api.host}")
    print(f"Port: {config.api.port}")
    print(f"Debug: {config.api.debug}")
    print(f"CORS Origins: {', '.join(config.api.cors_origins)}")

def display_tenant_configurations():
    """Display generated tenant configurations"""
    print_header("Generated Tenant Configurations")
    
    tenant_configs = config.get_sample_tenant_configs()
    
    for tenant_id, tenant_info in tenant_configs.items():
        print_section(f"Tenant: {tenant_id}")
        print(f"Name: {tenant_info['metadata']['name']}")
        print(f"Description: {tenant_info['metadata']['description']}")
        print(f"Admin Password: {tenant_info['password']}")
        
        siem_config = tenant_info['siem_config']
        print(f"SIEM Server IP: {siem_config['siem_server_ip']}")
        print(f"SIEM Server Port: {siem_config['siem_server_port']}")
        print(f"Protocol: {siem_config['siem_protocol']}")
        print(f"Syslog Format: {siem_config['syslog_format']}")
        print(f"Facility: {siem_config['facility']}")
        print(f"Severity: {siem_config['severity']}")
        print(f"Enabled: {siem_config['enabled']}")
        print(f"Setup Instructions: {siem_config['setup_instructions'][:100]}...")

def display_network_calculation():
    """Display network calculation details"""
    print_header("Network Calculation Details")
    
    import ipaddress
    
    base_network = ipaddress.IPv4Network(f"{config.siem.base_ip}/{config.siem.network_mask}", strict=False)
    print(f"Base Network: {base_network}")
    print(f"Network Address: {base_network.network_address}")
    print(f"Broadcast Address: {base_network.broadcast_address}")
    print(f"Total Hosts: {base_network.num_addresses - 2}")
    
    print_section("Tenant IP Assignments")
    tenant_configs = config.get_sample_tenant_configs()
    
    for i, (tenant_id, tenant_info) in enumerate(tenant_configs.items()):
        siem_config = tenant_info['siem_config']
        ip = ipaddress.IPv4Address(siem_config['siem_server_ip'])
        offset = int(ip) - int(base_network.network_address)
        print(f"{tenant_id}: {siem_config['siem_server_ip']} (offset: {offset})")

def display_password_examples():
    """Display password generation examples"""
    print_header("Password Generation Examples")
    
    print_section("Generated Passwords")
    for i in range(5):
        password = config.generate_secure_password(12)
        print(f"Password {i+1}: {password}")
    
    print_section("Password Requirements")
    print(f"Minimum Length: {config.security.password_min_length}")
    print(f"Require Special Characters: {config.security.password_require_special_chars}")
    print("Character Sets: lowercase, uppercase, digits")
    if config.security.password_require_special_chars:
        print("Special Characters: !@#$%^&*()_+-=[]{}|;:,.<>?")

def validate_configuration():
    """Validate the current configuration"""
    print_header("Configuration Validation")
    
    errors = config.validate_configuration()
    
    if not errors:
        print("✅ All configuration parameters are valid!")
    else:
        print("❌ Configuration validation failed:")
        for error in errors:
            print(f"  - {error}")

def generate_env_file():
    """Generate a .env file with current configuration"""
    print_header("Environment File Generation")
    
    env_content = f"""# BITS-SIEM Environment Configuration
# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

# Database Configuration
DATABASE_URL={config.database.url}
DATABASE_HOST={config.database.host}
DATABASE_PORT={config.database.port}
DATABASE_NAME={config.database.name}
DATABASE_USER={config.database.user}
DATABASE_PASSWORD={config.database.password}

# SIEM Server Configuration
SIEM_BASE_IP={config.siem.base_ip}
SIEM_BASE_PORT={config.siem.base_port}
SIEM_NETWORK_MASK={config.siem.network_mask}
SIEM_PROTOCOL_DEFAULT={config.siem.protocol_default}
SIEM_FORMAT_DEFAULT={config.siem.format_default}

# JWT Configuration
JWT_SECRET_KEY={config.security.jwt_secret}
JWT_ALGORITHM={config.security.jwt_algorithm}
JWT_EXPIRATION_HOURS={config.security.jwt_expiration_hours}

# API Configuration
API_HOST={config.api.host}
API_PORT={config.api.port}
API_DEBUG={str(config.api.debug).lower()}
API_CORS_ORIGINS={','.join(config.api.cors_origins)}

# Security Configuration
CSRF_ENABLED={str(config.security.csrf_enabled).lower()}
CSRF_EXPIRATION_HOURS={config.security.csrf_expiration_hours}
PASSWORD_MIN_LENGTH={config.security.password_min_length}
PASSWORD_REQUIRE_SPECIAL_CHARS={str(config.security.password_require_special_chars).lower()}

# Development Configuration
DEBUG={str(config.debug).lower()}
ENVIRONMENT={config.environment}
"""
    
    env_file_path = ".env"
    try:
        with open(env_file_path, 'w') as f:
            f.write(env_content)
        print(f"✅ Environment file generated: {env_file_path}")
    except Exception as e:
        print(f"❌ Failed to generate environment file: {e}")

def main():
    """Main function"""
    print("BITS-SIEM Configuration Generator")
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Display all configurations
    display_environment_config()
    display_tenant_configurations()
    display_network_calculation()
    display_password_examples()
    validate_configuration()
    generate_env_file()
    
    print_header("Summary")
    print("✅ Configuration generation completed successfully!")
    print("\nNext steps:")
    print("1. Review the generated configurations above")
    print("2. Copy the generated .env file to your project root")
    print("3. Update any values as needed for your environment")
    print("4. Start the services with: docker-compose up -d")
    print("5. Use the generated passwords to login to the system")

if __name__ == "__main__":
    main() 