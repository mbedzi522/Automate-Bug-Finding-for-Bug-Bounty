"""
Configuration management for Bug Hunter Tool
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for the bug hunting tool"""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration"""
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
        
        # Load environment variables
        self._load_env_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'general': {
                'max_threads': 10,
                'timeout': 30,
                'user_agent': 'BugHunter/1.0 (Automated Security Scanner)',
                'delay_between_requests': 0.1,
                'max_retries': 3
            },
            'reconnaissance': {
                'subdomain_enumeration': True,
                'port_scanning': True,
                'service_detection': True,
                'technology_detection': True,
                'directory_enumeration': True,
                'default_ports': '80,443,8080,8443,3000,5000,8000,9000',
                'top_ports': 1000
            },
            'vulnerability_scanning': {
                'web_vulnerabilities': True,
                'network_vulnerabilities': True,
                'ssl_tls_checks': True,
                'cms_vulnerabilities': True,
                'nuclei_templates': True,
                'custom_payloads': True
            },
            'ai_analysis': {
                'enabled': False,
                'gemini_api_key': '',
                'model': 'gemini-pro',
                'max_tokens': 4096,
                'temperature': 0.3,
                'analysis_types': [
                    'vulnerability_prioritization',
                    'false_positive_detection',
                    'payload_generation',
                    'code_analysis'
                ]
            },
            'reporting': {
                'format': 'html',
                'include_screenshots': True,
                'include_raw_output': False,
                'severity_levels': ['critical', 'high', 'medium', 'low', 'info'],
                'auto_submit': False
            },
            'tools': {
                'nmap': {
                    'path': '/usr/bin/nmap',
                    'default_args': '-sS -sV -O --script=default'
                },
                'nuclei': {
                    'path': '/usr/local/bin/nuclei',
                    'templates_path': '~/.nuclei-templates',
                    'default_args': '-silent -no-color'
                },
                'sublist3r': {
                    'path': 'sublist3r',
                    'engines': 'all',
                    'threads': 40
                },
                'gobuster': {
                    'path': '/usr/bin/gobuster',
                    'wordlist': '/usr/share/wordlists/dirb/common.txt',
                    'threads': 50
                },
                'sqlmap': {
                    'path': '/usr/bin/sqlmap',
                    'default_args': '--batch --random-agent'
                },
                'nikto': {
                    'path': '/usr/bin/nikto',
                    'default_args': '-ask no'
                }
            },
            'wordlists': {
                'subdomains': [
                    '/usr/share/wordlists/subdomains-top1million-5000.txt',
                    '/usr/share/wordlists/subdomains.txt'
                ],
                'directories': [
                    '/usr/share/wordlists/dirb/common.txt',
                    '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
                ],
                'files': [
                    '/usr/share/wordlists/dirb/extensions_common.txt'
                ]
            },
            'output': {
                'base_dir': './reports',
                'create_subdirs': True,
                'timestamp_format': '%Y%m%d_%H%M%S',
                'compress_reports': False
            }
        }
    
    def _load_config_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    file_config = json.load(f)
                elif config_file.endswith(('.yml', '.yaml')):
                    file_config = yaml.safe_load(f)
                else:
                    raise ValueError("Unsupported config file format. Use JSON or YAML.")
                
                # Merge with default config
                self._deep_merge(self.config, file_config)
        except Exception as e:
            raise Exception(f"Error loading config file {config_file}: {str(e)}")
    
    def _load_env_config(self):
        """Load configuration from environment variables"""
        # Gemini API key
        gemini_key = os.getenv('GEMINI_API_KEY')
        if gemini_key:
            self.config['ai_analysis']['gemini_api_key'] = gemini_key
            self.config['ai_analysis']['enabled'] = True
        
        # Other environment variables
        env_mappings = {
            'BH_MAX_THREADS': ('general', 'max_threads', int),
            'BH_TIMEOUT': ('general', 'timeout', int),
            'BH_USER_AGENT': ('general', 'user_agent', str),
            'BH_OUTPUT_DIR': ('output', 'base_dir', str),
        }
        
        for env_var, (section, key, type_func) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                try:
                    self.config[section][key] = type_func(value)
                except (ValueError, TypeError):
                    pass  # Ignore invalid values
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def get(self, section: str, key: str = None, default=None):
        """Get configuration value"""
        if key is None:
            return self.config.get(section, default)
        
        section_data = self.config.get(section, {})
        if isinstance(section_data, dict):
            return section_data.get(key, default)
        else:
            return default
    
    def set(self, section: str, key: str, value: Any):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def save(self, output_file: str):
        """Save current configuration to file"""
        try:
            with open(output_file, 'w') as f:
                if output_file.endswith('.json'):
                    json.dump(self.config, f, indent=2)
                elif output_file.endswith(('.yml', '.yaml')):
                    yaml.dump(self.config, f, default_flow_style=False)
                else:
                    raise ValueError("Unsupported output format. Use .json or .yaml")
        except Exception as e:
            raise Exception(f"Error saving config to {output_file}: {str(e)}")
    
    def validate(self) -> bool:
        """Validate configuration"""
        required_tools = ['nmap', 'nuclei', 'sublist3r', 'gobuster']
        
        for tool in required_tools:
            tool_path = self.get('tools', tool, {}).get('path')
            if not tool_path or not self._check_tool_exists(tool_path):
                print(f"Warning: {tool} not found at {tool_path}")
                return False
        
        return True
    
    def _check_tool_exists(self, tool_path: str) -> bool:
        """Check if a tool exists and is executable"""
        if tool_path.startswith('/'):
            return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)
        else:
            # Check in PATH
            import shutil
            return shutil.which(tool_path) is not None
    
    def get_gemini_config(self) -> Dict[str, Any]:
        """Get Gemini API configuration"""
        return self.get('ai_analysis', default={})
    
    def is_ai_enabled(self) -> bool:
        """Check if AI analysis is enabled"""
        return (self.get('ai_analysis', 'enabled', False) and 
                bool(self.get('ai_analysis', 'gemini_api_key')))
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.get('tools', tool_name, {})
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return json.dumps(self.config, indent=2)

