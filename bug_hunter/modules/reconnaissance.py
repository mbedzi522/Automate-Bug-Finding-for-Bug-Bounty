"""
Reconnaissance Module - Automated information gathering
"""

import subprocess
import json
import logging
import re
import socket
import requests
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import dns.resolver

class ReconModule:
    """Reconnaissance module for automated information gathering"""
    
    def __init__(self, config):
        """Initialize reconnaissance module"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('general', 'timeout', 30)
        self.max_threads = config.get('general', 'max_threads', 10)
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive reconnaissance on target"""
        self.logger.info(f"Starting reconnaissance for {target}")
        
        results = {
            'target': target,
            'subdomains': [],
            'open_ports': [],
            'services': {},
            'technologies': {},
            'directories': [],
            'dns_records': {},
            'ssl_info': {},
            'whois_info': {},
            'metadata': {
                'scan_time': None,
                'tools_used': []
            }
        }
        
        try:
            # Subdomain enumeration
            self.logger.info("Performing subdomain enumeration...")
            results['subdomains'] = self._enumerate_subdomains(target)
            results['metadata']['tools_used'].append('sublist3r')
            
            # Port scanning
            self.logger.info("Performing port scanning...")
            results['open_ports'] = self._port_scan(target)
            results['metadata']['tools_used'].append('nmap')
            
            # Service detection
            self.logger.info("Detecting services...")
            results['services'] = self._detect_services(target, results['open_ports'])
            
            # Technology detection
            self.logger.info("Detecting technologies...")
            results['technologies'] = self._detect_technologies(target)
            
            # Directory enumeration
            self.logger.info("Enumerating directories...")
            results['directories'] = self._enumerate_directories(target)
            results['metadata']['tools_used'].append('gobuster')
            
            # DNS enumeration
            self.logger.info("Performing DNS enumeration...")
            results['dns_records'] = self._enumerate_dns(target)
            
            # SSL/TLS information
            self.logger.info("Gathering SSL/TLS information...")
            results['ssl_info'] = self._get_ssl_info(target)
            
            self.logger.info(f"Reconnaissance completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {str(e)}")
            raise
        
        return results
    
    def _enumerate_subdomains(self, target: str) -> List[str]:
        """Enumerate subdomains using multiple methods"""
        subdomains = set()
        
        try:
            # Method 1: Sublist3r
            sublist3r_results = self._run_sublist3r(target)
            subdomains.update(sublist3r_results)
            
            # Method 2: DNS brute force
            dns_results = self._dns_bruteforce(target)
            subdomains.update(dns_results)
            
            # Method 3: Certificate transparency logs
            ct_results = self._check_certificate_transparency(target)
            subdomains.update(ct_results)
            
        except Exception as e:
            self.logger.error(f"Error enumerating subdomains: {str(e)}")
        
        return list(subdomains)
    
    def _run_sublist3r(self, target: str) -> List[str]:
        """Run Sublist3r for subdomain enumeration"""
        try:
            cmd = [
                'sublist3r',
                '-d', target,
                '-t', str(self.config.get('tools', 'sublist3r', {}).get('threads', 40)),
                '-o', f'/tmp/sublist3r_{target}.txt'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                try:
                    with open(f'/tmp/sublist3r_{target}.txt', 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                    return subdomains
                except FileNotFoundError:
                    return []
            else:
                self.logger.warning(f"Sublist3r failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Sublist3r timed out")
            return []
        except Exception as e:
            self.logger.error(f"Error running Sublist3r: {str(e)}")
            return []
    
    def _dns_bruteforce(self, target: str) -> List[str]:
        """Perform DNS brute force for subdomain discovery"""
        subdomains = []
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'mobile', 'secure', 'vpn', 'remote',
            'portal', 'support', 'help', 'docs', 'cdn', 'static', 'assets'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{target}"
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
        
        return subdomains
    
    def _check_certificate_transparency(self, target: str) -> List[str]:
        """Check certificate transparency logs for subdomains"""
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip()
                        if domain and domain.endswith(target):
                            subdomains.append(domain)
            
        except Exception as e:
            self.logger.error(f"Error checking certificate transparency: {str(e)}")
        
        return list(set(subdomains))
    
    def _port_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform port scanning using Nmap"""
        open_ports = []
        
        try:
            # Get port range from config
            default_ports = self.config.get('reconnaissance', 'default_ports', '80,443,8080,8443,3000,5000,8000,9000')
            top_ports = self.config.get('reconnaissance', 'top_ports', 1000)
            
            # Run Nmap scan
            cmd = [
                'nmap',
                '-sS',  # SYN scan
                '-sV',  # Version detection
                '--top-ports', str(top_ports),
                '-T4',  # Aggressive timing
                '--open',  # Only show open ports
                '-oX', f'/tmp/nmap_{target}.xml',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                # Parse Nmap output
                open_ports = self._parse_nmap_output(result.stdout)
            else:
                self.logger.warning(f"Nmap scan failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("Nmap scan timed out")
        except Exception as e:
            self.logger.error(f"Error during port scan: {str(e)}")
        
        return open_ports
    
    def _parse_nmap_output(self, nmap_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap output to extract port information"""
        ports = []
        
        # Simple regex parsing (could be improved with XML parsing)
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?'
        
        for line in nmap_output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port_info = {
                    'port': int(match.group(1)),
                    'protocol': match.group(2),
                    'service': match.group(3),
                    'version': match.group(4) if match.group(4) else 'Unknown'
                }
                ports.append(port_info)
        
        return ports
    
    def _detect_services(self, target: str, open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect services running on open ports"""
        services = {}
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Try to get more detailed service information
            try:
                if port in [80, 8080, 3000, 5000, 8000]:
                    # HTTP service
                    http_info = self._probe_http_service(target, port, False)
                    services[f"{port}/http"] = http_info
                elif port in [443, 8443]:
                    # HTTPS service
                    https_info = self._probe_http_service(target, port, True)
                    services[f"{port}/https"] = https_info
                else:
                    # Other services
                    services[f"{port}/{service}"] = {
                        'service': service,
                        'version': port_info.get('version', 'Unknown')
                    }
                    
            except Exception as e:
                self.logger.error(f"Error detecting service on port {port}: {str(e)}")
        
        return services
    
    def _probe_http_service(self, target: str, port: int, is_https: bool) -> Dict[str, Any]:
        """Probe HTTP/HTTPS service for detailed information"""
        protocol = 'https' if is_https else 'http'
        url = f"{protocol}://{target}:{port}"
        
        service_info = {
            'url': url,
            'status_code': None,
            'server': None,
            'title': None,
            'technologies': [],
            'headers': {}
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            service_info['status_code'] = response.status_code
            service_info['headers'] = dict(response.headers)
            
            # Extract server information
            service_info['server'] = response.headers.get('Server', 'Unknown')
            
            # Extract page title
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            if title_match:
                service_info['title'] = title_match.group(1).strip()
            
            # Basic technology detection
            service_info['technologies'] = self._detect_web_technologies(response)
            
        except Exception as e:
            self.logger.error(f"Error probing HTTP service at {url}: {str(e)}")
        
        return service_info
    
    def _detect_technologies(self, target: str) -> Dict[str, Any]:
        """Detect technologies used by the target"""
        technologies = {
            'web_server': None,
            'cms': None,
            'frameworks': [],
            'languages': [],
            'databases': [],
            'cdn': None
        }
        
        try:
            # Try to access the main website
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{target}"
                    response = requests.get(url, timeout=10, verify=False)
                    
                    # Detect web server
                    server_header = response.headers.get('Server', '')
                    if server_header:
                        technologies['web_server'] = server_header
                    
                    # Detect technologies from headers and content
                    tech_info = self._detect_web_technologies(response)
                    technologies.update(tech_info)
                    
                    break  # If successful, no need to try other protocol
                    
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error detecting technologies: {str(e)}")
        
        return technologies
    
    def _detect_web_technologies(self, response) -> Dict[str, Any]:
        """Detect web technologies from HTTP response"""
        technologies = {
            'cms': None,
            'frameworks': [],
            'languages': [],
            'cdn': None
        }
        
        headers = response.headers
        content = response.text.lower()
        
        # CMS Detection
        cms_indicators = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'administrator'],
            'magento': ['magento', 'mage/'],
            'shopify': ['shopify', 'cdn.shopify.com']
        }
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in content for indicator in indicators):
                technologies['cms'] = cms
                break
        
        # Framework Detection
        framework_indicators = {
            'react': ['react', '_react'],
            'angular': ['angular', 'ng-'],
            'vue': ['vue.js', '__vue__'],
            'bootstrap': ['bootstrap'],
            'jquery': ['jquery']
        }
        
        for framework, indicators in framework_indicators.items():
            if any(indicator in content for indicator in indicators):
                technologies['frameworks'].append(framework)
        
        # Language Detection
        language_indicators = {
            'php': ['x-powered-by: php', '.php'],
            'asp.net': ['x-aspnet-version', 'asp.net'],
            'python': ['x-powered-by: python'],
            'ruby': ['x-powered-by: ruby'],
            'java': ['jsessionid', 'j_security_check']
        }
        
        for language, indicators in language_indicators.items():
            if any(indicator in str(headers).lower() or indicator in content for indicator in indicators):
                technologies['languages'].append(language)
        
        # CDN Detection
        cdn_headers = ['cf-ray', 'x-cache', 'x-served-by', 'x-amz-cf-id']
        for header in cdn_headers:
            if header in headers:
                if 'cloudflare' in str(headers.get(header, '')).lower():
                    technologies['cdn'] = 'Cloudflare'
                elif 'amazon' in str(headers.get(header, '')).lower():
                    technologies['cdn'] = 'Amazon CloudFront'
                else:
                    technologies['cdn'] = 'Unknown CDN'
                break
        
        return technologies
    
    def _enumerate_directories(self, target: str) -> List[Dict[str, Any]]:
        """Enumerate directories using Gobuster"""
        directories = []
        
        try:
            # Get wordlist from config
            wordlist = self.config.get('tools', 'gobuster', {}).get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            threads = self.config.get('tools', 'gobuster', {}).get('threads', 50)
            
            # Try both HTTP and HTTPS
            for protocol in ['https', 'http']:
                url = f"{protocol}://{target}"
                
                cmd = [
                    'gobuster',
                    'dir',
                    '-u', url,
                    '-w', wordlist,
                    '-t', str(threads),
                    '-q',  # Quiet mode
                    '--no-error',
                    '-o', f'/tmp/gobuster_{target}_{protocol}.txt'
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0:
                        # Parse results
                        try:
                            with open(f'/tmp/gobuster_{target}_{protocol}.txt', 'r') as f:
                                for line in f:
                                    if line.strip():
                                        parts = line.strip().split()
                                        if len(parts) >= 2:
                                            directories.append({
                                                'url': parts[0],
                                                'status_code': parts[1] if len(parts) > 1 else 'Unknown',
                                                'size': parts[2] if len(parts) > 2 else 'Unknown'
                                            })
                        except FileNotFoundError:
                            pass
                    
                    # If HTTPS works, don't try HTTP
                    if protocol == 'https' and directories:
                        break
                        
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Gobuster timed out for {protocol}://{target}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error enumerating directories: {str(e)}")
        
        return directories
    
    def _enumerate_dns(self, target: str) -> Dict[str, List[str]]:
        """Enumerate DNS records"""
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(target, record_type)
                for answer in answers:
                    dns_records[record_type].append(str(answer))
            except Exception:
                # Record type not found or error occurred
                pass
        
        return dns_records
    
    def _get_ssl_info(self, target: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information"""
        ssl_info = {}
        
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
        except Exception as e:
            self.logger.error(f"Error getting SSL info: {str(e)}")
        
        return ssl_info

