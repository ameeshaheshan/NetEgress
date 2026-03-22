"""
Remediation Engine - Provides mitigation recommendations
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class RemediationEngine:
    """Provides remediation recommendations for SSRF vulnerabilities"""
    
    def __init__(self):
        """Initialize remediation engine with mitigation strategies"""
        try:
            self.mitigations = {
                'SSRF_CLOUD_METADATA': {
                    'title': 'Cloud Metadata SSRF',
                    'severity': 'CRITICAL',
                    'description': 'Application can access cloud provider metadata endpoints, potentially exposing credentials and sensitive configuration.',
                    'recommendations': [
                        'Implement strict allowlist of permitted domains/IPs',
                        'Block access to 169.254.169.254 and metadata.google.internal',
                        'Use IMDSv2 (AWS) which requires session tokens',
                        'Disable metadata endpoints if not needed',
                        'Implement network segmentation to restrict metadata access',
                        'Use Web Application Firewall (WAF) rules to block metadata requests'
                    ],
                    'code_examples': {
                        'python': '''# Example: Validate and restrict URLs
import ipaddress
from urllib.parse import urlparse

BLOCKED_IPS = ['169.254.169.254', '127.0.0.1']
BLOCKED_DOMAINS = ['metadata.google.internal', 'metadata']

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        
        # Block metadata domains
        if parsed.hostname in BLOCKED_DOMAINS:
            return False
        
        # Resolve and check IP
        ip = ipaddress.ip_address(parsed.hostname)
        
        # Block private IPs
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
            
        # Block specific IPs
        if str(ip) in BLOCKED_IPS:
            return False
            
        return True
    except:
        return False
'''
                    }
                },
                
                'SSRF_FILE_DISCLOSURE': {
                    'title': 'File Disclosure via SSRF',
                    'severity': 'CRITICAL',
                    'description': 'Application can read local files through SSRF, exposing sensitive system files and credentials.',
                    'recommendations': [
                        'Restrict URL schemes to http/https only',
                        'Block file://, gopher://, dict://, and other dangerous protocols',
                        'Implement strict input validation on URL parameters',
                        'Use allowlist of permitted domains',
                        'Run application with minimal file system permissions',
                        'Disable URL wrappers in PHP (allow_url_fopen, allow_url_include)'
                    ],
                    'code_examples': {
                        'python': '''# Example: Protocol validation
from urllib.parse import urlparse

ALLOWED_SCHEMES = ['http', 'https']

def validate_url_scheme(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise ValueError(f"Scheme {parsed.scheme} not allowed")
        return True
    except Exception as e:
        logger.error(f"Invalid URL: {e}")
        return False
'''
                    }
                },
                
                'SSRF_INTERNAL_SERVICE': {
                    'title': 'Internal Service Access via SSRF',
                    'severity': 'HIGH',
                    'description': 'Application can access internal services (databases, caches, APIs) through SSRF.',
                    'recommendations': [
                        'Implement network segmentation to isolate internal services',
                        'Use authentication for all internal services',
                        'Block access to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)',
                        'Implement egress filtering at network level',
                        'Use service mesh with mTLS for internal communication',
                        'Monitor and alert on unusual outbound connections'
                    ],
                    'code_examples': {
                        'python': '''# Example: Block private IP ranges
import ipaddress

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or 
                   ip.is_link_local or ip.is_reserved)
    except:
        return False
'''
                    }
                },
                
                'SSRF_SENSITIVE_DATA': {
                    'title': 'Sensitive Data Exposure via SSRF',
                    'severity': 'HIGH',
                    'description': 'SSRF vulnerability exposing sensitive data such as API keys, credentials, or configuration.',
                    'recommendations': [
                        'Implement URL allowlist with strict validation',
                        'Use indirect object references instead of direct URLs',
                        'Sanitize and validate all URL inputs',
                        'Implement rate limiting on URL fetching endpoints',
                        'Log and monitor all outbound requests',
                        'Use dedicated service accounts with minimal permissions'
                    ],
                    'code_examples': {
                        'python': '''# Example: URL allowlist
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def is_allowed_domain(url):
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.hostname in ALLOWED_DOMAINS
    except:
        return False
'''
                    }
                },
                
                'SSRF_ANOMALY_DETECTED': {
                    'title': 'Potential SSRF (Anomaly Detected)',
                    'severity': 'MEDIUM',
                    'description': 'Anomalous behavior detected that may indicate SSRF vulnerability.',
                    'recommendations': [
                        'Investigate the anomalous responses manually',
                        'Implement comprehensive input validation',
                        'Use URL parsing libraries to validate and sanitize inputs',
                        'Implement timeout and size limits for outbound requests',
                        'Monitor application logs for suspicious URL patterns',
                        'Consider implementing a proxy service for outbound requests'
                    ],
                    'code_examples': {
                        'python': '''# Example: Request validation and limits
import requests

def safe_fetch(url, timeout=5, max_size=1048576):
    # Validate URL first
    if not is_safe_url(url):
        raise ValueError("Unsafe URL")
    
    # Fetch with limits
    response = requests.get(
        url,
        timeout=timeout,
        stream=True,
        allow_redirects=False
    )
    
    # Check size
    if int(response.headers.get('content-length', 0)) > max_size:
        raise ValueError("Response too large")
    
    return response
'''
                    }
                },
                
                'SSRF_NETWORK_ERROR': {
                    'title': 'Network-based SSRF Indicator',
                    'severity': 'MEDIUM',
                    'description': 'Network errors suggest the application is attempting to connect to specified hosts.',
                    'recommendations': [
                        'Implement strict URL validation',
                        'Use DNS resolution validation before making requests',
                        'Implement network-level egress filtering',
                        'Monitor and log all outbound connection attempts',
                        'Use a dedicated proxy for external requests',
                        'Implement circuit breakers for failing connections'
                    ],
                    'code_examples': {
                        'python': '''# Example: DNS validation
import socket

def validate_dns(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        if not is_public_ip(ip):
            raise ValueError(f"Hostname resolves to private IP: {ip}")
        return ip
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {hostname}")
'''
                    }
                },
                
                'SSRF_OOB_CONFIRMED': {
                    'title': 'SSRF Confirmed via Out-of-Band',
                    'severity': 'CRITICAL',
                    'description': 'SSRF confirmed through out-of-band interaction (DNS/HTTP callback).',
                    'recommendations': [
                        'IMMEDIATE ACTION REQUIRED - Active SSRF vulnerability confirmed',
                        'Disable the vulnerable endpoint immediately',
                        'Implement comprehensive URL validation',
                        'Deploy network-level egress filtering',
                        'Audit all code that makes outbound HTTP requests',
                        'Implement security monitoring and alerting',
                        'Consider bug bounty disclosure if applicable'
                    ],
                    'code_examples': {
                        'python': '''# Example: Comprehensive SSRF protection
class SSRFProtection:
    BLOCKED_SCHEMES = ['file', 'gopher', 'dict', 'ftp']
    ALLOWED_DOMAINS = []  # Strict allowlist
    
    @staticmethod
    def validate(url):
        from urllib.parse import urlparse
        import ipaddress
        
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme.lower() in SSRFProtection.BLOCKED_SCHEMES:
            raise ValueError("Blocked URL scheme")
        
        # Check domain allowlist
        if SSRFProtection.ALLOWED_DOMAINS:
            if parsed.hostname not in SSRFProtection.ALLOWED_DOMAINS:
                raise ValueError("Domain not in allowlist")
        
        # Resolve and check IP
        try:
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private or ip_obj.is_loopback:
                raise ValueError("Private IP not allowed")
        except:
            raise ValueError("Invalid hostname")
        
        return True
'''
                    }
                }
            }
            
            logger.info(f"Remediation engine initialized with {len(self.mitigations)} mitigation strategies")
            
        except Exception as e:
            logger.error(f"Error initializing remediation engine: {e}")
            raise
    
    def get_remediation(self, vulnerability_type: str) -> Optional[Dict]:
        """
        Get remediation recommendations for a vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            Remediation dictionary or None
        """
        try:
            return self.mitigations.get(vulnerability_type)
        except Exception as e:
            logger.error(f"Error getting remediation: {e}")
            return None
    
    def generate_remediation_report(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Generate comprehensive remediation report
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Remediation report dictionary
        """
        try:
            if not vulnerabilities:
                return {
                    'total_vulnerabilities': 0,
                    'severity_breakdown': {},
                    'recommendations': []
                }
            
            # Group by vulnerability type
            vuln_by_type = {}
            severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for vuln in vulnerabilities:
                vuln_type = vuln.get('vulnerability_type', 'UNKNOWN')
                
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                
                vuln_by_type[vuln_type].append(vuln)
                
                # Count severity
                mitigation = self.get_remediation(vuln_type)
                if mitigation:
                    severity = mitigation.get('severity', 'MEDIUM')
                else:
                    # Fallback for unrecognized vulnerability types
                    severity = 'MEDIUM'
                
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            # Generate recommendations
            recommendations = []
            
            for vuln_type, vulns in vuln_by_type.items():
                mitigation = self.get_remediation(vuln_type)
                
                if mitigation:
                    recommendations.append({
                        'vulnerability_type': vuln_type,
                        'count': len(vulns),
                        'severity': mitigation['severity'],
                        'title': mitigation['title'],
                        'description': mitigation['description'],
                        'recommendations': mitigation['recommendations'],
                        'code_examples': mitigation.get('code_examples', {}),
                        'affected_payloads': [v.get('payload', 'unknown') for v in vulns[:5]]  # Limit to 5
                    })
                else:
                    # Generic fallback recommendation
                    recommendations.append({
                        'vulnerability_type': vuln_type,
                        'count': len(vulns),
                        'severity': 'MEDIUM',
                        'title': f"Uncategorized SSRF Vulnerability: {vuln_type}",
                        'description': 'Scanner detected potentially unsafe outward behavior without a specific signature match.',
                        'recommendations': ['Investigate the affected endpoint manually for SSRF risk.', 'Validate all URL inputs strictly.', 'Monitor application logs.'],
                        'code_examples': {},
                        'affected_payloads': [v.get('payload', 'unknown') for v in vulns[:5]]
                    })
            
            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            recommendations.sort(key=lambda x: severity_order.get(x['severity'], 99))
            
            report = {
                'total_vulnerabilities': len(vulnerabilities),
                'unique_vulnerability_types': len(vuln_by_type),
                'severity_breakdown': severity_count,
                'recommendations': recommendations,
                'summary': self._generate_summary(severity_count, len(vulnerabilities))
            }
            
            logger.info(f"Generated remediation report for {len(vulnerabilities)} vulnerabilities")
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating remediation report: {e}")
            return {
                'total_vulnerabilities': 0,
                'error': str(e)
            }
    
    def _generate_summary(self, severity_count: Dict, total: int) -> str:
        """Generate executive summary"""
        try:
            critical = severity_count.get('CRITICAL', 0)
            high = severity_count.get('HIGH', 0)
            medium = severity_count.get('MEDIUM', 0)
            
            summary = f"Detected {total} SSRF vulnerabilities: "
            
            parts = []
            if critical > 0:
                parts.append(f"{critical} CRITICAL")
            if high > 0:
                parts.append(f"{high} HIGH")
            if medium > 0:
                parts.append(f"{medium} MEDIUM")
            
            summary += ", ".join(parts) if parts else "0 severity issues"
            
            if critical > 0:
                summary += ". IMMEDIATE ACTION REQUIRED for critical vulnerabilities."
            elif high > 0:
                summary += ". Prompt remediation recommended for high severity issues."
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return "Error generating summary"
