"""
Verification Module - Content Analysis and OOB Interaction Detection
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityMatch:
    """Represents a detected vulnerability"""
    pattern_name: str
    matched_content: str
    confidence: float
    severity: str


class Verifier:
    """Verifies SSRF vulnerabilities through content analysis"""
    
    def __init__(self):
        """Initialize verifier with detection patterns"""
        try:
            # Define sensitive content patterns
            self.patterns = {
                # AWS Credentials
                'aws_access_key': {
                    'regex': re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
                    'severity': 'CRITICAL',
                    'confidence': 0.95
                },
                'aws_secret_key': {
                    'regex': re.compile(r'aws_secret_access_key.*?["\']([A-Za-z0-9/+=]{40})["\']', re.IGNORECASE),
                    'severity': 'CRITICAL',
                    'confidence': 0.95
                },
                
                # Cloud Metadata
                'aws_metadata': {
                    'regex': re.compile(r'(ami-id|instance-id|instance-type|local-ipv4|public-ipv4)', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.90
                },
                'gcp_metadata': {
                    'regex': re.compile(r'(project-id|numeric_project_id|instance/id|instance/name)', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.90
                },
                'azure_metadata': {
                    'regex': re.compile(r'(subscriptionId|resourceGroupName|vmId|location)', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.85
                },
                
                # System Files
                'etc_passwd': {
                    'regex': re.compile(r'root:.*?:0:0:', re.MULTILINE),
                    'severity': 'CRITICAL',
                    'confidence': 0.98
                },
                'etc_shadow': {
                    'regex': re.compile(r'root:\$[0-9]\$', re.MULTILINE),
                    'severity': 'CRITICAL',
                    'confidence': 0.98
                },
                'etc_hosts': {
                    'regex': re.compile(r'127\.0\.0\.1\s+localhost', re.MULTILINE),
                    'severity': 'MEDIUM',
                    'confidence': 0.70
                },
                
                # Private Keys
                'private_key': {
                    'regex': re.compile(r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', re.IGNORECASE),
                    'severity': 'CRITICAL',
                    'confidence': 0.95
                },
                
                # Database Credentials
                'db_connection': {
                    'regex': re.compile(r'(mysql|postgresql|mongodb)://[^:]+:[^@]+@', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.85
                },
                
                # API Keys
                'api_key': {
                    'regex': re.compile(r'(api[_-]?key|apikey|api[_-]?secret)[\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.80
                },
                
                # Internal Network Info
                'internal_ip': {
                    'regex': re.compile(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
                    'severity': 'MEDIUM',
                    'confidence': 0.75
                },
                
                # Redis/Memcached
                'redis_info': {
                    'regex': re.compile(r'redis_version:|used_memory:|connected_clients:', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.90
                },
                
                # Docker/Kubernetes
                'docker_socket': {
                    'regex': re.compile(r'/var/run/docker\.sock|docker\.sock', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.85
                },
                'k8s_token': {
                    'regex': re.compile(r'/var/run/secrets/kubernetes\.io', re.IGNORECASE),
                    'severity': 'HIGH',
                    'confidence': 0.90
                },
            }
            
            logger.info(f"Verifier initialized with {len(self.patterns)} detection patterns")
            
        except Exception as e:
            logger.error(f"Error initializing verifier: {e}")
            raise
    
    def analyze_content(self, content: bytes, url: str = "") -> List[VulnerabilityMatch]:
        """
        Analyze response content for sensitive information
        
        Args:
            content: Response content to analyze
            url: URL that was requested (for context)
            
        Returns:
            List of vulnerability matches
        """
        try:
            matches = []
            
            # Convert bytes to string, handling encoding errors
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Error decoding content: {e}")
                text_content = str(content)
            
            # Check each pattern
            for pattern_name, pattern_info in self.patterns.items():
                try:
                    regex = pattern_info['regex']
                    found = regex.search(text_content)
                    
                    if found:
                        matched_text = found.group(0)
                        
                        # Truncate long matches
                        if len(matched_text) > 200:
                            matched_text = matched_text[:200] + "..."
                        
                        match = VulnerabilityMatch(
                            pattern_name=pattern_name,
                            matched_content=matched_text,
                            confidence=pattern_info['confidence'],
                            severity=pattern_info['severity']
                        )
                        
                        matches.append(match)
                        logger.info(f"Found {pattern_name} in response from {url}")
                        
                except Exception as e:
                    logger.error(f"Error checking pattern {pattern_name}: {e}")
                    continue
            
            return matches
            
            return matches
            
        except Exception as e:
            logger.error(f"Error analyzing content: {e}")
            return []

    def analyze_headers(self, headers: Dict[str, str]) -> List[VulnerabilityMatch]:
        """
        Analyze response headers for suspicious internal headers
        
        Args:
            headers: Response headers
            
        Returns:
            List of vulnerability matches
        """
        try:
            matches = []
            internal_header_keys = [
                'x-internal', 'server-internal', 'x-backend-server', 
                'x-upstream', 'x-forwarded-server', 'x-backend-ip'
            ]
            
            for key, value in headers.items():
                lower_key = key.lower()
                if any(k in lower_key for k in internal_header_keys):
                    match = VulnerabilityMatch(
                        pattern_name=f"header_{lower_key}",
                        matched_content=f"{key}: {value}",
                        confidence=0.80,
                        severity='HIGH'
                    )
                    matches.append(match)
                    logger.info(f"Found suspicious header {key}")
            
            return matches
            
        except Exception as e:
            logger.error(f"Error analyzing headers: {e}")
            return []
    
    def check_oob_interaction(self, oob_domain: Optional[str] = None) -> bool:
        """
        Check for out-of-band interactions
        
        Args:
            oob_domain: Domain to check for interactions (e.g., Burp Collaborator)
            
        Returns:
            True if interaction detected
        """
        try:
            if not oob_domain:
                logger.info("No OOB domain configured - skipping OOB check")
                return False
            
            # Placeholder for OOB interaction checking
            # In a real implementation, this would:
            # 1. Query the OOB service API (Burp Collaborator, interact.sh, etc.)
            # 2. Check for DNS/HTTP interactions
            # 3. Return True if any interactions found
            
            logger.info(f"OOB check for domain {oob_domain} - not implemented")
            return False
            
        except Exception as e:
            logger.error(f"Error checking OOB interaction: {e}")
            return False
    
    def calculate_vulnerability_score(
        self,
        response: Dict,
        is_anomalous: bool,
        anomaly_reasons: List[str],
        content_matches: List[VulnerabilityMatch],
        oob_detected: bool = False
    ) -> Tuple[bool, float, str]:
        """
        Calculate overall vulnerability score with false positive filtering
        """
        try:
            # MASTER FALSE POSITIVE FILTER
            # If the response contains generic error markers, it's likely a scan artifact, not a success
            negative_indicators = [
                'missing parameter', 'illegal character', 'invalid url', 
                'not found', 'bad request', 'sql error', 'syntax error',
                'internal server error', 'unexpected token', 'failed to parse',
                'stockapi', 'destination' # Specific for academy labs false positives
            ]
            
            content_str = ""
            if response and 'content' in response:
                try:
                    content_str = response['content'].decode('utf-8', errors='ignore').lower()
                except:
                    content_str = str(response['content']).lower()

            has_negative = any(ind in content_str for ind in negative_indicators)

            confidence = 0.0
            vulnerability_type = "UNKNOWN"
            
            # 1. CRITICAL: OOB detection is definitive evidence
            if oob_detected:
                confidence = 0.98
                vulnerability_type = "SSRF_OOB_CONFIRMED"
                return True, confidence, vulnerability_type
            
            # 2. HIGH/CRITICAL: Content matches (Regex-verified sensitive data)
            if content_matches:
                # Filter out content matches that are just the negative indicators themselves
                valid_matches = [m for m in content_matches if m.matched_content.lower() not in negative_indicators]
                
                if valid_matches:
                    severity_scores = {'CRITICAL': 0.95, 'HIGH': 0.85, 'MEDIUM': 0.65, 'LOW': 0.45}
                    max_conf = max(match.confidence for match in valid_matches)
                    max_sev = max((severity_scores.get(match.severity, 0.5) for match in valid_matches), default=0.5)
                    
                    confidence = (max_conf + max_sev) / 2
                    
                    # Determine type
                    match_types = [match.pattern_name for match in valid_matches]
                    if any(x in m for m in match_types for x in ['aws','gcp','azure']): vulnerability_type = "SSRF_CLOUD_METADATA"
                    elif any(x in m for m in match_types for x in ['passwd','shadow','key']): vulnerability_type = "SSRF_FILE_DISCLOSURE"
                    else: vulnerability_type = "SSRF_SENSITIVE_DATA"
                    
                    # If we found real data but ALSO error markers, reduce confidence slightly but keep it high
                    if has_negative: confidence *= 0.8
                    
                    return True, confidence, vulnerability_type

            # 3. LOW/MEDIUM: Heuristic Anomaly detection (No hard evidence found)
            if is_anomalous:
                # If we have negative indicators, the "anomaly" is just an error message. DROPPED.
                if has_negative:
                    return False, 0.05, "NOT_VULNERABLE (FALSE_POSITIVE_FILTERED)"

                # Strongest heuristic: Status code change (e.g., 200 -> 500 when probing internal)
                status_change = any("status code" in r for r in anomaly_reasons)
                
                if status_change and len(anomaly_reasons) >= 2:
                    confidence = 0.45 # Capped because we have no content proof
                    vulnerability_type = "SSRF_HEURISTIC_ANOMALY"
                    return True, confidence, vulnerability_type
                
                # Single anomaly (Size/Time) - potential Blind SSRF
                confidence = 0.25
                vulnerability_type = "SSRF_POTENTIAL_ANOMALY"
                return True, confidence, vulnerability_type
            
            # 4. TRIVIAL: Network errors
            error_indicators = ['connection refused', 'timeout', 'no route', 'unreachable']
            if any(ind in content_str for ind in error_indicators):
                return True, 0.20, "SSRF_NETWORK_INDICATOR"
            
            return False, 0.0, "NOT_VULNERABLE"
            
        except Exception as e:
            logger.error(f"Error calculating vulnerability score: {e}")
            return False, 0.0, "ERROR"
    
    def verify_vulnerability(
        self,
        test_result: Dict,
        oob_domain: Optional[str] = None
    ) -> Dict:
        """
        Comprehensive vulnerability verification
        
        Args:
            test_result: Test result from scanner
            oob_domain: Optional OOB domain for interaction checking
            
        Returns:
            Enhanced test result with verification data
        """
        try:
            if not test_result or 'response' not in test_result:
                logger.warning("Invalid test result for verification")
                return test_result
            
            response = test_result['response']
            
            # Analyze content
            content_matches = []
            if 'content' in response and response['content']:
                content_matches = self.analyze_content(
                    response['content'],
                    test_result.get('test_url', '')
                )
            
            # Analyze headers
            if 'headers' in response:
                header_matches = self.analyze_headers(response['headers'])
                content_matches.extend(header_matches)
            
            # Check OOB
            oob_detected = self.check_oob_interaction(oob_domain)
            
            # Calculate vulnerability score
            is_vulnerable, confidence, vuln_type = self.calculate_vulnerability_score(
                response,
                test_result.get('is_anomalous', False),
                test_result.get('anomaly_reasons', []),
                content_matches,
                oob_detected
            )
            
            # Update test result
            test_result['vulnerable'] = is_vulnerable
            test_result['confidence'] = confidence
            test_result['vulnerability_type'] = vuln_type
            test_result['content_matches'] = [
                {
                    'pattern': match.pattern_name,
                    'matched': match.matched_content,
                    'severity': match.severity,
                    'confidence': match.confidence
                }
                for match in content_matches
            ]
            test_result['oob_detected'] = oob_detected
            
            if is_vulnerable:
                logger.warning(
                    f"VULNERABILITY DETECTED: {vuln_type} "
                    f"(confidence: {confidence:.2%}) "
                    f"for payload: {test_result.get('payload', 'unknown')}"
                )
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error verifying vulnerability: {e}")
            return test_result
