"""
Core SSRF Scanner Engine with Async Support and Rate Limiting
"""

import asyncio
import aiohttp
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class BaselineMetrics:
    """Stores baseline metrics for anomaly detection"""
    avg_response_size: float
    status_codes: Dict[int, int]
    content_hash: str
    avg_response_time: float
    headers_fingerprint: str


class RateLimiter:
    """Token bucket rate limiter for controlling request rate"""
    
    def __init__(self, requests_per_second: int = 10):
        """
        Initialize rate limiter
        
        Args:
            requests_per_second: Maximum requests allowed per second
        """
        try:
            self.rate = requests_per_second
            self.tokens = requests_per_second
            self.max_tokens = requests_per_second
            self.last_update = time.time()
            self.lock = asyncio.Lock()
            logger.info(f"Rate limiter initialized: {requests_per_second} req/s")
        except Exception as e:
            logger.error(f"Error initializing rate limiter: {e}")
            raise
    
    async def acquire(self):
        """Acquire a token, waiting if necessary"""
        try:
            async with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                
                # Add tokens based on elapsed time
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens < 1:
                    # Calculate wait time
                    wait_time = (1 - self.tokens) / self.rate
                    await asyncio.sleep(wait_time)
                    self.tokens = 0
                else:
                    self.tokens -= 1
        except Exception as e:
            logger.error(f"Error in rate limiter acquire: {e}")
            # Don't block on error, just log
            pass


class SSRFScanner:
    """Main SSRF Scanner with async capabilities"""
    
    def __init__(
        self,
        target_url: str,
        requests_per_second: int = 10,
        max_concurrent: int = 50,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None
    ):
        """
        Initialize SSRF Scanner
        
        Args:
            target_url: Target URL to scan
            requests_per_second: Rate limit for requests
            max_concurrent: Maximum concurrent connections
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
            proxy: Proxy URL if needed
            cookies: Dictionary of cookies
        """
        try:
            self.target_url = target_url
            self.rate_limiter = RateLimiter(requests_per_second)
            self.semaphore = asyncio.Semaphore(max_concurrent)
            self.timeout = aiohttp.ClientTimeout(total=timeout)
            self.user_agent = user_agent or "SSRF-Scanner/1.0"
            self.proxy = proxy
            self.cookies = cookies or {}
            self.session: Optional[aiohttp.ClientSession] = None
            self.baseline: Optional[BaselineMetrics] = None
            self.results = []
            
            # Hybrid RAG Engine
            from .rag_engine import SSRFKnowledgeManager
            self.rag = SSRFKnowledgeManager()
            
            logger.info(f"SSRF Scanner initialized for target: {target_url}")
            logger.info("Hybrid RAG Engine loaded.")
            logger.info(f"Config: {requests_per_second} req/s, {max_concurrent} concurrent, {timeout}s timeout")
        except Exception as e:
            logger.error(f"Error initializing SSRF Scanner: {e}")
            raise
    
    async def __aenter__(self):
        """Async context manager entry"""
        try:
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=50)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent},
                cookies=self.cookies
            )
            logger.info("HTTP session created")
            return self
        except Exception as e:
            logger.error(f"Error creating HTTP session: {e}")
            raise
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        try:
            if self.session:
                await self.session.close()
                logger.info("HTTP session closed")
        except Exception as e:
            logger.error(f"Error closing HTTP session: {e}")
    
    async def make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        allow_redirects: bool = True
    ) -> Optional[Dict]:
        """
        Make an HTTP request with rate limiting and error handling
        
        Args:
            url: URL to request
            method: HTTP method
            headers: Additional headers
            data: Request body
            allow_redirects: Whether to follow redirects
            
        Returns:
            Dictionary with response data or None on error
        """
        try:
            # Acquire rate limit token
            await self.rate_limiter.acquire()
            
            # Acquire semaphore for concurrency control
            async with self.semaphore:
                if not self.session:
                    logger.error("Session not initialized")
                    return None
                
                # Merge headers
                req_headers = headers or {}
                
                start_time = time.time()
                
                try:
                    async with self.session.request(
                        method,
                        url,
                        headers=req_headers,
                        data=data,
                        allow_redirects=allow_redirects,
                        proxy=self.proxy,
                        ssl=False  # Allow self-signed certs for testing
                    ) as response:
                        content = await response.read()
                        response_time = time.time() - start_time
                        
                        result = {
                            'url': url,
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'content': content,
                            'content_length': len(content),
                            'response_time': response_time,
                            'method': method
                        }
                        
                        logger.debug(f"Request to {url}: {response.status} ({response_time:.2f}s)")
                        return result
                        
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout requesting {url}")
                    return {
                        'url': url,
                        'error': 'timeout',
                        'status_code': 0,
                        'content': b'',
                        'content_length': 0,
                        'response_time': self.timeout.total
                    }
                except aiohttp.ClientError as e:
                    logger.warning(f"Client error requesting {url}: {e}")
                    return {
                        'url': url,
                        'error': str(e),
                        'status_code': 0,
                        'content': b'',
                        'content_length': 0,
                        'response_time': time.time() - start_time
                    }
                except Exception as e:
                    logger.error(f"Unexpected error requesting {url}: {e}")
                    return {
                        'url': url,
                        'error': str(e),
                        'status_code': 0,
                        'content': b'',
                        'content_length': 0,
                        'response_time': time.time() - start_time
                    }
                    
        except Exception as e:
            logger.error(f"Error in make_request: {e}")
            return None
    
    async def establish_baseline(
        self, 
        num_probes: int = 10,
        method: str = "GET",
        post_data: Optional[Dict[str, str]] = None,
        param: Optional[str] = None
    ) -> BaselineMetrics:
        """
        Establish baseline metrics by probing the target multiple times
        
        Args:
            num_probes: Number of baseline probes to perform
            method: HTTP method to use (GET or POST)
            post_data: POST parameters for baseline (if using POST)
            param: Parameter to inject canary into
            
        Returns:
            BaselineMetrics object
        """
        try:
            logger.info(f"Establishing baseline with {num_probes} probes using {method}...")
            
            response_sizes = []
            response_times = []
            status_codes = defaultdict(int)
            content_hashes = []
            headers_list = []
            
            # Create tasks based on method
            # Create tasks based on method
            if method.upper() == "POST":
                import urllib.parse
                
                tasks = []
                for _ in range(num_probes):
                    # Create fresh copy of post data
                    current_post_data = post_data.copy() if post_data else {}
                    
                    # Inject canary if param specified
                    if param:
                        current_post_data[param] = "SSRF_BASELINE_CANARY"
                        
                    body = urllib.parse.urlencode(current_post_data)
                    
                    tasks.append(
                        self.make_request(
                            self.target_url,
                            method="POST",
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            data=body
                        )
                    )
            else:
                # GET
                if param:
                    separator = '&' if '?' in self.target_url else '?'
                    url = f"{self.target_url}{separator}{param}=SSRF_BASELINE_CANARY"
                    tasks = [self.make_request(url) for _ in range(num_probes)]
                else:
                    tasks = [self.make_request(self.target_url) for _ in range(num_probes)]
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                if isinstance(response, Exception):
                    logger.warning(f"Baseline probe failed: {response}")
                    continue
                    
                if response and 'error' not in response:
                    response_sizes.append(response['content_length'])
                    response_times.append(response['response_time'])
                    status_codes[response['status_code']] += 1
                    
                    # Hash content for comparison
                    content_hash = hashlib.md5(response['content']).hexdigest()
                    content_hashes.append(content_hash)
                    
                    # Create headers fingerprint
                    headers_str = ''.join(sorted(response['headers'].keys()))
                    headers_list.append(headers_str)
            
            if not response_sizes:
                logger.error("Failed to establish baseline - no successful probes")
                raise Exception("Baseline establishment failed")
            
            # Calculate metrics
            avg_size = sum(response_sizes) / len(response_sizes)
            avg_time = sum(response_times) / len(response_times)
            
            # Use most common hash and headers
            most_common_hash = max(set(content_hashes), key=content_hashes.count)
            most_common_headers = max(set(headers_list), key=headers_list.count)
            
            baseline = BaselineMetrics(
                avg_response_size=avg_size,
                status_codes=dict(status_codes),
                content_hash=most_common_hash,
                avg_response_time=avg_time,
                headers_fingerprint=most_common_headers
            )
            
            self.baseline = baseline
            
            logger.info(f"Baseline established: avg_size={avg_size:.0f}B, "
                       f"avg_time={avg_time:.2f}s, status_codes={dict(status_codes)}")
            
            return baseline
            
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")
            raise
    
    def is_anomalous(self, response: Dict, threshold: float = 0.3) -> Tuple[bool, List[str]]:
        """
        Check if a response is anomalous compared to baseline
        
        Args:
            response: Response dictionary
            threshold: Anomaly threshold (0-1)
            
        Returns:
            Tuple of (is_anomalous, reasons)
        """
        try:
            if not self.baseline or not response or 'error' in response:
                return False, []
            
            reasons = []
            
            # Check status code
            if response['status_code'] not in self.baseline.status_codes:
                reasons.append(f"Unusual status code: {response['status_code']}")
            
            # Check response size deviation
            size_diff = abs(response['content_length'] - self.baseline.avg_response_size)
            size_deviation = size_diff / max(self.baseline.avg_response_size, 1)
            
            if size_deviation > threshold:
                reasons.append(f"Response size deviation: {size_deviation:.2%}")
            
            # Check content hash
            content_hash = hashlib.md5(response['content']).hexdigest()
            if content_hash != self.baseline.content_hash:
                reasons.append("Content hash mismatch")
            
            # Check response time
            time_diff = abs(response['response_time'] - self.baseline.avg_response_time)
            time_deviation = time_diff / max(self.baseline.avg_response_time, 0.1)
            
            if time_deviation > 2.0:  # More lenient for timing
                reasons.append(f"Response time deviation: {time_deviation:.2%}")
            
            return len(reasons) > 0, reasons
            
        except Exception as e:
            logger.error(f"Error checking anomaly: {e}")
            return False, []
    
    async def test_payload(
        self, 
        payload: str, 
        param: str = "url",
        method: str = "GET",
        post_data: Optional[Dict[str, str]] = None
    ) -> Optional[Dict]:
        """
        Test a single SSRF payload
        
        Args:
            payload: SSRF payload to test
            param: Parameter name to inject into
            method: HTTP method (GET or POST)
            post_data: Additional POST parameters
            
        Returns:
            Test result dictionary
        """
        try:
            if method.upper() == "POST":
                # For POST requests, send parameter in body
                body_params = post_data.copy() if post_data else {}
                body_params[param] = payload
                
                # URL encode the body
                import urllib.parse
                body = urllib.parse.urlencode(body_params)
                
                response = await self.make_request(
                    self.target_url,
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=body
                )
                test_url = f"{self.target_url} [POST: {param}={payload}]"
            else:
                # For GET requests, append to URL
                separator = '&' if '?' in self.target_url else '?'
                test_url = f"{self.target_url}{separator}{param}={payload}"
                response = await self.make_request(test_url)
            
            if not response:
                return None
            
            # Check for anomalies
            is_anomalous, reasons = self.is_anomalous(response)
            
            # RAG-Enhanced Detection (Smart Signal)
            rag_match = None
            try:
                # Try to decode content for RAG, fallback to binary if needed
                resp_text = response['content'].decode('utf-8', errors='ignore')
                rag_match = self.rag.detect_match(resp_text)
            except Exception as e:
                logger.debug(f"RAG detection failed for {payload}: {e}")

            vulnerable = is_anomalous
            vuln_type = "Anomaly Detected" if is_anomalous else None
            confidence = 0.7 if is_anomalous else 0.0

            if rag_match:
                logger.info(f"[SMART DETECTION] RAG matched successful pattern for {payload}!")
                vulnerable = True
                vuln_type = f"RAG: {rag_match['type']}"
                confidence = max(confidence, rag_match['confidence'])

            result = {
                'payload': payload,
                'test_url': test_url,
                'response': response,
                'is_anomalous': is_anomalous,
                'anomaly_reasons': reasons,
                'vulnerable': vulnerable,
                'vulnerability_type': vuln_type,
                'confidence': confidence,
                'rag_match': rag_match
            }
            
            logger.debug(f"Tested: {payload} -> Status: {response['status_code']}, Size: {response['content_length']}")
            return result
            
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {e}")
            return None
