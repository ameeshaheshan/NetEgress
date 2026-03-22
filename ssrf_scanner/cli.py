import argparse
import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
import time

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from .core import SSRFScanner
from .attack_modules import PayloadManager, AttackModules
from .verification import Verifier
from .remediation import RemediationEngine
from .reporting import Reporter
from .colors import log_info, log_error, log_warning, log_success, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET, Style
import urllib.parse

# Custom Log Formatter with Colorama
class ColorLogFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': BLUE + Style.BRIGHT,
        'INFO': GREEN + Style.BRIGHT,
        'WARNING': YELLOW + Style.BRIGHT,
        'ERROR': RED + Style.BRIGHT,
        'CRITICAL': MAGENTA + Style.BRIGHT
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, WHITE + Style.BRIGHT)
        time_str = self.formatTime(record, self.datefmt)
        return f"{YELLOW}{Style.BRIGHT}[{time_str}]{RESET}{color}[{record.levelname}]{RESET} {record.getMessage()}"

# Configure handlers explicitly to apply custom formatter to the console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColorLogFormatter(datefmt='%Y-%m-%d %H:%M:%S'))

file_handler = logging.FileHandler('ssrf_scanner.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[file_handler, console_handler]
)
logger = logging.getLogger(__name__)


class TqdmLoggingHandler(logging.Handler):
    """Logging handler that uses tqdm.write to avoid breaking progress bars"""
    def __init__(self, level=logging.NOTSET):
        super().__init__(level)

    def emit(self, record):
        try:
            msg = self.format(record)
            if tqdm:
                tqdm.write(msg)
            else:
                sys.stdout.write(msg + '\n')
                sys.stdout.flush()
            self.flush()
        except Exception:
            self.handleError(record)


class ColoredHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom help formatter with colors"""
    
    def __init__(self, prog):
        super().__init__(prog, max_help_position=60, width=120)

    def _get_help_string(self, action):
        help_text = super()._get_help_string(action)
        return f"{WHITE}{help_text}{RESET}"

    def _format_action_invocation(self, action):
        if not action.option_strings:
            default = self._get_default_metavar_for_positional(action)
            metavar, = self._metavar_formatter(action, default)(1)
            return f"{CYAN}{metavar}{RESET}"
        
        parts = []
        if action.nargs == 0:
            parts.extend([f"{CYAN}{option}{RESET}" for option in action.option_strings])
        else:
            default = self._get_default_metavar_for_optional(action)
            args_string = self._format_args(action, default)
            for option in action.option_strings:
                parts.append(f"{CYAN}{option}{RESET} {YELLOW}{args_string}{RESET}")
        
        return ', '.join(parts)

    def _format_usage(self, usage, actions, groups,e):
        usage_text = super()._format_usage(usage, actions, groups, e)
        return f"{YELLOW}{usage_text}{RESET}"

    def start_section(self, heading):
        super().start_section(f"{MAGENTA}{Style.BRIGHT}{heading}{RESET}")


class SSRFScannerCLI:
    """Command-line interface for SSRF Scanner"""
    
    def __init__(self):
        """Initialize CLI"""
        try:
            self.parser = self._create_parser()
            logger.info("CLI initialized")
        except Exception as e:
            logger.error(f"Error initializing CLI: {e}")
            raise
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        try:
            parser = argparse.ArgumentParser(
                description=f'{GREEN}SSRF Scanner - Automated SSRF Detection and Mitigation Tool{RESET}',
                formatter_class=ColoredHelpFormatter,
                epilog=f'''
{YELLOW}Examples:{RESET}
  {WHITE}# Basic GET scan{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com/fetch?url={RESET}

  {WHITE}# POST parameter scan{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com/api --method POST --param stockApi{RESET}

  {WHITE}# Scan with custom rate limiting{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com/api --rps 5 --concurrent 20{RESET}

  {WHITE}# Scan specific attack phases{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com --phases local_ips cloud_metadata{RESET}
  
  {WHITE}# POST with additional parameters{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com/api --method POST --param url --post-data "productId=1&storeId=1"{RESET}

  {WHITE}# Generate all report formats{RESET}
  {CYAN}python -m ssrf_scanner.cli --url http://example.com --output-format all{RESET}
                '''
            )
            
            # Target specification (mutually exclusive group not used to allow flexible logic check later)
            parser.add_argument(
                '--url',
                type=str,
                help='Target URL to scan'
            )
            
            parser.add_argument(
                '--urls-file',
                type=str,
                help='File containing list of URLs to scan'
            )
            
            # Optional arguments
            parser.add_argument(
                '--rps',
                type=int,
                default=10,
                help='Requests per second (default: 10)'
            )
            
            parser.add_argument(
                '--concurrent',
                '--threads',
                '-t',
                type=int,
                default=50,
                help='Maximum concurrent connections/threads (default: 50)'
            )
            
            parser.add_argument(
                '--timeout',
                type=int,
                default=10,
                help='Request timeout in seconds (default: 10)'
            )
            
            parser.add_argument(
                '--user-agent',
                type=str,
                help='Custom user agent string'
            )
            
            parser.add_argument(
                '--proxy',
                type=str,
                help='Proxy URL (e.g., http://proxy:8080)'
            )
            
            parser.add_argument(
                '--payloads-dir',
                type=str,
                default='payloads',
                help='Directory containing payload files (default: payloads)'
            )
            
            parser.add_argument(
                '--output-dir',
                type=str,
                default='reports',
                help='Output directory for reports (default: reports)'
            )
            
            parser.add_argument(
                '--output-format',
                type=str,
                choices=['json', 'csv', 'html', 'all'],
                default='all',
                help='Report output format (default: all)'
            )
            
            parser.add_argument(
                '--phases',
                type=str,
                nargs='+',
                choices=[
                    'local_ips', 'cloud_metadata', 'protocol_confusion',
                    'crlf_injection', 'bypass_encoding', 'dns_rebinding',
                    'port_scanning', 'parameter_fuzzing', 'header_injection',
                    'xxe_ssrf', 'all'
                ],
                default=['all'],
                help='Attack phases to execute (default: all)'
            )
            
            # Deprecated flag alias? No, we just used parser features above.
            # But let's keep the user's specific request for '-t' clear.
            
            parser.add_argument(
                '--baseline-probes',
                type=int,
                default=10,
                help='Number of baseline probes (default: 10)'
            )
            
            parser.add_argument(
                '--oob-domain',
                type=str,
                help='Out-of-band domain for interaction detection (e.g., Burp Collaborator)'
            )
            
            parser.add_argument(
                '--test-mode',
                action='store_true',
                help='Test mode - only perform baseline and safe checks'
            )
            
            parser.add_argument(
                '--verbose',
                action='store_true',
                help='Enable verbose logging'
            )
            
            parser.add_argument(
                '--quiet',
                action='store_true',
                help='Suppress progress bars and non-essential output'
            )
            
            parser.add_argument(
                '--method',
                type=str,
                choices=['GET', 'POST'],
                default='GET',
                help='HTTP method to use (default: GET)'
            )
            
            parser.add_argument(
                '--param',
                type=str,
                default='url',
                help='Parameter name to inject payloads into (default: url)'
            )
            
            parser.add_argument(
                '--post-data',
                type=str,
                help='Additional POST parameters in format: key1=value1&key2=value2'
            )

            parser.add_argument(
                '--cookie',
                type=str,
                help='Cookie string (e.g., "session=abc12345")'
            )
            
            parser.add_argument(
                '--dashboard',
                action='store_true',
                help='Enable real-time dashboard reporting'
            )
            
            return parser
            
        except Exception as e:
            logger.error(f"Error creating parser: {e}")
            raise
    
    async def run_scan(self, args) -> dict:
        """
        Run SSRF scan
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Scan results dictionary
        """
        try:
            scan_start_time = datetime.now()
            start_timestamp = time.time()
            
            logger.info(f"Starting SSRF scan of {args.url}")
            
            # Initialize components
            payload_manager = PayloadManager(args.payloads_dir)
            attack_modules = AttackModules(payload_manager)
            verifier = Verifier()
            remediation_engine = RemediationEngine()
            remediation_engine = RemediationEngine()
            reporter = Reporter(args.output_dir)
            
            # Dashboard Emitter
            dashboard = None
            if args.dashboard:
                dashboard = DashboardEmitter()
                await dashboard.connect()
                await dashboard.emit('SCAN_START', {'target_url': args.url})
            
            # Parse cookies if provided
            cookies = {}
            if args.cookie:
                try:
                    for part in args.cookie.split(';'):
                        if '=' in part:
                            key, value = part.strip().split('=', 1)
                            cookies[key.strip()] = value.strip()
                except Exception as e:
                    logger.error(f"Error parsing cookies: {e}")
                    print(f"[!] Error parsing cookies: {e}")

            # Create scanner
            async with SSRFScanner(
                target_url=args.url,
                requests_per_second=args.rps,
                max_concurrent=args.concurrent,
                timeout=args.timeout,
                user_agent=args.user_agent,
                proxy=args.proxy,
                cookies=cookies
            ) as scanner:
                
                # Parse POST data if provided
                post_data = {}
                if args.post_data:
                    import urllib.parse
                    post_data = dict(urllib.parse.parse_qsl(args.post_data))
                
                # Establish baseline
                if not args.quiet:
                    print(f"\n[*] Establishing baseline with {args.baseline_probes} probes using {args.method}...")
                
                try:
                    baseline = await scanner.establish_baseline(
                        args.baseline_probes,
                        method=args.method,
                        post_data=post_data,
                        param=args.param
                    )
                    if dashboard:
                        await dashboard.emit('BASELINE_DONE', {})
                except Exception as e:
                    logger.error(f"Failed to establish baseline: {e}")
                    print(f"[!] Error establishing baseline: {e}")
                    return self._create_error_result(str(e), scan_start_time)
                
                if args.test_mode:
                    print("[*] Test mode - skipping attack phases")
                    return self._create_test_result(baseline, scan_start_time)
                
                # Get attack payloads
                if not args.quiet:
                    print("\n[*] Generating attack payloads...")
                
                all_payloads = attack_modules.get_all_attack_payloads(args.url)
                
                # Filter phases if specified
                if 'all' not in args.phases:
                    all_payloads = {k: v for k, v in all_payloads.items() if k in args.phases}
                
                # Flatten payloads for testing
                test_queue = []
                for phase, payloads in all_payloads.items():
                    for payload in payloads:
                        if isinstance(payload, dict):
                            # Handle parameter/header payloads
                            test_queue.append((phase, payload))
                        else:
                            # Handle simple string payloads
                            test_queue.append((phase, payload))
                
                total_tests = len(test_queue)
                
                if not args.quiet:
                    print(f"\n[*] Testing {total_tests} payloads across {len(all_payloads)} attack phases...")
                
                # Run tests with parallel workers
                vulnerabilities = []
                total_requests = 0
                
                if tqdm and not args.quiet:
                    progress_bar = tqdm(total=total_tests, desc="Scanning", unit="payload")
                    # Setup tqdm-aware logging
                    tqdm_handler = TqdmLoggingHandler()
                    tqdm_handler.setFormatter(ColorLogFormatter(datefmt='%Y-%m-%d %H:%M:%S'))
                    
                    # Store original handlers and replace them
                    root_logger = logging.getLogger()
                    old_handlers = root_logger.handlers[:]
                    for h in old_handlers:
                        if isinstance(h, logging.StreamHandler):
                            root_logger.removeHandler(h)
                    root_logger.addHandler(tqdm_handler)
                else:
                    progress_bar = None
                    tqdm_handler = None
                
                # Queue for payload tests
                queue = asyncio.Queue()
                for item in test_queue:
                    queue.put_nowait(item)
                
                async def worker():
                    nonlocal total_requests
                    while not queue.empty():
                        try:
                            phase, payload = await queue.get()
                            
                            # Test payload
                            if isinstance(payload, dict):
                                # Handle parameter/header payloads
                                if 'param' in payload:
                                    result = await scanner.test_payload(
                                        payload['payload'], 
                                        payload['param'],
                                        method=args.method,
                                        post_data=post_data
                                    )
                                else:
                                    result = None
                            else:
                                # Simple payload
                                result = await scanner.test_payload(
                                    payload,
                                    param=args.param,
                                    method=args.method,
                                    post_data=post_data
                                )
                            
                            if dashboard:
                                await dashboard.emit('PAYLOAD_TEST', {'payload': payload, 'phase': phase})
                            
                            total_requests += 1
                            
                            if result:
                                # Verify vulnerability
                                verified_result = verifier.verify_vulnerability(result, args.oob_domain)
                                verified_result['attack_phase'] = phase
                                
                                if verified_result.get('vulnerable', False):
                                    # Perform RAG-based context retrieval and expert analysis
                                    if hasattr(scanner, 'rag'):
                                        context = scanner.rag.retrieve_context(verified_result.get('vulnerability_type', 'SSRF'))
                                        if context:
                                            # Store a simple summary for the report
                                            best_match = context[0]['metadata'].get('title', 'Historical SSRF Pattern')
                                            reasoning = context[0]['content'][:100] + "..."
                                            verified_result['rag_analysis'] = f"Matched Pattern: {best_match}\nContext: {reasoning}"
                                            
                                            # Provide a live RAG hint in the terminal
                                            rag_msg = f"{CYAN + Style.BRIGHT}[RAG] Intelligence Match: {best_match}{RESET}"
                                            if progress_bar:
                                                tqdm.write(rag_msg)
                                            else:
                                                print(rag_msg)
                                    
                                    vulnerabilities.append(verified_result)
                                    
                                    if dashboard:
                                        await dashboard.emit('VULN_FOUND', verified_result)
                                    
                                    if not args.quiet:
                                        vuln_type = verified_result.get('vulnerability_type', 'UNKNOWN')
                                        confidence = verified_result.get('confidence', 0)
                                        msg = f"\n{RED + Style.BRIGHT}[!] VULNERABILITY: {vuln_type} (confidence: {confidence:.0%}){RESET}"
                                        if progress_bar:
                                            tqdm.write(msg)
                                        else:
                                            print(msg)
                            
                            if progress_bar:
                                progress_bar.update(1)
                            elif not args.quiet:
                                # Fallback progress
                                sys.stdout.write(f"\r[*] Progress: {total_requests}/{total_tests} payloads tested...")
                                sys.stdout.flush()
                                
                            queue.task_done()
                        except Exception as e:
                            logger.error(f"Worker error: {e}")
                            queue.task_done()

                # Start workers based on concurrent/threads setting
                num_workers = min(args.concurrent, total_tests)
                workers = [asyncio.create_task(worker()) for _ in range(num_workers)]
                
                # Wait for all payloads to be processed
                await asyncio.gather(*workers)
                
                if progress_bar:
                    progress_bar.close()
                    # Restore original logging handlers
                    if tqdm_handler:
                        root_logger.removeHandler(tqdm_handler)
                        for h in old_handlers:
                            root_logger.addHandler(h)
                elif not args.quiet:
                    print() # New line after finishing fallback progress
                
                # Generate remediation report
                remediation_report = remediation_engine.generate_remediation_report(vulnerabilities)
                
                # Create scan results
                scan_end_time = datetime.now()
                duration = time.time() - start_timestamp
                
                scan_results = {
                    'scan_info': {
                        'target_url': args.url,
                        'scan_type': 'full' if 'all' in args.phases else 'partial',
                        'phases_tested': list(all_payloads.keys())
                    },
                    'scan_start_time': scan_start_time.isoformat(),
                    'scan_end_time': scan_end_time.isoformat(),
                    'duration_seconds': duration,
                    'total_requests': total_requests,
                    'vulnerabilities_found': len(vulnerabilities),
                    'baseline': baseline,
                    'vulnerabilities': vulnerabilities,
                    'remediation': remediation_report
                }
                
                if dashboard:
                    await dashboard.emit('SCAN_END', {'total_requests': total_requests, 'vulnerabilities': len(vulnerabilities)})
                    await dashboard.disconnect()
                
                return scan_results
                
        except Exception as e:
            logger.error(f"Error running scan: {e}")
            raise
    
    def _create_error_result(self, error_msg: str, start_time: datetime) -> dict:
        """Create error result"""
        return {
            'scan_info': {'error': error_msg},
            'scan_start_time': start_time.isoformat(),
            'scan_end_time': datetime.now().isoformat(),
            'duration_seconds': 0,
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'vulnerabilities': [],
            'remediation': {}
        }
    
    def _create_test_result(self, baseline, start_time: datetime) -> dict:
        """Create test mode result"""
        return {
            'scan_info': {'mode': 'test'},
            'scan_start_time': start_time.isoformat(),
            'scan_end_time': datetime.now().isoformat(),
            'duration_seconds': 0,
            'total_requests': 10,
            'vulnerabilities_found': 0,
            'baseline': baseline,
            'vulnerabilities': [],
            'remediation': {}
        }
    
    def run(self):
        """Main entry point"""
        try:
            # Parse arguments
            args = self.parser.parse_args()
            
            # Set logging level
            if args.verbose:
                logging.getLogger().setLevel(logging.DEBUG)
            elif args.quiet:
                logging.getLogger().setLevel(logging.WARNING)
            
            # --dashboard flag: ensure server is running and open browser
            if args.dashboard:
                self._ensure_dashboard_running()
            
            # Print banner
            if not args.quiet:
                self._print_banner()
            
            # Validate targets
            if not args.url and not args.urls_file:
                log_error("You must provide either --url or --urls-file")
                sys.exit(1)
            
            targets = []
            if args.url:
                targets.append(args.url)
            
            if args.urls_file:
                try:
                    with open(args.urls_file, 'r') as f:
                        file_urls = [line.strip() for line in f if line.strip()]
                    
                    # Filtering Logic
                    # Load parameter whitelist
                    payload_manager = PayloadManager(args.payloads_dir)
                    param_payloads = payload_manager.load_payloads('parameter_payloads.txt')
                    param_whitelist = set(param_payloads)
                    
                    log_info(f"Loaded {len(param_whitelist)} parameters for whitelist filtering")
                    
                    filtered_targets = []
                    for url in file_urls:
                        # Parse URL parameters
                        parsed = urllib.parse.urlparse(url)
                        params = urllib.parse.parse_qs(parsed.query)
                        
                        # Check if any param name is in the whitelist
                        # We check keys of params dictionary
                        if any(key in param_whitelist for key in params.keys()):
                            filtered_targets.append(url)
                        else:
                            logger.debug(f"Skipping {url} - no matching parameter")
                    
                    log_info(f"Loaded {len(file_urls)} URLs from file. {len(filtered_targets)} matched parameter whitelist.")
                    targets.extend(filtered_targets)
                    
                except Exception as e:
                    log_error(f"Error reading URLs file: {e}")
                    sys.exit(1)
            
            if not targets:
                log_warning("No valid targets to scan.")
                sys.exit(0)
                
            log_info(f"Starting scan of {len(targets)} targets...")
            
            final_exit_code = 0
            
            for i, target_url in enumerate(targets):
                print(f"\n{YELLOW + Style.BRIGHT}[*] Scanning Target {i+1}/{len(targets)}: {target_url}{RESET}")
                
                # Update args.url for the scan
                args.url = target_url
                
                # Run scan
                scan_results = asyncio.run(self.run_scan(args))
                
                # Generate reports
                if not args.quiet:
                    print("\n[*] Generating reports...")
                
                reporter = Reporter(args.output_dir)
                
                try:
                    # Create unique output directory or name for bulk?
                    # For now, Reporter likely uses timestamp, so they won't overwrite unless same second
                    # But better to separate if possible. 
                    # The current Reporter implementation uses timestamp.
                    
                    if args.output_format == 'all':
                        reports = reporter.generate_all_reports(scan_results)
                        if not args.quiet:
                            print("\n[+] Reports generated:")
                            for format_type, filepath in reports.items():
                                print(f"    - {format_type.upper()}: {filepath}")
                    elif args.output_format == 'json':
                        filepath = reporter.generate_json_report(scan_results)
                        if not args.quiet:
                            print(f"\n[+] JSON report: {filepath}")
                    elif args.output_format == 'csv':
                        filepath = reporter.generate_csv_report(scan_results)
                        if not args.quiet:
                            print(f"\n[+] CSV report: {filepath}")
                    elif args.output_format == 'html':
                        filepath = reporter.generate_html_report(scan_results)
                        if not args.quiet:
                            print(f"\n[+] HTML report: {filepath}")
                except Exception as e:
                    logger.error(f"Error generating reports: {e}")
                    log_error(f"Error generating reports: {e}")
                
                # Print summary
                if not args.quiet:
                    self._print_summary(scan_results)
                
                if scan_results['vulnerabilities_found'] > 0:
                    final_exit_code = 1
            
            sys.exit(final_exit_code)
                
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            sys.exit(130)
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            print(f"\n[!] Fatal error: {e}")
            sys.exit(1)
    
    def _ensure_dashboard_running(self):
        """Start dashboard server if not already running, then open browser."""
        import subprocess
        import webbrowser
        import socket
        import os
        import time

        dashboard_url = "http://127.0.0.1:5000"

        # Check if the dashboard is already running on port 5000
        def is_port_open(host, port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex((host, port)) == 0

        if not is_port_open('127.0.0.1', 5000):
            # Dashboard is not running - start it now
            dashboard_script = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'dashboard_server.py'
            )
            try:
                if os.name == 'nt':
                    subprocess.Popen(
                        [sys.executable, dashboard_script],
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                else:
                    subprocess.Popen(
                        [sys.executable, dashboard_script],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                logger.info("[Dashboard] Server starting...")
                # Wait up to 4 seconds for the server to be ready
                for _ in range(8):
                    time.sleep(0.5)
                    if is_port_open('127.0.0.1', 5000):
                        break
            except Exception as e:
                logger.warning(f"[Dashboard] Could not start dashboard server: {e}")
                return
        else:
            logger.info("[Dashboard] Server already running on port 5000.")

        # Open the browser
        try:
            webbrowser.open(dashboard_url)
            print(f"\n[Dashboard] Opened at {dashboard_url} — live updates will appear during scan.\n")
        except Exception as e:
            logger.warning(f"[Dashboard] Could not open browser: {e}. Visit {dashboard_url} manually.")

    def _print_banner(self):
        """Print ASCII banner"""
        banner = '''
===============================================================
                                                           
              SSRF Scanner v1.0.0                       
         Automated SSRF Detection & Mitigation             
                                                           
===============================================================
        '''
        print(banner)
    
    def _print_summary(self, scan_results: dict):
        """Print scan summary"""
        try:
            print("\n" + "="*60)
            print("SCAN SUMMARY")
            print("="*60)
            
            print(f"Target URL:          {scan_results['scan_info'].get('target_url', 'N/A')}")
            print(f"Duration:            {scan_results['duration_seconds']:.2f} seconds")
            print(f"Total Requests:      {scan_results['total_requests']}")
            print(f"Vulnerabilities:     {scan_results['vulnerabilities_found']}")
            
            remediation = scan_results.get('remediation', {})
            severity = remediation.get('severity_breakdown', {})
            
            if severity:
                print(f"\nSeverity Breakdown:")
                print(f"  CRITICAL:          {severity.get('CRITICAL', 0)}")
                print(f"  HIGH:              {severity.get('HIGH', 0)}")
                print(f"  MEDIUM:            {severity.get('MEDIUM', 0)}")
                print(f"  LOW:               {severity.get('LOW', 0)}")
            
            if scan_results['vulnerabilities_found'] > 0:
                print(f"\n[!] {remediation.get('summary', 'Vulnerabilities detected')}")
            else:
                print("\n[+] No vulnerabilities detected")
            
            print("="*60)
            
        except Exception as e:
            logger.error(f"Error printing summary: {e}")


def main():
    """Main entry point"""
    try:
        cli = SSRFScannerCLI()
        cli.run()
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        sys.exit(1)


class DashboardEmitter:
    """
    Emits scan events to the real-time dashboard via HTTP POST.

    The scanner POSTs events to /api/scan-event on the dashboard server,
    which re-broadcasts them to all connected browser clients via Socket.IO.

    Key design points:
    - Uses asyncio.get_event_loop().run_in_executor() so HTTP POST never
      blocks the asyncio event loop.
    - PAYLOAD_TEST events are throttled (1 per 5 payloads) to avoid server flood.
    - All errors are silently logged so the scan is never interrupted.
    """

    DASHBOARD_URL = "http://127.0.0.1:5000"

    def __init__(self, url: str = None):
        base = url if url else self.DASHBOARD_URL
        self._endpoint = f"{base}/api/scan-event"
        self._session = None
        self._available = False
        self._payload_test_count = 0
        self._PAYLOAD_TEST_INTERVAL = 5   # emit 1 in every 5 PAYLOAD_TEST events
        self._check_server()

    def _check_server(self):
        """Synchronously check if dashboard is reachable and warm up session."""
        import requests as _req
        self._session = _req.Session()
        try:
            r = self._session.get(self.DASHBOARD_URL, timeout=2)
            self._available = (r.status_code < 500)
            if self._available:
                logger.info("[Dashboard] Server reachable at %s", self.DASHBOARD_URL)
            else:
                logger.warning("[Dashboard] Server returned %s. Events disabled.", r.status_code)
        except Exception as e:
            logger.warning("[Dashboard] Server not reachable: %s. Events will be skipped.", e)
            self._available = False

    def _post_sync(self, event_type: str, payload: dict):
        """Synchronous POST — called in a thread pool executor."""
        if not self._available or not self._session:
            return
        
        def _make_serializable(obj):
            if isinstance(obj, bytes):
                return obj.decode('utf-8', errors='ignore')
            if isinstance(obj, dict):
                return {k: _make_serializable(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_make_serializable(x) for x in obj]
            return obj

        try:
            serializable_payload = _make_serializable(payload)
            self._session.post(
                self._endpoint,
                json={"type": event_type, "payload": serializable_payload},
                timeout=2
            )
        except Exception as e:
            logger.debug("[Dashboard] emit %s failed: %s", event_type, e)

    async def connect(self):
        """No persistent connection needed."""
        pass

    async def emit(self, event_type: str, payload: dict):
        """
        Emit a dashboard event.
        Runs HTTP POST in a thread executor so it never blocks asyncio.
        PAYLOAD_TEST events are throttled.
        """
        if not self._available:
            return

        # Throttle PAYLOAD_TEST to avoid flooding the server
        if event_type == "PAYLOAD_TEST":
            self._payload_test_count += 1
            if self._payload_test_count % self._PAYLOAD_TEST_INTERVAL != 0:
                return

        # Run the blocking HTTP POST in the thread pool
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._post_sync, event_type, payload)

    async def disconnect(self):
        """Close the requests session cleanly."""
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass


if __name__ == '__main__':
    main()
