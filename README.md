# SSRF Scanner

A high-performance, asynchronous Python tool for detecting, mitigating, and assessing SSRF (Server-Side Request Forgery) vulnerabilities.

## Features

- ✅ **10 Attack Phases**: Comprehensive coverage of SSRF attack vectors
- ✅ **Async Architecture**: High-performance scanning with `aiohttp` and `asyncio`
- ✅ **Smart Baseline Detection**: Anomaly detection based on response patterns
- ✅ **Rate Limiting**: Adaptive throttling to avoid overwhelming targets
- ✅ **Content Analysis**: Pattern matching for sensitive data (AWS keys, /etc/passwd, etc.)
- ✅ **Multiple Report Formats**: JSON, CSV, and HTML reports
- ✅ **Comprehensive Error Handling**: Robust error handling throughout
- ✅ **Remediation Guidance**: Detailed mitigation recommendations with code examples

## Attack Phases

1. **Local IP & Internal Network** - Tests localhost and private IP ranges
2. **Cloud Metadata** - Targets AWS, GCP, Azure metadata endpoints
3. **Protocol & Scheme Confusion** - Tests file://, gopher://, dict://, etc.
4. **CRLF Injection** - Header injection attacks
5. **Advanced Bypasses & Encoding** - URL encoding, double encoding, etc.
6. **DNS Rebinding** - DNS manipulation attacks
7. **Port Scanning** - Internal port discovery
8. **Parameter Fuzzing** - Tests common URL parameters
9. **Header Injection** - X-Forwarded-For and similar headers
10. **XXE-based SSRF** - XML External Entity attacks

## Installation

```bash
# Clone or navigate to the project directory
cd "Final Project/SSRF Automation"

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
python -m ssrf_scanner.cli --url http://example.com/fetch?url=
```

### Custom Rate Limiting

```bash
python -m ssrf_scanner.cli --url http://example.com/api --rps 5 --concurrent 20
```

### Specific Attack Phases

```bash
python -m ssrf_scanner.cli --url http://example.com --phases local_ips cloud_metadata
```

### All Options

```bash
python -m ssrf_scanner.cli --help
```

## Command-Line Options

| Option              | Description                                  | Default          |
| ------------------- | -------------------------------------------- | ---------------- |
| `--url`             | Target URL to scan (required)                | -                |
| `--rps`             | Requests per second                          | 10               |
| `--concurrent`      | Maximum concurrent connections               | 50               |
| `--timeout`         | Request timeout in seconds                   | 10               |
| `--user-agent`      | Custom user agent string                     | SSRF-Scanner/1.0 |
| `--proxy`           | Proxy URL                                    | None             |
| `--payloads-dir`    | Directory containing payload files           | payloads         |
| `--output-dir`      | Output directory for reports                 | reports          |
| `--output-format`   | Report format (json/csv/html/all)            | all              |
| `--phases`          | Attack phases to execute                     | all              |
| `--baseline-probes` | Number of baseline probes                    | 10               |
| `--oob-domain`      | Out-of-band domain for interaction detection | None             |
| `--test-mode`       | Test mode - only baseline checks             | False            |
| `--verbose`         | Enable verbose logging                       | False            |
| `--quiet`           | Suppress progress bars                       | False            |

## Output

The scanner generates three types of reports:

### JSON Report

Detailed machine-readable format with all scan data.

### CSV Report

Tabular format for easy import into spreadsheets.

### HTML Report

Beautiful, interactive report with:

- Executive summary with severity breakdown
- Detailed vulnerability findings
- Remediation recommendations with code examples
- Visual severity indicators

## Architecture

```
ssrf_scanner/
├── __init__.py          # Package initialization
├── __main__.py          # Entry point
├── cli.py               # Command-line interface
├── core.py              # Async engine, rate limiting, baseline detection
├── attack_modules.py    # 10 attack phase implementations
├── verification.py      # Content analysis and vulnerability verification
├── remediation.py       # Mitigation recommendations
└── reporting.py         # JSON/CSV/HTML report generation
```

## Error Handling

All modules include comprehensive error handling:

- Try-catch blocks around all critical operations
- Graceful degradation on failures
- Detailed logging to `ssrf_scanner.log`
- User-friendly error messages

## Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only. Always obtain proper authorization before scanning any target.

- Use responsibly and ethically
- Respect rate limits
- Obtain written permission before testing
- Follow responsible disclosure practices

## Examples

### Test Mode (Safe)

```bash
python -m ssrf_scanner.cli --url http://example.com --test-mode
```

### Full Scan with Proxy

```bash
python -m ssrf_scanner.cli --url http://example.com --proxy http://127.0.0.1:8080
```

### Scan with OOB Detection

```bash
python -m ssrf_scanner.cli --url http://example.com --oob-domain your-collaborator-domain.com
```

## Troubleshooting

### Import Errors

Make sure all dependencies are installed:

```bash
pip install -r requirements.txt
```

### Baseline Establishment Fails

- Check if the target URL is accessible
- Verify network connectivity
- Try increasing timeout: `--timeout 30`

### No Vulnerabilities Found

- Ensure the target has a vulnerable parameter
- Try different attack phases
- Check logs in `ssrf_scanner.log`

## License

This tool is provided for educational and authorized security testing purposes only.

## Author

SSRF Automation Team
