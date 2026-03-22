"""
Quick Start Guide - SSRF Scanner
"""

# Installation
print("Step 1: Install dependencies")
print("pip install -r requirements.txt")
print()

# Basic usage examples
print("Step 2: Run the scanner")
print()

print("Example 1: Test mode (safe)")
print("python -m ssrf_scanner.cli --url http://example.com --test-mode")
print()

print("Example 2: Basic scan")
print("python -m ssrf_scanner.cli --url http://example.com/fetch?url=")
print()

print("Example 3: Scan with custom rate limiting")
print("python -m ssrf_scanner.cli --url http://example.com/api --rps 5 --concurrent 20")
print()

print("Example 4: Scan specific attack phases")
print("python -m ssrf_scanner.cli --url http://example.com --phases local_ips cloud_metadata")
print()

print("Example 5: Generate HTML report only")
print("python -m ssrf_scanner.cli --url http://example.com --output-format html")
print()

print("Example 6: Verbose mode for debugging")
print("python -m ssrf_scanner.cli --url http://example.com --verbose")
print()

print("Step 3: View reports")
print("Reports are saved in the 'reports/' directory:")
print("  - JSON: Machine-readable format")
print("  - CSV: Spreadsheet-friendly format")
print("  - HTML: Visual report with remediation")
