#!/usr/bin/env python3
"""
URL Parameter Finder - Based on ParamSpider
Uses Wayback Machine to find URLs with parameters
Adapted for SSRF Automation Tool
"""

import requests
import random
import time
import os
import socket
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Color Codes matching app.py
RED = Fore.RED 
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW 
CYAN = Fore.CYAN 
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

# Configuration
INPUT_FILE = Path("recon/subdomains.txt")
OUTPUT_FILE = Path("recon/urls.txt")
MAX_RETRIES = 3

# File extensions to exclude
EXCLUDED_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
    ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", 
    ".otf", ".mp4", ".txt", ".ico", ".xml", ".zip", ".tar", ".gz"
]

# User agents for requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
]

def now():
    """Get current timestamp formatted as string."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log_info(msg):
    """Log informational message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{GREEN + Style.BRIGHT}[INFO]{RESET} {msg}")

def log_error(msg):
    """Log error message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{RED + Style.BRIGHT}[ERROR]{RESET} {msg}")

def has_extension(url, extensions):
    """Check if URL ends with one of the extensions."""
    try:
        parsed_url = urlparse(url)
        path = parsed_url.path
        extension = os.path.splitext(path)[1].lower()
        return extension in extensions
    except:
        return False

def resolve_ip(domain):
    """Resolve IP address for a domain."""
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unknown"

def clean_url(url):
    """Clean URL by removing redundant port information."""
    parsed_url = urlparse(url)
    
    # Remove default ports
    if (parsed_url.port == 80 and parsed_url.scheme == "http") or \
       (parsed_url.port == 443 and parsed_url.scheme == "https"):
        parsed_url = parsed_url._replace(netloc=parsed_url.netloc.rsplit(":", 1)[0])
    
    return parsed_url.geturl()

def fetch_wayback_urls(domain):
    """Fetch URLs from Wayback Machine for a domain."""
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    
    for attempt in range(MAX_RETRIES):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(wayback_uri, headers=headers, timeout=60)
            response.raise_for_status()
            
            urls = response.text.strip().split('\n')
            return [url.strip() for url in urls if url.strip()]
            
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                log_info(f"Retry {attempt + 1}/{MAX_RETRIES} for {domain}")
                time.sleep(3)
            else:
                log_error(f"Failed to fetch URLs for {domain}: {e}")
                return []
    
    return []

def filter_param_urls(urls):
    """Filter URLs to keep only those with parameters."""
    param_urls = set()
    
    for url in urls:
        # Skip if has excluded extension
        if has_extension(url, EXCLUDED_EXTENSIONS):
            continue
        
        # Clean the URL
        cleaned = clean_url(url)
        
        # Only keep URLs with query parameters
        if "?" in cleaned:
            param_urls.add(cleaned)
    
    return list(param_urls)

def read_domains(path):
    """Read domains from file."""
    if not path.exists():
        log_error(f"Input file not found: {path}")
        return []
    
    domains = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower()
        # Remove http/https prefix
        line = line.replace('https://', '').replace('http://', '')
        if line and not line.startswith('#'):
            domains.append(line)
    
    return list(set(domains))  # Remove duplicates

def run_param_finder():
    """Main function to find URLs with parameters."""
    log_info("Starting URL parameter discovery using Wayback Machine...")
    
    # Read domains
    domains = read_domains(INPUT_FILE)
    if not domains:
        log_error("No domains found in recon/subdomains.txt")
        return
    
    log_info(f"Processing {len(domains)} domains...")
    
    all_param_urls = set()
    
    for i, domain in enumerate(domains, 1):
        ip_address = resolve_ip(domain)
        log_info(f"[{i}/{len(domains)}] Fetching URLs for {CYAN}{domain}{RESET} | IP : {RED}{ip_address}{RESET}")
        
        # Fetch URLs from Wayback Machine
        urls = fetch_wayback_urls(domain)
        
        if not urls:
            log_info(f"No URLs found for {domain}")
            continue
        
        log_info(f"Found {len(urls)} total URLs for {domain}")
        
        # Filter for parameterized URLs
        param_urls = filter_param_urls(urls)
        
        if param_urls:
            log_info(f"{GREEN}Found {len(param_urls)} parameterized URLs{RESET}")
            all_param_urls.update(param_urls)
            
            # Show first few examples
            for url in list(param_urls)[:3]:
                print(f"    {CYAN}- {url}{RESET}")
            if len(param_urls) > 3:
                print(f"    ... and {len(param_urls) - 3} more")
        else:
            log_info(f"No parameterized URLs found for {domain}")
    
    # Save results
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    if all_param_urls:
        OUTPUT_FILE.write_text("\n".join(sorted(all_param_urls)), encoding="utf-8")
        
        print(f"\n{GREEN + Style.BRIGHT}{'='*60}{RESET}")
        print(f"{GREEN + Style.BRIGHT}[+] PARAMETER DISCOVERY COMPLETED!{RESET}")
        print(f"{GREEN + Style.BRIGHT}[+] Total parameterized URLs found: {len(all_param_urls)}{RESET}")
        print(f"{GREEN + Style.BRIGHT}[+] Saved to: {OUTPUT_FILE}{RESET}")
        print(f"{GREEN + Style.BRIGHT}{'='*60}{RESET}")
    else:
        # Create empty file
        OUTPUT_FILE.write_text("", encoding="utf-8")
        
        print(f"\n{RED}[!] WARNING: No URLs with parameters were found.{RESET}")
        print(f"{RED}[!] This could mean:{RESET}")
        print(f"{RED}    - The domains are not archived in Wayback Machine{RESET}")
        print(f"{RED}    - The domains don't have URLs with query parameters{RESET}")
        print(f"{RED}    - Try with more well-known domains{RESET}")

if __name__ == "__main__":
    run_param_finder()
