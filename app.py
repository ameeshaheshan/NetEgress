import os
import time
import requests
import subprocess
import sys
import webbrowser
import atexit
from datetime import datetime
from banners.banner import net_egress_banner, net_egress_banner_without_animation, net_egress_menu, net_egress_menu_updated
from dotenv import load_dotenv
from colorama import Fore, Style, init

# --- Dashboard Auto-Start Logic ---
dashboard_process = None

def start_dashboard():
    global dashboard_process
    try:
        # Start dashboard_server.py in a new process
        if os.name == 'nt':
            # On Windows, use CREATE_NO_WINDOW to keep it hidden or CREATE_NEW_CONSOLE if you want a separate window.
            # User wants it to start "with the same time", usually background is preferred for seamless experience.
            dashboard_process = subprocess.Popen(
                [sys.executable, "dashboard_server.py"], 
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        else:
            dashboard_process = subprocess.Popen(
                [sys.executable, "dashboard_server.py"], 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            )
    except Exception as e:
        print(f"Error auto-starting dashboard: {e}")

def cleanup_dashboard():
    global dashboard_process
    if dashboard_process:
        dashboard_process.terminate()

# Register cleanup
atexit.register(cleanup_dashboard)

# Start the dashboard server immediately
start_dashboard()

# Handle --dashboard flag
if "--dashboard" in sys.argv:
    # Small delay to ensure server is up before opening browser
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5000")
# ----------------------------------

# Import URL crawler function
# Import URL crawler function
# Deep URL crawling module removed
run_batch_crawler = None


# Initialize colorama
init(autoreset=True)

# Color Codes 
RED = Fore.RED 
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW 
BLUE = Fore.BLUE 
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN 
WHITE = Fore.WHITE
RESET = Style.RESET_ALL

# Main menu loop
while True:
    net_egress_banner()
    try:
        net_egress_menu_updated()
    except NameError:
        net_egress_menu()
    print('')

    try:
        user_choice = int(input(YELLOW + Style.BRIGHT + "./NET-EGRESS >>> " + RESET))
        if user_choice < 1 or user_choice > 5:
            print(RED + Style.BRIGHT + "Invalid choice. Please select a number between 1 and 5." + RESET)
            time.sleep(2)
            os.system("cls" if os.name == "nt" else "clear")
            continue
        
        # Exit option
        if user_choice == 5:
            print(GREEN + Style.BRIGHT + "Exiting NET-EGRESS. Goodbye!" + RESET)
            break
        
        # Option 2: Start SSRF Scanner
        if user_choice == 2:
            print(GREEN + Style.BRIGHT + "\n[*] Starting SSRF Scanner..." + RESET)
            time.sleep(1) # Reduced sleep for better UX
            
            # Run the scanner help menu first
            os.system("python -m ssrf_scanner.cli --help")
            
            # Interactive Scanner Shell
            while True:
                print('')
                try:
                    cmd_input = input(WHITE + Style.BRIGHT + "./NET-EGRESS >>> " + Style.RESET_ALL).strip()
                    
                    if not cmd_input:
                        continue
                        
                    if cmd_input.lower() in ['exit', 'back', 'menu', 'quit']:
                        break
                        
                    if cmd_input.lower() == 'help':
                        os.system("python -m ssrf_scanner.cli --help")
                        continue
                    
                    # Command Construction & Validation
                    final_cmd = ""
                    
                    if cmd_input.startswith("python -m ssrf_scanner.cli"):
                        final_cmd = cmd_input
                        if "--dashboard" not in final_cmd:
                            final_cmd += " --dashboard"
                    elif cmd_input.startswith("-"):
                        # Shortcut: User just typed flags
                        final_cmd = f"python -m ssrf_scanner.cli {cmd_input} --dashboard"
                    else:
                        print(RED + "Invalid command. Only ssrf_scanner commands or '--flags' allowed." + RESET)
                        print(YELLOW + "Type 'back' to return to menu." + RESET)
                        continue
                        
                    # Execute
                    print(CYAN + f"[*] Executing: {final_cmd}" + RESET)
                    os.system(final_cmd)
                    
                except KeyboardInterrupt:
                    print('\n')
                    continue
            
            continue

        # Option 3: Common SSRF CVEs (Interactive Search & Download)
        if user_choice == 3:
            from ssrf_scanner.exploit_db import (
                is_ssrf_related, search_exploits, download_exploit, 
                list_local_exploits, run_exploit, ensure_cve_folder
            )
            
            ensure_cve_folder()
            
            while True:
                print(GREEN + Style.BRIGHT + "\n[*] Common SSRF CVE's & Real-time Exploit Search" + RESET)
                print(CYAN + "[1] Search Exploit-DB (Real-time GitLab Database)" + RESET)
                print(CYAN + "[2] List & Run Downloaded CVE's" + RESET)
                print(CYAN + "[3] Back to Main Menu" + RESET)
                
                try:
                    sub_choice = input(YELLOW + "\nSelect an option: " + RESET).strip()
                    
                    if sub_choice == '3' or not sub_choice:
                        break
                        
                    if sub_choice == '1':
                        keyword = input(WHITE + "\nEnter keyword or CVE (e.g., SSRF, CVE-2021-26855): " + RESET).strip()
                        if not keyword:
                            continue
                            
                        if not is_ssrf_related(keyword):
                            print(RED + "[!] Access Denied: Query must be SSRF-related for security filtering." + RESET)
                            continue
                            
                        results = search_exploits(keyword)
                        if not results:
                            print(YELLOW + f"[!] No results found for '{keyword}' in curated SSRF database." + RESET)
                            continue
                            
                        print(GREEN + f"\n[+] Search Results for '{keyword}':" + RESET)
                        for i, (edb_id, title, cve, desc) in enumerate(results, 1):
                            print(f"{WHITE}[{i}] {CYAN}{cve or 'EDB-'+edb_id}{RESET} - {WHITE}{title}{RESET}")
                            print(f"    {Style.DIM}{desc}{Style.RESET_ALL}")
                            
                        pick = input(YELLOW + "\nSelect a number to download (or 'b' to go back): " + RESET).strip()
                        if pick.lower() == 'b':
                            continue
                            
                        try:
                            idx = int(pick) - 1
                            if 0 <= idx < len(results):
                                edb_id, title, cve, _ = results[idx]
                                download_exploit(edb_id, title, cve=cve)
                            else:
                                print(RED + "[!] Invalid selection." + RESET)
                        except ValueError:
                            print(RED + "[!] Please enter a valid number." + RESET)
                            
                    elif sub_choice == '2':
                        from ssrf_scanner.exploit_db import CVE_FOLDER
                        local_files = list_local_exploits()
                        if not local_files:
                            print(YELLOW + "\n[!] No exploits found in CVE/ folder. Download some first!" + RESET)
                            continue
                            
                        print(GREEN + "\n[+] Available Exploits in CVE/ folder:" + RESET)
                        for i, filename in enumerate(local_files, 1):
                            print(f"{WHITE}[{i}] {CYAN}{filename}{RESET}")
                            
                        pick = input(YELLOW + "\nSelect a number to view/run (or 'b' to go back): " + RESET).strip()
                        if pick.lower() == 'b':
                            continue
                            
                        try:
                            idx = int(pick) - 1
                            if 0 <= idx < len(local_files):
                                filename = local_files[idx]
                                md_file = filename + ".md"
                                md_path = os.path.join(CVE_FOLDER, md_file)
                                
                                if os.path.exists(md_path):
                                    print(GREEN + f"\n[*] Options for {filename}:" + RESET)
                                    print(CYAN + "[1] View Run Instructions (.md)" + RESET)
                                    print(CYAN + "[2] Execute Exploit" + RESET)
                                    action = input(YELLOW + "\nChoice: " + RESET).strip()
                                    
                                    if action == '1':
                                        with open(md_path, 'r') as f:
                                            print("\n" + "="*40)
                                            print(WHITE + f.read() + RESET)
                                            print("="*40)
                                            input(YELLOW + "\nPress Enter to continue..." + RESET)
                                    elif action == '2':
                                        run_exploit(filename)
                                else:
                                    run_exploit(filename)
                            else:
                                print(RED + "[!] Invalid selection." + RESET)
                        except ValueError:
                            print(RED + "[!] Please enter a valid number." + RESET)
                            
                except KeyboardInterrupt:
                    print("\n")
                    break
                    
            continue

        # Option 4: Launch Advanced Real-time Dashboard
        if user_choice == 4:
            print(GREEN + Style.BRIGHT + "\n[*] Opening Advanced Real-time Dashboard..." + RESET)
            
            try:
                # The server is already started in the background on app launch. 
                # We just need to open the browser here.
                webbrowser.open("http://localhost:5000")
                print(GREEN + "[+] Dashboard opened in your browser!" + RESET)
                print(YELLOW + "[*] If it didn't open, visit http://localhost:5000 manually." + RESET)
            except Exception as e:
                print(RED + f"[!] Error opening dashboard: {e}" + RESET)
            
            input(YELLOW + "\nPress Enter to return to main menu..." + RESET)
            os.system("cls" if os.name == "nt" else "clear")
            continue
        
    except ValueError:
        print(RED + Style.BRIGHT + "Invalid input. Please enter a numeric value between 1 and 4." + RESET)
        time.sleep(2)
        continue
    

    except KeyboardInterrupt:
        print(RED + Style.BRIGHT + "\nUser interrupted the process." + RESET)
        break

    if user_choice == 1:
        net_egress_banner_without_animation()

        # check folders exist
        os.makedirs("recon", exist_ok=True)
        os.makedirs("config", exist_ok=True)

        SUB_FILE = "recon/subdomains.txt"
        ENV_FILE = "config/.env"

        def now():
            """Get current timestamp formatted as string."""
            return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        def log_info(msg):
            """Log informational message with timestamp."""
            print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{GREEN + Style.BRIGHT}[INFO]{RESET} {msg}")

        def log_error(msg):
            """Log error message with timestamp."""
            print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{RED + Style.BRIGHT}[ERROR]{RESET} {msg}")

        def clean_domain_name(domain):
            """Remove *. and www. prefixes from domain."""
            domain = domain.lower().strip()
            if domain.startswith("*."):
                domain = domain[2:]
            if domain.startswith("www."):
                domain = domain[4:]
            return domain

        def save_subdomains(subdomains, overwrite=False):
            """
            Save subdomains to file.
            - overwrite=True: replace file with given list
            - overwrite=False: append only NEW entries not already in file
            
            Automatically removes 'www.' and '*.' prefixes and ensures uniqueness.
            """
            # Clean and deduplicate input subdomains
            cleaned_subdomains = sorted({clean_domain_name(sub) for sub in subdomains if sub.strip()})
            
            existing = set()
            if os.path.exists(SUB_FILE):
                with open(SUB_FILE, "r") as f:
                    # Also clean existing domains when reading to ensure proper deduplication
                    existing = {clean_domain_name(line) for line in f if line.strip()}

            written = 0
            if overwrite:
                with open(SUB_FILE, "w") as f:
                    for sub in cleaned_subdomains:
                        f.write(sub + "\n")
                        written += 1
            else:
                with open(SUB_FILE, "a") as f:
                    for sub in cleaned_subdomains:
                        if sub not in existing:
                            f.write(sub + "\n")
                            # Add to existing set to catch duplicates within the same batch if any logical error occurred (though set handles it)
                            existing.add(sub)
                            written += 1

            log_info(f"{written} unique subdomains saved in {SUB_FILE}")

        def crtsh_enum(domain, max_attempts=5, base_sleep=2.0):
            """
            Fetch subdomains from crt.sh with retries and backoff.
            """
            log_info("Enumerating subdomains using crt.sh.")
            url = f"https://crt.sh/?q=%25.{domain}&output=json"

            for attempt in range(1, max_attempts + 1):
                try:
                    # (connect timeout, read timeout)
                    resp = requests.get(url, timeout=(10, 45))
                    resp.raise_for_status()

                    # crt.sh output value validation
                    try:
                        data = resp.json()
                    except ValueError:
                        raise RuntimeError("crt.sh did not return JSON (possibly rate-limited).")

                    subs = set()
                    for entry in data:
                        name_val = entry.get("name_value", "")
                        for sub in name_val.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(domain.lower()):
                                subs.add(sub)
                    return sorted(subs)

                except (requests.exceptions.ReadTimeout,
                        requests.exceptions.ConnectTimeout,
                        requests.exceptions.ConnectionError,
                        RuntimeError) as e:
                    if attempt < max_attempts:
                        sleep_s = base_sleep * (2 ** (attempt - 1))
                        log_info(f"crt.sh attempt {attempt}/{max_attempts} failed ({e}). Retrying in {sleep_s:.1f}s...")
                        time.sleep(sleep_s)
                    else:
                        log_error(f"Error fetching from crt.sh after {max_attempts} attempts: {e}")
                        return []
                except requests.exceptions.HTTPError as e:
                    code = getattr(e.response, "status_code", None)
                    if code in (429, 500, 502, 503, 504) and attempt < max_attempts:
                        sleep_s = base_sleep * (2 ** (attempt - 1))
                        log_info(f"crt.sh HTTP {code} on attempt {attempt}/{max_attempts}. Retrying in {sleep_s:.1f}s...")
                        time.sleep(sleep_s)
                        continue
                    log_error(f"HTTP error from crt.sh: {e}")
                    return []
                except Exception as e:
                    log_error(f"Unexpected error from crt.sh: {e}")
                    return []

        def vt_enum(domain):
            """
            Fetch subdomains from VirusTotal API.
            """
            load_dotenv(ENV_FILE)
            api_key = os.getenv("VT_API_KEY")

            if not api_key:
                log_error("No VirusTotal API key set.")
                api_key = input("Enter your VirusTotal API key: ").strip()
                # Persist to .env
                with open(ENV_FILE, "w") as f:
                    f.write(f"VT_API_KEY={api_key}\n")
                log_info("API key saved in config/.env")

            log_info("Enumerating subdomains using virustotal api.")
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": api_key}

            subs = set()
            next_url = url
            while next_url:
                try:
                    resp = requests.get(next_url, headers=headers, timeout=(10, 45))
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as e:
                    log_error(f"Error fetching from VirusTotal: {e}")
                    break

                for item in data.get("data", []):
                    sid = item.get("id", "").strip().lower()
                    if sid.endswith(domain.lower()):
                        subs.add(sid)

                # pagination
                links = data.get("links", {})
                next_url = links.get("next")

            return sorted(subs)

        # === Main flow ===
        print('')
        print(Fore.RED + Style.BRIGHT + f"{GREEN + Style.BRIGHT}[INFO]{RED + Style.BRIGHT} Enter Target Domain Name (example.com) " + Style.RESET_ALL)
        domain = input(WHITE + Style.BRIGHT + "./NET-EGRESS >>> " + Style.RESET_ALL)

        crt_subs = crtsh_enum(domain)
        if crt_subs:
            save_subdomains(crt_subs, overwrite=True)
        else:
            try:
                with open(SUB_FILE, "w") as f:
                    pass  # Create empty file
                log_info(f"0 subdomains saved in {SUB_FILE}")
            except IOError as e:
                log_error(f"Failed to create {SUB_FILE}: {e}")

        vt_subs = vt_enum(domain)
        if vt_subs:
            save_subdomains(vt_subs, overwrite=False)
        else:
            log_info("0 subdomains saved in recon/subdomains.txt")

        # ============================ URL Parameter Discovery ============================
        log_info("Starting URL parameter discovery from subdomains...")
        
        # Run parameter finder using Wayback Machine
        try:
            log_info("Running parameter finder on discovered subdomains...")
            from url_param_finder import run_param_finder
            run_param_finder()
            log_info("Parameter discovery completed!")
        except KeyboardInterrupt:
            log_error("Parameter discovery interrupted by user.")
        except Exception as e:
            log_error(f"Error running parameter finder: {e}")
        
        # ============================ Deep URL Crawling ============================
        # DEEP URL CRAWLING PHASE REMOVED BY USER REQUEST
        
        print('')
        print(Fore.GREEN + Style.BRIGHT + "="*60 + Style.RESET_ALL)
        print(Fore.GREEN + Style.BRIGHT + "🎉 RECONNAISSANCE PHASE COMPLETED! 🎉" + Style.RESET_ALL)
        print(Fore.GREEN + Style.BRIGHT + "="*60 + Style.RESET_ALL)
        print('')
        print(Fore.YELLOW + "📁 Results saved in:" + Style.RESET_ALL)
        print(Fore.WHITE + "   - recon/subdomains.txt (Discovered subdomains)" + Style.RESET_ALL)
        print(Fore.WHITE + "   - recon/urls.txt (URLs with parameters)" + Style.RESET_ALL)
        print('')
        
        print(Fore.CYAN + Style.BRIGHT + "[*] Recon finished. Please run Option 2 to scan the discovered URLs." + Style.RESET_ALL)
        print('')
        
        # After completing option 1, return to menu
        input(YELLOW + "\nPress Enter to return to main menu..." + RESET)
        os.system("cls" if os.name == "nt" else "clear")
