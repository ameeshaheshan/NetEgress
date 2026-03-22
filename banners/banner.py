import os
import time

# CRITICAL: Set UTF-8 mode BEFORE importing colorama
# This allows Unicode characters while still letting colorama convert ANSI codes
os.environ['PYTHONIOENCODING'] = 'utf-8'

from colorama import *

# Initialize colorama with conversion enabled
# convert=True: Converts ANSI codes to Windows console API calls
# autoreset=True: Auto-reset colors after each print
init(autoreset=True, convert=True, strip=False)

os.system("cls" if os.name == "nt" else "clear")

# Color Codes 
RED = Fore.RED 
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW 
BLUE = Fore.BLUE 
MAGENTA = Fore.MAGENTA
CYAN = Fore.CYAN 
WHITE = Fore.WHITE

def net_egress_banner():
    banner = f"""
    {MAGENTA + Style.BRIGHT}███╗░░██╗███████╗████████╗░░░░░░███████╗░██████╗░██████╗░███████╗░██████╗░██████╗
    {MAGENTA + Style.BRIGHT}████╗░██║██╔════╝╚══██╔══╝░░░░░░██╔════╝██╔════╝░██╔══██╗██╔════╝██╔════╝██╔════╝ {RED + Style.BRIGHT} Author: Ameesha Heshan
    {MAGENTA + Style.BRIGHT}██╔██╗██║█████╗░░░░░██║░░░█████╗█████╗░░██║░░██╗░██████╔╝█████╗░░╚█████╗░╚█████╗░ {RED + Style.BRIGHT} Version: 1.0.0
    {MAGENTA + Style.BRIGHT}██║╚████║██╔══╝░░░░░██║░░░╚════╝██╔══╝░░██║░░╚██╗██╔══██╗██╔══╝░░░╚═══██╗░╚═══██╗ {RED + Style.BRIGHT} GitHub: ameeshaheshan
    {MAGENTA + Style.BRIGHT}██║░╚███║███████╗░░░██║░░░░░░░░░███████╗╚██████╔╝██║░░██║███████╗██████╔╝██████╔╝ {RED + Style.BRIGHT} CINEC - Faculty of Computing
    {MAGENTA + Style.BRIGHT}╚═╝░░╚══╝╚══════╝░░░╚═╝░░░░░░░░░╚══════╝░╚═════╝░╚═╝░░╚═╝╚══════╝╚═════╝░╚═════╝░
    {MAGENTA + Style.BRIGHT}=================================================================================
                    {CYAN + Style.BRIGHT}[ NetEgress - SSRF Scanner & Egress Analyzer ]{Style.RESET_ALL}
                        {YELLOW + Style.BRIGHT}For LAB / Authorized Use Only{Style.RESET_ALL}
    {MAGENTA + Style.BRIGHT}=================================================================================
    """

    # Print line by line with animation (preserves color codes)
    for line in banner.splitlines():
        print(line)
        time.sleep(0.05)  # Small delay between lines for animation effect

# ======================================================

def net_egress_banner_without_animation():
    banner = f"""
    {MAGENTA + Style.BRIGHT}███╗░░██╗███████╗████████╗░░░░░░███████╗░██████╗░██████╗░███████╗░██████╗░██████╗
    {MAGENTA + Style.BRIGHT}████╗░██║██╔════╝╚══██╔══╝░░░░░░██╔════╝██╔════╝░██╔══██╗██╔════╝██╔════╝██╔════╝ {RED + Style.BRIGHT} Author: Ameesha Heshan
    {MAGENTA + Style.BRIGHT}██╔██╗██║█████╗░░░░░██║░░░█████╗█████╗░░██║░░██╗░██████╔╝█████╗░░╚█████╗░╚█████╗░ {RED + Style.BRIGHT} Version: 1.0.0
    {MAGENTA + Style.BRIGHT}██║╚████║██╔══╝░░░░░██║░░░╚════╝██╔══╝░░██║░░╚██╗██╔══██╗██╔══╝░░░╚═══██╗░╚═══██╗ {RED + Style.BRIGHT} GitHub: ameeshaheshan
    {MAGENTA + Style.BRIGHT}██║░╚███║███████╗░░░██║░░░░░░░░░███████╗╚██████╔╝██║░░██║███████╗██████╔╝██████╔╝ {RED + Style.BRIGHT} CINEC - Faculty of Computing
    {MAGENTA + Style.BRIGHT}╚═╝░░╚══╝╚══════╝░░░╚═╝░░░░░░░░░╚══════╝░╚═════╝░╚═╝░░╚═╝╚══════╝╚═════╝░╚═════╝░
    =================================================================================
                    {CYAN + Style.BRIGHT}[ NetEgress - SSRF Scanner & Egress Analyzer ]{Style.RESET_ALL}
                        {YELLOW + Style.BRIGHT}For LAB / Authorized Use Only{Style.RESET_ALL}
    {MAGENTA + Style.BRIGHT}=================================================================================
    """
    os.system("cls" if os.name == "nt" else "clear")
    print(banner)

# =======================================================

# NetEgress - Tool Menu

def net_egress_menu():
    menu = f"""
    [1] Start Recon     [2] Start SSRF Scanner    [3] Common SSRF CVE's    [4] Exit
    """
    print(Fore.CYAN + Style.BRIGHT + menu + Style.RESET_ALL)

def net_egress_menu_updated():
    menu = f"""
    [1] Start Recon             [2] Start SSRF Scanner      [3] Common SSRF CVE's
    [4] Launch Dashboard        [5] Exit
    """
    print(Fore.CYAN + Style.BRIGHT + menu + Style.RESET_ALL)
