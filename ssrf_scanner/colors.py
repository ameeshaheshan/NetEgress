from colorama import Fore, Style, init
from datetime import datetime

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

def now():
    """Get current timestamp formatted as string."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log_info(msg):
    """Log informational message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{GREEN + Style.BRIGHT}[INFO]{RESET} {msg}")

def log_error(msg):
    """Log error message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{RED + Style.BRIGHT}[ERROR]{RESET} {msg}")

def log_warning(msg):
    """Log warning message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{YELLOW + Style.BRIGHT}[WARN]{RESET} {msg}")

def log_success(msg):
    """Log success message with timestamp."""
    print(f"{YELLOW + Style.BRIGHT}[{now()}]{RESET}{GREEN + Style.BRIGHT}[SUCCESS]{RESET} {msg}")
