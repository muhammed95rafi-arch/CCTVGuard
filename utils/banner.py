from colorama import Fore, Style

def print_banner():
    banner = f"""
{Fore.RED}
 ██████╗ ██████╗████████╗██╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║     ██║        ██║   ██║   ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║     ██║        ██║   ╚██╗ ██╔╝██║   ██║╚██╗ ██╔╝██╔══██║██╔══██╗██║  ██║
╚██████╗╚██████╗   ██║    ╚████╔╝ ╚██████╔╝ ╚████╔╝ ██║  ██║██║  ██║██████╔╝
 ╚═════╝ ╚═════╝   ╚═╝     ╚═══╝   ╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{Style.RESET_ALL}
{Fore.CYAN}        CCTV Security Assessment Tool v1.0{Style.RESET_ALL}
{Fore.YELLOW}        For Educational & Authorized Testing Only{Style.RESET_ALL}
{Fore.GREEN}        SOC Portfolio | github.com/muhammed95rafi-arch{Style.RESET_ALL}
{Fore.RED}        Only test cameras you own or have permission to test{Style.RESET_ALL}
    """
    print(banner)

def print_section(title):
    print(f"\n{Fore.CYAN}{'='*65}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  [*] {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

def print_success(msg):  print(f"{Fore.GREEN}  [+] {msg}{Style.RESET_ALL}")
def print_warning(msg):  print(f"{Fore.YELLOW}  [!] {msg}{Style.RESET_ALL}")
def print_error(msg):    print(f"{Fore.RED}  [-] {msg}{Style.RESET_ALL}")
def print_info(msg):     print(f"{Fore.CYAN}  [*] {msg}{Style.RESET_ALL}")
def print_critical(msg): print(f"{Fore.RED}{Style.BRIGHT}  [CRITICAL] {msg}{Style.RESET_ALL}")
