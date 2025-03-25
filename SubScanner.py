import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor
import sys
from urllib3.exceptions import InsecureRequestWarning
from colorama import init, Fore, Style
import ssl
import socket
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Colorama'yı başlat
init()

def print_banner():
    banner = r"""
      _________    ___.     _________                                         
     /   _____/__ _\_ |__  /   _____/ ____ _____    ____   ____   ___________ 
     \_____  \|  |  \ __ \ \_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \\
     /        \  |  / \_\ \/        \  \___ / __ \|   |  \   |  \  ___/|  | \/
    /_______  /____/|___  /_______  /\___  >____  /___|  /___|  /\___  >__|   
            \/          \/        \/     \/     \/     \/     \/     \/       
    """
    print(Fore.WHITE + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80)
    print(Fore.GREEN + " " * 25 + "Subdomain Scanner v1.0")
    print(Fore.GREEN + " " * 25 + "Coded By: Zer0Crypt0" + Style.RESET_ALL)
    print(Fore.YELLOW + "=" * 80 + "\n" + Style.RESET_ALL)

def check_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True
    except:
        return False

def check_http_status(subdomain):
    try:
        urls = [f"http://{subdomain}", f"https://{subdomain}"]
        for url in urls:
            try:
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code == 200:
                    return True
            except:
                continue
        return False
    except:
        return False

def find_subdomains(domain):
    subdomains = set()
    accessible = set()
    ssl_status = {}
    
    # Alt alan listesi
    wordlist = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
        "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
        "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
        "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
        "apps", "download", "remote", "db", "forums", "store", "relay", "files", "newsletter",
        "app", "live", "owa", "en", "start", "sms", "office", "exchange", "ipv4"
    ]

    print(f"\n[*] {domain} için alt alan taraması başlatılıyor...")
    print("[*] Bu işlem biraz zaman alabilir...\n")

    def check_subdomain(subdomain):
        try:
            dns.resolver.resolve(f"{subdomain}.{domain}", "A")
            full_subdomain = f"{subdomain}.{domain}"
            subdomains.add(full_subdomain)
            # SSL durumunu kontrol et
            has_ssl = check_ssl_certificate(full_subdomain)
            ssl_status[full_subdomain] = has_ssl
            if check_http_status(full_subdomain):
                accessible.add(full_subdomain)
        except:
            pass

    with ThreadPoolExecutor(max_workers=30) as executor:
        executor.map(check_subdomain, wordlist)

    print("=" * 70)
    print(f"BULUNAN ALT ALANLAR ({len(subdomains)}):")
    print("=" * 70)
    for subdomain in sorted(subdomains):
        ssl_text = f"{Fore.GREEN}[+] Has SSL Certificate{Style.RESET_ALL}" if ssl_status.get(subdomain, False) else f"{Fore.RED}[-] Hasn't SSL Certificate{Style.RESET_ALL}"
        print(f"{Fore.WHITE}[+] {subdomain:<40}{Style.RESET_ALL} {ssl_text}")

    print("\n" + "=" * 70)
    print(f"ERİŞİLEBİLİR ALT ALANLAR ({len(accessible)}):")
    print("=" * 70)
    for subdomain in sorted(accessible):
        ssl_text = f"{Fore.GREEN}[+] Has SSL Certificate{Style.RESET_ALL}" if ssl_status.get(subdomain, False) else f"{Fore.RED}[-] Hasn't SSL Certificate{Style.RESET_ALL}"
        print(f"{Fore.WHITE}[+] {subdomain:<40}{Style.RESET_ALL} {ssl_text}")

if __name__ == "__main__":
    print_banner()
    if len(sys.argv) != 2:
        print(Fore.RED + "Kullanım: python3 SubScanner.py domain.com" + Style.RESET_ALL)
        sys.exit(1)
    
    domain = sys.argv[1]
    find_subdomains(domain)
