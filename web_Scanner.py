"""
Web Vulnerability Scanner
Author: Hariharan
"""

import requests
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_SQLI = ["' OR 1=1 --", "\" OR \"1\"=\"1", "admin' --"]
DEFAULT_XSS = ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>"]
DEFAULT_LFI = ["../../../../etc/passwd", "../windows/win.ini", "../../boot.ini"]
DEFAULT_IDOR = ["1", "2", "3", "100", "999"]

def sqli_scan(url, param, payloads=DEFAULT_SQLI):
    print(Fore.YELLOW + "[*] SQLi scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "syntax error" in r.text.lower() or "mysql" in r.text.lower():
                print(Fore.GREEN + f"[+] SQLi detected with payload: {payload}")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

def xss_scan(url, param, payloads=DEFAULT_XSS):
    print(Fore.YELLOW + "[*] XSS scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if payload in r.text:
                print(Fore.GREEN + f"[+] XSS detected with payload: {payload}")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

def lfi_scan(url, param, payloads=DEFAULT_LFI):
    print(Fore.YELLOW + "[*] LFI scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "root:x" in r.text or "etc/passwd" in r.text:
                print(Fore.GREEN + f"[+] LFI detected with payload: {payload}")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

def idor_scan(url, param, values=DEFAULT_IDOR):
    print(Fore.YELLOW + "[*] IDOR scan")
    baseline = None
    try:
        r = requests.get(url, params={param: values[0]}, timeout=5)
        baseline = r.text
    except Exception as e:
        print(Fore.RED + f"Error baseline: {e}")
        return

    for val in values[1:]:
        try:
            r = requests.get(url, params={param: val}, timeout=5)
            if r.text != baseline and r.status_code == 200:
                print(Fore.GREEN + f"[+] Possible IDOR with value: {val} (response differs from baseline)")
        except Exception as e:
            print(Fore.RED + f"Error: {e}")

if __name__ == "__main__":
    target_url = input("Enter target URL (e.g. http://example.com/login): ").strip()
    if not target_url.startswith("http"):
        print(Fore.RED + "Invalid URL. Please include http:// or https://")
    else:
        sqli_scan(target_url, "username")
        xss_scan(target_url, "search")
        lfi_scan(target_url, "file")
        idor_scan(target_url, "id")
