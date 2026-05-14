
import requests

def load_payloads(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def sqli_scan(url, param, payloads):
    print("[*] SQLi scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "syntax error" in r.text.lower() or "mysql" in r.text.lower():
                print(f"[+] SQLi detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def xss_scan(url, param, payloads):
    print("[*] XSS scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if payload in r.text:
                print(f"[+] XSS detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def lfi_scan(url, param, payloads):
    print("[*] LFI scan")
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if "root:x" in r.text or "etc/passwd" in r.text:
                print(f"[+] LFI detected with payload: {payload}")
        except Exception as e:
            print(f"Error: {e}")

def idor_scan(url, param, values):
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
    sqli_payloads = load_payloads("payloads/sqli.txt")
    xss_payloads = load_payloads("payloads/xss.txt")
    lfi_payloads = load_payloads("payloads/lfi.txt")
    idor_values = ["1", "2", "3", "100", "999"]

    sqli_scan(target_url, "username", sqli_payloads)
    xss_scan(target_url, "search", xss_payloads)
    lfi_scan(target_url, "file", lfi_payloads)
    idor_scan("http://testphp.vulnweb.com/profile.php", "id", idor_values)
