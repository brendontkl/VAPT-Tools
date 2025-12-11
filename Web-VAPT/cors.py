#!/usr/bin/env python3
import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init
from datetime import datetime
import warnings
import urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

# ------------------------------
# Utilities
# ------------------------------

def print_response_summary(resp):
    print(Fore.CYAN + f"\n=== Response from {resp.url} ===" + Style.RESET_ALL)
    print(f"Status: {resp.status_code}")
    print("Headers:")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")

def classify_cors(resp, origin_tested):
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acc = resp.headers.get("Access-Control-Allow-Credentials")
    issues = []

    if acao:
        if acao == origin_tested:
            issues.append("Origin reflected → Potential CORS bypass")
        elif acao == "*":
            if acc and acc.lower() == "true":
                issues.append("Wildcard + credentials → Critical misconfig")
            else:
                issues.append("Wildcard origin allowed")
        else:
            issues.append(f"Specific ACAO: {acao}")

    if acc and acc.lower() == "true":
        issues.append("Credentials allowed")

    return issues if issues else ["No obvious CORS issue"]

def categorize_result(issues):
    joined = " ".join(issues).lower()
    if "bypass" in joined or "critical" in joined:
        return "Successful"
    elif "wildcard" in joined or "credentials" in joined or "specific acao" in joined:
        return "Interesting"
    elif "error" in joined:
        return "Failed"
    else:
        return "Failed"

# ------------------------------
# Test cases
# ------------------------------

def run_cors_tests(url, host, method, cookies, headers, body_data):
    tests = [
        ("Malicious origin", "https://evil.com"),
        ("Null origin", "null"),
        ("Subdomain origin", f"https://evil.{host}"),
        ("Case variation", f"https://{host.upper()}"),
        ("Trailing slash", f"https://{host}/"),
        ("HTTP scheme", f"http://{host}"),
        ("Multiple origins", "https://evil.com https://another.com"),
    ]

    results = {"Successful": [], "Interesting": [], "Failed": []}

    for name, origin in tests:
        print(Fore.YELLOW + f"\n--- Test: {name} (Origin={origin}) ---" + Style.RESET_ALL)
        try:
            resp = requests.request(
                method,
                url,
                headers={**headers, "Origin": origin},
                cookies=cookies,
                data=body_data if method in ["POST", "PUT"] else None,
                timeout=8,
                verify=False
            )
            print_response_summary(resp)
            issues = classify_cors(resp, origin)
            category = categorize_result(issues)
            results[category].append((name, issues))
            for issue in issues:
                print(Fore.GREEN + f"[+] {issue}" + Style.RESET_ALL if category == "Successful"
                      else Fore.YELLOW + f"[!] {issue}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error during {name}: {e}" + Style.RESET_ALL)
            results["Failed"].append((name, [f"Error: {e}"]))

    # Preflight test
    print(Fore.YELLOW + "\n--- Test: Preflight request ---" + Style.RESET_ALL)
    try:
        preflight_headers = {
            **headers,
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Header"
        }
        resp = requests.options(url, headers=preflight_headers, cookies=cookies, timeout=8, verify=False)
        print_response_summary(resp)
        issues = []
        if "Access-Control-Allow-Methods" in resp.headers:
            issues.append(f"Allowed methods: {resp.headers['Access-Control-Allow-Methods']}")
        if "Access-Control-Allow-Headers" in resp.headers:
            issues.append(f"Allowed headers: {resp.headers['Access-Control-Allow-Headers']}")
        if not issues:
            issues = ["No obvious CORS issue"]
        category = categorize_result(issues)
        results[category].append(("Preflight", issues))
        for issue in issues:
            print(Fore.GREEN + f"[+] {issue}" + Style.RESET_ALL if category == "Successful"
                  else Fore.YELLOW + f"[!] {issue}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error during Preflight: {e}" + Style.RESET_ALL)
        results["Failed"].append(("Preflight", [f"Error: {e}"]))

    return results

# ------------------------------
# Interactive CLI
# ------------------------------

def run_interactive():
    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Automated CORS Exploitation ===\n" + Style.RESET_ALL)

    target_url = input("Target URL (e.g. https://www.example.com/api): ").strip()
    parsed = urlparse(target_url if "://" in target_url else ("https://" + target_url))
    host = parsed.hostname or ""

    method = input("HTTP method to use (GET/POST/PUT) [default GET]: ").strip().upper() or "GET"

    body_data = None
    if method in ["POST", "PUT"]:
        print("\nEnter body data for the request (press Enter on blank line to finish):")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        body_data = "\n".join(lines)

    # Collect cookies
    cookies = {}
    print("\nEnter authentication cookies (name=value). Press Enter on blank line to finish:")
    while True:
        line = input("Cookie: ").strip()
        if not line:
            break
        if "=" in line:
            name, value = line.split("=", 1)
            cookies[name.strip()] = value.strip()

    # Collect headers
    headers = {}
    print("\nEnter additional headers (name:value). Press Enter on blank line to finish:")
    while True:
        line = input("Header: ").strip()
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip()] = value.strip()

    print(f"\nTarget parsed → Host: {host} | URL: {target_url} | Method: {method}")
    print(f"Cookies: {cookies}")
    print(f"Headers: {headers}")
    if body_data:
        print(f"Body data:\n{body_data}")

    results = run_cors_tests(target_url, host, method, cookies, headers, body_data)

    # Summary page
    print(Fore.BLUE + Style.BRIGHT + "\n=== CORS Summary ===" + Style.RESET_ALL)
    for group in ["Successful", "Interesting", "Failed"]:
        print(f"{Fore.GREEN if group=='Successful' else (Fore.YELLOW if group=='Interesting' else Fore.RED)}{group}:{Style.RESET_ALL}")
        if not results[group]:
            print("  - None")
        else:
            for test, issues in results[group]:
                print(f"  - {test}:")
                for issue in issues:
                    print(f"      * {issue}")

    print(Fore.CYAN + f"\nCompleted at {datetime.now().isoformat(timespec='seconds')}" + Style.RESET_ALL)

if __name__ == "__main__":
    run_interactive()