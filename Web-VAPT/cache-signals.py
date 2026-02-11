#!/usr/bin/env python3
"""Cache Poisoning Signal Checks (Heuristic)

Safer "signal" checks only (does NOT try to persist poison):
- Baseline request: show cache hints (Age, X-Cache, CF-Cache-Status, Vary, Cache-Control, Via...)
- Variant requests: add common unkeyed headers with a unique marker
- Flag if marker is reflected (body/headers) while cache hints exist

Confirm in Burp before writing a finding.
"""

from __future__ import annotations

import random, string
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Proto",
    "X-Forwarded-Scheme",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Rewrite-URL",
]

CACHE_HINT_HEADERS = [
    "Age", "X-Cache", "X-Cache-Hits", "CF-Cache-Status", "Via", "X-Served-By", "Cache-Control", "Surrogate-Control", "Vary"
]


def _rand(n: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _cache_hints(resp: requests.Response) -> dict:
    return {h: resp.headers.get(h) for h in CACHE_HINT_HEADERS if resp.headers.get(h) is not None}


def _reflected(resp: requests.Response, marker: str) -> bool:
    if marker in str(resp.headers):
        return True
    try:
        return marker in resp.text[:200000]
    except Exception:
        return False


def _get(url: str, headers: dict, timeout: int = 12) -> requests.Response:
    return requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=True)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Cache Poisoning Signal Checks (Heuristic) ===\n" + Style.RESET_ALL)

    url = input("Enter a target URL (cacheable GET if possible): ").strip()
    if not url:
        return

    p = urlparse(url)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + "[!] Invalid URL." + Style.RESET_ALL)
        return

    base_headers = {"User-Agent": "web-vapt-toolkit/1.0"}

    print(Fore.MAGENTA + "\n--- Baseline ---" + Style.RESET_ALL)
    r0 = _get(url, base_headers)
    print(Fore.CYAN + f"Status: {r0.status_code} | len={len(r0.content or b'')}" + Style.RESET_ALL)
    hints = _cache_hints(r0)
    print("Cache hints:", hints if hints else "(none)")

    marker = "vapt" + _rand()
    findings = []

    for hdr in UNKEYED_HEADERS[:4]:
        hh = dict(base_headers)
        hh[hdr] = marker

        print(Fore.MAGENTA + f"\n--- Variant: {hdr}: {marker} ---" + Style.RESET_ALL)
        r1 = _get(url, hh)
        print(Fore.CYAN + f"Status: {r1.status_code} | len={len(r1.content or b'')}" + Style.RESET_ALL)
        hints1 = _cache_hints(r1)
        print("Cache hints:", hints1 if hints1 else "(none)")

        if _reflected(r1, marker):
            findings.append(hdr)
            print(Fore.YELLOW + f"[?] Marker reflected with {hdr} (possible unkeyed input reflection)" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + "[-] No marker reflection." + Style.RESET_ALL)

    print(Fore.BLUE + Style.BRIGHT + "\n=== Summary ===" + Style.RESET_ALL)
    if not findings:
        print(Fore.GREEN + "No obvious cache-poisoning reflection signals detected." + Style.RESET_ALL)
    else:
        for hdr in findings:
            print(Fore.YELLOW + f"- {hdr}: marker reflected (verify caching + persistence in Burp)" + Style.RESET_ALL)


if __name__ == "__main__":
    run_interactive()
