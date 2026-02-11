#!/usr/bin/env python3
"""HTTP Methods / Dangerous Verbs Check

Sends OPTIONS and lightweight probes for TRACE / PUT / DELETE.
"""

from __future__ import annotations

import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

RISKY = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT"}


def run_check(url: str, timeout: int = 12) -> None:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {url}" + Style.RESET_ALL)
        return

    s = requests.Session()
    headers = {"User-Agent": "web-vapt-toolkit/1.0"}

    print(Fore.MAGENTA + f"\n=== {url} ===" + Style.RESET_ALL)
    try:
        r = s.options(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
    except Exception as e:
        print(Fore.YELLOW + f"[!] OPTIONS failed: {e}" + Style.RESET_ALL)
        return

    allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods") or ""
    allow_set = {m.strip().upper() for m in allow.split(",") if m.strip()}

    print(Fore.CYAN + f"Allow/ACAM: {allow or '(not provided)'}" + Style.RESET_ALL)

    risky = sorted([m for m in allow_set if m in RISKY])
    if risky:
        print(Fore.RED + f"[!] Risky methods advertised: {', '.join(risky)}" + Style.RESET_ALL)

    for m in ["TRACE", "PUT", "DELETE"]:
        try:
            rr = s.request(m, url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
            if rr.status_code not in (400, 401, 403, 404, 405):
                print(Fore.YELLOW + f"[?] {m} returned {rr.status_code} (check if functional)" + Style.RESET_ALL)
            else:
                print(Fore.BLUE + f"[-] {m} returned {rr.status_code}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.BLUE + f"[-] {m} probe failed ({e})" + Style.RESET_ALL)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== HTTP Methods Check ===\n" + Style.RESET_ALL)
    url = input("Enter target URL (e.g. https://example.com/): ").strip()
    if url:
        run_check(url)


if __name__ == "__main__":
    run_interactive()
