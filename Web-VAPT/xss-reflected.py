#!/usr/bin/env python3
"""Reflected XSS Quick Probe (Heuristic)

- Paste URLs with query parameters
- Injects a unique marker payload into each parameter (one at a time)
- Flags reflection in response body (raw / escaped)

Not a full scanner. Confirm context + escaping in Burp.
"""

from __future__ import annotations

import html, random, string
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote_plus
import requests
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

BASE_PAYLOAD = "<svg/onload=alert(1)>"


def _rand(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _collect_urls() -> list[str]:
    print(Fore.CYAN + "Paste URLs (one per line). Blank line to start.\n" + Style.RESET_ALL)
    out = []
    while True:
        line = input().strip()
        if not line:
            break
        out.append(line)
    return out


def _rebuild(u: str, params: list[tuple[str, str]]) -> str:
    p = urlparse(u)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params, doseq=True), p.fragment))


def _reflection(body: str, marker: str) -> tuple[bool, str]:
    if marker in body:
        return True, "RAW reflection"
    if html.escape(marker) in body:
        return True, "HTML-escaped reflection"
    if quote_plus(marker) in body:
        return True, "URL-encoded reflection"
    return False, ""


def test_url(u: str, timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    if not params:
        print(Fore.BLUE + f"[-] No query parameters: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)
    s = requests.Session()
    headers = {"User-Agent": "web-vapt-toolkit/1.0"}

    for k, _ in params:
        marker = f"{BASE_PAYLOAD}{_rand()}"
        mu = _rebuild(u, [(pk, (marker if pk == k else pv)) for pk, pv in params])

        try:
            r = s.get(mu, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        body = r.text[:200000]
        ok, why = _reflection(body, marker)
        ct = r.headers.get("Content-Type", "").lower()

        if ok and "raw" in why.lower() and ("text/html" in ct or "<html" in body.lower()):
            print(Fore.RED + f"  - {k}: POTENTIAL XSS ({why}) -> {r.status_code}" + Style.RESET_ALL)
        elif ok:
            print(Fore.YELLOW + f"  - {k}: reflection detected ({why}) -> {r.status_code}" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no reflection -> {r.status_code}" + Style.RESET_ALL)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Reflected XSS Quick Probe (Heuristic) ===\n" + Style.RESET_ALL)
    urls = _collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]
    for u in urls:
        test_url(u)


if __name__ == "__main__":
    run_interactive()
