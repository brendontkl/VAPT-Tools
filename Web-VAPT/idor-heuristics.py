#!/usr/bin/env python3
"""IDOR Heuristics (Numeric ID Mutation)

Mutates numeric ID-like query parameters (+/-1) and compares responses.
Works best with an authenticated cookie/header.

Heuristic only — validate authorization with proper user context.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

ID_KEYS = {"id", "user", "userid", "user_id", "account", "account_id", "profile", "order", "invoice", "doc", "document", "item", "record", "uid"}


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


def _candidates(params: list[tuple[str, str]]) -> list[str]:
    out = set()
    for k, v in params:
        if re.fullmatch(r"\d{1,18}", v or ""):
            kl = k.lower()
            if kl in ID_KEYS or kl.endswith("_id") or kl.endswith("id"):
                out.add(k)
    return sorted(out)


def _summary(r: requests.Response) -> tuple[int, int, str]:
    return r.status_code, len(r.content or b""), r.headers.get("Content-Type", "")


def run_on_url(u: str, s: requests.Session, headers: dict, timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    keys = _candidates(params)
    if not keys:
        print(Fore.BLUE + f"[-] No obvious numeric ID params: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)

    try:
        r0 = s.get(u, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
    except Exception as e:
        print(Fore.YELLOW + f"[!] Baseline failed: {e}" + Style.RESET_ALL)
        return

    st0, ln0, ct0 = _summary(r0)
    print(Fore.CYAN + f"Baseline: {st0} | len={ln0} | {ct0}" + Style.RESET_ALL)

    for k in keys:
        v0 = next((v for kk, v in params if kk == k), None)
        if v0 is None:
            continue
        try:
            n = int(v0)
        except Exception:
            continue

        for d in (-1, +1):
            mu = _rebuild(u, [(pk, (str(n + d) if pk == k else pv)) for pk, pv in params])
            try:
                r1 = s.get(mu, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
            except Exception as e:
                print(Fore.BLUE + f"  - {k}{d:+}: request failed ({e})" + Style.RESET_ALL)
                continue

            st1, ln1, _ = _summary(r1)
            if st0 == 200 and st1 == 200:
                diff = abs(ln1 - ln0)
                if diff > 50 and diff < max(4000, int(ln0 * 0.25)):
                    print(Fore.YELLOW + f"  - {k}{d:+}: POSSIBLE IDOR (200 OK, len {ln0}->{ln1})" + Style.RESET_ALL)
                else:
                    print(Fore.BLUE + f"  - {k}{d:+}: 200 OK (len {ln1})" + Style.RESET_ALL)
            elif st1 in (401, 403, 404, 405):
                print(Fore.GREEN + f"  - {k}{d:+}: blocked ({st1})" + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"  - {k}{d:+}: status {st1} (len {ln1})" + Style.RESET_ALL)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== IDOR Heuristics (Numeric ID Mutation) ===\n" + Style.RESET_ALL)

    urls = _collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]

    auth = input("\nOptional: Authorization header value (e.g. 'Bearer xxx'). Blank if none: ").strip()
    cookie = input("Optional: Cookie header value (paste from Burp). Blank if none: ").strip()

    headers = {"User-Agent": "web-vapt-toolkit/1.0"}
    if auth:
        headers["Authorization"] = auth
    if cookie:
        headers["Cookie"] = cookie

    s = requests.Session()
    for u in urls:
        run_on_url(u, s, headers)


if __name__ == "__main__":
    run_interactive()
