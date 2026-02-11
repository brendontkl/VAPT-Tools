#!/usr/bin/env python3
"""Open Redirect Tester (heuristic)

Paste URLs (from Burp). The tool finds common redirect parameters and swaps them to a probe URL,
then checks if the server redirects externally.

Confirm in Burp (context + allowlist behavior).
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

REDIRECT_PARAMS = {
    "next","url","target","dest","destination","redir","redirect","redirect_url","redirect_uri",
    "return","returnto","return_to","continue","goto","out","view","callback","cb","forward","to","uri","path","file","redirectURL"
}

PROBE_URL = "https://example.com/"


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


def test_url(u: str, timeout: int = 12) -> None:
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        print(Fore.YELLOW + f"[!] Invalid URL: {u}" + Style.RESET_ALL)
        return

    params = parse_qsl(p.query, keep_blank_values=True)
    cand = [k for k, _ in params if k.lower() in REDIRECT_PARAMS or k.lower().endswith(("_url", "_uri"))]
    if not cand:
        print(Fore.BLUE + f"[-] No redirect-like params: {u}" + Style.RESET_ALL)
        return

    print(Fore.MAGENTA + f"\n=== Testing: {u} ===" + Style.RESET_ALL)
    s = requests.Session()
    headers = {"User-Agent": "web-vapt-toolkit/1.0"}

    for k in sorted(set(cand)):
        mu = _rebuild(u, [(pk, (PROBE_URL if pk == k else pv)) for pk, pv in params])
        try:
            r = s.get(mu, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            if "example.com" in loc:
                print(Fore.GREEN + f"  - {k}: POSSIBLE open redirect (Location -> {loc})" + Style.RESET_ALL)
            else:
                print(Fore.CYAN + f"  - {k}: redirect observed (Location -> {loc})" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no redirect (status {r.status_code})" + Style.RESET_ALL)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== Open Redirect Tester ===\n" + Style.RESET_ALL)
    urls = _collect_urls()
    if not urls:
        one = input("Enter a single URL to test: ").strip()
        if one:
            urls = [one]
    for u in urls:
        test_url(u)


if __name__ == "__main__":
    run_interactive()
