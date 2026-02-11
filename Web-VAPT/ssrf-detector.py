#!/usr/bin/env python3
"""SSRF Candidate Detector (Passive + Optional Probes)

Passive: identifies likely SSRF parameters in URLs.
Optional probes: if you provide a probe URL (e.g. Burp Collaborator), replaces candidate params with it and
looks for common SSRF-style error signals. (Still not confirmation without OOB logs.)
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
from colorama import Fore, Style, init
import warnings, urllib3

init(autoreset=True)
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

CANDIDATE_KEYS = {
    "url", "uri", "link", "path", "dest", "destination", "next", "redirect", "redirect_url", "redirect_uri",
    "callback", "return", "continue", "to", "site", "domain", "host", "proxy", "image", "img", "avatar",
    "file", "download", "feed", "endpoint", "api", "webhook", "target", "forward", "out"
}

ERROR_SIGS = [
    "connection refused", "econnrefused", "timed out", "etimedout", "no route to host", "enetunreach",
    "name or service not known", "temporary failure in name resolution", "getaddrinfo",
    "invalid url", "unsupported protocol", "only http", "blocked", "disallowed host", "forbidden host"
]


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


def _is_candidate(k: str) -> bool:
    kl = k.lower()
    return kl in CANDIDATE_KEYS or kl.endswith(("_url", "_uri", "_host", "_domain", "_link"))


def analyze(u: str) -> list[str]:
    p = urlparse(u)
    params = parse_qsl(p.query, keep_blank_values=True)
    return sorted({k for k, _ in params if _is_candidate(k)})


def probe(u: str, keys: list[str], probe_url: str, timeout: int = 12) -> None:
    p = urlparse(u)
    params = parse_qsl(p.query, keep_blank_values=True)
    s = requests.Session()
    headers = {"User-Agent": "web-vapt-toolkit/1.0"}

    for k in keys:
        mu = _rebuild(u, [(pk, (probe_url if pk == k else pv)) for pk, pv in params])
        try:
            r = s.get(mu, headers=headers, verify=False, timeout=timeout, allow_redirects=True)
        except Exception as e:
            print(Fore.YELLOW + f"  - {k}: request failed ({e})" + Style.RESET_ALL)
            continue

        hay = (r.text[:5000] + str(r.headers)).lower()
        sig = next((s for s in ERROR_SIGS if s in hay), None)
        if sig:
            print(Fore.YELLOW + f"  - {k}: error signal '{sig}' -> {r.status_code} (verify with OOB logs)" + Style.RESET_ALL)
        else:
            print(Fore.BLUE + f"  - {k}: no obvious error signal -> {r.status_code}" + Style.RESET_ALL)


def run_interactive() -> None:
    print(Fore.CYAN + Style.BRIGHT + "\n=== SSRF Candidate Detector ===\n" + Style.RESET_ALL)
    urls = _collect_urls()
    if not urls:
        one = input("Enter a single URL to analyze: ").strip()
        if one:
            urls = [one]

    probe_url = input("\nOptional: Enter probe URL (e.g. Burp Collaborator). Blank to skip active probes: ").strip()

    for u in urls:
        keys = analyze(u)
        if not keys:
            print(Fore.BLUE + f"\n[-] No obvious SSRF params: {u}" + Style.RESET_ALL)
            continue

        print(Fore.MAGENTA + f"\n=== {u} ===" + Style.RESET_ALL)
        print(Fore.CYAN + f"Candidate params: {', '.join(keys)}" + Style.RESET_ALL)
        print("Recommendations:")
        print("  - Confirm with OOB logs (Collaborator/DNS).")
        print("  - Try URL parser bypasses (@, #, redirects, encoding, IP formats).")

        if probe_url:
            print(Fore.CYAN + "\nActive probe (still not confirmation without OOB):" + Style.RESET_ALL)
            probe(u, keys, probe_url)


if __name__ == "__main__":
    run_interactive()
