#!/usr/bin/env python3
"""SSL / TLS Audit Tool (testssl-like, lightweight)

Fixes false positives by enumerating ciphers via REAL negotiated intersections.

- Protocol support checks (TLS 1.0/1.1/1.2/1.3)
- Certificate summary (subject/issuer/expiry/signature/key length)
- Cipher enumeration:
  * TLS <= 1.2: uses ssock.shared_ciphers() to list actual server-supported ciphers.
  * TLS 1.3: attempts enumeration via set_ciphersuites() when available; else shows negotiated cipher only.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Tuple, Optional, Set

from colorama import Fore, Style, init
from cryptography import x509
from cryptography.hazmat.backends import default_backend

init(autoreset=True)

BANNER = f"""{Fore.CYAN}{Style.BRIGHT}
 ___    ___    _             ___                             
(  _`\\ (  _`\\ ( )           (  _`\\                           
| (_(_)| (_(_)| |    ______ | (_(_)  ___   _   _   ___ ___   
`\\__ \\ `\\__ \\ | |  _(______)|  _)_ /' _ `\\( ) ( )/' _ ` _ `\\ 
( )_) |( )_) || |_( )       | (_( )| ( ) || (_) || ( ) ( ) | 
`\\____)`\\____)(____/'       (____/'(_) (_)`\\___/'(_) (_) (_) 
{Style.RESET_ALL}
"""

LOCAL_CVE_MAP = {
    "rc4": [
        "CVE-2013-2566: RC4 biases allow plaintext recovery",
        "CVE-2015-2808: RC4 stream cipher deemed insecure",
    ],
    "3des": [
        "CVE-2016-2183: SWEET32 (64-bit block ciphers like 3DES)",
    ],
    "cbc": [
        "CVE-2011-3389: BEAST attack against TLS CBC",
        "CVE-2014-3566: POODLE attack against SSLv3 CBC",
    ],
    "sha1": [
        "CVE-2017-18217: SHA-1 collision attacks (legacy signatures/MACs)",
    ],
    "md5": [
        "CVE-2008-2100: MD5 certificate forgery / collisions",
    ],
    "null": [
        "NULL cipher suites provide no encryption",
    ],
    "export": [
        "EXPORT cipher suites are weak by design",
    ],
}


def parse_host(target: str) -> Tuple[str, int]:
    p = urlparse(target.strip())
    host = p.hostname or target.strip()
    port = p.port or 443
    return host, port


def is_weak(cipher_name: str) -> bool:
    n = cipher_name.lower()
    return (
        "rc4" in n or "3des" in n or "des-" in n or "cbc" in n or "md5" in n
        or "null" in n or "export" in n
        or ("sha" in n and "sha256" not in n and "sha384" not in n and "sha512" not in n)
    )


def get_local_cves(cipher_name: str) -> List[str]:
    n = cipher_name.lower()
    out: List[str] = []
    for key, cves in LOCAL_CVE_MAP.items():
        if key in n:
            out.extend(cves)
    return out


def _dial(host: str, port: int, ctx: ssl.SSLContext, server_hostname: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=6)
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


def check_protocols(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Protocol Support ==={Style.RESET_ALL}")
    versions = [
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    for name, ver in versions:
        if ver is None:
            print(f"  - {name}: {Fore.YELLOW}UNKNOWN (runtime lacks TLSVersion){Style.RESET_ALL}")
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            ssock = _dial(host, port, ctx, host)
            try:
                print(f"  - {name}: {Fore.GREEN}SUPPORTED{Style.RESET_ALL} (negotiated: {ssock.version()})")
            finally:
                ssock.close()
        except Exception:
            print(f"  - {name}: {Fore.RED}NOT SUPPORTED{Style.RESET_ALL}")


def check_certificate(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Certificate Checks ==={Style.RESET_ALL}")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        exp = cert.not_valid_after_utc
        print(f"  - Subject: {subject}")
        print(f"  - Issuer:  {issuer}")
        print(f"  - Expires: {exp}")
        if exp < datetime.now(timezone.utc):
            print(f"    {Fore.RED}Certificate expired!{Style.RESET_ALL}")
        sigalg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        print(f"  - Signature Algorithm: {sigalg}")
        if sigalg.lower() in ("sha1", "md5"):
            print(f"    {Fore.RED}Weak signature algorithm!{Style.RESET_ALL}")
        key = cert.public_key()
        try:
            ks = key.key_size
            print(f"  - Key Size: {ks} bits")
            if ks < 2048:
                print(f"    {Fore.RED}Weak key size (<2048)!{Style.RESET_ALL}")
        except Exception:
            pass
    except Exception as e:
        print(f"  {Fore.RED}Failed to read certificate: {e}{Style.RESET_ALL}")


def _shared_ciphers_tls12(host: str, port: int) -> List[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ssock = _dial(host, port, ctx, host)
    try:
        c = ssock.shared_ciphers() or []
        return [x[0] for x in c if x and x[0]]
    finally:
        ssock.close()


def _tls13_cipher_enum(host: str, port: int) -> Tuple[Set[str], Optional[str]]:
    common = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
    ]
    supported: Set[str] = set()
    note: Optional[str] = None

    # negotiated cipher
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ssock = _dial(host, port, ctx, host)
        try:
            if (ssock.version() or "").startswith("TLSv1.3"):
                c = ssock.cipher()
                if c and c[0]:
                    supported.add(c[0])
        finally:
            ssock.close()
    except Exception:
        pass

    if not hasattr(ssl.SSLContext, "set_ciphersuites"):
        note = "Runtime does not support set_ciphersuites(); listing negotiated TLS 1.3 cipher only."
        return supported, note

    for cs in common:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_ciphersuites(cs)  # type: ignore[attr-defined]
            ssock = _dial(host, port, ctx, host)
            try:
                if (ssock.version() or "").startswith("TLSv1.3"):
                    c = ssock.cipher()
                    if c and c[0] == cs:
                        supported.add(cs)
            finally:
                ssock.close()
        except Exception:
            continue

    return supported, note


def check_ciphers(host: str, port: int) -> None:
    print(f"\n{Fore.MAGENTA}=== Cipher Enumeration ==={Style.RESET_ALL}")
    strong: Set[str] = set()
    weak: Set[str] = set()

    try:
        tls12 = _shared_ciphers_tls12(host, port)
        for c in tls12:
            (weak if is_weak(c) else strong).add(c)
    except Exception as e:
        print(f"  {Fore.YELLOW}TLS<=1.2 cipher list unavailable: {e}{Style.RESET_ALL}")

    tls13, note = _tls13_cipher_enum(host, port)
    for c in tls13:
        (weak if is_weak(c) else strong).add(c)

    if note:
        print(f"  {Fore.YELLOW}{note}{Style.RESET_ALL}")

    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Cipher Summary ==={Style.RESET_ALL}\n")

    print(f"{Fore.GREEN}Strong Ciphers:{Style.RESET_ALL}")
    print("  - None" if not strong else "\n".join(f"  - {c}" for c in sorted(strong)))

    print(f"\n{Fore.RED}Weak Ciphers:{Style.RESET_ALL}")
    if not weak:
        print("  - None")
    else:
        for c in sorted(weak):
            print(f"  - {c}")
            for cv in get_local_cves(c)[:3]:
                print(f"      {Fore.YELLOW}{cv}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Total unique supported ciphers observed: {len(strong) + len(weak)}{Style.RESET_ALL}")


def run_interactive() -> None:
    print(BANNER)
    target = input(f"{Fore.CYAN}Enter target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()
    host, port = parse_host(target)
    print(f"\n[+] Target: {Fore.CYAN}{host}:{port}{Style.RESET_ALL}")
    check_protocols(host, port)
    check_certificate(host, port)
    check_ciphers(host, port)
    print(f"\n{Fore.BLUE}{Style.BRIGHT}=== Audit Complete ==={Style.RESET_ALL}")


if __name__ == "__main__":
    run_interactive()
