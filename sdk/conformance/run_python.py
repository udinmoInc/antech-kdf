#!/usr/bin/env python3
"""Run conformance vectors through the Python ctypes SDK."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python" / "src"))

import antech_kdf  # noqa: E402


def hex_decode(s: str | None) -> bytes | None:
    if s is None:
        return None
    return bytes.fromhex(s) if s else b""


def main() -> int:
    doc = json.loads((ROOT / "sdk" / "conformance" / "vectors.json").read_text(encoding="utf-8"))
    failed = 0
    for case in doc["cases"]:
        cfg = antech_kdf.Config(**case["config"])
        password = hex_decode(case["password_hex"]) or b""
        salt = hex_decode(case["salt_hex"]) or b""
        # Optional: omit key = absent; "" hex = present empty; hex string = present
        has_secret = "secret_hex" in case
        has_ad = "associated_data_hex" in case
        secret = hex_decode(case["secret_hex"]) if has_secret else None
        ad = hex_decode(case["associated_data_hex"]) if has_ad else None
        try:
            if has_secret or has_ad:
                encoded = antech_kdf.hash_with_inputs_and_salt(
                    password, salt, cfg, secret=secret, associated_data=ad
                )
            else:
                encoded = antech_kdf.hash_with_config_and_salt(password, salt, cfg)
            digest = encoded.rsplit("$", 1)[-1]
            if digest != case["digest_hex"]:
                print(f"FAIL {case['id']}: digest mismatch got={digest}")
                failed += 1
                continue
            if has_secret or has_ad:
                if not antech_kdf.verify_with_inputs(
                    password, encoded, secret=secret, associated_data=ad
                ):
                    print(f"FAIL {case['id']}: verify_with_inputs")
                    failed += 1
                    continue
            else:
                if not antech_kdf.verify(password, encoded):
                    print(f"FAIL {case['id']}: verify")
                    failed += 1
                    continue
            print(f"ok   {case['id']}")
        except Exception as e:
            print(f"FAIL {case['id']}: {e}")
            failed += 1
    print(f"{len(doc['cases']) - failed}/{len(doc['cases'])} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
