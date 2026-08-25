#!/usr/bin/env python3
"""Run conformance vectors through the Python ctypes SDK."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python" / "src"))

import antech_kdf  # noqa: E402


def hex_decode(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


def main() -> int:
    doc = json.loads((ROOT / "sdk" / "conformance" / "vectors.json").read_text(encoding="utf-8"))
    failed = 0
    for case in doc["cases"]:
        cfg = antech_kdf.Config(**case["config"])
        password = hex_decode(case["password_hex"])
        salt = hex_decode(case["salt_hex"])
        try:
            encoded = antech_kdf.hash_with_config_and_salt(password, salt, cfg)
            digest = encoded.rsplit("$", 1)[-1]
            if digest != case["digest_hex"]:
                print(f"FAIL {case['id']}: digest mismatch")
                failed += 1
                continue
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
