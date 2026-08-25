#!/usr/bin/env python3
"""Synchronize VERSION into all SDK package manifests."""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


def replace_file(path: Path, pattern: str, repl: str, flags: int = 0) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    new = re.sub(pattern, repl, text, count=1, flags=flags)
    if new != text:
        path.write_text(new, encoding="utf-8")
        print(f"updated {path.relative_to(ROOT)}")


def main() -> None:
    print(f"VERSION={VERSION}")
    # Cargo workspace
    replace_file(
        ROOT / "Cargo.toml",
        r'(version\s*=\s*")[^"]+(")',
        rf'\g<1>{VERSION}\g<2>',
    )
    replace_file(
        ROOT / "research" / "code" / "Cargo.toml",
        r'(version\s*=\s*")[^"]+(")',
        rf'\g<1>{VERSION}\g<2>',
    )
    # Python
    replace_file(
        ROOT / "bindings" / "python" / "pyproject.toml",
        r'(version\s*=\s*")[^"]+(")',
        rf'\g<1>{VERSION}\g<2>',
    )
    # Node
    pkg = ROOT / "bindings" / "node" / "package.json"
    if pkg.exists():
        data = json.loads(pkg.read_text(encoding="utf-8"))
        data["version"] = VERSION
        pkg.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"updated {pkg.relative_to(ROOT)}")
    # Go
    replace_file(
        ROOT / "bindings" / "go" / "antech.go",
        r'(const Version = ")[^"]+(")',
        rf'\g<1>{VERSION}\g<2>',
    )
    # .NET
    replace_file(
        ROOT / "bindings" / "dotnet" / "Antech.Kdf" / "Antech.Kdf.csproj",
        r'(<Version>)[^<]+(</Version>)',
        rf'\g<1>{VERSION}\g<2>',
    )
    # Java
    replace_file(
        ROOT / "bindings" / "java" / "pom.xml",
        r'(<version>)[^<]+(</version>)',
        rf'\g<1>{VERSION}\g<2>',
        flags=re.IGNORECASE,
    )
    # schema
    schema = ROOT / "sdk" / "schema.json"
    if schema.exists():
        data = json.loads(schema.read_text(encoding="utf-8"))
        data["version"] = VERSION
        schema.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"updated {schema.relative_to(ROOT)}")
    print("done")


if __name__ == "__main__":
    main()
