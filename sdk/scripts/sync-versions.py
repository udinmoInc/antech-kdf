#!/usr/bin/env python3
"""Push VERSION + sdk/package-meta.json into package manifests and binding version constants.

  python sdk/scripts/sync-versions.py
  python sdk/scripts/sync-versions.py --list
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
META = json.loads((ROOT / "sdk" / "package-meta.json").read_text(encoding="utf-8"))

A, E, L = META["author"], META["email"], META["license"]
REPO, HOME, DOCS, BUGS = META["repository"], META["homepage"], META["docs"], META["bugs"]
DESC, ORG, COPY = META["description"], META["organization"], META["copyright"]
AE = f"{A} <{E}>"


def rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def write(p: Path, text: str, report: list[str]) -> None:
    if not p.exists() or read(p) == text:
        return
    p.write_text(text, encoding="utf-8")
    report.append(rel(p))
    print(f"  updated {rel(p)}")


def sub(text: str, pattern: str, repl: str, flags: int = 0, count: int = 1) -> str:
    return re.sub(pattern, repl, text, count=count, flags=flags)


def patch(p: Path, *ops: tuple[str, str], flags: int = 0, report: list[str] | None = None) -> None:
    if not p.exists():
        return
    text = read(p)
    new = text
    for pattern, repl in ops:
        new = sub(new, pattern, repl, flags=flags)
    if report is not None:
        write(p, new, report)


def write_json(p: Path, data: object, report: list[str]) -> None:
    write(p, json.dumps(data, indent=2) + "\n", report)


# --- version constants in source (VERSION only; author lives in manifests) ---

SOURCE_VERSIONS: list[tuple[Path, str]] = [
    (ROOT / "bindings/python/src/antech_kdf/__init__.py", r'(__version__\s*=\s*")[^"]+(")'),
    (ROOT / "bindings/node/src/index.ts", r'(export const VERSION = ")[^"]+(")'),
    (ROOT / "bindings/go/antech.go", r'(const Version = ")[^"]+(")'),
    (ROOT / "bindings/dotnet/Antech.Kdf/AntechKdf.cs", r'(public const string Version = ")[^"]+(")'),
    (ROOT / "bindings/java/src/main/java/com/udinmo/antech/AntechKdf.java", r'(PACKAGE_VERSION = ")[^"]+(")'),
    (ROOT / "bindings/php/src/Antech.php", r"(public const VERSION = ')[^']+(')"),
    (ROOT / "bindings/ruby/lib/antech_kdf.rb", r'(VERSION = ")[^"]+(")'),
    (ROOT / "bindings/dart/lib/antech_kdf.dart", r"(const String packageVersion = ')[^']+(')"),
    (ROOT / "bindings/perl/lib/Antech/Kdf.pm", r"(our \$VERSION = ')[^']+(')"),
    (ROOT / "bindings/lua/antech_kdf.lua", r'(VERSION = ")[^"]+(")'),
    (ROOT / "bindings/nim/antech_kdf.nim", r'(packageVersion\* = ")[^"]+(")'),
    (ROOT / "bindings/julia/src/AntechKdf.jl", r'(const PACKAGE_VERSION = ")[^"]+(")'),
    (ROOT / "bindings/crystal/src/antech_kdf.cr", r'(VERSION = ")[^"]+(")'),
    (ROOT / "bindings/zig/src/antech_kdf.zig", r'(package_version = ")[^"]+(")'),
    (ROOT / "bindings/r/R/antech.R", r'(PACKAGE_VERSION <- ")[^"]+(")'),
    (ROOT / "bindings/swift/Sources/AntechKdf/AntechKdf.swift", r'(static let version = ")[^"]+(")'),
    (ROOT / "bindings/haskell/src/Antech/Kdf.hs", r'(then pure ")[^"]+(")'),
    (ROOT / "bindings/kotlin/build.gradle.kts", r'(^version\s*=\s*")[^"]+(")'),
]


def sync_source_versions(report: list[str]) -> None:
    for path, pattern in SOURCE_VERSIONS:
        flags = re.M if pattern.startswith("(^") else 0
        patch(path, (pattern, rf"\g<1>{VERSION}\g<2>"), flags=flags, report=report)


def sync_cargo(report: list[str]) -> None:
    for cargo in (ROOT / "Cargo.toml", ROOT / "research/code/Cargo.toml"):
        patch(
            cargo,
            (r'(^version\s*=\s*")[^"]+(")', rf'\g<1>{VERSION}\g<2>'),
            (r'(^authors\s*=\s*\["?)[^"\]]+("?\])', rf'\g<1>{AE}\g<2>'),
            (r'(^license\s*=\s*")[^"]+(")', rf'\g<1>{L}\g<2>'),
            (r'(^repository\s*=\s*")[^"]+(")', rf'\g<1>{REPO}\g<2>'),
            (r'(^homepage\s*=\s*")[^"]+(")', rf'\g<1>{HOME}\g<2>'),
            flags=re.M,
            report=report,
        )
    patch(
        ROOT / "fuzz/harness/Cargo.toml",
        (r'(^version\s*=\s*")[^"]+(")', rf'\g<1>{VERSION}\g<2>'),
        flags=re.M,
        report=report,
    )


def sync_python_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/python/pyproject.toml"
    if not p.exists():
        return
    text = read(p)
    text = sub(text, r'(version\s*=\s*")[^"]+(")', rf'\g<1>{VERSION}\g<2>')
    text = sub(text, r'(description\s*=\s*")[^"]*(")', rf'\g<1>{DESC}\g<2>')
    text = sub(text, r'(license\s*=\s*\{\s*text\s*=\s*")[^"]+("\s*\})', rf'\g<1>{L}\g<2>')
    authors = f'authors = [{{ name = "{A}", email = "{E}" }}]'
    text = sub(text, r"^authors\s*=\s*.*$", authors, flags=re.M)
    urls = (
        "[project.urls]\n"
        f'Homepage = "{HOME}"\n'
        f'Documentation = "{DOCS}"\n'
        f'Repository = "{REPO}"\n'
        f'Bug Tracker = "{BUGS}"\n'
    )
    if "[project.urls]" in text:
        text = sub(text, r"\[project\.urls\][^\[]*", urls.rstrip() + "\n\n", count=1)
    else:
        text = text.rstrip() + "\n\n" + urls
    write(p, text.rstrip() + "\n", report)

    init = ROOT / "bindings/python/src/antech_kdf/__init__.py"
    patch(init, (r'(__version__\s*=\s*")[^"]+(")', rf'\g<1>{VERSION}\g<2>'), report=report)


def sync_node_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/node/package.json"
    if not p.exists():
        return
    data = json.loads(read(p))
    data.update(
        {
            "version": VERSION,
            "description": DESC,
            "license": L,
            "author": {"name": A, "email": E, "url": HOME},
            "homepage": HOME,
            "bugs": {"url": BUGS, "email": E},
            "repository": {"type": "git", "url": f"git+{REPO}.git"},
        }
    )
    write_json(p, data, report)


def sync_php_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/php/composer.json"
    if not p.exists():
        return
    data = json.loads(read(p))
    data.update(
        {
            "version": VERSION,
            "description": DESC,
            "license": L,
            "authors": [{"name": A, "email": E, "homepage": HOME}],
            "homepage": HOME,
            "support": {"email": E, "issues": BUGS, "source": REPO, "docs": DOCS},
        }
    )
    write_json(p, data, report)


def sync_dotnet_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/dotnet/Antech.Kdf/Antech.Kdf.csproj"
    if not p.exists():
        return
    text = read(p)

    def prop(t: str, tag: str, val: str) -> str:
        if re.search(rf"<{tag}>", t):
            return sub(t, rf"(<{tag}>)[^<]*(</{tag}>)", rf"\g<1>{val}\g<2>")
        return sub(t, r"(</PropertyGroup>)", rf"    <{tag}>{val}</{tag}>\n  \g<1>")

    for tag, val in (
        ("Version", VERSION),
        ("Authors", A),
        ("Company", ORG),
        ("Copyright", COPY),
        ("Description", DESC),
        ("PackageLicenseExpression", L),
        ("RepositoryUrl", REPO),
        ("PackageProjectUrl", HOME),
    ):
        text = prop(text, tag, val)
    write(p, text, report)


def sync_java_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/java/pom.xml"
    if not p.exists():
        return
    text = read(p)
    text = sub(
        text,
        r"(<artifactId>antech-kdf</artifactId>\s*<version>)[^<]+(</version>)",
        rf"\g<1>{VERSION}\g<2>",
    )
    text = sub(text, r"(<description>)[^<]*(</description>)", rf"\g<1>{DESC}\g<2>")
    org = f"""  <organization>
    <name>{ORG}</name>
    <url>{HOME}</url>
  </organization>
  <developers>
    <developer>
      <name>{A}</name>
      <email>{E}</email>
      <organization>{ORG}</organization>
      <organizationUrl>{HOME}</organizationUrl>
    </developer>
  </developers>
  <licenses>
    <license>
      <name>{L}</name>
      <url>{REPO}</url>
    </license>
  </licenses>
  <url>{HOME}</url>
  <scm>
    <url>{REPO}</url>
    <connection>scm:git:{REPO}.git</connection>
  </scm>
"""
    if "<organization>" in text:
        text = sub(text, r"  <organization>.*?</scm>\n", org, flags=re.S)
    else:
        text = sub(text, r"(  <description>.*?</description>\n)", rf"\g<1>{org}", flags=re.S)
    write(p, text, report)


def sync_ruby_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/ruby/antech_kdf.gemspec"
    patch(
        p,
        (r'(s\.version\s*=\s*")[^"]+(")', rf'\g<1>{VERSION}\g<2>'),
        (r'(s\.authors\s*=\s*\["?)[^"\]]+("?\])', rf'\g<1>{A}\g<2>'),
        (r'(s\.email\s*=\s*\["?)[^"\]]+("?\])', rf'\g<1>{E}\g<2>'),
        (r'(s\.homepage\s*=\s*")[^"]+(")', rf'\g<1>{HOME}\g<2>'),
        (r'(s\.summary\s*=\s*")[^"]*(")', rf'\g<1>{DESC}\g<2>'),
        report=report,
    )


def sync_dart_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/dart/pubspec.yaml"
    if not p.exists():
        return
    text = read(p)
    text = sub(text, r"(^version:\s*)\S+", rf"\g<1>{VERSION}", flags=re.M)
    text = sub(text, r"(^description:\s*).*$", rf"\g<1>{DESC}", flags=re.M)
    text = sub(text, r"(^homepage:\s*).*$", rf"\g<1>{HOME}", flags=re.M)
    if "repository:" not in text:
        text = sub(
            text,
            r"(^homepage:\s*.*\n)",
            rf"\g<1>repository: {REPO}\nissue_tracker: {BUGS}\n",
            flags=re.M,
        )
    write(p, text, report)


def sync_haskell_manifest(report: list[str]) -> None:
    p = ROOT / "bindings/haskell/antech-kdf.cabal"
    if not p.exists():
        return
    text = read(p)
    fields = {
        "version": VERSION,
        "synopsis": DESC,
        "homepage": HOME,
        "bug-reports": BUGS,
        "author": A,
        "maintainer": E,
        "copyright": COPY,
    }
    for key, val in fields.items():
        if re.search(rf"^{key}:", text, re.M):
            text = sub(text, rf"(^{key}:\s*).*$", rf"\g<1>{val}", flags=re.M)
        else:
            text = sub(text, r"(^version:\s*.*\n)", rf"\g<1>{key}: {val}\n", flags=re.M)
    write(p, text, report)


def sync_c_header(report: list[str]) -> None:
    p = ROOT / "bindings/c/antech_kdf.h"
    if not p.exists():
        return
    text = read(p)
    line = f" * Package: antech-kdf {VERSION} — {AE}\n"
    if " * Package:" in text:
        text2 = sub(text, r" \* Package:.*\n", line)
    else:
        text2 = sub(text, r"(/\*\*\n \* Antech KDF — C ABI\n)", rf"\g<1>{line}")
    # drop extra Author/License/Home lines if present from older sync
    text2 = sub(text2, r" \* Author:.*\n", "", count=0)
    text2 = sub(text2, r" \* License:.*\n", "", count=0)
    text2 = sub(text2, r" \* Home:.*\n", "", count=0)
    write(p, text2, report)


def sync_schema(report: list[str]) -> None:
    p = ROOT / "sdk/schema.json"
    if not p.exists():
        return
    data = json.loads(read(p))
    data.update({"version": VERSION, "author": A, "email": E, "license": L, "homepage": HOME})
    write_json(p, data, report)


def sync_docs(report: list[str]) -> None:
    p = ROOT / "docs/sdk/overview.mdx"
    if p.exists():
        text = read(p)
        text2 = sub(text, r"(All published packages track release \*\*)[^*]+(\*\*)", rf"\g<1>{VERSION}\g<2>")
        text2 = re.sub(r"(antech-kdf@)[0-9]+\.[0-9]+\.[0-9]+", rf"\g<1>{VERSION}", text2)
        text2 = re.sub(r"(antech-kdf==)[0-9]+\.[0-9]+\.[0-9]+", rf"\g<1>{VERSION}", text2)
        text2 = re.sub(r"(--version )[0-9]+\.[0-9]+\.[0-9]+", rf"\g<1>{VERSION}", text2)
        write(p, text2, report)
    patch(
        ROOT / "README.md",
        (r"(current release \*\*)[^*]+(\*\*)", rf"\g<1>{VERSION}\g<2>"),
        report=report,
    )


TARGETS = [
    "VERSION",
    "sdk/package-meta.json",
    "Cargo.toml + research/code/Cargo.toml",
    "bindings/*/ package manifests",
    "binding source VERSION constants",
    "bindings/c/antech_kdf.h",
    "sdk/schema.json",
    "docs/sdk/overview.mdx",
]


def apply() -> int:
    print(f"VERSION={VERSION}  author={A} <{E}>")
    report: list[str] = []
    sync_cargo(report)
    sync_python_manifest(report)
    sync_node_manifest(report)
    sync_php_manifest(report)
    sync_dotnet_manifest(report)
    sync_java_manifest(report)
    sync_ruby_manifest(report)
    sync_dart_manifest(report)
    sync_haskell_manifest(report)
    sync_source_versions(report)
    sync_c_header(report)
    sync_schema(report)
    sync_docs(report)
    print(f"done ({len(set(report))} files updated)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        print(f"VERSION={VERSION}\nAuthor={AE}\nLicense={L}\n")
        for t in TARGETS:
            print(f"  - {t}")
        return 0
    return apply()


if __name__ == "__main__":
    sys.exit(main())
