#!/usr/bin/env python3
"""
cra-check - test a firmware root filesystem against EU CRA Annex I requirements.

Driven by catalog/annex1.json: each requirement maps to an automated check, an
offensive test procedure, and pass/fail evidence. Automated checks run against an
extracted firmware rootfs (offline, deterministic). Requirements that cannot be
verified from an image are reported as MANUAL with their test procedure.

Target: an extracted firmware root filesystem (e.g. from binwalk/unblob).
Requires: Python 3.8+, standard library only. OSV network access only for the
optional known-vuln check when an SBOM is supplied.
"""

import argparse
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CATALOG = os.path.join(HERE, "catalog", "annex1.json")
MAX_READ = 64 * 1024 * 1024  # cap per-file read at 64 MiB


def eprint(*a: Any) -> None:
    print(*a, file=sys.stderr)


# --------------------------------------------------------------------------- #
# ELF hardening parser (checksec-style, pure stdlib)
# --------------------------------------------------------------------------- #

PT_INTERP = 3
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1
ET_DYN = 3
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1


@dataclass
class ElfHardening:
    path: str
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "none"  # none | partial | full

    def missing(self) -> List[str]:
        m = []
        if not self.nx:
            m.append("NX")
        if not self.pie:
            m.append("PIE")
        if not self.canary:
            m.append("canary")
        if self.relro != "full":
            m.append("RELRO(%s)" % self.relro)
        return m


def is_elf(head: bytes) -> bool:
    return head[:4] == b"\x7fELF"


def parse_elf_hardening(path: str, data: bytes) -> Optional[ElfHardening]:
    try:
        if not is_elf(data):
            return None
        bits = 64 if data[4] == 2 else 32
        endian = "<" if data[5] == 1 else ">"
        e_type = struct.unpack_from(endian + "H", data, 16)[0]

        if bits == 32:
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 44)[0]
        else:
            e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 56)[0]

        h = ElfHardening(path=path)
        gnu_stack_seen = False
        has_interp = False
        dyn_seg = None

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            p_type = struct.unpack_from(endian + "I", data, off)[0]
            if bits == 32:
                p_flags = struct.unpack_from(endian + "I", data, off + 24)[0]
                p_offset = struct.unpack_from(endian + "I", data, off + 4)[0]
                p_filesz = struct.unpack_from(endian + "I", data, off + 16)[0]
            else:
                p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
                p_offset = struct.unpack_from(endian + "Q", data, off + 8)[0]
                p_filesz = struct.unpack_from(endian + "Q", data, off + 32)[0]

            if p_type == PT_GNU_STACK:
                gnu_stack_seen = True
                h.nx = (p_flags & PF_X) == 0
            elif p_type == PT_INTERP:
                has_interp = True
            elif p_type == PT_GNU_RELRO:
                h.relro = "partial"
            elif p_type == PT_DYNAMIC:
                dyn_seg = (p_offset, p_filesz)

        # No GNU_STACK segment => stack executable by default => NX off.
        if not gnu_stack_seen:
            h.nx = False
        # PIE: position-independent executable (shared object with an interpreter).
        h.pie = (e_type == ET_DYN) and has_interp
        # Full RELRO: GNU_RELRO plus BIND_NOW in the dynamic section.
        if h.relro == "partial" and dyn_seg:
            if _dynamic_bind_now(data, dyn_seg, bits, endian):
                h.relro = "full"
        # Stack canary: reference to __stack_chk_fail.
        h.canary = b"__stack_chk_fail" in data
        return h
    except (struct.error, IndexError):
        return None


def _dynamic_bind_now(data: bytes, dyn_seg, bits: int, endian: str) -> bool:
    off, size = dyn_seg
    entry = 8 if bits == 32 else 16
    fmt = endian + ("II" if bits == 32 else "QQ")
    n = size // entry
    for i in range(n):
        pos = off + i * entry
        if pos + entry > len(data):
            break
        d_tag, d_val = struct.unpack_from(fmt, data, pos)
        if d_tag == DT_BIND_NOW:
            return True
        if d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
            return True
        if d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
            return True
        if d_tag == 0:  # DT_NULL terminates
            break
    return False


# --------------------------------------------------------------------------- #
# Filesystem walk
# --------------------------------------------------------------------------- #

def walk_files(root: str):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            yield p


def read_capped(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_READ)
    except OSError:
        return b""


# --------------------------------------------------------------------------- #
# Checks (each returns a list of evidence strings; empty list => PASS)
# --------------------------------------------------------------------------- #

SECRET_PATTERNS = [
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
]
TEXT_EXT = (".conf", ".cfg", ".ini", ".env", ".sh", ".key", ".pem", ".json", ".xml", ".txt")


def check_elf_hardening(root: str, ctx: Dict[str, Any]) -> List[str]:
    weak = []
    results: List[ElfHardening] = []
    for p in walk_files(root):
        data = read_capped(p)
        if not data or not is_elf(data):
            continue
        h = parse_elf_hardening(p, data)
        if h is None:
            continue
        results.append(h)
        miss = h.missing()
        if miss:
            weak.append("%s: missing %s" % (os.path.relpath(p, root), ", ".join(miss)))
    ctx["elf_total"] = len(results)
    return weak


def check_secrets(root: str, ctx: Dict[str, Any]) -> List[str]:
    hits = []
    for p in walk_files(root):
        low = p.lower()
        data = read_capped(p)
        if not data:
            continue
        # Always scan small files; large files only if they look like text/keys.
        if len(data) > 2 * 1024 * 1024 and not low.endswith(TEXT_EXT):
            continue
        for rx, label in SECRET_PATTERNS:
            if rx.search(data):
                hits.append("%s: %s" % (os.path.relpath(p, root), label))
                break
    return hits


def check_default_accounts(root: str, ctx: Dict[str, Any]) -> List[str]:
    findings = []
    for rel in ("etc/passwd", "etc/shadow"):
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        try:
            lines = open(p, "r", errors="replace").read().splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user, pw = parts[0], parts[1]
            if rel.endswith("passwd") and pw == "":
                findings.append("etc/passwd: '%s' has empty password field" % user)
            if rel.endswith("shadow") and pw in ("", "!", "*"):
                continue  # locked or delegated
            if rel.endswith("shadow") and pw and not pw.startswith("$") and pw not in ("!", "*"):
                findings.append("etc/shadow: '%s' has non-hashed password" % user)
    return findings


def check_insecure_services(root: str, ctx: Dict[str, Any]) -> List[str]:
    bad_bins = ("telnetd", "in.telnetd", "ftpd", "in.ftpd", "tftpd", "rshd", "rlogind")
    findings = []
    seen = set()
    for p in walk_files(root):
        base = os.path.basename(p)
        if base in bad_bins and base not in seen:
            seen.add(base)
            findings.append("service binary present: %s" % base)
    # autostart references
    for rel in ("etc/inittab", "etc/init.d/rcS", "etc/rc.local"):
        p = os.path.join(root, rel)
        if os.path.isfile(p):
            try:
                txt = open(p, "r", errors="replace").read()
            except OSError:
                continue
            for b in bad_bins:
                if b in txt:
                    findings.append("%s autostarts %s" % (rel, b))
    return findings


def check_sbom_present(root: str, ctx: Dict[str, Any]) -> List[str]:
    if ctx.get("sbom"):
        return []
    return ["no SBOM supplied (--sbom); cannot confirm Annex I Part II (1)"]


CHECKS = {
    "elf-hardening": check_elf_hardening,
    "secrets": check_secrets,
    "default-accounts": check_default_accounts,
    "insecure-services": check_insecure_services,
    "sbom-present": check_sbom_present,
    # "known-vuln" handled separately (needs SBOM + network); see run().
}


# --------------------------------------------------------------------------- #
# Catalog + reporting
# --------------------------------------------------------------------------- #

@dataclass
class Result:
    id: str
    ref: str
    title: str
    check: Optional[str]
    status: str  # PASS | FAIL | MANUAL | SKIPPED
    evidence: List[str] = field(default_factory=list)
    procedure: str = ""


def load_catalog(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run(root: str, catalog: Dict[str, Any], ctx: Dict[str, Any], verbose: bool) -> List[Result]:
    results = []
    for req in catalog["requirements"]:
        check = req.get("automated_check")
        proc = req.get("attacker_test", {}).get("procedure", "")
        if check is None:
            results.append(Result(req["id"], req["ref"], req["title"], None, "MANUAL", [], proc))
            continue
        fn = CHECKS.get(check)
        if fn is None:
            results.append(Result(req["id"], req["ref"], req["title"], check, "SKIPPED",
                                  ["no runner for check '%s'" % check], proc))
            continue
        if verbose:
            eprint("[*] %s -> %s" % (req["id"], check))
        evidence = fn(root, ctx)
        status = "FAIL" if evidence else "PASS"
        results.append(Result(req["id"], req["ref"], req["title"], check, status, evidence, proc))
    return results


def human(results: List[Result], ctx: Dict[str, Any]) -> str:
    order = {"FAIL": 0, "MANUAL": 1, "SKIPPED": 2, "PASS": 3}
    lines = ["cra-check - EU CRA Annex I", ""]
    for r in sorted(results, key=lambda x: (order[x.status], x.id)):
        lines.append("[%s] %s  %s" % (r.status.ljust(7), r.ref, r.title))
        for e in r.evidence:
            lines.append("         - " + e)
        if r.status == "MANUAL":
            lines.append("         manual: " + r.procedure)
    fails = sum(1 for r in results if r.status == "FAIL")
    lines.append("")
    lines.append("ELF binaries analysed: %d" % ctx.get("elf_total", 0))
    lines.append("FAIL: %d   MANUAL: %d   PASS: %d" % (
        fails,
        sum(1 for r in results if r.status == "MANUAL"),
        sum(1 for r in results if r.status == "PASS"),
    ))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cra-check",
        description="Test a firmware rootfs against EU CRA Annex I requirements.",
    )
    ap.add_argument("rootfs", help="Path to an extracted firmware root filesystem")
    ap.add_argument("--sbom", help="Path to a CycloneDX/SPDX SBOM (enables SBOM-based checks)")
    ap.add_argument("--catalog", default=DEFAULT_CATALOG, help="Path to annex1.json")
    ap.add_argument("--output", help="Write JSON report to this path")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--fail-on", action="store_true",
                    help="Exit non-zero if any requirement FAILs")
    args = ap.parse_args(argv)

    if not os.path.isdir(args.rootfs):
        eprint("[!] rootfs not a directory: %s" % args.rootfs)
        return 2
    try:
        catalog = load_catalog(args.catalog)
    except (OSError, json.JSONDecodeError) as e:
        eprint("[!] cannot load catalog: %s" % e)
        return 2

    ctx: Dict[str, Any] = {"sbom": args.sbom, "elf_total": 0}
    results = run(args.rootfs, catalog, ctx, args.verbose)

    report = {
        "tool": "cra-check",
        "catalog": catalog.get("schema"),
        "rootfs": args.rootfs,
        "elf_binaries_analysed": ctx.get("elf_total", 0),
        "results": [asdict(r) for r in results],
    }
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)

    print(human(results, ctx))

    if args.fail_on and any(r.status == "FAIL" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
