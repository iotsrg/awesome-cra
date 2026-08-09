#!/usr/bin/env python3
"""
cra-sbom-gate - CRA Annex I Part I (1) gate for SBOMs.

Takes a CycloneDX or SPDX SBOM (JSON), cross-checks every component against the
OSV.dev vulnerability database, and flags known-vulnerable components as a
violation of CRA Annex I, Part I, requirement (1):

    "products with digital elements shall be made available on the market
     without known exploitable vulnerabilities."

Deterministic and reproducible: same SBOM + same OSV state => same result.

Target: any product shipping a CycloneDX or SPDX JSON SBOM.
Requires: Python 3.8+, network access to https://api.osv.dev (unless --offline).
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
USER_AGENT = "cra-sbom-gate/0.1"


@dataclass
class Component:
    name: str
    version: str
    purl: Optional[str] = None


@dataclass
class Finding:
    component: str
    version: str
    purl: Optional[str]
    vuln_ids: List[str] = field(default_factory=list)
    summaries: Dict[str, str] = field(default_factory=dict)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


# --------------------------------------------------------------------------- #
# SBOM parsing
# --------------------------------------------------------------------------- #

def load_sbom(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def detect_format(doc: Dict[str, Any]) -> str:
    if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        return "cyclonedx"
    if doc.get("spdxVersion") or "packages" in doc:
        return "spdx"
    raise ValueError("Unrecognized SBOM format: expected CycloneDX or SPDX JSON")


def parse_cyclonedx(doc: Dict[str, Any]) -> List[Component]:
    out: List[Component] = []
    for comp in doc.get("components", []):
        name = comp.get("name")
        version = comp.get("version")
        if not name or not version:
            continue
        out.append(Component(name=name, version=str(version), purl=comp.get("purl")))
    return out


def parse_spdx(doc: Dict[str, Any]) -> List[Component]:
    out: List[Component] = []
    for pkg in doc.get("packages", []):
        name = pkg.get("name")
        version = pkg.get("versionInfo")
        if not name or not version:
            continue
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        out.append(Component(name=name, version=str(version), purl=purl))
    return out


def parse_components(doc: Dict[str, Any]) -> List[Component]:
    fmt = detect_format(doc)
    comps = parse_cyclonedx(doc) if fmt == "cyclonedx" else parse_spdx(doc)
    # de-duplicate on (name, version, purl)
    seen = set()
    unique: List[Component] = []
    for c in comps:
        key = (c.name, c.version, c.purl)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


# --------------------------------------------------------------------------- #
# OSV querying
# --------------------------------------------------------------------------- #

def _osv_query_obj(comp: Component) -> Optional[Dict[str, Any]]:
    if not comp.purl:
        return None  # without a purl OSV cannot resolve the ecosystem reliably
    # OSV rejects a separate `version` field when the purl already carries one
    # (pkg:type/name@version). Send version separately only if the purl omits it.
    if "@" in comp.purl.split("/", 1)[-1]:
        return {"package": {"purl": comp.purl}}
    return {"package": {"purl": comp.purl}, "version": comp.version}


def _post_json(url: str, payload: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url: str, timeout: int) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_osv(
    components: List[Component], timeout: int, verbose: bool
) -> List[Finding]:
    queryable = [c for c in components if c.purl]
    skipped = len(components) - len(queryable)
    if skipped and verbose:
        eprint(f"[i] {skipped} component(s) skipped (no purl, ecosystem unknown)")
    if not queryable:
        return []

    findings: List[Finding] = []
    # OSV batch endpoint accepts many queries; chunk to stay well within limits.
    chunk = 100
    for i in range(0, len(queryable), chunk):
        batch = queryable[i : i + chunk]
        payload = {"queries": [_osv_query_obj(c) for c in batch]}
        try:
            result = _post_json(OSV_BATCH_URL, payload, timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            eprint(f"[!] OSV query failed for batch {i // chunk}: {e}")
            raise SystemExit(2)

        for comp, res in zip(batch, result.get("results", [])):
            vulns = res.get("vulns") or []
            if not vulns:
                continue
            ids = [v.get("id") for v in vulns if v.get("id")]
            findings.append(
                Finding(component=comp.name, version=comp.version, purl=comp.purl, vuln_ids=ids)
            )
            if verbose:
                eprint(f"[+] {comp.name}@{comp.version}: {', '.join(ids)}")
        time.sleep(0.2)  # be polite to the public API
    return findings


def enrich_summaries(findings: List[Finding], timeout: int, verbose: bool) -> None:
    for f in findings:
        for vid in f.vuln_ids:
            try:
                detail = _get_json(OSV_VULN_URL + vid, timeout)
                f.summaries[vid] = detail.get("summary") or detail.get("details", "")[:200]
            except Exception as e:  # noqa: BLE001 - enrichment is best-effort
                if verbose:
                    eprint(f"[i] could not enrich {vid}: {e}")
            time.sleep(0.1)


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def build_report(
    sbom_path: str, total: int, findings: List[Finding]
) -> Dict[str, Any]:
    verdict = "FAIL" if findings else "PASS"
    return {
        "tool": "cra-sbom-gate",
        "cra_requirement": "Annex I, Part I, (1) - no known exploitable vulnerabilities",
        "sbom": sbom_path,
        "components_checked": total,
        "components_vulnerable": len(findings),
        "verdict": verdict,
        "findings": [asdict(f) for f in findings],
    }


def human_summary(report: Dict[str, Any]) -> str:
    lines = []
    lines.append("cra-sbom-gate - CRA Annex I Part I (1)")
    lines.append(f"SBOM:              {report['sbom']}")
    lines.append(f"Components checked: {report['components_checked']}")
    lines.append(f"Vulnerable:         {report['components_vulnerable']}")
    lines.append(f"Verdict:            {report['verdict']}")
    if report["findings"]:
        lines.append("")
        lines.append("Known-vulnerable components (Annex I Part I (1) violation):")
        for f in report["findings"]:
            lines.append(f"  - {f['component']}@{f['version']}")
            for vid in f["vuln_ids"]:
                summ = f["summaries"].get(vid, "")
                suffix = f" - {summ}" if summ else ""
                lines.append(f"      {vid}{suffix}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="cra-sbom-gate",
        description="Flag known-vulnerable SBOM components as a CRA Annex I Part I (1) violation.",
    )
    ap.add_argument("sbom", help="Path to a CycloneDX or SPDX SBOM in JSON")
    ap.add_argument("--output", help="Write JSON report to this path")
    ap.add_argument("--verbose", action="store_true", help="Verbose progress on stderr")
    ap.add_argument("--enrich", action="store_true", help="Fetch vuln summaries from OSV (slower)")
    ap.add_argument("--offline", action="store_true", help="Parse and count only, no OSV queries")
    ap.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds")
    ap.add_argument(
        "--fail-on-vuln",
        action="store_true",
        help="Exit non-zero when vulnerable components are found (for CI gating)",
    )
    args = ap.parse_args(argv)

    try:
        doc = load_sbom(args.sbom)
    except (OSError, json.JSONDecodeError) as e:
        eprint(f"[!] cannot read SBOM: {e}")
        return 2

    try:
        components = parse_components(doc)
    except ValueError as e:
        eprint(f"[!] {e}")
        return 2

    if args.verbose:
        eprint(f"[i] parsed {len(components)} component(s)")

    if args.offline:
        findings: List[Finding] = []
    else:
        findings = query_osv(components, args.timeout, args.verbose)
        if args.enrich and findings:
            enrich_summaries(findings, args.timeout, args.verbose)

    report = build_report(args.sbom, len(components), findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        if args.verbose:
            eprint(f"[i] JSON report written to {args.output}")

    print(human_summary(report))

    if args.fail_on_vuln and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
