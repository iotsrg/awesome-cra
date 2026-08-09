# cra-sbom-gate

A CRA **Annex I, Part I, requirement (1)** gate for SBOMs.

> "products with digital elements shall be made available on the market without known exploitable vulnerabilities."

The tool takes a CycloneDX or SPDX SBOM (JSON), cross-checks every component with a package URL (purl) against the [OSV.dev](https://osv.dev/) database, and reports any component with a known vulnerability as a violation. The result is deterministic and reproducible: the same SBOM against the same OSV state produces the same verdict.

## Why this and not a checklist

Most "CRA compliance" output is a checklist. This produces **evidence**: a named component, a version, and the exact vulnerability IDs that make shipping it a breach of Annex I Part I (1). A vendor can reproduce it from the SBOM alone.

## Requirements

- Python 3.8+
- Network access to `https://api.osv.dev` (or use `--offline` to parse/count only)
- No third-party dependencies (standard library only)

## Usage

Generate an SBOM (example, using Syft):

```bash
syft dir:/path/to/firmware/rootfs -o cyclonedx-json > sbom.json
```

Run the gate:

```bash
python3 cra_sbom_gate.py sbom.json --verbose
```

Write a machine-readable report and fail CI on any hit:

```bash
python3 cra_sbom_gate.py sbom.json --output report.json --fail-on-vuln
```

Fetch vulnerability summaries (slower, extra OSV calls):

```bash
python3 cra_sbom_gate.py sbom.json --enrich
```

## Options

| Flag | Effect |
|---|---|
| `--output <path>` | Write the JSON report |
| `--verbose` | Progress on stderr |
| `--enrich` | Pull vuln summaries from OSV |
| `--offline` | Parse and count only, no network |
| `--timeout <s>` | Per-request timeout (default 30) |
| `--fail-on-vuln` | Exit code 1 when vulnerable components found |

## Exit codes

- `0` - completed, no vulnerable components (or `--fail-on-vuln` not set)
- `1` - vulnerable components found and `--fail-on-vuln` set
- `2` - input or query error

## Limitations

- Components **without a purl** are skipped (OSV cannot resolve the ecosystem reliably). They are counted and reported as skipped under `--verbose`. This is stated honestly rather than guessed.
- "Known vulnerability" per OSV is not identical to "known **exploitable** vulnerability" in the CRA sense. Treat findings as candidates that require triage (a vuln may be unreachable in the shipped configuration). The tool flags; a human confirms exploitability.
- OSV coverage varies by ecosystem. Absence of a finding is not proof of absence of vulnerabilities.

## Sample output

Running against the bundled `examples/sample-cyclonedx.json` with `--enrich`:

```
cra-sbom-gate - CRA Annex I Part I (1)
SBOM:              examples/sample-cyclonedx.json
Components checked: 3
Vulnerable:         1
Verdict:            FAIL

Known-vulnerable components (Annex I Part I (1) violation):
  - requests@2.19.0
      GHSA-x84v-xcm2-53pg - Insufficiently Protected Credentials in Requests
      PYSEC-2018-28 - The Requests package before 2.20.0 sends an HTTP Authorization header ...
      ...
```

Note: the `libexpat` and `zlib` entries in the sample use `pkg:generic` purls, which
OSV does not index, so they are queried but return no matches. Real firmware SBOMs
from Syft typically emit ecosystem-specific purls (`pkg:deb`, `pkg:apk`, `pkg:pypi`,
`pkg:npm`) that OSV resolves.
