# cra-check

Test a firmware root filesystem against **EU CRA Annex I** requirements.

Each requirement lives in [`catalog/annex1.json`](catalog/annex1.json) with three things attached: an automated check, an offensive test procedure, and the evidence that decides pass/fail. `cra-check` runs the automated checks against an extracted rootfs and prints a per-requirement verdict. Requirements that cannot be judged from an image (secure update, CVD contact) are reported as `MANUAL` with their procedure.

Stdlib only. Offline and deterministic. No install.

## Why it is different

Compliance repos are prose and links. Scanners (checksec, Grype) find issues but do not know what a CRA requirement is. `cra-check` maps concrete, runnable checks to specific Annex I requirement IDs and produces reproducible evidence.

## Usage

```bash
# extract a firmware image first, e.g. with binwalk/unblob, then:
python3 cra_check.py /path/to/rootfs --verbose --fail-on
```

Add SBOM-based checks:

```bash
python3 cra_check.py /path/to/rootfs --sbom sbom.json --output report.json
```

## Checks (v0.1)

| Check | CRA requirement | What it does |
|---|---|---|
| `elf-hardening` | Part I (2)(k) | Parses every ELF for NX, PIE, stack canary, RELRO |
| `secrets` | Part I (2)(e) | Finds private keys and hardcoded tokens |
| `default-accounts` | Part I (2)(b) | Empty/non-hashed passwords in `/etc/passwd`, `/etc/shadow` |
| `insecure-services` | Part I (2)(j) | telnetd/ftpd/rshd present or autostarted |
| `sbom-present` | Part II (1) | Confirms a machine-readable SBOM was supplied |
| `known-vuln` | Part I (1) | SBOM components vs OSV (see `cra-sbom-gate`) |
| _manual_ | Part I (2)(c), Part II (5) | Secure update, CVD contact - procedure only |

The `elf-hardening` parser is a pure-stdlib checksec: NX from `PT_GNU_STACK`, PIE from `ET_DYN`+`PT_INTERP`, canary from `__stack_chk_fail`, full RELRO from `PT_GNU_RELRO`+`BIND_NOW`. Verified against `readelf`.

## Output

- Human table sorted FAIL first.
- JSON report with `--output` (per-requirement id, ref, status, evidence).
- Exit code 1 with `--fail-on` when any requirement FAILs (CI gate).

## Status values

- `PASS` - check ran, no evidence of violation.
- `FAIL` - check ran, evidence attached.
- `MANUAL` - requires a device/manual procedure; not judgeable from an image.
- `SKIPPED` - no runner available (e.g. `known-vuln` needs an SBOM).

## Limitations

- Heuristic checks flag candidates; confirm exploitability before reporting a finding.
- `elf-hardening` reports per-binary facts; whether a missing mitigation is exploitable depends on the binary.
- `known-vuln` is not wired into this engine yet; use `cra-sbom-gate` for now.
