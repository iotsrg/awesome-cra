# Roadmap - CRA Offensive Testing Project

Status: draft. Direction pending final go/no-go.

## 1. Why this exists

An exhaustive compliance-side reference already exists ([awesome-cra-compliance](https://github.com/cra-compliance-lab/awesome-cra-compliance)). This project does not compete with it. It builds the **offensive counterpart** that repo cannot: how to actually **test a device against CRA essential requirements and prove the result** with reproducible evidence.

One-line positioning:

> The offensive-security guide to CRA testing, plus the tooling that produces the evidence.

## 2. Differentiator (what makes this not a duplicate)

| Existing compliance list | This project |
|---|---|
| Points at standards, guidance, tools | Ships methodology + working tools |
| Compliance/assessor seat | Attacker/researcher seat |
| "Component has a known CVE" | "Vulnerable path is reachable and triggerable" |
| Documents obligations | Proves pass/fail with captured evidence |

Every deliverable must survive the two-phase test: hypothesis, then deterministic reproducible proof. No checklist output without evidence.

## 3. Scope

**In scope**
- Annex I essential requirements, mapped to concrete offensive test procedures.
- Firmware, embedded, IoT, BLE targets.
- Evidence formats a manufacturer or CSIRT can reproduce (Art. 14 aligned).

**Out of scope**
- Legal/compliance advice, certification paperwork, notified-body process.
- Weaponized exploitation (stop at proof-of-control per the RCE boundary).
- Duplicating the existing compliance link list.

## 4. Workstreams

### A. CRA Offensive Testing Playbook (methodology)
For each Annex I requirement, one structured entry:
`requirement -> attacker position -> test procedure -> tool/command -> evidence that constitutes pass/fail`.

The core artifact. Cannot be "beaten on breadth" because it is procedure, not links.

### B. cra-reach (tool)
Firmware image + SBOM -> for each known-CVE component, determine whether the vulnerable symbol/function is present and reachable in the shipped binary. Output: `unreachable` vs `reachable candidate`. Turns "known CVE" into "known exploitable", which is what CRA legally means.

### C. Ground-truth firmware corpus (benchmark)
Small set of deliberately-vulnerable firmware images, each labelled with the CRA requirement it violates and the expected evidence. Validates scanners and doubles as a PoC library.

## 5. Phases and milestones

### Phase 0 - Reset and decide (week 1)
- [ ] Confirm go/no-go on the pivot.
- [ ] Retire or repurpose the awesome-list content (keep the useful CRA-context sections as Playbook front-matter).
- [ ] Lock repo name and structure.
- Deliverable: this ROADMAP accepted, repo skeleton for the new direction.

### Phase 1 - Playbook skeleton (weeks 1-2)
- [ ] Enumerate every Annex I Part I and Part II requirement as a row.
- [ ] Define the entry template (requirement / attacker position / procedure / tooling / evidence / pass-fail).
- [ ] Populate 3 fully-worked reference entries end to end:
  - Secure update (unsigned/downgrade firmware flash).
  - Confidentiality (cleartext transport or plaintext secret on flash).
  - No known exploitable vulnerabilities (SBOM + reachability).
- Deliverable: `playbook/` with template + 3 complete entries, each with captured evidence.

### Phase 2 - cra-reach MVP (weeks 2-4)
- [ ] Parse SBOM (reuse existing CycloneDX/SPDX parser).
- [ ] Extract shipped binaries from a firmware root; resolve symbols/imports.
- [ ] For each CVE component, map to affected symbol(s) where known; check presence.
- [ ] Reachability pass from entry points (call graph, dead-code awareness). Start with a coarse "symbol present and imported" heuristic, then refine.
- [ ] Output JSON + SARIF: `unreachable` vs `reachable-candidate`, with evidence.
- Deliverable: `cra-reach` runnable on the corpus, downgrades at least one Grype false positive with proof.

### Phase 3 - Corpus v1 (weeks 3-5, parallel with Phase 2)
- [ ] 3-5 firmware images (or minimal rootfs), each with one labelled CRA violation.
- [ ] Ground-truth file: requirement, location, expected evidence, expected tool verdict.
- Deliverable: `corpus/` usable to validate cra-reach and Playbook procedures.

### Phase 4 - Integration and hardening (weeks 5-6)
- [ ] Playbook entries reference corpus images and cra-reach output as their worked evidence.
- [ ] CI: run cra-reach against corpus, assert expected verdicts.
- [ ] Contribution guide for adding new requirement entries and corpus samples.
- Deliverable: coherent v0.1 - Playbook + tool + corpus that cross-reference.

### Phase 5 - Extend coverage (ongoing)
- [ ] Fill remaining Annex I entries.
- [ ] Add BLE/GATT and hardware-debug (JTAG/UART) procedures.
- [ ] Optional: contribute the firmware/offensive resources back to the compliance list.

## 6. Success criteria

- A researcher can pick any Annex I requirement and follow a procedure that yields reproducible pass/fail evidence.
- cra-reach demonstrably reduces false positives versus a plain CVE scanner, with proof on the corpus.
- Every Playbook entry has captured evidence, not description.
- Zero duplicated value versus the existing compliance list.

## 7. Open decisions

- Repo name (e.g. `cra-offensive`, `cra-red`, `cra-proving-ground`).
- Corpus hosting: build-from-source recipes vs checked-in minimal images (size, licensing).
- cra-reach language: Python for parsing/orchestration; decide on the binary-analysis backend (angr, radare2/r2pipe, Ghidra headless, or lief for a lighter symbol-level first pass).
- Whether to keep the existing awesome-list files or delete them.

## 8. Non-goals

- Not a compliance certification tool.
- Not another link list.
- Not a weaponization framework.
