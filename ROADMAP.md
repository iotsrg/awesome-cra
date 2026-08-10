# Roadmap - CRA Offensive Testing

Status: draft.

## Positioning

Compliance-side references already exist (see [awesome-cra-compliance](https://github.com/cra-compliance-lab/awesome-cra-compliance)). This project is the offensive counterpart: **test a device against CRA Annex I and prove pass/fail with reproducible evidence.**

Rule: hypothesis, then deterministic proof. No verdict without evidence.

## Deliverables

- **Playbook** - each Annex I requirement mapped to: attacker position -> test procedure -> tool/command -> pass/fail evidence.
- **cra-reach** - firmware + SBOM -> is the CVE'd code reachable in the shipped binary. Turns "known CVE" into "known exploitable".
- **Corpus** - deliberately-vulnerable firmware, each labelled with the requirement it breaks and the expected evidence.

## Phases

| Phase | Output |
|---|---|
| 0. Reset | Pivot confirmed, repo skeleton, list files repurposed |
| 1. Playbook skeleton | Entry template + 3 worked entries (secure update, confidentiality, known-vuln) with captured evidence |
| 2. cra-reach MVP | SBOM -> symbol presence -> reachability -> JSON/SARIF; downgrades one scanner false positive with proof |
| 3. Corpus v1 | 3-5 labelled images + ground-truth file |
| 4. Integration | Playbook cites corpus + cra-reach output; CI asserts expected verdicts |
| 5. Extend | Remaining Annex I entries; BLE/GATT and JTAG/UART procedures |

## Success criteria

- Any Annex I requirement has a procedure yielding reproducible pass/fail evidence.
- cra-reach measurably cuts false positives vs a plain CVE scanner, proven on the corpus.
- Zero duplicated value vs the compliance list.

## Open decisions

1. Repo name (`cra-offensive`, `cra-red`, `cra-proving-ground`).
2. cra-reach backend: `lief` (symbol-level, fast MVP) first, call-graph (`angr`/`radare2`) later.
3. Keep or delete the awesome-list files.
4. Corpus: build-from-source recipes vs checked-in minimal images.

## Non-goals

Not compliance certification. Not another link list. Not weaponization (stop at proof-of-control).
