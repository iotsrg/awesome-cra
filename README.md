# Awesome CRA [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A curated list of resources for the **EU Cyber Resilience Act** (Regulation (EU) 2024/2847), written from a **product-security and offensive-security** angle - not just compliance paperwork.

The CRA sets mandatory cybersecurity requirements for **products with digital elements** (hardware, software, and the cloud backends they depend on) placed on the EU market. This list maps the regulation to concrete engineering: firmware signing, SBOMs, coordinated disclosure, and the tooling that produces real evidence of (non-)compliance.

**Scope of this list:** things an engineer, security researcher, or product team can actually use. Legal-only commentary is kept to the essential primary sources.

## Contents

- [Key Dates](#key-dates)
- [Primary Sources](#primary-sources)
- [Official Guidance](#official-guidance)
- [Standards](#standards)
- [Scope and Classification](#scope-and-classification)
- [Annex I Mapped to Engineering](#annex-i-mapped-to-engineering)
- [Conformity Assessment Routes](#conformity-assessment-routes)
- [Technical Documentation (Annex VII)](#technical-documentation-annex-vii)
- [SBOM Tooling](#sbom-tooling)
- [Vulnerability Data and Known-CVE Checking](#vulnerability-data-and-known-cve-checking)
- [Coordinated Vulnerability Disclosure](#coordinated-vulnerability-disclosure)
- [Firmware Update Security](#firmware-update-security)
- [Reporting Obligations](#reporting-obligations)
- [Open Source and the CRA](#open-source-and-the-cra)
- [Related Regulations](#related-regulations)
- [Related Lists](#related-lists)
- [Tools in this Repo](#tools-in-this-repo)
- [Contributing](#contributing)

## Key Dates

| Date | Milestone |
|---|---|
| 10 Dec 2024 | Regulation entered into force |
| 27 Jul 2026 | Commission published practical implementation guidance |
| 11 Jun 2026 | Conformity assessment bodies notification provisions apply |
| 11 Sep 2026 | Reporting obligations (Article 14) apply - actively exploited vulns and severe incidents |
| 11 Dec 2027 | Full application - all essential requirements, CE marking, conformity assessment |

## Primary Sources

- [Regulation (EU) 2024/2847 - full text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) - the authoritative legal text.
- [Cyber Resilience Act - European Commission policy page](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) - official overview, FAQ, and updates.

## Official Guidance

- [Commission practical implementation guidance](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) - published 27 July 2026 to help manufacturers, developers, and businesses meet their CRA obligations.
- [CRA Summary](https://digital-strategy.ec.europa.eu/en/policies/cra-summary) - official plain-language summary of scope and obligations.
- [European Commission - CRA FAQ](https://digital-strategy.ec.europa.eu/en/faqs/cyber-resilience-act-faqs) - clarifications on scope, actors, and obligations.
- [ENISA](https://www.enisa.europa.eu/) - EU agency operating the single reporting platform and issuing technical guidance.

## Standards

The Commission issued **Standardisation Request M/606**, accepted by CEN, CENELEC, and ETSI, covering **41 harmonised standards** targeted for delivery around Q3 2026. Applying a harmonised standard (once cited in the Official Journal) gives a presumption of conformity with the mapped Annex I requirements.

**Status (as of mid-2026):** no CRA harmonised standard is yet ratified as an EN or cited in the Official Journal. Several EN 40000 drafts have passed public enquiry; the first citations are expected in the second half of 2026. Until then, conformity must be demonstrated against Annex I directly. Verify the current state before relying on any specific standard.

- [CEN-CENELEC JTC 13](https://www.cencenelec.eu/areas-of-work/cen-cenelec-topics/cybersecurity-and-data-protection/) - the technical committee developing the horizontal **EN 40000 series** (WG9) mapped to CRA Annex I.
- [Standardisation Request accepted (CEN-CENELEC news)](https://www.cencenelec.eu/news-events/news/2025/newsletter/ots-62-cra/) - announcement that CEN, CENELEC, and ETSI accepted M/606.
- [ETSI EN 303 645](https://www.etsi.org/technologies/consumer-iot-security) - consumer IoT baseline security; widely used reference that aligns with several Annex I requirements.

## Scope and Classification

The conformity route depends on the product's risk tier:

- **Default** - most consumer IoT and software. Self-assessment (Module A).
- **Important, Class I** (Annex III) - password managers, VPNs, browsers, routers, antivirus, physical/logical access control. Self-assessment allowed only if a harmonized standard is applied.
- **Important, Class II** (Annex III) - hypervisors, firewalls, IDS/IPS, tamper-resistant microcontrollers, industrial routers. Third-party assessment required.
- **Critical** (Annex IV) - HSMs, smart meter gateways, secure elements / smartcards. Third-party plus possible mandatory EU certification (EUCC).

## Annex I Mapped to Engineering

The essential requirements, translated into things you can test and produce evidence for.

**Part I - Product security properties**

| Requirement | Concrete failure mode a researcher can demonstrate |
|---|---|
| No known exploitable vulnerabilities at ship time | Bundled library with an unpatched public CVE (see [cra-sbom-gate](#tools-in-this-repo)) |
| Secure by default configuration | Default/hardcoded credentials, open debug services |
| Confidentiality (encryption in transit/at rest) | Cleartext protocol, interceptable traffic, plaintext secrets on flash |
| Integrity of code and data | Unsigned firmware, no anti-rollback, mutable config |
| Minimize attack surface | Exposed UART/JTAG, unnecessary open ports, debug endpoints |
| Exploit mitigation | Missing ASLR/stack canaries/NX in shipped binaries |
| Secure update mechanism | Firmware update without signature verification or downgrade protection |

**Part II - Vulnerability handling**

| Requirement | What it means in practice |
|---|---|
| Component inventory (SBOM) | Machine-readable SBOM, at least top-level dependencies |
| CVD policy + reporting contact | Reachable security contact, published disclosure policy, `security.txt` |
| Public disclosure of fixed vulns | Security advisories once a patch ships |
| Secure update distribution | Signed updates, integrity verification |

## Conformity Assessment Routes

Which route a manufacturer may use depends on the product tier (see [Scope and Classification](#scope-and-classification)). The modules come from the New Legislative Framework (Decision 768/2008/EC).

| Module | Name | When usable |
|---|---|---|
| **A** | Internal control (self-assessment) | Default products, and Class I products **if** a harmonised standard is fully applied |
| **B + C** | EU-type examination + conformity to type | Class I without a harmonised standard, and Class II; requires a notified body |
| **H** | Full quality assurance | Alternative third-party route for Class I/II |
| European cybersecurity certification | Under the Cybersecurity Act (e.g. EUCC) | Critical products (Annex IV), where mandated |

Self-assessment is only available where explicitly permitted; higher tiers require a **notified body**.

## Technical Documentation (Annex VII)

The manufacturer must compile and keep a technical file. At minimum it contains:

- General product description and intended purpose.
- Design, development, and production information.
- **Cybersecurity risk assessment** the product is designed against.
- The list of harmonised standards or other specifications applied.
- **SBOM** and information on the vulnerability handling process.
- Test reports demonstrating conformity with Annex I.
- The EU Declaration of Conformity.

Retention: for at least **10 years** after the product is placed on the market, or the support period, whichever is longer.

## SBOM Tooling

- [Syft](https://github.com/anchore/syft) - generate SBOMs (CycloneDX, SPDX) from images, filesystems, and firmware roots.
- [CycloneDX](https://cyclonedx.org/) - SBOM standard with a strong security/VEX focus.
- [SPDX](https://spdx.dev/) - ISO-standard SBOM format.
- [Dependency-Track](https://dependencytrack.org/) - continuous SBOM analysis platform.
- [BSI TR-03183-2](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html) - German technical guideline defining concrete SBOM content requirements, widely used as the practical baseline for CRA SBOMs.
- [cra-sbom-cli](https://github.com/cra-compliance-lab/cra-sbom-cli) - validates SBOM format/metadata completeness against CRA expectations and generates PDF reports. Complements [cra-sbom-gate](#tools-in-this-repo): quality validation vs. known-vulnerability gating.

## Vulnerability Data and Known-CVE Checking

- [OSV.dev](https://osv.dev/) - open, precise vulnerability database with a free batch API. Backbone of [cra-sbom-gate](#tools-in-this-repo).
- [OSV-Scanner](https://github.com/google/osv-scanner) - scan SBOMs and lockfiles against OSV.
- [Grype](https://github.com/anchore/grype) - vulnerability scanner for SBOMs and container images.
- [Trivy](https://github.com/aquasecurity/trivy) - broad scanner covering OS packages, dependencies, and IaC.
- [NIST NVD](https://nvd.nist.gov/) - the US National Vulnerability Database, CVE enrichment source.

## Coordinated Vulnerability Disclosure

- [securitytxt.org](https://securitytxt.org/) - RFC 9116 `security.txt`, the reporting contact the CRA effectively mandates.
- [disclose.io](https://disclose.io/) - open-source CVD policy templates and safe-harbor language.
- [FIRST CVD guidelines](https://www.first.org/global/sigs/vulnerability-coordination/multiparty/) - multi-party coordination reference.

## Firmware Update Security

- [TUF - The Update Framework](https://theupdateframework.io/) - secure software update system design.
- [SUIT (RFC 9019)](https://datatracker.ietf.org/doc/rfc9019/) - IETF architecture for IoT firmware updates.
- [MCUboot](https://www.mcuboot.com/) - secure bootloader with signature verification and rollback protection for embedded devices.

## Reporting Obligations

Article 14 requires manufacturers to notify the relevant national CSIRT and ENISA (via a single platform) when they become aware of:

- **Actively exploited vulnerability**: early warning within **24 hours**, notification within **72 hours**, final report within **14 days**.
- **Severe incident**: early warning within **24 hours**, notification within **72 hours**, final report within **1 month**.

The clock is the manufacturer's and starts on awareness - which a researcher's report can create.

Reports go to the **ENISA Single Reporting Platform (SRP)** - one submission, routed simultaneously to the national CSIRT coordinator and ENISA. The 24-hour early warning only needs an indication of active exploitation and the affected Member States; technical detail follows in the 72-hour notification.

**Voluntary reporting (relevant to researchers):** any person - not only manufacturers - may voluntarily notify a vulnerability, cyber threat, incident, or near miss. Voluntary reporting adds no new obligations to the notifier.

- [ENISA Single Reporting Platform (SRP)](https://www.enisa.europa.eu/topics/product-security-and-certification/single-reporting-platform-srp) - official platform page.
- [cyberresilienceact.eu - reporting](https://www.cyberresilienceact.eu/reporting.html) - independent explainer of the Article 14 reporting flow and timelines.

## Open Source and the CRA

- Non-commercial open source developed outside a commercial activity is **out of scope**.
- The CRA introduces the **open-source software steward** (Article 24) - a lighter-touch regime, with no administrative fines, for foundations that systematically support FOSS used in commercial products.
- Contributing a patch or hosting a repo does not make you a manufacturer; monetizing or commercializing does. Commercial vendors remain fully responsible for the open-source components they ship.

- [OpenSSF - Cyber Resilience Act resources](https://openssf.org/category/policy/cra/) - where the open-source community works through the steward role and CRA tooling in practice.

## Related Regulations

- [NIS2 Directive (2022/2555)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) - covers operators of essential/important services; complements CRA which covers the products.
- [RED Delegated Regulation 2022/30](https://eur-lex.europa.eu/eli/reg_del/2022/30/oj) - cybersecurity requirements for radio equipment; overlaps CRA for wireless devices.
- [Cybersecurity Act (2019/881)](https://eur-lex.europa.eu/eli/reg/2019/881/oj) - provides the certification schemes CRA relies on for critical products.

## Related Lists

Other curated CRA collections. This list differs by taking a **product-security and offensive-security** angle (Annex I mapped to failure modes, evidence-producing tooling) rather than a compliance-officer angle.

- [cra-compliance-lab/awesome-cra-compliance](https://github.com/cra-compliance-lab/awesome-cra-compliance) - the most comprehensive compliance-side reference: regulation, harmonised standards, EUCC, SBOM tooling, webinar decks, cluster projects. Start here for compliance.
- [zealience/Cyber-Resilience-Act](https://github.com/zealience/Cyber-Resilience-Act) - CRA reading list and Article 14 explainers with templates.

## Tools in this Repo

- [**cra-check**](tools/cra-check) - tests an extracted firmware root filesystem against **CRA Annex I** requirements, driven by a machine-readable catalog ([annex1.json](tools/cra-check/catalog/annex1.json)) that maps each requirement to an automated check, an offensive test procedure, and pass/fail evidence. Includes a stdlib `checksec` (NX/PIE/canary/RELRO), secrets, default-account, and insecure-service checks. Offline, deterministic, CI-gateable. This is the project's core artifact.
- [**cra-sbom-gate**](tools/cra-sbom-gate) - a **known-vulnerability gate**, not a format validator. Takes a CycloneDX or SPDX SBOM, cross-checks every component against the OSV database, and flags known-vulnerable components as a violation of **Annex I Part I (1)** ("no known exploitable vulnerabilities at the time of placing on the market"). Deterministic, reproducible, evidence-producing. Pairs with format validators like [cra-sbom-cli](https://github.com/cra-compliance-lab/cra-sbom-cli), which check SBOM completeness rather than component vulnerabilities.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Every entry must be a real, reachable resource that a practitioner can use - no filler, no dead links.

## License

[![CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](LICENSE)

To the extent possible under law, the author has waived all copyright and related rights to this work.
