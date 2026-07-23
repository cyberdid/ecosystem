# zubair-trabzada/ai-legal-claude — upstream review

> **Status:** external Claude-specific prompt corpus; downloaded and statically reviewed; not installed, trusted, or promoted into the ecosystem.

**Reviewed:** 2026-07-15
**Local snapshot:** `/home/snow/projects/ai-legal-claude`
**Commit:** `19ece98df260c4c645bdd750f6e2eb48af2bd6c4`
**Upstream:** <https://github.com/zubair-trabzada/ai-legal-claude>

## Short answer

`ai-legal-claude` is not a legal AI model, legal database, deterministic rule engine, RAG system, or hosted application. It is a small collection of Markdown prompts for Claude Code, plus an installer and two ReportLab scripts.

The useful part is its legal-review taxonomy, checklists, report structures, and plain-language workflow. The unsafe part is that the repository presents generated risk scores, financial exposure, compliance conclusions, and contract recommendations with substantially more confidence than the implementation and evidence support.

**Ecosystem decision:** keep it as an untrusted external reference and possible evaluation-seed corpus. Do not install it globally or use its output as legal advice, a compliance attestation, or an autonomous signing decision.

## Snapshot and maturity

At the reviewed snapshot:

- 27 non-Git files, approximately 760 KiB;
- 4 commits and one commit author;
- 21 Markdown files, 2 shell scripts, 2 Python files, one SVG, and one sample PDF;
- 14 advertised skills: one `/legal` router plus 13 task-specific skills;
- 5 advertised legal subagents;
- no release tags or published GitHub releases;
- no test suite, CI workflow, package manifest, dependency lock, benchmark, evaluation corpus, security policy, or contribution guide;
- no `LICENSE` file.

The absent license is important: public source is visible for review, but reuse, modification, and redistribution rights are not established by an open-source license.

Popularity is not validation. The GitHub page showed about 1.6k stars and 350 forks at review time, while the repository itself contained only four commits and no released version.

## What is actually inside

```text
README and curl installer
        |
        v
~/.claude/skills/legal/SKILL.md          main natural-language router
~/.claude/skills/legal-*/SKILL.md        13 task prompts
~/.claude/agents/legal-*.md              5 intended subagent prompts
        |
        v
Markdown analysis or generated contract
        |
        v
ReportLab PDF script                     optional presentation layer
```

The task prompts cover:

- full contract review;
- clause risks and missing protections;
- contract comparison and plain-language explanation;
- negotiation counter-proposals;
- NDAs, privacy policies, terms of service, and business agreements;
- freelancer-oriented review;
- website compliance review;
- PDF report generation.

This is a **prompt harness fragment**, not a complete legal system. Claude supplies nearly all reasoning, extraction, classification, scoring, and drafting. The repository does not provide a legal knowledge base, current-law retrieval, authoritative citations, deterministic checks, or an enforcement boundary.

## Flagship five-agent workflow

`/legal review` tells Claude to run five roles in parallel:

| Role | Advertised weight | Intended output |
|---|---:|---|
| Clause analyst | 20% | clause inventory and classification |
| Risk assessor | 25% | severity and exposure |
| Compliance checker | 20% | jurisdiction/regulatory flags |
| Terms mapper | 15% | obligations, deadlines, and triggers |
| Recommendations engine | 20% | proposed fixes and negotiation priorities |

The architecture is only described in prompts. There is no orchestrator program, typed inter-agent protocol, run record, aggregation implementation, or proof that the roles executed independently.

Three internal inconsistencies matter:

1. The agent prompts do not emit compatible numerical subscores from which the weighted `Contract Safety Score` can be reproducibly calculated.
2. The recommendations role says it uses the other agents' results, while the review prompt says all five roles launch simultaneously; no dependency or result-passing mechanism is defined.
3. The full contract is intended to be copied into several agent contexts, multiplying token cost and the confidentiality surface without proving better recall or accuracy.

The final 0–100 score is therefore an LLM-generated presentation artifact, not a calibrated legal-risk metric.

## Current Claude Code compatibility

Current Claude Code documentation requires skills and custom subagents to be Markdown definitions with YAML frontmatter. A skill needs a `SKILL.md`; its directory determines the direct command name and its `description` supports discovery. Custom subagents require at least `name` and `description` frontmatter.

The reviewed repository does not meet that contract consistently:

- the main `legal/SKILL.md` has no YAML frontmatter;
- 6 of the 13 task-specific skills have no YAML frontmatter;
- all 5 agent files lack the required subagent frontmatter;
- the agents do not restrict their tools;
- `/legal review ...` is a prompt-level router convention, not a native nested skill namespace;
- no compatibility test pins a Claude Code version or confirms discovery and invocation.

Consequently, the repository cannot rely on current Claude Code discovering and spawning the advertised skills and agents as described. Some individual `legal-*` skills are closer to the documented format, but the flagship workflow is not verified end to end.

Primary references:

- Claude Code: <https://code.claude.com/docs/en/slash-commands>
- Claude Code subagents: <https://code.claude.com/docs/en/sub-agents>

## Broken PDF contract

The PDF workflow has a concrete implementation mismatch:

| Skill expects | Repository provides |
|---|---|
| `generate_pdf_report.py` | `scripts/generate_legal_pdf.py` |
| `--input analysis.md --output report.pdf` | positional `<json_data_file> [output_path]` |
| Markdown input | `json.load(...)` input |

Therefore the skill first fails to locate the bundled script. If the path is manually corrected, the documented flags and Markdown input are still incompatible with the Python implementation. The prompt may instead ask Claude to generate a new inline script, bypassing the bundled code entirely.

The actual PDF script implements useful visual elements, but not the complete report contract advertised by the PDF skill. The sample-contract generator also contains an author-specific hard-coded macOS output path, so it is not portable as written.

Static verification performed during review:

- both Python files compile;
- both shell scripts pass `bash -n`;
- the checkout remains clean after verification;
- no dependency installation, Claude configuration change, model call, website scan, or legal-document processing was performed.

These checks establish syntax only, not legal correctness or end-to-end behavior.

## Installer and uninstall risks

The README promotes:

```sh
curl -fsSL https://raw.githubusercontent.com/zubair-trabzada/ai-legal-claude/main/install.sh | bash
```

This executes mutable `main` branch code without a pinned commit, checksum, signature, preview, or local review. The installer then writes global personal Claude configuration under `~/.claude/skills` and `~/.claude/agents`, making the prompts available across unrelated projects.

Additional lifecycle problems:

- existing files with the same names can be overwritten without backup or ownership adoption;
- there is no installation manifest, version lock, or recorded file hashes;
- installation is global rather than project-scoped;
- `reportlab` is detected but not installed or locked;
- the uninstaller removes hard-coded directories and agent files without proving that it created them;
- pre-existing user-owned files with matching names can therefore be destroyed by uninstall.

This conflicts directly with ecosystem requirements for preview, ownership, safe projection, rollback, and uninstall.

## Legal and evidence limits

### Contract review

The prompts can help a human notice clauses and prepare questions. They cannot establish that every clause was extracted correctly, that a scanned PDF or table was interpreted correctly, or that cited legal rules are current and applicable.

The repository lacks:

- a mandatory jurisdiction, governing-law, party-role, and effective-date gate;
- source-grounded clause/page citations and extraction confidence;
- OCR/layout validation for scanned contracts, schedules, exhibits, and tables;
- current authoritative legal retrieval with effective dates;
- deterministic calculation of dates, notice periods, caps, or formulae;
- calibrated risk or financial-exposure models;
- a lawyer-review/approval gate before consequential recommendations;
- a benchmark measuring false negatives on dangerous clauses.

Its `SIGN`, `NEGOTIATE`, `ESCALATE`, or `REJECT` style outputs are consequential recommendations. A disclaimer is useful disclosure, but it does not turn an unvalidated workflow into a safe decision system.

### GDPR

The compliance prompt treats EU/EEA accessibility too broadly as an applicability signal. Official EU guidance says territorial scope depends on EU establishment or, for a non-EU entity, offering goods/services to or monitoring people in the EU. Mere technical accessibility from the EU is not sufficient.

It also cannot verify from a public website many facts needed for compliance: processor contracts, lawful-basis records, retention implementation, breach procedures, security controls, cross-border transfer mechanisms, or whether a DPO is legally required.

Primary references:

- European Commission applicability guidance: <https://commission.europa.eu/law/law-topic/data-protection/reform/rules-business-and-organisations/application-regulation/who-does-data-protection-law-apply_en>
- EDPB territorial-scope guidelines: <https://www.edpb.europa.eu/documents/guideline/guidelines-32018-on-the-territorial-scope-of-the-gdpr-article-3-version-adopted_en>

### CCPA

The prompt sometimes reduces applicability to serving California residents. Official California guidance limits the general rule to for-profit businesses doing business in California that meet specified revenue, data-volume, or revenue-source thresholds. The workflow may not know those internal facts from a URL.

Primary reference: <https://www.oag.ca.gov/privacy/ccpa>

### ADA and WCAG

The repository blurs legislation, legal applicability, and a technical accessibility checklist. US DOJ guidance differentiates Title II public entities and Title III businesses open to the public. For Title III, DOJ describes flexibility in satisfying general ADA requirements and says technical standards such as WCAG provide useful guidance. Automated tools can help, but DOJ explicitly warns that a clean automated report does not necessarily establish accessibility and recommends pairing automation with manual checks.

Primary reference: <https://www.ada.gov/resources/web-guidance/>

### PCI DSS and SOC 2

A public website scan, a security badge, or policy text cannot validate PCI DSS. PCI SSC describes environment scoping, applicable SAQs or Reports on Compliance, testing, attestations, possible approved scans, and submission to the relevant compliance-accepting entity. It also states that unofficial certificates are not recognized evidence.

Primary references:

- PCI DSS self-assessment process: <https://www.pcisecuritystandards.org/faqs/1134/>
- recognized evidence: <https://www.pcisecuritystandards.org/faqs/1220/>

SOC 2 is likewise an attestation over controls and evidence, not a conclusion that can be produced from visible website content.

## Security, privacy, and operational risk

The repository processes documents likely to contain confidential commercial terms, signatures, personal data, pricing, and trade secrets. It defines no data-protection boundary for them.

Missing controls include:

- client consent and approved model/deployment selection;
- redaction, data-loss prevention, retention, residency, and deletion policy;
- privilege/confidentiality handling and audit records;
- prompt-injection defenses for hostile clauses, PDFs, or websites;
- tool and network allowlists;
- sandboxing for parsers and generated scripts;
- typed output schemas and provenance;
- output-path preview and overwrite protection;
- separation between analysis and authorization.

The contract or fetched webpage must be treated as untrusted data. Nothing inside it may grant tools, change policy, or instruct the agent to ignore the workflow.

## What is worth keeping

The repository still contains useful design material:

- broad clause and missing-protection checklists;
- separation of clause inventory, risks, obligations, and recommendations;
- useful plain-language report structures;
- explicit `[VERIFY]` markers in some drafting workflows;
- negotiation-focused replacement-language patterns;
- a readable client-report template;
- a small synthetic contract artifact for future test-fixture design.

These are candidate reference inputs, not canonical legal truth.

## Ecosystem classification

| Dimension | Decision |
|---|---|
| Core runtime | No |
| Active deployment | No |
| Trusted skill package | No |
| Legal/compliance authority | No |
| External prompt/reference corpus | Yes |
| Evaluation seed | Potentially, after licensing and expert review |
| Vendor-neutral | No; tightly coupled to Claude Code paths and conventions |
| Multi-agent evidence | No task-specific evaluation evidence |

The repository should remain outside the trusted core. If adopted later, its valuable taxonomies should be extracted into vendor-neutral, versioned reference contracts rather than copied into global Claude configuration.

## Required path to a safe legal-review capability

1. **Define the use boundary:** issue spotting and document preparation, never autonomous legal advice or compliance attestation.
2. **Use typed intake:** jurisdiction, governing law, user role, contract type, effective date, business facts, confidentiality class, and approved deployment.
3. **Isolate ingestion:** malware-safe/OCR-aware parsing, prompt-injection boundaries, page and clause provenance, and extraction confidence.
4. **Ground legal rules:** authoritative sources, jurisdiction and effective-date metadata, citations, and expiry/revalidation policy.
5. **Separate facts from inferences:** contract text, extracted facts, legal assumptions, model suggestions, and human decisions must remain distinct.
6. **Replace arbitrary scores:** show evidence-backed findings and uncertainty; introduce a score only after calibration against an expert-labeled corpus.
7. **Enforce policy outside prompts:** the broker decides model, tools, egress, writes, and approvals.
8. **Require human approval:** a qualified lawyer or authorized reviewer must approve consequential outputs.
9. **Evaluate before multi-agent use:** compare a strong single-agent baseline against specialist roles on recall, false negatives, citation accuracy, cost, latency, and confidentiality exposure.
10. **Package through safe projections:** preview, project scope, pinned source, ownership manifest, hashes, rollback, and uninstall.

## Final verdict

`ai-legal-claude` is a polished **demo and prompt/checklist collection**, not a production legal assistant. Its strongest value for this ecosystem is educational: it shows a useful task decomposition and report UX. Its weakest point is the gap between confident marketing and an untested prompt-only implementation.

Use it to design tests and taxonomies. Do not treat its score, financial estimates, generated legal documents, or compliance labels as verified facts.
