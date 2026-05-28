# Control mapping

Each rule in `policy/rmf.rego` maps to one or more primary-source controls.
This document is the authoritative mapping; cite it in audit conversations.

## Sources

- **NIST AI RMF 1.0** — <https://www.nist.gov/itl/ai-risk-management-framework>
- **NIST AI 600-1 (GenAI Profile)** — <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- **EU AI Act** (consolidated text) — <https://artificialintelligenceact.eu/the-act/>
- **ISO/IEC 42001:2023** — <https://www.iso.org/standard/81230.html>
- **OWASP LLM Top 10** — <https://owasp.org/www-project-top-10-for-large-language-model-applications/>
- **MITRE ATLAS** — <https://atlas.mitre.org/>
- **FinOps Foundation AI WG** — <https://www.finops.org/wg/ai/>

## Rule → control mapping

| Rule (rmf.rego) | NIST AI RMF | NIST AI 600-1 | EU AI Act | OWASP LLM | Other |
|---|---|---|---|---|---|
| `accountability_officer` | GOVERN-1.3 | — | Art.9 | — | ISO 42001 §5.1 |
| `risk_tier_declared` | GOVERN-2 (all) | §2 | Art.9, Art.6 | — | ISO 42001 §6.1.1 |
| `data_lineage_attached` | MAP-2, MAP-4 | §3.1 | Art.10 | LLM06 | — |
| `eval_set_required` | MEASURE-2.7 | §4 | Art.15 | LLM09 | — |
| `prompt_versioned` | MEASURE-2.7 | §3.2 | — | LLM01 | — |
| `model_version_pinned` | MAP-3.4 | §3.3 | Art.11, Art.13 | — | NIST SSDF PW.4.4 |
| `guardrails_present` | MEASURE-2.5 | §5 | Art.13, Art.15 | LLM01/02/06 | MITRE ATLAS |
| `audit_evidence_sink` | MEASURE-3.3 | §6 | Art.12 (Logging) | — | ISO 42001 A.6.2.4 |
| `human_oversight_pattern` | GOVERN-3, MANAGE-2 | §5 | Art.14 | — | — |
| `cost_attribution` | — | — | — | — | FinOps for AI |
| `eu_high_risk_conformity` | — | — | Annex III, Art.43 | — | — |
| `model_provider_pinned` | MAP-3.4 | §3.3 | Art.11 | — | NIST SSDF PO.5 |

## Audit walk-through

For an auditor reviewing your AI workload deploys, this bundle provides:

1. **Evidence of enforcement** — admission-controller logs show every
   blocked or allowed deploy, with the rule(s) cited.
2. **Mapping** — this document maps every blocked rule to the primary
   source control it implements.
3. **Coverage** — the rule set covers the most commonly-audited
   obligations across NIST AI RMF and EU AI Act high-risk Art.9–15.

What this bundle does **not** provide (intentionally out of scope):

- Conformity assessment process (manual, organisation-specific)
- Stakeholder consultation evidence
- Model card content (the policy verifies the *reference* exists, not the content)
- Risk-management process documentation
