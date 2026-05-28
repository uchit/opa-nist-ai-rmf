# opa-nist-ai-rmf

> OPA / Rego policy bundle enforcing **NIST AI Risk Management Framework**
> and **EU AI Act** controls on AI workload manifests at deploy time.
>
> A reference implementation, not a vendor product. Slot it into a
> Kubernetes admission controller, a Terraform validation step, or a
> CI policy check. Tested. Documented. MIT-licensed.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OPA](https://img.shields.io/badge/OPA-v1.0+-7d4698)](https://www.openpolicyagent.org/)
[![Tests](https://img.shields.io/badge/tests-passing-43d39e)](#tests)

---

## Why this exists

Most enterprises in 2026 are being asked the same question by their
regulators, auditors and procurement teams: *"How do you actually
enforce the NIST AI RMF and EU AI Act controls on your AI workloads?"*

The usual answer is "we have a policy document." That's not enforcement;
that's hope.

This bundle turns the controls into **deploy-time machine checks** —
the kind of policy that breaks the build when an AI workload manifest
doesn't carry the audit-evidence pipeline, the human-oversight
mechanism, or the model-version pin a regulator can verify.

It is intentionally **opinionated, small, and runnable today**.
Pair it with [Open Policy Agent](https://www.openpolicyagent.org/),
[Kyverno](https://kyverno.io/), [Conftest](https://www.conftest.dev/) or
similar. Use it as-is, fork it for your context.

Companion to
[hellouchit.com/writing/genai-9-controls](https://hellouchit.com/writing/genai-9-controls.html)
and the
[Regulated GenAI Platform reference architecture](https://hellouchit.com/reference-architectures/regulated-genai-platform.html).

---

## What it checks

Each rule maps to a specific control in NIST AI RMF and (where applicable)
EU AI Act articles. See [`docs/control-mapping.md`](docs/control-mapping.md)
for the full mapping table.

| Rule | Maps to | What it enforces |
|---|---|---|
| `accountability_officer` | NIST GOVERN-1.3, EU AI Act Art.9 | Manifest must declare a named, contactable AI accountability officer |
| `risk_tier_declared` | NIST GOVERN-2, EU AI Act Art.9 | Workload must declare its risk tier (low / medium / high) with rationale |
| `data_lineage_attached` | NIST MAP-2, EU AI Act Art.10 | Reference to data lineage (catalogue ID, source domain) required |
| `eval_set_required` | NIST MEASURE-2.7, AI 600-1 §4 | Reference to active eval set required on prod deploys |
| `prompt_versioned` | NIST MEASURE-2.7 | Inline / hard-coded prompts blocked; prompt registry reference required |
| `model_version_pinned` | NIST MAP-3.4, EU AI Act Art.11 | Floating-tag model references blocked; semantic version required |
| `guardrails_present` | OWASP LLM01, MITRE ATLAS | At least one input and one output guardrail layer declared |
| `audit_evidence_sink` | NIST MEASURE-3.3, EU AI Act Art.12 | Workload must declare audit-evidence sink + retention policy |
| `human_oversight_pattern` | NIST GOVERN-3, EU AI Act Art.14 | Human-in-the-loop pattern declared for high-risk tier |
| `cost_attribution` | FinOps for AI | Cost-attribution tag for billing aggregation required |
| `eu_high_risk_conformity` | EU AI Act Annex III | Workloads tagged `eu_high_risk: true` need conformity-assessment reference |
| `model_provider_pinned` | NIST MAP-3.4, supply chain | Model provider + region pinned (no `provider: any`) |

---

## Quickstart — 60 seconds

```bash
# 1. Clone
git clone https://github.com/uchit/opa-nist-ai-rmf
cd opa-nist-ai-rmf

# 2. Install OPA (macOS / Linux)
brew install opa  # or: curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_$(uname -s)_$(uname -m) && chmod +x opa

# 3. Evaluate a sample manifest
opa eval -d policy/ -i examples/compliant.yaml 'data.ai.rmf.deny'
# []   ← empty = compliant, deploy allowed

opa eval -d policy/ -i examples/missing-evals.yaml 'data.ai.rmf.deny'
# ["eval_set_required: workload 'fraud-scoring' is risk_tier=high but has no eval_set reference (NIST MEASURE-2.7)"]

# 4. Run the test suite
opa test policy/ tests/
# PASS: 24/24
```

---

## Wire it into Kubernetes (Gatekeeper)

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: nistairmfworkload
spec:
  crd:
    spec:
      names:
        kind: NistAIRMFWorkload
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package nistairmfworkload
        import data.ai.rmf
        violation[{"msg": msg}] {
          msg := rmf.deny[_]
        }
```

Apply the constraint to your AI workload namespace; deploys missing
required annotations now fail at admission with a citation.

---

## Wire it into CI (Conftest)

```yaml
# .github/workflows/policy.yaml
- name: Validate against NIST AI RMF
  uses: instrumenta/conftest-action@master
  with:
    files: manifests/
    policy: policy/
```

---

## Wire it into Terraform

```hcl
# Use the policy bundle as a Sentinel/OPA pre-apply check
# against terraform plan output containing `module "ai_workload"`
```

See [`examples/terraform/`](examples/terraform/) for a worked example.

---

## Workload manifest schema

Every AI workload manifest must include these top-level fields. The
schema is intentionally **prefix-namespaced** under `ai_workload` so it
co-exists cleanly with your existing manifests:

```yaml
apiVersion: v1
kind: AIWorkload
metadata:
  name: fraud-scoring
  annotations:
    ai_workload.accountability_officer: "name@company.com"
    ai_workload.risk_tier: "high"  # low | medium | high
    ai_workload.risk_rationale: "Customer-facing lending decision; EU AI Act Annex III"
    ai_workload.eu_high_risk: "true"
    ai_workload.conformity_assessment_ref: "CA-2026-fraud-v3"
spec:
  data:
    lineage_ref: "catalogue://customer-domain/transactions-v7"
  model:
    provider: "anthropic"
    region: "ap-southeast-2"
    version: "claude-sonnet-4-6"     # NOT "latest"
  prompt:
    registry_ref: "prompts://fraud/scoring/v12"   # NOT inline
  evals:
    set_ref: "evals://fraud-scoring/golden-50"
  guardrails:
    input: ["lakera-guard", "pii-redaction"]
    output: ["bedrock-guardrails", "citation-required"]
  observability:
    audit_sink: "s3://audit-bucket/fraud-scoring/"
    retention_days: 2555
  oversight:
    pattern: "human-review-above-10k"
    sla_minutes: 240
  cost:
    attribution_tag: "team:fraud-platform"
```

---

## Tests

```bash
opa test policy/ tests/ -v
```

24 unit tests covering: each rule's positive case (allow), negative
case (deny with citation), and at least one edge case (boundary
values, EU-specific flag interactions, risk-tier transitions).

See [`tests/`](tests/) for the test files.

---

## Roadmap

Versioned releases roughly quarterly, tracking framework updates:

- **v0.1** *(this release)* — NIST AI RMF 1.0, EU AI Act baseline, 12 rules.
- **v0.2** — ISO/IEC 42001 control mapping (audit-relevant subset).
- **v0.3** — Australian DISR Voluntary AI Safety Standard guardrails.
- **v0.4** — Agent-specific controls (multi-step trajectories, tool-use scoping).

---

## Contributing

PRs welcome. Two rules of thumb:

1. **Every rule cites a primary source.** No "best practice" claims; the
   policy must point to a published standard or regulator document.
2. **Every rule has both a positive and negative test.** Untested rules
   are removed.

Bug reports, missing controls, regulatory-update PRs all appreciated.

---

## License

[MIT](LICENSE) — use, fork, redistribute. Attribution appreciated but
not required.

---

## Acknowledgements

Built on [Open Policy Agent](https://www.openpolicyagent.org/) (CNCF
graduated). Inspired by the
[NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework),
[NIST AI 600-1 (GenAI Profile)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf),
[EU AI Act](https://artificialintelligenceact.eu/the-act/),
[ISO/IEC 42001](https://www.iso.org/standard/81230.html),
[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
and [MITRE ATLAS](https://atlas.mitre.org/).

Maintained by [Uchit Vyas](https://hellouchit.com/). Companion work:
[the 4-Discipline Stack framework](https://hellouchit.com/4-discipline-stack/),
[the 6 practitioner diagnostics](https://hellouchit.com/tools/), and
[the State of Enterprise Tech in Regulated Industries 2026](https://hellouchit.com/state-of-2026/).
