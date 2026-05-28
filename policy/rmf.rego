# Package: ai.rmf
#
# OPA / Rego policy bundle enforcing NIST AI Risk Management Framework
# and EU AI Act controls on AI workload manifests at deploy time.
#
# Maintained at https://github.com/uchit/opa-nist-ai-rmf
# License: MIT
#
# Each rule cites a primary source. Each rule has positive + negative tests.

package ai.rmf

import rego.v1

# ─────────────────────────────────────────────────────────────────────────
# Entrypoint
# ─────────────────────────────────────────────────────────────────────────

# deny is the public API: a non-empty set blocks the deploy.
# Each violation includes the rule name, the workload, the explanation
# and the standard citation.

deny contains msg if {
	some rule_name in _rule_names
	some msg in _check(rule_name)
}

_rule_names := [
	"accountability_officer",
	"risk_tier_declared",
	"data_lineage_attached",
	"eval_set_required",
	"prompt_versioned",
	"model_version_pinned",
	"guardrails_present",
	"audit_evidence_sink",
	"human_oversight_pattern",
	"cost_attribution",
	"eu_high_risk_conformity",
	"model_provider_pinned",
]

# Dispatch table — each rule_name maps to its check function
_check(rule_name) := result if {
	rule_name == "accountability_officer"
	result := check_accountability_officer
} else := result if {
	rule_name == "risk_tier_declared"
	result := check_risk_tier_declared
} else := result if {
	rule_name == "data_lineage_attached"
	result := check_data_lineage_attached
} else := result if {
	rule_name == "eval_set_required"
	result := check_eval_set_required
} else := result if {
	rule_name == "prompt_versioned"
	result := check_prompt_versioned
} else := result if {
	rule_name == "model_version_pinned"
	result := check_model_version_pinned
} else := result if {
	rule_name == "guardrails_present"
	result := check_guardrails_present
} else := result if {
	rule_name == "audit_evidence_sink"
	result := check_audit_evidence_sink
} else := result if {
	rule_name == "human_oversight_pattern"
	result := check_human_oversight_pattern
} else := result if {
	rule_name == "cost_attribution"
	result := check_cost_attribution
} else := result if {
	rule_name == "eu_high_risk_conformity"
	result := check_eu_high_risk_conformity
} else := result if {
	rule_name == "model_provider_pinned"
	result := check_model_provider_pinned
}

# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────

_name := input.metadata.name

_ann := object.get(input.metadata, "annotations", {})

_risk_tier := lower(object.get(_ann, "ai_workload.risk_tier", ""))

_is_high_risk if _risk_tier == "high"

_is_eu_high_risk if lower(object.get(_ann, "ai_workload.eu_high_risk", "false")) == "true"

# ─────────────────────────────────────────────────────────────────────────
# Rules
# ─────────────────────────────────────────────────────────────────────────

# RULE 1 — Accountability officer
# NIST AI RMF GOVERN-1.3 · EU AI Act Art.9
check_accountability_officer contains msg if {
	officer := object.get(_ann, "ai_workload.accountability_officer", "")
	officer == ""
	msg := sprintf("accountability_officer: workload '%s' has no ai_workload.accountability_officer annotation (NIST GOVERN-1.3 · EU AI Act Art.9)", [_name])
}

# RULE 2 — Risk tier declared
# NIST AI RMF GOVERN-2 · EU AI Act Art.9
check_risk_tier_declared contains msg if {
	not _risk_tier in {"low", "medium", "high"}
	msg := sprintf("risk_tier_declared: workload '%s' must declare ai_workload.risk_tier as low|medium|high (NIST GOVERN-2 · EU AI Act Art.9)", [_name])
}

check_risk_tier_declared contains msg if {
	_risk_tier in {"medium", "high"}
	rationale := trim(object.get(_ann, "ai_workload.risk_rationale", ""), " ")
	rationale == ""
	msg := sprintf("risk_tier_declared: workload '%s' is risk_tier=%s but has no ai_workload.risk_rationale (NIST GOVERN-2)", [_name, _risk_tier])
}

# RULE 3 — Data lineage attached
# NIST AI RMF MAP-2 · EU AI Act Art.10
check_data_lineage_attached contains msg if {
	lineage := object.get(object.get(input.spec, "data", {}), "lineage_ref", "")
	lineage == ""
	msg := sprintf("data_lineage_attached: workload '%s' has no spec.data.lineage_ref (NIST MAP-2 · EU AI Act Art.10)", [_name])
}

# RULE 4 — Eval set required (always for high; recommended for others)
# NIST AI RMF MEASURE-2.7 · NIST AI 600-1 §4
check_eval_set_required contains msg if {
	_risk_tier in {"medium", "high"}
	eval_ref := object.get(object.get(input.spec, "evals", {}), "set_ref", "")
	eval_ref == ""
	msg := sprintf("eval_set_required: workload '%s' is risk_tier=%s but has no spec.evals.set_ref (NIST MEASURE-2.7)", [_name, _risk_tier])
}

# RULE 5 — Prompt versioned (no inline prompts)
# NIST AI RMF MEASURE-2.7 · OWASP LLM01
check_prompt_versioned contains msg if {
	prompt := object.get(input.spec, "prompt", {})
	registry := object.get(prompt, "registry_ref", "")
	inline := object.get(prompt, "inline", "")
	registry == ""
	inline == ""
	msg := sprintf("prompt_versioned: workload '%s' has no spec.prompt.registry_ref (NIST MEASURE-2.7 · OWASP LLM01)", [_name])
}

check_prompt_versioned contains msg if {
	prompt := object.get(input.spec, "prompt", {})
	object.get(prompt, "inline", "") != ""
	object.get(prompt, "registry_ref", "") == ""
	msg := sprintf("prompt_versioned: workload '%s' uses spec.prompt.inline; require spec.prompt.registry_ref instead (NIST MEASURE-2.7)", [_name])
}

# RULE 6 — Model version pinned (no floating tags)
# NIST AI RMF MAP-3.4 · EU AI Act Art.11
check_model_version_pinned contains msg if {
	model := object.get(input.spec, "model", {})
	version := object.get(model, "version", "")
	version == ""
	msg := sprintf("model_version_pinned: workload '%s' has no spec.model.version (NIST MAP-3.4 · EU AI Act Art.11)", [_name])
}

check_model_version_pinned contains msg if {
	version := lower(object.get(object.get(input.spec, "model", {}), "version", ""))
	version in {"latest", "stable", "current", "default"}
	msg := sprintf("model_version_pinned: workload '%s' uses floating tag '%s'; require semantic version (NIST MAP-3.4)", [_name, version])
}

# RULE 7 — Guardrails present (input + output for medium/high)
# OWASP LLM01/02/06 · MITRE ATLAS
check_guardrails_present contains msg if {
	_risk_tier in {"medium", "high"}
	g := object.get(input.spec, "guardrails", {})
	input_g := object.get(g, "input", [])
	count(input_g) == 0
	msg := sprintf("guardrails_present: workload '%s' has no spec.guardrails.input (OWASP LLM01 · MITRE ATLAS)", [_name])
}

check_guardrails_present contains msg if {
	_risk_tier in {"medium", "high"}
	g := object.get(input.spec, "guardrails", {})
	output_g := object.get(g, "output", [])
	count(output_g) == 0
	msg := sprintf("guardrails_present: workload '%s' has no spec.guardrails.output (OWASP LLM06)", [_name])
}

# RULE 8 — Audit evidence sink + retention
# NIST AI RMF MEASURE-3.3 · EU AI Act Art.12
check_audit_evidence_sink contains msg if {
	obs := object.get(input.spec, "observability", {})
	sink := object.get(obs, "audit_sink", "")
	sink == ""
	msg := sprintf("audit_evidence_sink: workload '%s' has no spec.observability.audit_sink (NIST MEASURE-3.3 · EU AI Act Art.12)", [_name])
}

check_audit_evidence_sink contains msg if {
	obs := object.get(input.spec, "observability", {})
	retention := object.get(obs, "retention_days", 0)
	retention < 365
	msg := sprintf("audit_evidence_sink: workload '%s' has retention_days=%d, minimum is 365 (NIST MEASURE-3.3)", [_name, retention])
}

# RULE 9 — Human oversight pattern (required for high-risk)
# NIST AI RMF GOVERN-3 · EU AI Act Art.14
check_human_oversight_pattern contains msg if {
	_is_high_risk
	pattern := object.get(object.get(input.spec, "oversight", {}), "pattern", "")
	pattern == ""
	msg := sprintf("human_oversight_pattern: workload '%s' is risk_tier=high but has no spec.oversight.pattern (EU AI Act Art.14)", [_name])
}

# RULE 10 — Cost attribution tag (FinOps for AI)
check_cost_attribution contains msg if {
	tag := object.get(object.get(input.spec, "cost", {}), "attribution_tag", "")
	tag == ""
	msg := sprintf("cost_attribution: workload '%s' has no spec.cost.attribution_tag (FinOps for AI)", [_name])
}

# RULE 11 — EU high-risk conformity assessment reference
# EU AI Act Annex III + Art.43
check_eu_high_risk_conformity contains msg if {
	_is_eu_high_risk
	ca_ref := object.get(_ann, "ai_workload.conformity_assessment_ref", "")
	ca_ref == ""
	msg := sprintf("eu_high_risk_conformity: workload '%s' is eu_high_risk but has no conformity_assessment_ref (EU AI Act Annex III · Art.43)", [_name])
}

# RULE 12 — Model provider + region pinned (supply chain)
# NIST AI RMF MAP-3.4 · supply chain provenance
check_model_provider_pinned contains msg if {
	model := object.get(input.spec, "model", {})
	provider := lower(object.get(model, "provider", ""))
	provider in {"", "any"}
	msg := sprintf("model_provider_pinned: workload '%s' must pin spec.model.provider (NIST MAP-3.4)", [_name])
}

check_model_provider_pinned contains msg if {
	_is_high_risk
	region := object.get(object.get(input.spec, "model", {}), "region", "")
	region == ""
	msg := sprintf("model_provider_pinned: workload '%s' is high-risk but has no spec.model.region (data-residency)", [_name])
}
