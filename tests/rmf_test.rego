package ai.rmf_test

import rego.v1
import data.ai.rmf

# ─────────────────────────────────────────────────────────────────────────
# Test helpers — fixtures
# ─────────────────────────────────────────────────────────────────────────

# A minimally-compliant high-risk workload. Each test mutates this base
# to introduce one violation and asserts deny contains the matching rule.
base := {
	"apiVersion": "v1",
	"kind": "AIWorkload",
	"metadata": {
		"name": "fraud-scoring",
		"annotations": {
			"ai_workload.accountability_officer": "ai-officer@example.com",
			"ai_workload.risk_tier": "high",
			"ai_workload.risk_rationale": "Customer-facing lending decision",
			"ai_workload.eu_high_risk": "true",
			"ai_workload.conformity_assessment_ref": "CA-2026-fraud-v3",
		},
	},
	"spec": {
		"data": {"lineage_ref": "catalogue://customer-domain/transactions-v7"},
		"model": {
			"provider": "anthropic",
			"region": "ap-southeast-2",
			"version": "claude-sonnet-4-6",
		},
		"prompt": {"registry_ref": "prompts://fraud/scoring/v12"},
		"evals": {"set_ref": "evals://fraud-scoring/golden-50"},
		"guardrails": {
			"input": ["lakera-guard", "pii-redaction"],
			"output": ["bedrock-guardrails", "citation-required"],
		},
		"observability": {
			"audit_sink": "s3://audit-bucket/fraud-scoring/",
			"retention_days": 2555,
		},
		"oversight": {
			"pattern": "human-review-above-10k",
			"sla_minutes": 240,
		},
		"cost": {"attribution_tag": "team:fraud-platform"},
	},
}

# Mutate a nested field by JSON pointer-like path
patch(obj, path, value) := json.patch(obj, [{"op": "replace", "path": path, "value": value}])

remove(obj, path) := json.patch(obj, [{"op": "remove", "path": path}])

# Helper to extract just the rule prefixes from deny messages
denied_rules(deny_set) := {rule |
	some msg in deny_set
	parts := split(msg, ":")
	rule := parts[0]
}

# ─────────────────────────────────────────────────────────────────────────
# Positive case — compliant workload produces zero violations
# ─────────────────────────────────────────────────────────────────────────

test_compliant_workload_allowed if {
	count(rmf.deny) == 0 with input as base
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 1 — Accountability officer
# ─────────────────────────────────────────────────────────────────────────

test_missing_accountability_officer if {
	mutated := remove(base, "/metadata/annotations/ai_workload.accountability_officer")
	"accountability_officer" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 2 — Risk tier
# ─────────────────────────────────────────────────────────────────────────

test_missing_risk_tier if {
	mutated := patch(base, "/metadata/annotations/ai_workload.risk_tier", "")
	"risk_tier_declared" in denied_rules(rmf.deny) with input as mutated
}

test_invalid_risk_tier if {
	mutated := patch(base, "/metadata/annotations/ai_workload.risk_tier", "extreme")
	"risk_tier_declared" in denied_rules(rmf.deny) with input as mutated
}

test_medium_risk_missing_rationale if {
	m1 := patch(base, "/metadata/annotations/ai_workload.risk_tier", "medium")
	m2 := patch(m1, "/metadata/annotations/ai_workload.risk_rationale", "")
	"risk_tier_declared" in denied_rules(rmf.deny) with input as m2
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 3 — Data lineage
# ─────────────────────────────────────────────────────────────────────────

test_missing_data_lineage if {
	mutated := patch(base, "/spec/data/lineage_ref", "")
	"data_lineage_attached" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 4 — Eval set
# ─────────────────────────────────────────────────────────────────────────

test_high_risk_missing_eval_set if {
	mutated := patch(base, "/spec/evals/set_ref", "")
	"eval_set_required" in denied_rules(rmf.deny) with input as mutated
}

test_low_risk_no_eval_set_ok if {
	m1 := patch(base, "/metadata/annotations/ai_workload.risk_tier", "low")
	m2 := patch(m1, "/spec/evals/set_ref", "")
	not "eval_set_required" in denied_rules(rmf.deny) with input as m2
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 5 — Prompt versioning
# ─────────────────────────────────────────────────────────────────────────

test_missing_prompt_registry if {
	mutated := patch(base, "/spec/prompt", {})
	"prompt_versioned" in denied_rules(rmf.deny) with input as mutated
}

test_inline_prompt_blocked if {
	mutated := patch(base, "/spec/prompt", {"inline": "You are a helpful assistant…"})
	"prompt_versioned" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 6 — Model version pinning
# ─────────────────────────────────────────────────────────────────────────

test_missing_model_version if {
	mutated := patch(base, "/spec/model/version", "")
	"model_version_pinned" in denied_rules(rmf.deny) with input as mutated
}

test_floating_tag_blocked if {
	mutated := patch(base, "/spec/model/version", "latest")
	"model_version_pinned" in denied_rules(rmf.deny) with input as mutated
}

test_stable_tag_blocked if {
	mutated := patch(base, "/spec/model/version", "stable")
	"model_version_pinned" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 7 — Guardrails
# ─────────────────────────────────────────────────────────────────────────

test_missing_input_guardrails if {
	mutated := patch(base, "/spec/guardrails/input", [])
	"guardrails_present" in denied_rules(rmf.deny) with input as mutated
}

test_missing_output_guardrails if {
	mutated := patch(base, "/spec/guardrails/output", [])
	"guardrails_present" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 8 — Audit evidence
# ─────────────────────────────────────────────────────────────────────────

test_missing_audit_sink if {
	mutated := patch(base, "/spec/observability/audit_sink", "")
	"audit_evidence_sink" in denied_rules(rmf.deny) with input as mutated
}

test_insufficient_retention if {
	mutated := patch(base, "/spec/observability/retention_days", 90)
	"audit_evidence_sink" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 9 — Human oversight
# ─────────────────────────────────────────────────────────────────────────

test_high_risk_missing_oversight if {
	mutated := patch(base, "/spec/oversight", {})
	"human_oversight_pattern" in denied_rules(rmf.deny) with input as mutated
}

test_low_risk_no_oversight_ok if {
	m1 := patch(base, "/metadata/annotations/ai_workload.risk_tier", "low")
	m2 := patch(m1, "/spec/oversight", {})
	not "human_oversight_pattern" in denied_rules(rmf.deny) with input as m2
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 10 — Cost attribution
# ─────────────────────────────────────────────────────────────────────────

test_missing_cost_tag if {
	mutated := patch(base, "/spec/cost/attribution_tag", "")
	"cost_attribution" in denied_rules(rmf.deny) with input as mutated
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 11 — EU high-risk conformity
# ─────────────────────────────────────────────────────────────────────────

test_eu_high_risk_missing_conformity if {
	mutated := patch(base, "/metadata/annotations/ai_workload.conformity_assessment_ref", "")
	"eu_high_risk_conformity" in denied_rules(rmf.deny) with input as mutated
}

test_non_eu_no_conformity_ok if {
	m1 := patch(base, "/metadata/annotations/ai_workload.eu_high_risk", "false")
	m2 := patch(m1, "/metadata/annotations/ai_workload.conformity_assessment_ref", "")
	not "eu_high_risk_conformity" in denied_rules(rmf.deny) with input as m2
}

# ─────────────────────────────────────────────────────────────────────────
# Rule 12 — Model provider pinning
# ─────────────────────────────────────────────────────────────────────────

test_missing_provider if {
	mutated := patch(base, "/spec/model/provider", "")
	"model_provider_pinned" in denied_rules(rmf.deny) with input as mutated
}

test_any_provider_blocked if {
	mutated := patch(base, "/spec/model/provider", "any")
	"model_provider_pinned" in denied_rules(rmf.deny) with input as mutated
}

test_high_risk_missing_region if {
	mutated := patch(base, "/spec/model/region", "")
	"model_provider_pinned" in denied_rules(rmf.deny) with input as mutated
}
