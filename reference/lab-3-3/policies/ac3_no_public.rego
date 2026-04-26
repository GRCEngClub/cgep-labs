# METADATA
# title: AC-3 - Access Enforcement (no public GCS or open firewall)
# description: "GCS buckets must enforce uniform_bucket_level_access AND public_access_prevention=enforced. Firewall rules must not allow 0.0.0.0/0 on management ports (22, 3389)."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: "Set uniform_bucket_level_access = true, public_access_prevention = \"enforced\". For firewalls, narrow source_ranges or remove the rule."
package compliance.ac3

import rego.v1

# --- GCS buckets ----------------------------------------------------

deny contains msg if {
	resource := bucket_resource[_]
	not bucket_locked_down(resource)
	msg := sprintf(
		"[AC-3] %s: bucket allows public access. Remediation: set uniform_bucket_level_access=true and public_access_prevention=\"enforced\".",
		[resource.address],
	)
}

bucket_resource contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "google_storage_bucket"
}

bucket_resource contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
	r.type == "google_storage_bucket"
}

bucket_locked_down(r) if {
	r.values.uniform_bucket_level_access == true
	r.values.public_access_prevention == "enforced"
}

# --- Firewall rules -------------------------------------------------

mgmt_port(p) if p == "22"
mgmt_port(p) if p == "3389"

public_range(s) if s == "0.0.0.0/0"
public_range(s) if s == "*"

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "google_compute_firewall"
	r.values.direction == "INGRESS"
	some src in r.values.source_ranges
	public_range(src)
	some allow in r.values.allow
	some port in allow.ports
	mgmt_port(port)
	msg := sprintf(
		"[AC-3] %s: management port %s open to %s. Remediation: narrow source_ranges or remove the rule.",
		[r.address, port, src],
	)
}
