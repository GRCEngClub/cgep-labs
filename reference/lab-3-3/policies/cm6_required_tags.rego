# METADATA
# title: CM-6 - Configuration Settings (required compliance labels)
# description: "Every taggable resource must carry the four required labels: project, environment, managed_by, compliance_scope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required labels (project, environment, managed_by, compliance_scope) to the resource. Or use provider default_labels."
package compliance.cm6

import rego.v1

required := {"project", "environment", "managed_by", "compliance_scope"}

# Resource types that should carry the required labels in this lab's scope.
labelable_type(t) if t == "google_storage_bucket"
labelable_type(t) if t == "google_compute_instance"
labelable_type(t) if t == "google_compute_disk"

deny contains msg if {
	resource := all_resources[_]
	labelable_type(resource.type)
	provided := provided_labels(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required labels %v. Remediation: add the missing labels to the resource.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if {
	some r in input.planned_values.root_module.resources
}

all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

provided_labels(resource) := keys if {
	resource.values.labels
	keys := {k | resource.values.labels[k]}
}

provided_labels(resource) := set() if {
	not resource.values.labels
}

sort_array(s) := sorted if {
	sorted := sort([x | some x in s])
}
