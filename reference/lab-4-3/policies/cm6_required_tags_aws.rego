# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# description: "Every taggable AWS resource must carry the four required tags: Project, Environment, ManagedBy, ComplianceScope."
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
#   remediation: "Add the four required tags. The cleanest way is provider default_tags so they're applied to every resource automatically."
package compliance.cm6_aws

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

# AWS resource types that should carry tags in this lab's scope.
labelable_type(t) if t == "aws_s3_bucket"
labelable_type(t) if t == "aws_dynamodb_table"
labelable_type(t) if t == "aws_lambda_function"
labelable_type(t) if t == "aws_kms_key"
labelable_type(t) if t == "aws_cloudtrail"

deny contains msg if {
	resource := all_resources[_]
	labelable_type(resource.type)
	provided := tag_keys(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add the missing tags or use provider default_tags.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

# Use tags_all (provider default_tags + resource-level tags merged) when present;
# otherwise fall back to tags.
tag_keys(resource) := keys if {
	resource.values.tags_all
	keys := {k | resource.values.tags_all[k]}
}

tag_keys(resource) := keys if {
	not resource.values.tags_all
	resource.values.tags
	keys := {k | resource.values.tags[k]}
}

tag_keys(resource) := set() if {
	not resource.values.tags_all
	not resource.values.tags
}

sort_array(s) := sorted if { sorted := sort([x | some x in s]) }
