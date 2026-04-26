# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_public_access_block referencing it, with all four flags true."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
#   remediation: "Add aws_s3_bucket_public_access_block { bucket = aws_s3_bucket.<name>.id, block_public_acls = true, block_public_policy = true, ignore_public_acls = true, restrict_public_buckets = true }."
package compliance.ac3_aws

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_complete_pab(bucket)
	msg := sprintf(
		"[AC-3] %s: missing or incomplete aws_s3_bucket_public_access_block. All four flags must be true.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

# A bucket has a complete PAB if a public-access-block resource references it
# AND its planned values set all four flags to true.
has_complete_pab(bucket_addr) if {
	pab := pab_for(bucket_addr)
	planned := pab_planned_values(pab.address)
	planned.block_public_acls == true
	planned.block_public_policy == true
	planned.ignore_public_acls == true
	planned.restrict_public_buckets == true
}

pab_for(bucket_addr) := pab if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_public_access_block"
	some ref in r.expressions.bucket.references
	pab_references_bucket(ref, bucket_addr)
	pab := {"address": sprintf("aws_s3_bucket_public_access_block.%s", [r.name])}
}

pab_references_bucket(ref, bucket_addr) if ref == bucket_addr
pab_references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

pab_planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}
