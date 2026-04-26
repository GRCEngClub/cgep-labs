# METADATA
# title: SC-28 - Encryption at Rest (AWS S3)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_server_side_encryption_configuration that references it."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package compliance.sc28_aws

import rego.v1

# Match by Terraform reference in `configuration`, not by literal bucket name in
# `planned_values`. At plan time the bucket name is often "(known after apply)".

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_encryption(bucket)
	msg := sprintf(
		"[SC-28] %s: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket.",
		[bucket],
	)
}

# Set of all aws_s3_bucket resource addresses in the configuration.
bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

# Encryption config exists if some aws_s3_bucket_server_side_encryption_configuration
# in the configuration references the bucket address (directly or via its .id).
has_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
