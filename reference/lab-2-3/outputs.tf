# outputs.tf

output "bucket_arn" {
  value       = aws_s3_bucket.primary.arn
  description = "ARN of the primary compliant bucket."
}

output "bucket_name" {
  value       = aws_s3_bucket.primary.id
  description = "Name of the primary compliant bucket."
}

output "log_bucket_arn" {
  value       = aws_s3_bucket.log.arn
  description = "ARN of the access-log bucket."
}

output "encryption_algorithm" {
  value = one([
    for rule in aws_s3_bucket_server_side_encryption_configuration.primary.rule :
    rule.apply_server_side_encryption_by_default[0].sse_algorithm
  ])
  description = "Server-side encryption algorithm in effect (SC-28 attestation)."
}
