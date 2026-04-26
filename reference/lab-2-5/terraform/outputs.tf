output "vault_name" {
  value = aws_s3_bucket.vault.id
}

output "vault_arn" {
  value = aws_s3_bucket.vault.arn
}

output "lock_mode" {
  value = var.lock_mode
}

output "retention_days" {
  value = var.retention_days
}
