package svc.securing_information

import data.lib.helpers

# KSI-SVC-SIN: Securing Information
# "Information is encrypted or otherwise secured from unwanted access or modification."

# --- Encryption at Rest ---

deny contains msg if {
	some rc in helpers.resources_by_type("aws_s3_bucket")
	rc.address in buckets_without_kms
	msg := sprintf("[KSI-SVC-SIN] S3 bucket '%s' must use SSE-KMS encryption", [rc.address])
}

buckets_without_kms contains address if {
	some rc in helpers.resources_by_type("aws_s3_bucket")
	address := rc.address
	not bucket_has_kms_encryption(address)
}

bucket_has_kms_encryption(bucket_address) if {
	some rc in helpers.resources_by_type("aws_s3_bucket_server_side_encryption_configuration")
	rc.change.after.bucket == bucket_address
	some rule in rc.change.after.rule
	some default_enc in rule.apply_server_side_encryption_by_default
	default_enc.sse_algorithm == "aws:kms"
}

bucket_has_kms_encryption(bucket_address) if {
	some rc in helpers.resources_by_type("aws_s3_bucket")
	rc.address == bucket_address
	some enc_config in rc.change.after.server_side_encryption_configuration
	some rule in enc_config.rule
	some default_enc in rule.apply_server_side_encryption_by_default
	default_enc.sse_algorithm == "aws:kms"
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_ebs_volume")
	not rc.change.after.encrypted
	msg := sprintf("[KSI-SVC-SIN] EBS volume '%s' must be encrypted", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_db_instance")
	not rc.change.after.storage_encrypted
	msg := sprintf("[KSI-SVC-SIN] RDS instance '%s' must have storage encryption enabled", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_rds_cluster")
	not rc.change.after.storage_encrypted
	msg := sprintf("[KSI-SVC-SIN] RDS cluster '%s' must have storage encryption enabled", [rc.address])
}

# --- Encryption in Transit ---

deny contains msg if {
	some rc in helpers.resources_by_type("aws_lb_listener")
	rc.change.after.protocol == "HTTP"
	rc.change.after.port == 80
	not has_redirect_to_https(rc)
	msg := sprintf("[KSI-SVC-SIN] Load balancer listener '%s' uses HTTP without HTTPS redirect", [rc.address])
}

has_redirect_to_https(rc) if {
	some action in rc.change.after.default_action
	action.type == "redirect"
	some redirect in action.redirect
	redirect.protocol == "HTTPS"
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_lb_listener")
	rc.change.after.protocol == "HTTPS"
	rc.change.after.ssl_policy == ""
	msg := sprintf("[KSI-SVC-SIN] HTTPS listener '%s' must specify an SSL policy", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_db_instance")
	not rc.change.after.ca_cert_identifier
	msg := sprintf("[KSI-SVC-SIN] RDS instance '%s' should have a CA certificate for encryption in transit", [rc.address])
}
