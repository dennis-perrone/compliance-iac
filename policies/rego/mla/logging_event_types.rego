package mla.logging_event_types

import data.lib.helpers

# KSI-MLA-LET: Logging Event Types
# "A list of information resources and event types that will be logged, monitored, and
#  audited is maintained and persistently reviewed to ensure these activities occur."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_cloudtrail")
	not rc.change.after.is_multi_region_trail
	msg := sprintf("[KSI-MLA-LET] CloudTrail '%s' must be configured as a multi-region trail", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_cloudtrail")
	not rc.change.after.enable_log_file_validation
	msg := sprintf("[KSI-MLA-LET] CloudTrail '%s' must have log file validation enabled", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_s3_bucket")
	not bucket_has_logging(rc.address)
	msg := sprintf("[KSI-MLA-LET] S3 bucket '%s' must have access logging enabled", [rc.address])
}

bucket_has_logging(bucket_address) if {
	some rc in helpers.resources_by_type("aws_s3_bucket_logging")
	rc.change.after.bucket == bucket_address
}

bucket_has_logging(bucket_address) if {
	some rc in helpers.resources_by_type("aws_s3_bucket")
	rc.address == bucket_address
	some _ in rc.change.after.logging
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_vpc")
	not vpc_has_flow_logs(rc.change.after_unknown.id)
	not vpc_has_flow_logs(rc.address)
	msg := sprintf("[KSI-MLA-LET] VPC '%s' must have flow logs enabled", [rc.address])
}

vpc_has_flow_logs(vpc_ref) if {
	some rc in helpers.resources_by_type("aws_flow_log")
	rc.change.after.vpc_id == vpc_ref
}
