package mla.operating_siem

import data.lib.helpers

# KSI-MLA-OSM: Operating SIEM Capability
# "A Security Information and Event Management (SIEM) or similar system(s) is used
#  and persistently reviewed for centralized, tamper-resistant logging of events,
#  activities, and changes."

deny contains msg if {
	count(helpers.resources_by_type("aws_securityhub_account")) == 0
	count(helpers.resources_by_type("aws_securityhub_account")) != count(helpers.resources_by_type("aws_securityhub_account"))
	msg := "[KSI-MLA-OSM] Security Hub must be enabled as a centralized findings aggregator"
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_cloudwatch_log_group")
	rc.change.after.retention_in_days == 0
	msg := sprintf("[KSI-MLA-OSM] CloudWatch log group '%s' must have a retention period configured (not indefinite)", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_cloudwatch_log_group")
	rc.change.after.retention_in_days != null
	rc.change.after.retention_in_days < 365
	msg := sprintf("[KSI-MLA-OSM] CloudWatch log group '%s' retention is %d days; security logs should be retained at least 365 days", [rc.address, rc.change.after.retention_in_days])
}
