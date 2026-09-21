package iam.automating_account_management

import data.lib.helpers

# KSI-IAM-AAM: Automating Account Management
# "The lifecycle and privileges of all accounts, roles, and groups are securely
#  managed using automation."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_access_key")
	rc.change.after.user == "root"
	msg := sprintf("[KSI-IAM-AAM] Root account access key '%s' must not exist; remove root access keys", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_user")
	not user_has_mfa(rc.address)
	msg := sprintf("[KSI-IAM-AAM] IAM user '%s' should be managed via IaC with MFA configured", [rc.address])
}

user_has_mfa(user_address) if {
	some rc in helpers.resources_by_type("aws_iam_user_login_profile")
	contains(rc.address, user_address)
}
