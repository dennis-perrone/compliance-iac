package iam.securing_non_user_auth

import data.lib.helpers

# KSI-IAM-SNU: Securing Non-User Authentication
# "Appropriately secure authentication methods are used and persistently reviewed
#  for non-user accounts and services."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_access_key")
	msg := sprintf("[KSI-IAM-SNU] IAM access key '%s' creates long-lived credentials; use IAM roles with OIDC or instance profiles instead", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_role")
	policy_doc := json.unmarshal(rc.change.after.assume_role_policy)
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	some principal_service in statement.Principal.Service
	principal_service == "lambda.amazonaws.com"
	not role_has_scoped_policy(rc.address)
	msg := sprintf("[KSI-IAM-SNU] Lambda execution role '%s' should have narrowly scoped permissions", [rc.address])
}

role_has_scoped_policy(role_address) if {
	some rc in helpers.resources_by_type("aws_iam_role_policy_attachment")
	contains(rc.address, role_address)
	not is_admin_policy(rc.change.after.policy_arn)
}

is_admin_policy(arn) if {
	arn == "arn:aws:iam::aws:policy/AdministratorAccess"
}

is_admin_policy(arn) if {
	arn == "arn:aws:iam::aws:policy/PowerUserAccess"
}
