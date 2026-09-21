package iam.ensuring_least_privilege

import data.lib.helpers

# KSI-IAM-ELP: Ensuring Least Privilege
# "Identity and access management measures are used and persistently reviewed to ensure
#  each user or device can only access the resources they need."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_policy")
	policy_doc := json.unmarshal(rc.change.after.policy)
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	some action in statement.Action
	action == "*"
	msg := sprintf("[KSI-IAM-ELP] IAM policy '%s' uses wildcard action (*); use least-privilege permissions", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_policy")
	policy_doc := json.unmarshal(rc.change.after.policy)
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	statement.Action == "*"
	msg := sprintf("[KSI-IAM-ELP] IAM policy '%s' uses wildcard action (*); use least-privilege permissions", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_role_policy")
	policy_doc := json.unmarshal(rc.change.after.policy)
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	some action in statement.Action
	action == "*"
	msg := sprintf("[KSI-IAM-ELP] IAM inline policy '%s' uses wildcard action (*); use least-privilege permissions", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_user_policy")
	msg := sprintf("[KSI-IAM-ELP] IAM user '%s' has an inline policy; attach managed policies to roles instead", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_group_policy")
	msg := sprintf("[KSI-IAM-ELP] IAM group '%s' has an inline policy; use managed policies instead", [rc.address])
}
