package iam.adopting_passwordless_methods

import data.lib.helpers

# KSI-IAM-APM: Adopting Passwordless Methods
# "Secure passwordless methods are used for user authentication and authorization
#  when feasible, otherwise strong passwords with phishing-resistant MFA is used."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_account_password_policy")
	rc.change.after.minimum_password_length < 14
	msg := sprintf("[KSI-IAM-APM] Password policy '%s' minimum length must be at least 14 characters", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_account_password_policy")
	not rc.change.after.require_symbols
	msg := sprintf("[KSI-IAM-APM] Password policy '%s' must require symbols", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_account_password_policy")
	rc.change.after.max_password_age > 90
	msg := sprintf("[KSI-IAM-APM] Password policy '%s' max age must not exceed 90 days (got %d)", [rc.address, rc.change.after.max_password_age])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_iam_account_password_policy")
	rc.change.after.password_reuse_prevention < 24
	msg := sprintf("[KSI-IAM-APM] Password policy '%s' must prevent reuse of at least 24 previous passwords", [rc.address])
}
