package svc.automating_secret_management

import data.lib.helpers

# KSI-SVC-ASM: Automating Secret Management
# "Management, protection, and regular rotation of digital keys, certificates,
#  and other secrets is automated and persistently reviewed."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_kms_key")
	not rc.change.after.enable_key_rotation
	msg := sprintf("[KSI-SVC-ASM] KMS key '%s' must have automatic key rotation enabled", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_secretsmanager_secret")
	not secret_has_rotation(rc.address)
	msg := sprintf("[KSI-SVC-ASM] Secret '%s' should have automatic rotation configured", [rc.address])
}

secret_has_rotation(secret_address) if {
	some rc in helpers.resources_by_type("aws_secretsmanager_secret_rotation")
	contains(rc.address, secret_address)
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_secretsmanager_secret")
	not rc.change.after.kms_key_id
	msg := sprintf("[KSI-SVC-ASM] Secret '%s' must be encrypted with a customer-managed KMS key", [rc.address])
}
