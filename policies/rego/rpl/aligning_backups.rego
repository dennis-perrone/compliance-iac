package rpl.aligning_backups

import data.lib.helpers

# KSI-RPL-ABO: Aligning Backups with Objectives
# "The alignment of machine-based information resource backups with defined
#  recovery objectives is persistently reviewed."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_backup_vault")
	not vault_has_lock(rc.address)
	msg := sprintf("[KSI-RPL-ABO] Backup vault '%s' should have a vault lock for deletion protection", [rc.address])
}

vault_has_lock(vault_address) if {
	some rc in helpers.resources_by_type("aws_backup_vault_lock_configuration")
	contains(rc.address, vault_address)
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_backup_plan")
	some rule in rc.change.after.rule
	not rule.lifecycle
	msg := sprintf("[KSI-RPL-ABO] Backup plan '%s' rule '%s' must define a lifecycle with retention periods", [rc.address, rule.rule_name])
}
