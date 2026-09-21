package svc.automating_config_management

import data.lib.helpers

# KSI-SVC-ACM: Automating Configuration Management
# "The configuration of machine-based information resources is managed using
#  automation and persistently reviewed for drift."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_config_configuration_recorder")
	some rg in rc.change.after.recording_group
	not rg.all_supported
	msg := sprintf("[KSI-SVC-ACM] AWS Config recorder '%s' must record all supported resource types", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_config_configuration_recorder_status")
	not rc.change.after.is_enabled
	msg := sprintf("[KSI-SVC-ACM] AWS Config recorder '%s' must be enabled", [rc.address])
}
