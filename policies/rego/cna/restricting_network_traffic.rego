package cna.restricting_network_traffic

import data.lib.helpers

# KSI-CNA-RNT: Restricting Network Traffic
# "Machine-based information resources are persistently reviewed to ensure they are
#  appropriately configured to limit inbound and outbound network traffic."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_security_group")
	some ingress in rc.change.after.ingress
	some cidr in ingress.cidr_blocks
	cidr == "0.0.0.0/0"
	ingress.from_port != 443
	msg := sprintf("[KSI-CNA-RNT] Security group '%s' allows unrestricted ingress (0.0.0.0/0) on port %d; only port 443 may be open to the internet", [rc.address, ingress.from_port])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_security_group")
	some ingress in rc.change.after.ingress
	some cidr in ingress.ipv6_cidr_blocks
	cidr == "::/0"
	ingress.from_port != 443
	msg := sprintf("[KSI-CNA-RNT] Security group '%s' allows unrestricted IPv6 ingress (::/0) on port %d; only port 443 may be open to the internet", [rc.address, ingress.from_port])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_security_group_rule")
	rc.change.after.type == "ingress"
	some cidr in rc.change.after.cidr_blocks
	cidr == "0.0.0.0/0"
	rc.change.after.from_port != 443
	msg := sprintf("[KSI-CNA-RNT] Security group rule '%s' allows unrestricted ingress (0.0.0.0/0) on port %d", [rc.address, rc.change.after.from_port])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_vpc_security_group_ingress_rule")
	rc.change.after.cidr_ipv4 == "0.0.0.0/0"
	rc.change.after.from_port != 443
	msg := sprintf("[KSI-CNA-RNT] VPC security group ingress rule '%s' allows unrestricted access on port %d", [rc.address, rc.change.after.from_port])
}
