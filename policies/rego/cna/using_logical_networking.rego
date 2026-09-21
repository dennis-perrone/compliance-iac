package cna.using_logical_networking

import data.lib.helpers

# KSI-CNA-ULN: Using Logical Networking
# "Logical networking and related capabilities are used and persistently reviewed
#  to enforce traffic flow controls."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_vpc")
	not vpc_has_nacl(rc.address)
	not vpc_has_nacl(rc.change.after_unknown.id)
	msg := sprintf("[KSI-CNA-ULN] VPC '%s' should have custom network ACLs for traffic flow control", [rc.address])
}

vpc_has_nacl(vpc_ref) if {
	some rc in helpers.resources_by_type("aws_network_acl")
	rc.change.after.vpc_id == vpc_ref
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_security_group")
	some egress in rc.change.after.egress
	some cidr in egress.cidr_blocks
	cidr == "0.0.0.0/0"
	egress.protocol == "-1"
	msg := sprintf("[KSI-CNA-ULN] Security group '%s' allows unrestricted egress (0.0.0.0/0 all protocols); restrict outbound traffic", [rc.address])
}
