package cna.reviewing_protections

import data.lib.helpers

# KSI-CNA-RVP: Reviewing Protections
# "The effectiveness of protection against denial of service attacks and other
#  unwanted activity for machine-based information resources is persistently reviewed."

deny contains msg if {
	some rc in helpers.resources_by_type("aws_lb")
	rc.change.after.load_balancer_type == "application"
	not lb_has_waf(rc.address)
	not lb_has_waf(rc.change.after_unknown.arn)
	msg := sprintf("[KSI-CNA-RVP] Application load balancer '%s' should have WAF associated for protection against unwanted activity", [rc.address])
}

lb_has_waf(lb_ref) if {
	some rc in helpers.resources_by_type("aws_wafv2_web_acl_association")
	rc.change.after.resource_arn == lb_ref
}
