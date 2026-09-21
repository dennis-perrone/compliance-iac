package cna.minimizing_attack_surface

import data.lib.helpers

# KSI-CNA-MAT: Minimizing Attack Surface
# "Machine-based information resources are persistently reviewed to ensure they
#  have a minimal attack surface and that lateral movement is minimized if compromised."

deny contains msg if {
	count(helpers.resources_by_type("aws_guardduty_detector")) == 0
	count(helpers.resources_by_type("aws_guardduty_detector")) != count(helpers.resources_by_type("aws_guardduty_detector"))
	msg := "[KSI-CNA-MAT] GuardDuty must be enabled for threat detection"
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_guardduty_detector")
	not rc.change.after.enable
	msg := sprintf("[KSI-CNA-MAT] GuardDuty detector '%s' must be enabled", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_instance")
	rc.change.after.associate_public_ip_address
	msg := sprintf("[KSI-CNA-MAT] EC2 instance '%s' has a public IP; use private subnets with NAT or load balancers", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_db_instance")
	rc.change.after.publicly_accessible
	msg := sprintf("[KSI-CNA-MAT] RDS instance '%s' must not be publicly accessible", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_s3_bucket_public_access_block")
	not rc.change.after.block_public_acls
	msg := sprintf("[KSI-CNA-MAT] S3 public access block '%s' must block public ACLs", [rc.address])
}

deny contains msg if {
	some rc in helpers.resources_by_type("aws_s3_bucket_public_access_block")
	not rc.change.after.block_public_policy
	msg := sprintf("[KSI-CNA-MAT] S3 public access block '%s' must block public policies", [rc.address])
}
