package lib.exceptions

import data.exceptions as exception_list

is_excepted(resource_address, ksi) if {
	some exc in exception_list
	exc.resource == resource_address
	exc.ksi == ksi
	not is_expired(exc)
}

is_expired(exc) if {
	time.now_ns() > time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [exc.expires]))
}

expired_exceptions contains exc if {
	some exc in exception_list
	is_expired(exc)
}
