package lib.helpers

resource_changes contains rc if {
	some rc in input.resource_changes
	some action in rc.change.actions
	action != "delete"
}

resources_by_type(type) := resources if {
	resources := [rc |
		some rc in resource_changes
		rc.type == type
	]
}

has_tag(resource, key) if {
	resource.change.after.tags[key]
}

has_tag(resource, key) if {
	resource.change.after.tags_all[key]
}
