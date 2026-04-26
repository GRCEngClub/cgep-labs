package compliance.ac3_test

import rego.v1
import data.compliance.ac3

compliant_bucket := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {
		"name": "good",
		"uniform_bucket_level_access": true,
		"public_access_prevention": "enforced",
	},
}]}}}

public_bucket := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {
		"name": "bad",
		"uniform_bucket_level_access": false,
		"public_access_prevention": "inherited",
	},
}]}}}

open_firewall := {"planned_values": {"root_module": {"resources": [{
	"address": "google_compute_firewall.open_ssh",
	"type": "google_compute_firewall",
	"values": {
		"name": "open-ssh",
		"direction": "INGRESS",
		"source_ranges": ["0.0.0.0/0"],
		"allow": [{"protocol": "tcp", "ports": ["22"]}],
	},
}]}}}

test_compliant_bucket_passes if {
	count(ac3.deny) == 0 with input as compliant_bucket
}

test_public_bucket_fails if {
	some msg in ac3.deny with input as public_bucket
	contains(msg, "AC-3")
}

test_open_management_port_fails if {
	some msg in ac3.deny with input as open_firewall
	contains(msg, "AC-3")
	contains(msg, "22")
}
