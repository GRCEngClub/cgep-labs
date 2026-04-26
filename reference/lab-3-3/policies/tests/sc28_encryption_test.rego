package compliance.sc28_test

import rego.v1
import data.compliance.sc28

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {
		"name": "good",
		"encryption": [{"default_kms_key_name": "projects/x/locations/us/keyRings/r/cryptoKeys/k"}],
	},
}]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {
		"name": "bad",
		"encryption": [],
	},
}]}}}

test_compliant_passes if {
	count(sc28.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in sc28.deny with input as noncompliant_input
	contains(msg, "SC-28")
	contains(msg, "google_storage_bucket.bad")
}
