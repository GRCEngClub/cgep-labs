package compliance.cm6_test

import rego.v1
import data.compliance.cm6

complete_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.good",
	"type": "google_storage_bucket",
	"values": {
		"name": "good",
		"labels": {
			"project": "x",
			"environment": "dev",
			"managed_by": "terraform",
			"compliance_scope": "cge-p-lab",
		},
	},
}]}}}

missing_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.bad",
	"type": "google_storage_bucket",
	"values": {
		"name": "bad",
		"labels": {"project": "x"},
	},
}]}}}

no_labels := {"planned_values": {"root_module": {"resources": [{
	"address": "google_storage_bucket.naked",
	"type": "google_storage_bucket",
	"values": {"name": "naked"},
}]}}}

test_complete_labels_pass if {
	count(cm6.deny) == 0 with input as complete_labels
}

test_partial_labels_fail if {
	some msg in cm6.deny with input as missing_labels
	contains(msg, "CM-6")
	contains(msg, "google_storage_bucket.bad")
}

test_no_labels_fail if {
	some msg in cm6.deny with input as no_labels
	contains(msg, "CM-6")
}
