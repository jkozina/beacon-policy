package beacon.verdict_test

import rego.v1

import data.beacon.verdict

test_ttl_exceeds_max_for_restricted_destination if {
  result := verdict.deny with input as {
    "spec": {
      "destination": {"dataClassification": "restricted"},
      "lifecycle": {"requestedTtlDays": 120}
    }
  }
  some d in result
  d.id == "TTL_EXCEEDS_MAX"
}

test_ttl_within_max_for_restricted_destination_passes if {
  result := verdict.deny with input as {
    "spec": {
      "destination": {"dataClassification": "restricted"},
      "lifecycle": {"requestedTtlDays": 30}
    }
  }
  not has_ttl_deny(result)
}

has_ttl_deny(denies) if {
  some d in denies
  d.id == "TTL_EXCEEDS_MAX"
}
