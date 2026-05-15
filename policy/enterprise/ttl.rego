package beacon.verdict

import rego.v1

max_ttl_days := 30 if {
  input.spec.destination.dataClassification == "restricted"
} else := 90 if {
  input.spec.source.environment == "prod"
} else := 180

deny contains {
  "id": "TTL_EXCEEDS_MAX",
  "message": sprintf("Requested TTL of %d days exceeds maximum of %d days", [input.spec.lifecycle.requestedTtlDays, max_ttl_days])
} if {
  input.spec.lifecycle.requestedTtlDays > max_ttl_days
}

default allow := false

allow if {
  count(deny) == 0
}
