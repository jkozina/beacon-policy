package beacon.verdict_test

import rego.v1
import data.beacon.verdict

test_unresolved_destination_denies if {
  d := verdict.deny with input as {"spec": {"destination": {"resolution": {"status": "ambiguous"}}, "source": {}, "lifecycle": {"requestedTtlDays": 10}}}
  some r in d
  r.id == "DESTINATION_UNRESOLVED"
}

test_retired_asset_denies if {
  d := verdict.deny with input as {
    "spec": {
      "destination": {"resolution": {"status": "resolved"}, "serviceNow": {"lifecycleState": "retired"}},
      "source": {}, "lifecycle": {"requestedTtlDays": 10}
    }
  }
  some r in d
  r.id == "DESTINATION_RETIRED"
}
