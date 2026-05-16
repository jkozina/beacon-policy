# policy/destinations/payments.rego
package beacon.verdict

import rego.v1

deny contains {
  "id": "PAYMENTS_DEST_BLOCKS_SOURCE_ZONE",
  "message": "Source trust zone is blocked by destination owner policy"
} if {
  input.spec.destination.serviceId == "app-payments-api"
  input.spec.source.trustZone == "internet"
}
