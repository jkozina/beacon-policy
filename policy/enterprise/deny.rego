# policy/enterprise/deny.rego
package beacon.verdict

import rego.v1

deny contains {
  "id": "DESTINATION_UNRESOLVED",
  "message": "Destination FQDN could not be resolved to an owned service"
} if {
  input.spec.destination.resolution.status != "resolved"
}

deny contains {
  "id": "DESTINATION_RETIRED",
  "message": "New connectivity cannot target a retired ServiceNow asset"
} if {
  input.spec.destination.serviceNow.lifecycleState == "retired"
}

deny contains {
  "id": "PUBLIC_TO_RESTRICTED_DENIED",
  "message": "Public-classified workloads cannot access restricted destinations"
} if {
  input.spec.source.dataClassification == "public"
  input.spec.destination.dataClassification == "restricted"
}
