package beacon.verdict_test

import rego.v1
import data.beacon.verdict

input_pci := {
  "spec": {
    "source": {"cluster": "eks-prod", "namespace": "orders"},
    "destination": {"complianceDomain": "pci", "dataClassification": "restricted", "serviceId": "app-x", "ownerTeam": "team-x"},
    "path": {"inspectionRequired": true},
    "lifecycle": {"requestedTtlDays": 30},
  }
}

test_pci_destination_emits_inspection_control if {
  c := verdict.controls with input as input_pci
  some t in c.transitive
  t.type == "equinix-pa"
}

test_restricted_destination_emits_owner_approval if {
  c := verdict.controls with input as input_pci
  some t in c.transitive
  t.type == "destination-owner-approval"
}
