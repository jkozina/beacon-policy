# policy/enterprise/controls.rego
package beacon.verdict

import rego.v1

controls := {
  "primary": primary_control,
  "transitive": transitive_controls,
}

primary_control := {
  "type": "istio-service-entry",
  "owner": "platform-mesh",
  "target": sprintf("%s/%s", [input.spec.source.cluster, input.spec.source.namespace])
}

transitive_controls contains c if {
  input.spec.path.inspectionRequired
  c := {"type": "equinix-pa", "owner": "network-security", "target": "hybrid-egress"}
}

transitive_controls contains c if {
  input.spec.destination.complianceDomain == "pci"
  c := {"type": "onprem-fabric-pa", "owner": "network-security", "target": "pci-datacenter-edge"}
}

transitive_controls contains c if {
  input.spec.destination.dataClassification == "restricted"
  c := {"type": "illumio", "owner": "segmentation", "target": sprintf("%s-workload-policy", [input.spec.destination.serviceId])}
}

transitive_controls contains c if {
  input.spec.destination.dataClassification == "restricted"
  c := {"type": "destination-owner-approval", "owner": input.spec.destination.ownerTeam, "target": input.spec.destination.serviceId}
}

matchedRules contains "TTL_RESTRICTED_DESTINATION_MAX_30D" if {
  input.spec.destination.dataClassification == "restricted"
  input.spec.lifecycle.requestedTtlDays <= 30
}

matchedRules contains "PCI_DESTINATION_REQUIRES_INSPECTION" if {
  input.spec.destination.complianceDomain == "pci"
}

matchedRules contains "RESTRICTED_DESTINATION_REQUIRES_OWNER_POLICY" if {
  input.spec.destination.dataClassification == "restricted"
}
