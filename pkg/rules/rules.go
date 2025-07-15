package rules

import (
	"k8s-scanner/pkg/types"
	"k8s-scanner/pkg/rules/cis"
	"k8s-scanner/pkg/rules/nist"
)

func RegisterCISRules(registry *types.RuleRegistry) {
	registry.Register(cis.NewPodSecurityContextRule())
	registry.Register(cis.NewPrivilegedContainerRule())
	registry.Register(cis.NewRootFilesystemRule())
	registry.Register(cis.NewCapabilitiesRule())
	registry.Register(cis.NewHostNetworkRule())
	registry.Register(cis.NewHostPIDRule())
	registry.Register(cis.NewHostIPCRule())
	registry.Register(cis.NewSeccompProfileRule())
	registry.Register(cis.NewAppArmorProfileRule())
	registry.Register(cis.NewServiceAccountTokenRule())
}

func RegisterNISTRules(registry *types.RuleRegistry) {
	registry.Register(nist.NewImageVulnerabilityRule())
	registry.Register(nist.NewContainerRuntimeRule())
	registry.Register(nist.NewNetworkSegmentationRule())
	registry.Register(nist.NewResourceLimitsRule())
	registry.Register(nist.NewSecretManagementRule())
	registry.Register(nist.NewAccessControlRule())
	registry.Register(nist.NewLoggingMonitoringRule())
	registry.Register(nist.NewImageSigningRule())
}