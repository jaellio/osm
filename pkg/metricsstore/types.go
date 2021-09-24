package metricsstore

import (
	corev1 "k8s.io/api/core/v1"
)

type KubeResource interface {
	// ListServices returns a list of all (monitored-namespace filtered) services in the mesh
	ListServices() []*corev1.Service

	// ListServiceAccounts returns a list of all (monitored-namespace filtered) service accounts in the mesh
	ListServiceAccounts() []*corev1.ServiceAccount

	// ListMonitoredNamespaces returns the namespaces monitored by the mesh
	ListMonitoredNamespaces() ([]string, error)

	// ListPods returns a list of pods part of the mesh
	ListPods() []*corev1.Pod
}

/*type SmiResource interface {
	// ListTrafficSplits lists SMI TrafficSplit resources
	ListTrafficSplits(...smi.TrafficSplitListOption) []*split.TrafficSplit

	// ListServiceAccounts lists ServiceAccount resources specified in SMI TrafficTarget resources
	ListServiceAccounts() []identity.K8sServiceAccount

	// ListHTTPTrafficSpecs lists SMI HTTPRouteGroup resources
	ListHTTPTrafficSpecs() []*spec.HTTPRouteGroup

	// GetHTTPRouteGroup returns an SMI HTTPRouteGroup resource given its name of the form <namespace>/<name>
	GetHTTPRouteGroup(string) *spec.HTTPRouteGroup

	// ListTCPTrafficSpecs lists SMI TCPRoute resources
	ListTCPTrafficSpecs() []*spec.TCPRoute

	// GetTCPRoute returns an SMI TCPRoute resource given its name of the form <namespace>/<name>
	GetTCPRoute(string) *spec.TCPRoute

	// ListTrafficTargets lists SMI TrafficTarget resources. An optional filter can be applied to filter the
	// returned list
	ListTrafficTargets(...smi.TrafficTargetListOption) []*access.TrafficTarget
}*/
