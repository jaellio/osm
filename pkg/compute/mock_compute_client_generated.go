// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/openservicemesh/osm/pkg/compute (interfaces: Interface)

// Package compute is a generated GoMock package.
package compute

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	v1alpha1 "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"
	endpoint "github.com/openservicemesh/osm/pkg/endpoint"
	identity "github.com/openservicemesh/osm/pkg/identity"
	models "github.com/openservicemesh/osm/pkg/models"
	service "github.com/openservicemesh/osm/pkg/service"
	v1alpha3 "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/access/v1alpha3"
	v1alpha4 "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/specs/v1alpha4"
	v1alpha20 "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/split/v1alpha2"
	types "k8s.io/apimachinery/pkg/types"
	rest "k8s.io/client-go/rest"
	cache "k8s.io/client-go/tools/cache"
	v1alpha10 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

// MockInterface is a mock of Interface interface.
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface.
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance.
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// AddMeshRootCertificateEventHandler mocks base method.
func (m *MockInterface) AddMeshRootCertificateEventHandler(arg0 cache.ResourceEventHandler) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddMeshRootCertificateEventHandler", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddMeshRootCertificateEventHandler indicates an expected call of AddMeshRootCertificateEventHandler.
func (mr *MockInterfaceMockRecorder) AddMeshRootCertificateEventHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMeshRootCertificateEventHandler", reflect.TypeOf((*MockInterface)(nil).AddMeshRootCertificateEventHandler), arg0)
}

// GetHTTPRouteGroup mocks base method.
func (m *MockInterface) GetHTTPRouteGroup(arg0 string) *v1alpha4.HTTPRouteGroup {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHTTPRouteGroup", arg0)
	ret0, _ := ret[0].(*v1alpha4.HTTPRouteGroup)
	return ret0
}

// GetHTTPRouteGroup indicates an expected call of GetHTTPRouteGroup.
func (mr *MockInterfaceMockRecorder) GetHTTPRouteGroup(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHTTPRouteGroup", reflect.TypeOf((*MockInterface)(nil).GetHTTPRouteGroup), arg0)
}

// GetHostnamesForService mocks base method.
func (m *MockInterface) GetHostnamesForService(arg0 service.MeshService, arg1 bool) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHostnamesForService", arg0, arg1)
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetHostnamesForService indicates an expected call of GetHostnamesForService.
func (mr *MockInterfaceMockRecorder) GetHostnamesForService(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHostnamesForService", reflect.TypeOf((*MockInterface)(nil).GetHostnamesForService), arg0, arg1)
}

// GetIngressBackendPolicyForService mocks base method.
func (m *MockInterface) GetIngressBackendPolicyForService(arg0 service.MeshService) *v1alpha1.IngressBackend {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIngressBackendPolicyForService", arg0)
	ret0, _ := ret[0].(*v1alpha1.IngressBackend)
	return ret0
}

// GetIngressBackendPolicyForService indicates an expected call of GetIngressBackendPolicyForService.
func (mr *MockInterfaceMockRecorder) GetIngressBackendPolicyForService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIngressBackendPolicyForService", reflect.TypeOf((*MockInterface)(nil).GetIngressBackendPolicyForService), arg0)
}

// GetMeshConfig mocks base method.
func (m *MockInterface) GetMeshConfig() v1alpha2.MeshConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshConfig")
	ret0, _ := ret[0].(v1alpha2.MeshConfig)
	return ret0
}

// GetMeshConfig indicates an expected call of GetMeshConfig.
func (mr *MockInterfaceMockRecorder) GetMeshConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshConfig", reflect.TypeOf((*MockInterface)(nil).GetMeshConfig))
}

// GetMeshRootCertificate mocks base method.
func (m *MockInterface) GetMeshRootCertificate(arg0 string) *v1alpha2.MeshRootCertificate {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshRootCertificate", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	return ret0
}

// GetMeshRootCertificate indicates an expected call of GetMeshRootCertificate.
func (mr *MockInterfaceMockRecorder) GetMeshRootCertificate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshRootCertificate", reflect.TypeOf((*MockInterface)(nil).GetMeshRootCertificate), arg0)
}

// GetMeshService mocks base method.
func (m *MockInterface) GetMeshService(arg0, arg1 string, arg2 uint16) (service.MeshService, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshService", arg0, arg1, arg2)
	ret0, _ := ret[0].(service.MeshService)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMeshService indicates an expected call of GetMeshService.
func (mr *MockInterfaceMockRecorder) GetMeshService(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshService", reflect.TypeOf((*MockInterface)(nil).GetMeshService), arg0, arg1, arg2)
}

// GetOSMNamespace mocks base method.
func (m *MockInterface) GetOSMNamespace() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOSMNamespace")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetOSMNamespace indicates an expected call of GetOSMNamespace.
func (mr *MockInterfaceMockRecorder) GetOSMNamespace() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOSMNamespace", reflect.TypeOf((*MockInterface)(nil).GetOSMNamespace))
}

// GetProxyConfig mocks base method.
func (m *MockInterface) GetProxyConfig(arg0 *models.Proxy, arg1 string, arg2 *rest.Config) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProxyConfig", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetProxyConfig indicates an expected call of GetProxyConfig.
func (mr *MockInterfaceMockRecorder) GetProxyConfig(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProxyConfig", reflect.TypeOf((*MockInterface)(nil).GetProxyConfig), arg0, arg1, arg2)
}

// GetProxyStatsHeaders mocks base method.
func (m *MockInterface) GetProxyStatsHeaders(arg0 *models.Proxy) (map[string]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProxyStatsHeaders", arg0)
	ret0, _ := ret[0].(map[string]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetProxyStatsHeaders indicates an expected call of GetProxyStatsHeaders.
func (mr *MockInterfaceMockRecorder) GetProxyStatsHeaders(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProxyStatsHeaders", reflect.TypeOf((*MockInterface)(nil).GetProxyStatsHeaders), arg0)
}

// GetResolvableEndpointsForService mocks base method.
func (m *MockInterface) GetResolvableEndpointsForService(arg0 service.MeshService) []endpoint.Endpoint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetResolvableEndpointsForService", arg0)
	ret0, _ := ret[0].([]endpoint.Endpoint)
	return ret0
}

// GetResolvableEndpointsForService indicates an expected call of GetResolvableEndpointsForService.
func (mr *MockInterfaceMockRecorder) GetResolvableEndpointsForService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetResolvableEndpointsForService", reflect.TypeOf((*MockInterface)(nil).GetResolvableEndpointsForService), arg0)
}

// GetSecret mocks base method.
func (m *MockInterface) GetSecret(arg0, arg1 string) *models.Secret {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecret", arg0, arg1)
	ret0, _ := ret[0].(*models.Secret)
	return ret0
}

// GetSecret indicates an expected call of GetSecret.
func (mr *MockInterfaceMockRecorder) GetSecret(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecret", reflect.TypeOf((*MockInterface)(nil).GetSecret), arg0, arg1)
}

// GetServicesForServiceIdentity mocks base method.
func (m *MockInterface) GetServicesForServiceIdentity(arg0 identity.ServiceIdentity) []service.MeshService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetServicesForServiceIdentity", arg0)
	ret0, _ := ret[0].([]service.MeshService)
	return ret0
}

// GetServicesForServiceIdentity indicates an expected call of GetServicesForServiceIdentity.
func (mr *MockInterfaceMockRecorder) GetServicesForServiceIdentity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetServicesForServiceIdentity", reflect.TypeOf((*MockInterface)(nil).GetServicesForServiceIdentity), arg0)
}

// GetTCPRoute mocks base method.
func (m *MockInterface) GetTCPRoute(arg0 string) *v1alpha4.TCPRoute {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTCPRoute", arg0)
	ret0, _ := ret[0].(*v1alpha4.TCPRoute)
	return ret0
}

// GetTCPRoute indicates an expected call of GetTCPRoute.
func (mr *MockInterfaceMockRecorder) GetTCPRoute(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTCPRoute", reflect.TypeOf((*MockInterface)(nil).GetTCPRoute), arg0)
}

// GetTelemetryConfig mocks base method.
func (m *MockInterface) GetTelemetryConfig(arg0 *models.Proxy) models.TelemetryConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTelemetryConfig", arg0)
	ret0, _ := ret[0].(models.TelemetryConfig)
	return ret0
}

// GetTelemetryConfig indicates an expected call of GetTelemetryConfig.
func (mr *MockInterfaceMockRecorder) GetTelemetryConfig(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTelemetryConfig", reflect.TypeOf((*MockInterface)(nil).GetTelemetryConfig), arg0)
}

// GetUpstreamTrafficSetting mocks base method.
func (m *MockInterface) GetUpstreamTrafficSetting(arg0 *types.NamespacedName) *v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpstreamTrafficSetting", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// GetUpstreamTrafficSetting indicates an expected call of GetUpstreamTrafficSetting.
func (mr *MockInterfaceMockRecorder) GetUpstreamTrafficSetting(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpstreamTrafficSetting", reflect.TypeOf((*MockInterface)(nil).GetUpstreamTrafficSetting), arg0)
}

// GetUpstreamTrafficSettingByHost mocks base method.
func (m *MockInterface) GetUpstreamTrafficSettingByHost(arg0 string) *v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpstreamTrafficSettingByHost", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// GetUpstreamTrafficSettingByHost indicates an expected call of GetUpstreamTrafficSettingByHost.
func (mr *MockInterfaceMockRecorder) GetUpstreamTrafficSettingByHost(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpstreamTrafficSettingByHost", reflect.TypeOf((*MockInterface)(nil).GetUpstreamTrafficSettingByHost), arg0)
}

// GetUpstreamTrafficSettingByNamespace mocks base method.
func (m *MockInterface) GetUpstreamTrafficSettingByNamespace(arg0 *types.NamespacedName) *v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpstreamTrafficSettingByNamespace", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// GetUpstreamTrafficSettingByNamespace indicates an expected call of GetUpstreamTrafficSettingByNamespace.
func (mr *MockInterfaceMockRecorder) GetUpstreamTrafficSettingByNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpstreamTrafficSettingByNamespace", reflect.TypeOf((*MockInterface)(nil).GetUpstreamTrafficSettingByNamespace), arg0)
}

// GetUpstreamTrafficSettingByService mocks base method.
func (m *MockInterface) GetUpstreamTrafficSettingByService(arg0 *service.MeshService) *v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpstreamTrafficSettingByService", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// GetUpstreamTrafficSettingByService indicates an expected call of GetUpstreamTrafficSettingByService.
func (mr *MockInterfaceMockRecorder) GetUpstreamTrafficSettingByService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpstreamTrafficSettingByService", reflect.TypeOf((*MockInterface)(nil).GetUpstreamTrafficSettingByService), arg0)
}

// IsMetricsEnabled mocks base method.
func (m *MockInterface) IsMetricsEnabled(arg0 *models.Proxy) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMetricsEnabled", arg0)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsMetricsEnabled indicates an expected call of IsMetricsEnabled.
func (mr *MockInterfaceMockRecorder) IsMetricsEnabled(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMetricsEnabled", reflect.TypeOf((*MockInterface)(nil).IsMetricsEnabled), arg0)
}

// IsMonitoredNamespace mocks base method.
func (m *MockInterface) IsMonitoredNamespace(arg0 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMonitoredNamespace", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsMonitoredNamespace indicates an expected call of IsMonitoredNamespace.
func (mr *MockInterfaceMockRecorder) IsMonitoredNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMonitoredNamespace", reflect.TypeOf((*MockInterface)(nil).IsMonitoredNamespace), arg0)
}

// ListEgressPolicies mocks base method.
func (m *MockInterface) ListEgressPolicies() []*v1alpha1.Egress {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEgressPolicies")
	ret0, _ := ret[0].([]*v1alpha1.Egress)
	return ret0
}

// ListEgressPolicies indicates an expected call of ListEgressPolicies.
func (mr *MockInterfaceMockRecorder) ListEgressPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEgressPolicies", reflect.TypeOf((*MockInterface)(nil).ListEgressPolicies))
}

// ListEgressPoliciesForServiceAccount mocks base method.
func (m *MockInterface) ListEgressPoliciesForServiceAccount(arg0 identity.K8sServiceAccount) []*v1alpha1.Egress {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEgressPoliciesForServiceAccount", arg0)
	ret0, _ := ret[0].([]*v1alpha1.Egress)
	return ret0
}

// ListEgressPoliciesForServiceAccount indicates an expected call of ListEgressPoliciesForServiceAccount.
func (mr *MockInterfaceMockRecorder) ListEgressPoliciesForServiceAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEgressPoliciesForServiceAccount", reflect.TypeOf((*MockInterface)(nil).ListEgressPoliciesForServiceAccount), arg0)
}

// ListEndpointsForIdentity mocks base method.
func (m *MockInterface) ListEndpointsForIdentity(arg0 identity.ServiceIdentity) []endpoint.Endpoint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEndpointsForIdentity", arg0)
	ret0, _ := ret[0].([]endpoint.Endpoint)
	return ret0
}

// ListEndpointsForIdentity indicates an expected call of ListEndpointsForIdentity.
func (mr *MockInterfaceMockRecorder) ListEndpointsForIdentity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEndpointsForIdentity", reflect.TypeOf((*MockInterface)(nil).ListEndpointsForIdentity), arg0)
}

// ListEndpointsForService mocks base method.
func (m *MockInterface) ListEndpointsForService(arg0 service.MeshService) []endpoint.Endpoint {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEndpointsForService", arg0)
	ret0, _ := ret[0].([]endpoint.Endpoint)
	return ret0
}

// ListEndpointsForService indicates an expected call of ListEndpointsForService.
func (mr *MockInterfaceMockRecorder) ListEndpointsForService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEndpointsForService", reflect.TypeOf((*MockInterface)(nil).ListEndpointsForService), arg0)
}

// ListHTTPTrafficSpecs mocks base method.
func (m *MockInterface) ListHTTPTrafficSpecs() []*v1alpha4.HTTPRouteGroup {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListHTTPTrafficSpecs")
	ret0, _ := ret[0].([]*v1alpha4.HTTPRouteGroup)
	return ret0
}

// ListHTTPTrafficSpecs indicates an expected call of ListHTTPTrafficSpecs.
func (mr *MockInterfaceMockRecorder) ListHTTPTrafficSpecs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListHTTPTrafficSpecs", reflect.TypeOf((*MockInterface)(nil).ListHTTPTrafficSpecs))
}

// ListIngressBackendPolicies mocks base method.
func (m *MockInterface) ListIngressBackendPolicies() []*v1alpha1.IngressBackend {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListIngressBackendPolicies")
	ret0, _ := ret[0].([]*v1alpha1.IngressBackend)
	return ret0
}

// ListIngressBackendPolicies indicates an expected call of ListIngressBackendPolicies.
func (mr *MockInterfaceMockRecorder) ListIngressBackendPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListIngressBackendPolicies", reflect.TypeOf((*MockInterface)(nil).ListIngressBackendPolicies))
}

// ListMeshRootCertificates mocks base method.
func (m *MockInterface) ListMeshRootCertificates() ([]*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListMeshRootCertificates")
	ret0, _ := ret[0].([]*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListMeshRootCertificates indicates an expected call of ListMeshRootCertificates.
func (mr *MockInterfaceMockRecorder) ListMeshRootCertificates() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListMeshRootCertificates", reflect.TypeOf((*MockInterface)(nil).ListMeshRootCertificates))
}

// ListNamespaces mocks base method.
func (m *MockInterface) ListNamespaces() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListNamespaces")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListNamespaces indicates an expected call of ListNamespaces.
func (mr *MockInterfaceMockRecorder) ListNamespaces() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListNamespaces", reflect.TypeOf((*MockInterface)(nil).ListNamespaces))
}

// ListRetryPolicies mocks base method.
func (m *MockInterface) ListRetryPolicies() []*v1alpha1.Retry {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRetryPolicies")
	ret0, _ := ret[0].([]*v1alpha1.Retry)
	return ret0
}

// ListRetryPolicies indicates an expected call of ListRetryPolicies.
func (mr *MockInterfaceMockRecorder) ListRetryPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRetryPolicies", reflect.TypeOf((*MockInterface)(nil).ListRetryPolicies))
}

// ListRetryPoliciesForServiceAccount mocks base method.
func (m *MockInterface) ListRetryPoliciesForServiceAccount(arg0 identity.K8sServiceAccount) []*v1alpha1.Retry {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRetryPoliciesForServiceAccount", arg0)
	ret0, _ := ret[0].([]*v1alpha1.Retry)
	return ret0
}

// ListRetryPoliciesForServiceAccount indicates an expected call of ListRetryPoliciesForServiceAccount.
func (mr *MockInterfaceMockRecorder) ListRetryPoliciesForServiceAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRetryPoliciesForServiceAccount", reflect.TypeOf((*MockInterface)(nil).ListRetryPoliciesForServiceAccount), arg0)
}

// ListSecrets mocks base method.
func (m *MockInterface) ListSecrets() []*models.Secret {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListSecrets")
	ret0, _ := ret[0].([]*models.Secret)
	return ret0
}

// ListSecrets indicates an expected call of ListSecrets.
func (mr *MockInterfaceMockRecorder) ListSecrets() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListSecrets", reflect.TypeOf((*MockInterface)(nil).ListSecrets))
}

// ListServiceExports mocks base method.
func (m *MockInterface) ListServiceExports() []*v1alpha10.ServiceExport {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceExports")
	ret0, _ := ret[0].([]*v1alpha10.ServiceExport)
	return ret0
}

// ListServiceExports indicates an expected call of ListServiceExports.
func (mr *MockInterfaceMockRecorder) ListServiceExports() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceExports", reflect.TypeOf((*MockInterface)(nil).ListServiceExports))
}

// ListServiceIdentitiesForService mocks base method.
func (m *MockInterface) ListServiceIdentitiesForService(arg0, arg1 string) ([]identity.ServiceIdentity, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceIdentitiesForService", arg0, arg1)
	ret0, _ := ret[0].([]identity.ServiceIdentity)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListServiceIdentitiesForService indicates an expected call of ListServiceIdentitiesForService.
func (mr *MockInterfaceMockRecorder) ListServiceIdentitiesForService(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceIdentitiesForService", reflect.TypeOf((*MockInterface)(nil).ListServiceIdentitiesForService), arg0, arg1)
}

// ListServiceImports mocks base method.
func (m *MockInterface) ListServiceImports() []*v1alpha10.ServiceImport {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceImports")
	ret0, _ := ret[0].([]*v1alpha10.ServiceImport)
	return ret0
}

// ListServiceImports indicates an expected call of ListServiceImports.
func (mr *MockInterfaceMockRecorder) ListServiceImports() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceImports", reflect.TypeOf((*MockInterface)(nil).ListServiceImports))
}

// ListServices mocks base method.
func (m *MockInterface) ListServices() []service.MeshService {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServices")
	ret0, _ := ret[0].([]service.MeshService)
	return ret0
}

// ListServices indicates an expected call of ListServices.
func (mr *MockInterfaceMockRecorder) ListServices() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServices", reflect.TypeOf((*MockInterface)(nil).ListServices))
}

// ListServicesForProxy mocks base method.
func (m *MockInterface) ListServicesForProxy(arg0 *models.Proxy) ([]service.MeshService, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServicesForProxy", arg0)
	ret0, _ := ret[0].([]service.MeshService)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListServicesForProxy indicates an expected call of ListServicesForProxy.
func (mr *MockInterfaceMockRecorder) ListServicesForProxy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServicesForProxy", reflect.TypeOf((*MockInterface)(nil).ListServicesForProxy), arg0)
}

// ListTCPTrafficSpecs mocks base method.
func (m *MockInterface) ListTCPTrafficSpecs() []*v1alpha4.TCPRoute {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTCPTrafficSpecs")
	ret0, _ := ret[0].([]*v1alpha4.TCPRoute)
	return ret0
}

// ListTCPTrafficSpecs indicates an expected call of ListTCPTrafficSpecs.
func (mr *MockInterfaceMockRecorder) ListTCPTrafficSpecs() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTCPTrafficSpecs", reflect.TypeOf((*MockInterface)(nil).ListTCPTrafficSpecs))
}

// ListTrafficSplits mocks base method.
func (m *MockInterface) ListTrafficSplits() []*v1alpha20.TrafficSplit {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTrafficSplits")
	ret0, _ := ret[0].([]*v1alpha20.TrafficSplit)
	return ret0
}

// ListTrafficSplits indicates an expected call of ListTrafficSplits.
func (mr *MockInterfaceMockRecorder) ListTrafficSplits() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTrafficSplits", reflect.TypeOf((*MockInterface)(nil).ListTrafficSplits))
}

// ListTrafficTargets mocks base method.
func (m *MockInterface) ListTrafficTargets() []*v1alpha3.TrafficTarget {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListTrafficTargets")
	ret0, _ := ret[0].([]*v1alpha3.TrafficTarget)
	return ret0
}

// ListTrafficTargets indicates an expected call of ListTrafficTargets.
func (mr *MockInterfaceMockRecorder) ListTrafficTargets() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTrafficTargets", reflect.TypeOf((*MockInterface)(nil).ListTrafficTargets))
}

// ListUpstreamTrafficSettings mocks base method.
func (m *MockInterface) ListUpstreamTrafficSettings() []*v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUpstreamTrafficSettings")
	ret0, _ := ret[0].([]*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// ListUpstreamTrafficSettings indicates an expected call of ListUpstreamTrafficSettings.
func (mr *MockInterfaceMockRecorder) ListUpstreamTrafficSettings() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUpstreamTrafficSettings", reflect.TypeOf((*MockInterface)(nil).ListUpstreamTrafficSettings))
}

// UpdateIngressBackendStatus mocks base method.
func (m *MockInterface) UpdateIngressBackendStatus(arg0 *v1alpha1.IngressBackend) (*v1alpha1.IngressBackend, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateIngressBackendStatus", arg0)
	ret0, _ := ret[0].(*v1alpha1.IngressBackend)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIngressBackendStatus indicates an expected call of UpdateIngressBackendStatus.
func (mr *MockInterfaceMockRecorder) UpdateIngressBackendStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIngressBackendStatus", reflect.TypeOf((*MockInterface)(nil).UpdateIngressBackendStatus), arg0)
}

// UpdateMeshRootCertificate mocks base method.
func (m *MockInterface) UpdateMeshRootCertificate(arg0 *v1alpha2.MeshRootCertificate) (*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateMeshRootCertificate", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateMeshRootCertificate indicates an expected call of UpdateMeshRootCertificate.
func (mr *MockInterfaceMockRecorder) UpdateMeshRootCertificate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMeshRootCertificate", reflect.TypeOf((*MockInterface)(nil).UpdateMeshRootCertificate), arg0)
}

// UpdateMeshRootCertificateStatus mocks base method.
func (m *MockInterface) UpdateMeshRootCertificateStatus(arg0 *v1alpha2.MeshRootCertificate) (*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateMeshRootCertificateStatus", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateMeshRootCertificateStatus indicates an expected call of UpdateMeshRootCertificateStatus.
func (mr *MockInterfaceMockRecorder) UpdateMeshRootCertificateStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMeshRootCertificateStatus", reflect.TypeOf((*MockInterface)(nil).UpdateMeshRootCertificateStatus), arg0)
}

// UpdateSecret mocks base method.
func (m *MockInterface) UpdateSecret(arg0 context.Context, arg1 *models.Secret) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateSecret", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateSecret indicates an expected call of UpdateSecret.
func (mr *MockInterfaceMockRecorder) UpdateSecret(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateSecret", reflect.TypeOf((*MockInterface)(nil).UpdateSecret), arg0, arg1)
}

// UpdateUpstreamTrafficSettingStatus mocks base method.
func (m *MockInterface) UpdateUpstreamTrafficSettingStatus(arg0 *v1alpha1.UpstreamTrafficSetting) (*v1alpha1.UpstreamTrafficSetting, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUpstreamTrafficSettingStatus", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUpstreamTrafficSettingStatus indicates an expected call of UpdateUpstreamTrafficSettingStatus.
func (mr *MockInterfaceMockRecorder) UpdateUpstreamTrafficSettingStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUpstreamTrafficSettingStatus", reflect.TypeOf((*MockInterface)(nil).UpdateUpstreamTrafficSettingStatus), arg0)
}

// VerifyProxy mocks base method.
func (m *MockInterface) VerifyProxy(arg0 *models.Proxy) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyProxy", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyProxy indicates an expected call of VerifyProxy.
func (mr *MockInterfaceMockRecorder) VerifyProxy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyProxy", reflect.TypeOf((*MockInterface)(nil).VerifyProxy), arg0)
}
