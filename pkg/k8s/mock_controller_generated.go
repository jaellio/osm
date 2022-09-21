// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/openservicemesh/osm/pkg/k8s (interfaces: Controller)

// Package k8s is a generated GoMock package.
package k8s

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	v1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	v1alpha1 "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"
	envoy "github.com/openservicemesh/osm/pkg/envoy"
	v1 "k8s.io/api/core/v1"
	types "k8s.io/apimachinery/pkg/types"
	cache "k8s.io/client-go/tools/cache"
)

// MockController is a mock of Controller interface.
type MockController struct {
	ctrl     *gomock.Controller
	recorder *MockControllerMockRecorder
}

// MockControllerMockRecorder is the mock recorder for MockController.
type MockControllerMockRecorder struct {
	mock *MockController
}

// NewMockController creates a new mock instance.
func NewMockController(ctrl *gomock.Controller) *MockController {
	mock := &MockController{ctrl: ctrl}
	mock.recorder = &MockControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockController) EXPECT() *MockControllerMockRecorder {
	return m.recorder
}

// AddMRCEventsHandler mocks base method.
func (m *MockController) AddMRCEventsHandler(arg0 cache.ResourceEventHandlerFuncs) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AddMRCEventsHandler", arg0)
}

// AddMRCEventsHandler indicates an expected call of AddMRCEventsHandler.
func (mr *MockControllerMockRecorder) AddMRCEventsHandler(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddMRCEventsHandler", reflect.TypeOf((*MockController)(nil).AddMRCEventsHandler), arg0)
}

// GetEndpoints mocks base method.
func (m *MockController) GetEndpoints(arg0, arg1 string) (*v1.Endpoints, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEndpoints", arg0, arg1)
	ret0, _ := ret[0].(*v1.Endpoints)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEndpoints indicates an expected call of GetEndpoints.
func (mr *MockControllerMockRecorder) GetEndpoints(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEndpoints", reflect.TypeOf((*MockController)(nil).GetEndpoints), arg0, arg1)
}

// GetMeshConfig mocks base method.
func (m *MockController) GetMeshConfig() v1alpha2.MeshConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshConfig")
	ret0, _ := ret[0].(v1alpha2.MeshConfig)
	return ret0
}

// GetMeshConfig indicates an expected call of GetMeshConfig.
func (mr *MockControllerMockRecorder) GetMeshConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshConfig", reflect.TypeOf((*MockController)(nil).GetMeshConfig))
}

// GetMeshRootCertificate mocks base method.
func (m *MockController) GetMeshRootCertificate(arg0 string) *v1alpha2.MeshRootCertificate {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMeshRootCertificate", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	return ret0
}

// GetMeshRootCertificate indicates an expected call of GetMeshRootCertificate.
func (mr *MockControllerMockRecorder) GetMeshRootCertificate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMeshRootCertificate", reflect.TypeOf((*MockController)(nil).GetMeshRootCertificate), arg0)
}

// GetNamespace mocks base method.
func (m *MockController) GetNamespace(arg0 string) *v1.Namespace {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespace", arg0)
	ret0, _ := ret[0].(*v1.Namespace)
	return ret0
}

// GetNamespace indicates an expected call of GetNamespace.
func (mr *MockControllerMockRecorder) GetNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespace", reflect.TypeOf((*MockController)(nil).GetNamespace), arg0)
}

// GetOSMNamespace mocks base method.
func (m *MockController) GetOSMNamespace() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOSMNamespace")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetOSMNamespace indicates an expected call of GetOSMNamespace.
func (mr *MockControllerMockRecorder) GetOSMNamespace() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOSMNamespace", reflect.TypeOf((*MockController)(nil).GetOSMNamespace))
}

// GetPodForProxy mocks base method.
func (m *MockController) GetPodForProxy(arg0 *envoy.Proxy) (*v1.Pod, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPodForProxy", arg0)
	ret0, _ := ret[0].(*v1.Pod)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPodForProxy indicates an expected call of GetPodForProxy.
func (mr *MockControllerMockRecorder) GetPodForProxy(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPodForProxy", reflect.TypeOf((*MockController)(nil).GetPodForProxy), arg0)
}

// GetService mocks base method.
func (m *MockController) GetService(arg0, arg1 string) *v1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetService", arg0, arg1)
	ret0, _ := ret[0].(*v1.Service)
	return ret0
}

// GetService indicates an expected call of GetService.
func (mr *MockControllerMockRecorder) GetService(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetService", reflect.TypeOf((*MockController)(nil).GetService), arg0, arg1)
}

// GetUpstreamTrafficSetting mocks base method.
func (m *MockController) GetUpstreamTrafficSetting(arg0 *types.NamespacedName) *v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUpstreamTrafficSetting", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// GetUpstreamTrafficSetting indicates an expected call of GetUpstreamTrafficSetting.
func (mr *MockControllerMockRecorder) GetUpstreamTrafficSetting(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUpstreamTrafficSetting", reflect.TypeOf((*MockController)(nil).GetUpstreamTrafficSetting), arg0)
}

// IsMonitoredNamespace mocks base method.
func (m *MockController) IsMonitoredNamespace(arg0 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMonitoredNamespace", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsMonitoredNamespace indicates an expected call of IsMonitoredNamespace.
func (mr *MockControllerMockRecorder) IsMonitoredNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMonitoredNamespace", reflect.TypeOf((*MockController)(nil).IsMonitoredNamespace), arg0)
}

// ListEgressPolicies mocks base method.
func (m *MockController) ListEgressPolicies() []*v1alpha1.Egress {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListEgressPolicies")
	ret0, _ := ret[0].([]*v1alpha1.Egress)
	return ret0
}

// ListEgressPolicies indicates an expected call of ListEgressPolicies.
func (mr *MockControllerMockRecorder) ListEgressPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListEgressPolicies", reflect.TypeOf((*MockController)(nil).ListEgressPolicies))
}

// ListIngressBackendPolicies mocks base method.
func (m *MockController) ListIngressBackendPolicies() []*v1alpha1.IngressBackend {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListIngressBackendPolicies")
	ret0, _ := ret[0].([]*v1alpha1.IngressBackend)
	return ret0
}

// ListIngressBackendPolicies indicates an expected call of ListIngressBackendPolicies.
func (mr *MockControllerMockRecorder) ListIngressBackendPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListIngressBackendPolicies", reflect.TypeOf((*MockController)(nil).ListIngressBackendPolicies))
}

// ListMeshRootCertificates mocks base method.
func (m *MockController) ListMeshRootCertificates() ([]*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListMeshRootCertificates")
	ret0, _ := ret[0].([]*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListMeshRootCertificates indicates an expected call of ListMeshRootCertificates.
func (mr *MockControllerMockRecorder) ListMeshRootCertificates() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListMeshRootCertificates", reflect.TypeOf((*MockController)(nil).ListMeshRootCertificates))
}

// ListNamespaces mocks base method.
func (m *MockController) ListNamespaces() ([]*v1.Namespace, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListNamespaces")
	ret0, _ := ret[0].([]*v1.Namespace)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListNamespaces indicates an expected call of ListNamespaces.
func (mr *MockControllerMockRecorder) ListNamespaces() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListNamespaces", reflect.TypeOf((*MockController)(nil).ListNamespaces))
}

// ListPods mocks base method.
func (m *MockController) ListPods() []*v1.Pod {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPods")
	ret0, _ := ret[0].([]*v1.Pod)
	return ret0
}

// ListPods indicates an expected call of ListPods.
func (mr *MockControllerMockRecorder) ListPods() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPods", reflect.TypeOf((*MockController)(nil).ListPods))
}

// ListRetryPolicies mocks base method.
func (m *MockController) ListRetryPolicies() []*v1alpha1.Retry {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListRetryPolicies")
	ret0, _ := ret[0].([]*v1alpha1.Retry)
	return ret0
}

// ListRetryPolicies indicates an expected call of ListRetryPolicies.
func (mr *MockControllerMockRecorder) ListRetryPolicies() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListRetryPolicies", reflect.TypeOf((*MockController)(nil).ListRetryPolicies))
}

// ListServiceAccounts mocks base method.
func (m *MockController) ListServiceAccounts() []*v1.ServiceAccount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceAccounts")
	ret0, _ := ret[0].([]*v1.ServiceAccount)
	return ret0
}

// ListServiceAccounts indicates an expected call of ListServiceAccounts.
func (mr *MockControllerMockRecorder) ListServiceAccounts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceAccounts", reflect.TypeOf((*MockController)(nil).ListServiceAccounts))
}

// ListServices mocks base method.
func (m *MockController) ListServices() []*v1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServices")
	ret0, _ := ret[0].([]*v1.Service)
	return ret0
}

// ListServices indicates an expected call of ListServices.
func (mr *MockControllerMockRecorder) ListServices() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServices", reflect.TypeOf((*MockController)(nil).ListServices))
}

// ListUpstreamTrafficSettings mocks base method.
func (m *MockController) ListUpstreamTrafficSettings() []*v1alpha1.UpstreamTrafficSetting {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUpstreamTrafficSettings")
	ret0, _ := ret[0].([]*v1alpha1.UpstreamTrafficSetting)
	return ret0
}

// ListUpstreamTrafficSettings indicates an expected call of ListUpstreamTrafficSettings.
func (mr *MockControllerMockRecorder) ListUpstreamTrafficSettings() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUpstreamTrafficSettings", reflect.TypeOf((*MockController)(nil).ListUpstreamTrafficSettings))
}

// UpdateIngressBackendStatus mocks base method.
func (m *MockController) UpdateIngressBackendStatus(arg0 *v1alpha1.IngressBackend) (*v1alpha1.IngressBackend, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateIngressBackendStatus", arg0)
	ret0, _ := ret[0].(*v1alpha1.IngressBackend)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateIngressBackendStatus indicates an expected call of UpdateIngressBackendStatus.
func (mr *MockControllerMockRecorder) UpdateIngressBackendStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateIngressBackendStatus", reflect.TypeOf((*MockController)(nil).UpdateIngressBackendStatus), arg0)
}

// UpdateMeshRootCertificate mocks base method.
func (m *MockController) UpdateMeshRootCertificate(arg0 *v1alpha2.MeshRootCertificate) (*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateMeshRootCertificate", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateMeshRootCertificate indicates an expected call of UpdateMeshRootCertificate.
func (mr *MockControllerMockRecorder) UpdateMeshRootCertificate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMeshRootCertificate", reflect.TypeOf((*MockController)(nil).UpdateMeshRootCertificate), arg0)
}

// UpdateMeshRootCertificateStatus mocks base method.
func (m *MockController) UpdateMeshRootCertificateStatus(arg0 *v1alpha2.MeshRootCertificate) (*v1alpha2.MeshRootCertificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateMeshRootCertificateStatus", arg0)
	ret0, _ := ret[0].(*v1alpha2.MeshRootCertificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateMeshRootCertificateStatus indicates an expected call of UpdateMeshRootCertificateStatus.
func (mr *MockControllerMockRecorder) UpdateMeshRootCertificateStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMeshRootCertificateStatus", reflect.TypeOf((*MockController)(nil).UpdateMeshRootCertificateStatus), arg0)
}

// UpdateUpstreamTrafficSettingStatus mocks base method.
func (m *MockController) UpdateUpstreamTrafficSettingStatus(arg0 *v1alpha1.UpstreamTrafficSetting) (*v1alpha1.UpstreamTrafficSetting, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UpdateUpstreamTrafficSettingStatus", arg0)
	ret0, _ := ret[0].(*v1alpha1.UpstreamTrafficSetting)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateUpstreamTrafficSettingStatus indicates an expected call of UpdateUpstreamTrafficSettingStatus.
func (mr *MockControllerMockRecorder) UpdateUpstreamTrafficSettingStatus(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateUpstreamTrafficSettingStatus", reflect.TypeOf((*MockController)(nil).UpdateUpstreamTrafficSettingStatus), arg0)
}
