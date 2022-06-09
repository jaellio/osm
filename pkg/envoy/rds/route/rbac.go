package route

import (
	xds_rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	xds_http_rbac "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openservicemesh/osm/pkg/envoy/rbac"

	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/trafficpolicy"
)

const (
	rbacPerRoutePolicyName = "rbac-for-route"
)

// buildInboundRBACFilterForRule builds an HTTP RBAC per route filter based on the given traffic policy rule.
// The principals in the RBAC policy are derived from the allowed service accounts specified in the given rule.
// The permissions in the RBAC policy are implicitly set to ANY (all permissions).
func buildInboundRBACFilterForRule(rule *trafficpolicy.Rule) (map[string]*any.Any, error) {
	if rule.AllowedServiceIdentities == nil {
		return nil, errors.Errorf("traffipolicy.Rule.AllowedServiceIdentities not set")
	}

	pb := &rbac.PolicyBuilder{}

	// Create the list of principals for this policy
	for downstream := range rule.AllowedServiceIdentities.Iter() {
		pb.AddPrincipal(downstream.(identity.ServiceIdentity).String())
	}

	// A single RBAC policy per route
	rbacPolicyMap := map[string]*xds_rbac.Policy{rbacPerRoutePolicyName: pb.Build()}

	// Map generic RBAC policy to HTTP RBAC policy
	httpRBAC := &xds_http_rbac.RBAC{
		Rules: &xds_rbac.RBAC{
			Action:   xds_rbac.RBAC_ALLOW, // Allows the request if and only if there is a policy that matches the request
			Policies: rbacPolicyMap,
		},
	}
	httpRBACPerRoute := &xds_http_rbac.RBACPerRoute{
		Rbac: httpRBAC,
	}

	marshalled, err := anypb.New(httpRBACPerRoute)
	if err != nil {
		return nil, err
	}

	return map[string]*any.Any{wellknown.HTTPRoleBasedAccessControl: marshalled}, nil
}
