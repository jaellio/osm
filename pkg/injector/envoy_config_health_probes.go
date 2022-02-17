package injector

import (
	_ "embed" // required to embed resources
	"fmt"
	"strings"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/errcode"

	xds_accesslog_filter "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	xds_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xds_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xds_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	xds_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	xds_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	xds_accesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/stream/v3"
	xds_lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	xds_wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	xds_hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	xds_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	xds_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	xds_wasm_ext "github.com/envoyproxy/go-control-plane/envoy/extensions/wasm/v3"
)

const (
	livenessCluster  = "liveness_cluster"
	readinessCluster = "readiness_cluster"
	startupCluster   = "startup_cluster"

	livenessListener  = "liveness_listener"
	readinessListener = "readiness_listener"
	startupListener   = "startup_listener"
)

func getLivenessCluster(originalProbe *healthProbe) *xds_cluster.Cluster {
	if originalProbe == nil {
		return nil
	}
	return getProbeCluster(livenessCluster, originalProbe.port)
}

func getReadinessCluster(originalProbe *healthProbe) *xds_cluster.Cluster {
	if originalProbe == nil {
		return nil
	}
	return getProbeCluster(readinessCluster, originalProbe.port)
}

func getStartupCluster(originalProbe *healthProbe) *xds_cluster.Cluster {
	if originalProbe == nil {
		return nil
	}
	return getProbeCluster(startupCluster, originalProbe.port)
}

func getProbeCluster(clusterName string, port int32) *xds_cluster.Cluster {
	return &xds_cluster.Cluster{
		Name: clusterName,
		ClusterDiscoveryType: &xds_cluster.Cluster_Type{
			Type: xds_cluster.Cluster_STATIC,
		},
		LbPolicy: xds_cluster.Cluster_ROUND_ROBIN,
		LoadAssignment: &xds_endpoint.ClusterLoadAssignment{
			ClusterName: clusterName,
			Endpoints: []*xds_endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*xds_endpoint.LbEndpoint{
						{
							HostIdentifier: &xds_endpoint.LbEndpoint_Endpoint{
								Endpoint: &xds_endpoint.Endpoint{
									Address: &xds_core.Address{
										Address: &xds_core.Address_SocketAddress{
											SocketAddress: &xds_core.SocketAddress{
												Address: constants.LocalhostIPAddress,
												PortSpecifier: &xds_core.SocketAddress_PortValue{
													PortValue: uint32(port),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func getLivenessListener(originalProbe *healthProbe) (*xds_listener.Listener, error) {
	if originalProbe == nil {
		return nil, nil
	}
	return getProbeListener(livenessListener, livenessCluster, livenessProbePath, livenessProbePort, originalProbe)
}

func getReadinessListener(originalProbe *healthProbe) (*xds_listener.Listener, error) {
	if originalProbe == nil {
		return nil, nil
	}
	return getProbeListener(readinessListener, readinessCluster, readinessProbePath, readinessProbePort, originalProbe)
}

func getStartupListener(originalProbe *healthProbe) (*xds_listener.Listener, error) {
	if originalProbe == nil {
		return nil, nil
	}
	return getProbeListener(startupListener, startupCluster, startupProbePath, startupProbePort, originalProbe)
}

func getProbeListener(listenerName, clusterName, newPath string, port int32, originalProbe *healthProbe) (*xds_listener.Listener, error) {
	var filterChain *xds_listener.FilterChain
	if originalProbe.isTCPSocket {
		httpAccessLog, err := getHTTPAccessLog()
		if err != nil {
			return nil, err
		}

		wasmFilter, err := getTCPSocketProbeWASMFilter(string(originalProbe.port))
		if err != nil {
			return nil, err
		}

		/*luaFilter, err := getTcpSocketProberLuaFilter(string(originalProbe.port))
		if err != nil {
			return nil, err
		}*/
		/*pbWasmFilter, err := ptypes.MarshalAny(wasmFilter)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
				Msgf("Error marshaling wasmFilter struct into an anypb.Any message")
			return nil, err
		}*/

		httpConnectionManager := &xds_http_connection_manager.HttpConnectionManager{
			CodecType:  xds_http_connection_manager.HttpConnectionManager_AUTO,
			StatPrefix: "health_probes_http",
			AccessLog: []*xds_accesslog_filter.AccessLog{
				httpAccessLog,
			},
			RouteSpecifier: &xds_http_connection_manager.HttpConnectionManager_RouteConfig{
				RouteConfig: &xds_route.RouteConfiguration{
					Name: "local_route",
					VirtualHosts: []*xds_route.VirtualHost{
						getVirtualHost(newPath, clusterName, originalProbe.path, originalProbe.timeout),
					},
				},
			},
			HttpFilters: []*xds_hcm.HttpFilter{
				wasmFilter,
				{
					Name: "envoy.filters.http.router", // must be last filter in filter chain
				},
			},
		}

		pbHTTPConnectionManager, err := ptypes.MarshalAny(httpConnectionManager)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
				Msgf("Error marshaling HttpConnectionManager struct into an anypb.Any message")
			return nil, err
		}

		tcpAccessLog, err := getTCPAccessLog()
		if err != nil {
			return nil, err
		}
		tcpProxy := &xds_tcp_proxy.TcpProxy{
			StatPrefix: "health_probes_tcp",
			AccessLog: []*xds_accesslog_filter.AccessLog{
				tcpAccessLog,
			},
			ClusterSpecifier: &xds_tcp_proxy.TcpProxy_Cluster{
				Cluster: clusterName,
			},
		}

		pbTCPProxy, err := ptypes.MarshalAny(tcpProxy)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
				Msgf("Error marshaling TcpProxy struct into an anypb.Any message")
			return nil, err
		}

		filterChain = &xds_listener.FilterChain{
			Filters: []*xds_listener.Filter{
				{
					Name: wellknown.TCPProxy,
					ConfigType: &xds_listener.Filter_TypedConfig{
						TypedConfig: pbTCPProxy,
					},
				},
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &xds_listener.Filter_TypedConfig{
						TypedConfig: pbHTTPConnectionManager,
					},
				},
			},
		}
	} else if originalProbe.isHTTP {
		httpAccessLog, err := getHTTPAccessLog()
		if err != nil {
			return nil, err
		}
		httpConnectionManager := &xds_http_connection_manager.HttpConnectionManager{
			CodecType:  xds_http_connection_manager.HttpConnectionManager_AUTO,
			StatPrefix: "health_probes_http",
			AccessLog: []*xds_accesslog_filter.AccessLog{
				httpAccessLog,
			},
			RouteSpecifier: &xds_http_connection_manager.HttpConnectionManager_RouteConfig{
				RouteConfig: &xds_route.RouteConfiguration{
					Name: "local_route",
					VirtualHosts: []*xds_route.VirtualHost{
						getVirtualHost(newPath, clusterName, originalProbe.path, originalProbe.timeout),
					},
				},
			},
			HttpFilters: []*xds_http_connection_manager.HttpFilter{
				{
					Name: "envoy.filters.http.router",
				},
			},
		}
		pbHTTPConnectionManager, err := ptypes.MarshalAny(httpConnectionManager)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
				Msgf("Error marshaling HttpConnectionManager struct into an anypb.Any message")
			return nil, err
		}
		filterChain = &xds_listener.FilterChain{
			Filters: []*xds_listener.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &xds_listener.Filter_TypedConfig{
						TypedConfig: pbHTTPConnectionManager,
					},
				},
			},
		}
	} else {
		tcpAccessLog, err := getTCPAccessLog()
		if err != nil {
			return nil, err
		}
		tcpProxy := &xds_tcp_proxy.TcpProxy{
			StatPrefix: "health_probes",
			AccessLog: []*xds_accesslog_filter.AccessLog{
				tcpAccessLog,
			},
			ClusterSpecifier: &xds_tcp_proxy.TcpProxy_Cluster{
				Cluster: clusterName,
			},
		}
		pbTCPProxy, err := ptypes.MarshalAny(tcpProxy)
		if err != nil {
			log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
				Msgf("Error marshaling TcpProxy struct into an anypb.Any message")
			return nil, err
		}
		filterChain = &xds_listener.FilterChain{
			Filters: []*xds_listener.Filter{
				{
					Name: wellknown.TCPProxy,
					ConfigType: &xds_listener.Filter_TypedConfig{
						TypedConfig: pbTCPProxy,
					},
				},
			},
		}
	}

	return &xds_listener.Listener{
		Name: listenerName,
		Address: &xds_core.Address{
			Address: &xds_core.Address_SocketAddress{
				SocketAddress: &xds_core.SocketAddress{
					Address: "0.0.0.0",
					PortSpecifier: &xds_core.SocketAddress_PortValue{
						PortValue: uint32(port),
					},
				},
			},
		},
		FilterChains: []*xds_listener.FilterChain{
			filterChain,
		},
	}, nil
}

//go:embed tcpsocketproberust3.wasm
var tcpSocketWASMBytes []byte

func getTCPSocketProbeWASMFilter(port string) (*xds_hcm.HttpFilter, error) {
	if len(tcpSocketWASMBytes) == 0 {
		return nil, nil
	}
	// does the port need to be in a struct/ need to be encoded to JSONP
	//protpb := &wrapperspb.StringValue{Value: port}
	//protoAny, err := ptypes.MarshalAny(protpb)
	//if err != nil {
	//	return nil, errors.Wrap(err, "Error marshalling Wasm config")
	//}

	wasmPlug := &xds_wasm.Wasm{
		Config: &xds_wasm_ext.PluginConfig{
			Name: "tcpsocketprobe",
			//Configuration: protoAny,
			Vm: &xds_wasm_ext.PluginConfig_VmConfig{
				VmConfig: &xds_wasm_ext.VmConfig{
					Runtime: "envoy.wasm.runtime.v8",
					Code: &envoy_config_core_v3.AsyncDataSource{
						Specifier: &envoy_config_core_v3.AsyncDataSource_Local{
							Local: &envoy_config_core_v3.DataSource{
								Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
									InlineBytes: tcpSocketWASMBytes,
								},
							},
						},
					},
					AllowPrecompiled: true,
				},
			},
		},
	}

	wasmAny, err := ptypes.MarshalAny(wasmPlug)
	if err != nil {
		return nil, errors.Wrap(err, "Error marshalling Wasm config")
	}

	return &xds_hcm.HttpFilter{
		Name: "envoy.filters.http.wasm",
		ConfigType: &xds_hcm.HttpFilter_TypedConfig{
			TypedConfig: wasmAny,
		},
	}, nil
}

func getTcpSocketProberLuaFilter(port string) (*xds_hcm.HttpFilter, error) {
	// TODO(jaellio): check port?
	addCallsReq := &strings.Builder{}
	addCallsReq.WriteString("--\nfunction envoy_on_request(request_handle)\n")
	addCallsReq.WriteString(fmt.Sprintf("  local host, port = \"127.0.0.1\", %s\n", port))
	addCallsReq.WriteString("  local socket = require(\"socket\")\n")
	addCallsReq.WriteString("  local tcp = assert(socket.tcp())\n")
	addCallsReq.WriteString("  tcp:connect(host, port)\n")
	addCallsReq.WriteString("  tcp:close()\n")
	addCallsReq.WriteString("  request_handle:respond(\n")
	addCallsReq.WriteString("    {[\":status\"] = \"200\"},\n")
	addCallsReq.WriteString("    \"works\")\n")
	addCallsReq.WriteString("end")

	lua := &xds_lua.Lua{
		InlineCode: addCallsReq.String(),
	}

	luaAny, err := ptypes.MarshalAny(lua)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling Lua filter")
	}

	return &xds_hcm.HttpFilter{
		Name: wellknown.Lua,
		ConfigType: &xds_hcm.HttpFilter_TypedConfig{
			TypedConfig: luaAny,
		},
	}, nil
}

func getVirtualHost(newPath, clusterName, originalProbePath string, routeTimeout time.Duration) *xds_route.VirtualHost {
	if routeTimeout < 1*time.Second {
		// This should never happen in practice because the minimum value in Kubernetes
		// is set to 1. However it is easy to check and setting the timeout to 0 will lead
		// to leaks.
		routeTimeout = 1 * time.Second
	}
	return &xds_route.VirtualHost{
		Name: "local_service",
		Domains: []string{
			"*",
		},
		Routes: []*xds_route.Route{
			{
				Match: &xds_route.RouteMatch{
					PathSpecifier: &xds_route.RouteMatch_Prefix{
						Prefix: newPath,
					},
				},
				Action: &xds_route.Route_Route{
					Route: &xds_route.RouteAction{
						ClusterSpecifier: &xds_route.RouteAction_Cluster{
							Cluster: clusterName,
						},
						PrefixRewrite: originalProbePath,
						Timeout:       ptypes.DurationProto(routeTimeout),
					},
				},
			},
		},
	}
}

// getHTTPAccessLog creates an Envoy AccessLog struct.
func getHTTPAccessLog() (*xds_accesslog_filter.AccessLog, error) {
	accessLog, err := ptypes.MarshalAny(getStdoutAccessLog())
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
			Msg("Error marshalling AccessLog object")
		return nil, err
	}
	return &xds_accesslog_filter.AccessLog{
		Name: envoy.AccessLoggerName,
		ConfigType: &xds_accesslog_filter.AccessLog_TypedConfig{
			TypedConfig: accessLog,
		},
	}, nil
}

// getTCPAccessLog creates an Envoy AccessLog struct.
func getTCPAccessLog() (*xds_accesslog_filter.AccessLog, error) {
	accessLog, err := ptypes.MarshalAny(getTCPStdoutAccessLog())
	if err != nil {
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrMarshallingXDSResource)).
			Msg("Error marshalling tcp AccessLog object")
		return nil, err
	}
	return &xds_accesslog_filter.AccessLog{
		Name: envoy.AccessLoggerName,
		ConfigType: &xds_accesslog_filter.AccessLog_TypedConfig{
			TypedConfig: accessLog,
		},
	}, nil
}

func getStdoutAccessLog() *xds_accesslog.StdoutAccessLog {
	accessLogger := &xds_accesslog.StdoutAccessLog{
		AccessLogFormat: &xds_accesslog.StdoutAccessLog_LogFormat{
			LogFormat: &xds_core.SubstitutionFormatString{
				Format: &xds_core.SubstitutionFormatString_JsonFormat{
					JsonFormat: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"start_time":            pbStringValue(`%START_TIME%`),
							"method":                pbStringValue(`%REQ(:METHOD)%`),
							"path":                  pbStringValue(`%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%`),
							"protocol":              pbStringValue(`%PROTOCOL%`),
							"response_code":         pbStringValue(`%RESPONSE_CODE%`),
							"response_code_details": pbStringValue(`%RESPONSE_CODE_DETAILS%`),
							"time_to_first_byte":    pbStringValue(`%RESPONSE_DURATION%`),
							"upstream_cluster":      pbStringValue(`%UPSTREAM_CLUSTER%`),
							"response_flags":        pbStringValue(`%RESPONSE_FLAGS%`),
							"bytes_received":        pbStringValue(`%BYTES_RECEIVED%`),
							"bytes_sent":            pbStringValue(`%BYTES_SENT%`),
							"duration":              pbStringValue(`%DURATION%`),
							"upstream_service_time": pbStringValue(`%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%`),
							"x_forwarded_for":       pbStringValue(`%REQ(X-FORWARDED-FOR)%`),
							"user_agent":            pbStringValue(`%REQ(USER-AGENT)%`),
							"request_id":            pbStringValue(`%REQ(X-REQUEST-ID)%`),
							"requested_server_name": pbStringValue("%REQUESTED_SERVER_NAME%"),
							"authority":             pbStringValue(`%REQ(:AUTHORITY)%`),
							"upstream_host":         pbStringValue(`%UPSTREAM_HOST%`),
						},
					},
				},
			},
		},
	}
	return accessLogger
}

func getTCPStdoutAccessLog() *xds_accesslog.StdoutAccessLog {
	accessLogger := &xds_accesslog.StdoutAccessLog{
		AccessLogFormat: &xds_accesslog.StdoutAccessLog_LogFormat{
			LogFormat: &xds_core.SubstitutionFormatString{
				Format: &xds_core.SubstitutionFormatString_JsonFormat{
					JsonFormat: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"start_time":            pbStringValue(`%START_TIME%`),
							"upstream_cluster":      pbStringValue(`%UPSTREAM_CLUSTER%`),
							"response_flags":        pbStringValue(`%RESPONSE_FLAGS%`),
							"bytes_received":        pbStringValue(`%BYTES_RECEIVED%`),
							"bytes_sent":            pbStringValue(`%BYTES_SENT%`),
							"duration":              pbStringValue(`%DURATION%`),
							"requested_server_name": pbStringValue("%REQUESTED_SERVER_NAME%"),
							"upstream_host":         pbStringValue(`%UPSTREAM_HOST%`),
						},
					},
				},
			},
		},
	}
	return accessLogger
}

func pbStringValue(v string) *structpb.Value {
	return &structpb.Value{
		Kind: &structpb.Value_StringValue{
			StringValue: v,
		},
	}
}
