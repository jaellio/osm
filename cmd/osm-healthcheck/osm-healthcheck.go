package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/httpserver"
	"github.com/rs/zerolog/log"
)

const (
	healthCheckPort = uint16(15904)
	healthCheckPath = "/osm-healthcheck"
)

func main() {
	// Initialize OSM's http service server
	httpServer := httpserver.NewHTTPServer(healthCheckPort)
	// TODO: Health/Liveness probes
	/*funcProbes := []health.Probes{xdsServer, smi.HealthChecker{DiscoveryClient: clientset.Discovery()}}
	httpServer.AddHandlers(map[string]http.Handler{
		httpserverconstants.HealthReadinessPath: health.ReadinessHandler(funcProbes, getHTTPHealthProbes()),
		httpserverconstants.HealthLivenessPath:  health.LivenessHandler(funcProbes, getHTTPHealthProbes()),
	})*/
	// Metr
	httpServer.AddHandler(healthCheckPath, GetHealthCheckHandler())

	// Start HTTP server
	err := httpServer.Start()
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to start OSM health check server")
	}
}

// GetVersionHandler returns an HTTP handler that returns the version info
func GetHealthCheckHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		port := req.Header.Get("Original-TCP-Port")
		if port == "" {
			log.Error().Msg("Header Original-TCP-Port not found in request")
		}

		address := fmt.Sprintf("%s:%s", constants.LocalhostIPAddress, port)
		conn, err := net.Dial("tcp", address)
		defer conn.Close()
		if err != nil {
			log.Error().Msgf("Failed to establish connection to %s: %s", address, err)

			//TODO(jaellio): what error code to use?
			w.WriteHeader(http.StatusNotImplemented)
			w.Header().Set("Content-Type", "application/json")
			resp := make(map[string]string)
			resp["message"] = fmt.Sprintf("Failed to establish connection to %s", address)
			jsonResp, err := json.Marshal(resp)
			if err != nil {
				log.Error().Err(err).Msgf("Error happened in JSON marshal. Err: %s", err)
			} else {
				w.Write(jsonResp)
			}
			return
		}
		log.Debug().Msgf("Successfully established connection %s", address)

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		resp := make(map[string]string)
		resp["message"] = fmt.Sprintf("Successfully established connection to %s", address)
		jsonResp, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msgf("Error happened in JSON marshal. Err: %s", err)
		} else {
			w.Write(jsonResp)
		}
		return
	})
}
