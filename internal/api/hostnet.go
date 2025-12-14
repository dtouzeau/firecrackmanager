package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"firecrackmanager/internal/hostnet"
)

// SetHostNetManager sets the host network manager for the API server
func (s *Server) SetHostNetManager(hm *hostnet.Manager, enabled bool) {
	s.hostNetMgr = hm
	s.enableHostNetworkManagement = enabled
}

// IsHostNetworkManagementEnabled returns whether host network management is enabled
func (s *Server) IsHostNetworkManagementEnabled() bool {
	return s.enableHostNetworkManagement
}

// registerHostNetRoutes registers host network management routes
func (s *Server) registerHostNetRoutes() {
	// Always register routes, but they will check if feature is enabled
	s.mux.HandleFunc("/api/hostnet/interfaces", s.requireAdmin(s.handleHostNetInterfaces))
	s.mux.HandleFunc("/api/hostnet/interfaces/", s.requireAdmin(s.handleHostNetInterface))
	s.mux.HandleFunc("/api/hostnet/routes", s.requireAdmin(s.handleHostNetRoutes))
	s.mux.HandleFunc("/api/hostnet/routes/", s.requireAdmin(s.handleHostNetRoute))
	s.mux.HandleFunc("/api/hostnet/dns", s.requireAdmin(s.handleHostNetDNS))
	s.mux.HandleFunc("/api/hostnet/status", s.requireAuth(s.handleHostNetStatus))
}

// handleHostNetStatus handles GET /api/hostnet/status - Check if feature is enabled
func (s *Server) handleHostNetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"enabled": s.enableHostNetworkManagement,
	})
}

// handleHostNetInterfaces handles GET /api/hostnet/interfaces - List all interfaces
func (s *Server) handleHostNetInterfaces(w http.ResponseWriter, r *http.Request) {
	if !s.enableHostNetworkManagement {
		s.jsonError(w, "Host network management is disabled", http.StatusForbidden)
		return
	}

	if s.hostNetMgr == nil {
		s.jsonError(w, "Host network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	interfaces, err := s.hostNetMgr.ListInterfaces()
	if err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"interfaces": interfaces,
	})
}

// handleHostNetInterface handles operations on a specific interface
// GET /api/hostnet/interfaces/{name} - Get interface details
// PUT /api/hostnet/interfaces/{name} - Configure interface
// POST /api/hostnet/interfaces/{name}/up - Bring interface up
// POST /api/hostnet/interfaces/{name}/down - Bring interface down
func (s *Server) handleHostNetInterface(w http.ResponseWriter, r *http.Request) {
	if !s.enableHostNetworkManagement {
		s.jsonError(w, "Host network management is disabled", http.StatusForbidden)
		return
	}

	if s.hostNetMgr == nil {
		s.jsonError(w, "Host network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse path: /api/hostnet/interfaces/{name}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/api/hostnet/interfaces/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		s.jsonError(w, "Interface name required", http.StatusBadRequest)
		return
	}

	ifaceName := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodGet:
		if action != "" {
			s.jsonError(w, "Invalid path", http.StatusBadRequest)
			return
		}
		s.handleGetInterface(w, ifaceName)

	case http.MethodPut:
		if action != "" {
			s.jsonError(w, "Invalid path", http.StatusBadRequest)
			return
		}
		s.handleConfigureInterface(w, r, ifaceName)

	case http.MethodPost:
		switch action {
		case "up":
			s.handleInterfaceUp(w, ifaceName)
		case "down":
			s.handleInterfaceDown(w, ifaceName)
		case "address":
			s.handleAddAddress(w, r, ifaceName)
		default:
			s.jsonError(w, "Invalid action", http.StatusBadRequest)
		}

	case http.MethodDelete:
		if action == "address" {
			s.handleRemoveAddress(w, r, ifaceName)
		} else {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGetInterface(w http.ResponseWriter, name string) {
	iface, err := s.hostNetMgr.GetInterface(name)
	if err != nil {
		s.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"interface": iface,
	})
}

func (s *Server) handleConfigureInterface(w http.ResponseWriter, r *http.Request, name string) {
	var config hostnet.InterfaceConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		s.jsonError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	config.Name = name

	if err := s.hostNetMgr.SetInterfaceConfig(config); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return updated interface
	iface, _ := s.hostNetMgr.GetInterface(name)
	s.jsonResponse(w, map[string]interface{}{
		"status":    "success",
		"message":   "Interface configured",
		"interface": iface,
	})
}

func (s *Server) handleInterfaceUp(w http.ResponseWriter, name string) {
	if err := s.hostNetMgr.SetInterfaceUp(name); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Interface brought up",
	})
}

func (s *Server) handleInterfaceDown(w http.ResponseWriter, name string) {
	if err := s.hostNetMgr.SetInterfaceDown(name); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Interface brought down",
	})
}

func (s *Server) handleAddAddress(w http.ResponseWriter, r *http.Request, ifaceName string) {
	var req struct {
		Address string `json:"address"` // CIDR format: 192.168.1.10/24
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Address == "" {
		s.jsonError(w, "Address is required", http.StatusBadRequest)
		return
	}

	if err := s.hostNetMgr.AddAddress(ifaceName, req.Address); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Address added",
	})
}

func (s *Server) handleRemoveAddress(w http.ResponseWriter, r *http.Request, ifaceName string) {
	var req struct {
		Address string `json:"address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Address == "" {
		s.jsonError(w, "Address is required", http.StatusBadRequest)
		return
	}

	if err := s.hostNetMgr.RemoveAddress(ifaceName, req.Address); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Address removed",
	})
}

// handleHostNetRoutes handles routes management
// GET /api/hostnet/routes - List all routes
// POST /api/hostnet/routes - Add a route
func (s *Server) handleHostNetRoutes(w http.ResponseWriter, r *http.Request) {
	if !s.enableHostNetworkManagement {
		s.jsonError(w, "Host network management is disabled", http.StatusForbidden)
		return
	}

	if s.hostNetMgr == nil {
		s.jsonError(w, "Host network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		routes, err := s.hostNetMgr.ListRoutes()
		if err != nil {
			s.jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"routes": routes,
		})

	case http.MethodPost:
		var req struct {
			Destination string `json:"destination"` // Network/CIDR or "default"
			Gateway     string `json:"gateway"`
			Interface   string `json:"interface"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Destination == "" {
			s.jsonError(w, "Destination is required", http.StatusBadRequest)
			return
		}

		if err := s.hostNetMgr.AddRoute(req.Destination, req.Gateway, req.Interface); err != nil {
			s.jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]string{
			"status":  "success",
			"message": "Route added",
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHostNetRoute handles DELETE /api/hostnet/routes/{destination}
func (s *Server) handleHostNetRoute(w http.ResponseWriter, r *http.Request) {
	if !s.enableHostNetworkManagement {
		s.jsonError(w, "Host network management is disabled", http.StatusForbidden)
		return
	}

	if s.hostNetMgr == nil {
		s.jsonError(w, "Host network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodDelete {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse destination from path - URL decode it
	path := strings.TrimPrefix(r.URL.Path, "/api/hostnet/routes/")
	if path == "" {
		s.jsonError(w, "Route destination required", http.StatusBadRequest)
		return
	}

	// Get gateway and interface from query params
	gateway := r.URL.Query().Get("gateway")
	iface := r.URL.Query().Get("interface")

	if err := s.hostNetMgr.DeleteRoute(path, gateway, iface); err != nil {
		s.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Route deleted",
	})
}

// handleHostNetDNS handles DNS configuration
// GET /api/hostnet/dns - Get DNS servers
// PUT /api/hostnet/dns - Set DNS servers
func (s *Server) handleHostNetDNS(w http.ResponseWriter, r *http.Request) {
	if !s.enableHostNetworkManagement {
		s.jsonError(w, "Host network management is disabled", http.StatusForbidden)
		return
	}

	if s.hostNetMgr == nil {
		s.jsonError(w, "Host network manager not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		servers := s.hostNetMgr.GetDNSServers()
		s.jsonResponse(w, map[string]interface{}{
			"dns_servers": servers,
		})

	case http.MethodPut:
		var req struct {
			DNSServers []string `json:"dns_servers"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.DNSServers) == 0 {
			s.jsonError(w, "At least one DNS server is required", http.StatusBadRequest)
			return
		}

		if err := s.hostNetMgr.SetDNSServers(req.DNSServers); err != nil {
			s.jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]string{
			"status":  "success",
			"message": "DNS servers updated",
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
