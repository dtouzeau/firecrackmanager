package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/kernel"
	"firecrackmanager/internal/network"
	"firecrackmanager/internal/setup"
	"firecrackmanager/internal/updater"
	"firecrackmanager/internal/version"
	"firecrackmanager/internal/vm"

	"github.com/gorilla/websocket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Server struct {
	db           *database.DB
	vmMgr        *vm.Manager
	netMgr       *network.Manager
	kernelMgr    *kernel.Manager
	mux          *http.ServeMux
	sessionMu    sync.RWMutex
	sessionCache map[string]*database.Session
	logger       func(string, ...interface{})
	updater      *updater.Updater
}

func NewServer(db *database.DB, vmMgr *vm.Manager, netMgr *network.Manager, kernelMgr *kernel.Manager, upd *updater.Updater, logger func(string, ...interface{})) *Server {
	s := &Server{
		db:           db,
		vmMgr:        vmMgr,
		netMgr:       netMgr,
		kernelMgr:    kernelMgr,
		mux:          http.NewServeMux(),
		sessionCache: make(map[string]*database.Session),
		logger:       logger,
		updater:      upd,
	}
	s.registerRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	// Public routes
	s.mux.HandleFunc("/api/login", s.handleLogin)
	s.mux.HandleFunc("/api/logout", s.handleLogout)

	// Protected API routes
	s.mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))

	// VM routes
	s.mux.HandleFunc("/api/vms", s.requireAuth(s.handleVMs))
	s.mux.HandleFunc("/api/vms/import", s.requireAuth(s.handleVMImport))
	s.mux.HandleFunc("/api/vms/export/", s.requireAuth(s.handleVMExportDownload))
	s.mux.HandleFunc("/api/vms/", s.requireAuth(s.handleVM))

	// Network routes
	s.mux.HandleFunc("/api/networks", s.requireAuth(s.handleNetworks))
	s.mux.HandleFunc("/api/networks/", s.requireAuth(s.handleNetwork))

	// Kernel routes
	s.mux.HandleFunc("/api/kernels", s.requireAuth(s.handleKernels))
	s.mux.HandleFunc("/api/kernels/", s.requireAuth(s.handleKernel))
	s.mux.HandleFunc("/api/kernels/download", s.requireAuth(s.handleKernelDownload))

	// RootFS routes
	s.mux.HandleFunc("/api/rootfs", s.requireAuth(s.handleRootFSList))
	s.mux.HandleFunc("/api/rootfs/", s.requireAuth(s.handleRootFS))
	s.mux.HandleFunc("/api/rootfs/download", s.requireAuth(s.handleRootFSDownload))
	s.mux.HandleFunc("/api/rootfs/create", s.requireAuth(s.handleRootFSCreate))
	s.mux.HandleFunc("/api/rootfs/upload", s.requireAuth(s.handleRootFSUpload))

	// User routes (admin only)
	s.mux.HandleFunc("/api/users", s.requireAdmin(s.handleUsers))
	s.mux.HandleFunc("/api/users/", s.requireAdmin(s.handleUser))

	// Group routes (admin only)
	s.mux.HandleFunc("/api/groups", s.requireAdmin(s.handleGroups))
	s.mux.HandleFunc("/api/groups/", s.requireAdmin(s.handleGroup))

	// Logs route
	s.mux.HandleFunc("/api/logs", s.requireAuth(s.handleLogs))
	s.mux.HandleFunc("/api/logs/", s.requireAuth(s.handleVMLogs))

	// Download progress
	s.mux.HandleFunc("/api/downloads/", s.requireAuth(s.handleDownloadProgress))

	// System status and Firecracker management
	s.mux.HandleFunc("/api/system/status", s.requireAuth(s.handleSystemStatus))
	s.mux.HandleFunc("/api/system/firecracker/check", s.requireAuth(s.handleFirecrackerCheck))
	s.mux.HandleFunc("/api/system/firecracker/upgrade", s.requireAdmin(s.handleFirecrackerUpgrade))

	// Ping endpoint for checking VM reachability
	s.mux.HandleFunc("/api/ping/", s.requireAuth(s.handlePing))

	// WebSocket console endpoint
	s.mux.HandleFunc("/api/vms/console/", s.handleVMConsole)
}

// Authentication middleware
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := s.getSession(r)
		if session == nil {
			s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Extend session
		s.db.ExtendSession(session.ID, 24*time.Hour)
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := s.getSession(r)
		if session == nil {
			s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if session.Role != "admin" {
			s.jsonError(w, "Forbidden", http.StatusForbidden)
			return
		}
		s.db.ExtendSession(session.ID, 24*time.Hour)
		next(w, r)
	}
}

func (s *Server) getSession(r *http.Request) *database.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	// Check cache first
	s.sessionMu.RLock()
	if sess, ok := s.sessionCache[cookie.Value]; ok {
		if time.Now().Before(sess.ExpiresAt) {
			s.sessionMu.RUnlock()
			return sess
		}
	}
	s.sessionMu.RUnlock()

	// Get from database
	sess, err := s.db.GetSession(cookie.Value)
	if err != nil || sess == nil {
		return nil
	}

	// Cache it
	s.sessionMu.Lock()
	s.sessionCache[cookie.Value] = sess
	s.sessionMu.Unlock()

	return sess
}

// Login handler
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := s.db.GetUserByUsername(req.Username)
	if err != nil || user == nil {
		s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	hash := sha256.Sum256([]byte(req.Password))
	if user.PasswordHash != hex.EncodeToString(hash[:]) {
		s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if !user.Active {
		s.jsonError(w, "Account disabled", http.StatusForbidden)
		return
	}

	// Create session
	sessionID := generateID()
	sess := &database.Session{
		ID:        sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.db.CreateSession(sess); err != nil {
		s.jsonError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})

	s.jsonResponse(w, map[string]interface{}{
		"status":   "success",
		"username": user.Username,
		"role":     user.Role,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		s.db.DeleteSession(cookie.Value)
		s.sessionMu.Lock()
		delete(s.sessionCache, cookie.Value)
		s.sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	s.jsonResponse(w, map[string]string{"status": "success"})
}

// Stats handler
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := s.db.GetStats()
	if err != nil {
		s.jsonError(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, stats)
}

// VM handlers
func (s *Server) handleVMs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		vms, err := s.db.ListVMs()
		if err != nil {
			s.jsonError(w, "Failed to list VMs", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"vms": vms})

	case http.MethodPost:
		var req struct {
			Name         string `json:"name"`
			VCPU         int    `json:"vcpu"`
			MemoryMB     int    `json:"memory_mb"`
			KernelID     string `json:"kernel_id"`
			RootFSID     string `json:"rootfs_id"`
			KernelArgs   string `json:"kernel_args"`
			NetworkID    string `json:"network_id"`
			DNSServers   string `json:"dns_servers"`
			SnapshotType string `json:"snapshot_type"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		// Verify kernel exists
		kernelImg, err := s.db.GetKernelImage(req.KernelID)
		if err != nil || kernelImg == nil {
			s.jsonError(w, "Kernel not found", http.StatusBadRequest)
			return
		}

		// Verify rootfs exists
		rootfs, err := s.db.GetRootFS(req.RootFSID)
		if err != nil || rootfs == nil {
			s.jsonError(w, "RootFS not found", http.StatusBadRequest)
			return
		}

		// Set defaults
		if req.VCPU <= 0 {
			req.VCPU = 1
		}
		if req.MemoryMB <= 0 {
			req.MemoryMB = 512
		}

		vmID := generateID()
		vmObj := &database.VM{
			ID:           vmID,
			Name:         req.Name,
			VCPU:         req.VCPU,
			MemoryMB:     req.MemoryMB,
			KernelPath:   kernelImg.Path,
			RootFSPath:   rootfs.Path,
			KernelArgs:   req.KernelArgs,
			DNSServers:   req.DNSServers,
			SnapshotType: req.SnapshotType,
			Status:       "stopped",
		}

		// Configure network if specified
		if req.NetworkID != "" {
			net, err := s.db.GetNetwork(req.NetworkID)
			if err != nil || net == nil {
				s.jsonError(w, "Network not found", http.StatusBadRequest)
				return
			}

			// Generate MAC address
			vmObj.MacAddress = network.GenerateMAC(vmID)

			// Allocate IP
			existingVMs, _ := s.db.GetVMsByNetwork(req.NetworkID)
			usedIPs := make([]string, 0, len(existingVMs))
			for _, v := range existingVMs {
				if v.IPAddress != "" {
					usedIPs = append(usedIPs, v.IPAddress)
				}
			}
			ip, err := network.AllocateIP(net.Subnet, net.Gateway, usedIPs)
			if err != nil {
				s.jsonError(w, "Failed to allocate IP: "+err.Error(), http.StatusInternalServerError)
				return
			}
			vmObj.IPAddress = ip
			vmObj.NetworkID = req.NetworkID
			vmObj.TapDevice = network.GenerateTAPName(vmID)

			// Build kernel args with IP configuration
			vmObj.KernelArgs = buildKernelArgs(req.KernelArgs, ip, net.Gateway)
		} else {
			// No network - use default kernel args if not specified
			if vmObj.KernelArgs == "" {
				vmObj.KernelArgs = "console=ttyS0 reboot=k panic=1 pci=off"
			}
		}

		if err := s.db.CreateVM(vmObj); err != nil {
			s.jsonError(w, "Failed to create VM: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(vmID, "info", "VM created")
		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"vm":     vmObj,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVM(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/vms/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		s.jsonError(w, "VM ID required", http.StatusBadRequest)
		return
	}

	vmID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "start":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.vmMgr.StartVM(vmID); err != nil {
			s.jsonError(w, "Failed to start VM: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success", "message": "VM started"})

	case "stop":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.vmMgr.StopVM(vmID); err != nil {
			s.jsonError(w, "Failed to stop VM: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success", "message": "VM stopped"})

	case "force-stop":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.vmMgr.ForceStopVM(vmID); err != nil {
			s.jsonError(w, "Failed to force stop VM: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success", "message": "VM force stopped"})

	case "status":
		status, err := s.vmMgr.GetVMStatus(vmID)
		if err != nil {
			s.jsonError(w, "Failed to get status: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": status})

	case "info":
		info, err := s.vmMgr.GetVMInfo(vmID)
		if err != nil {
			s.jsonError(w, "Failed to get info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, info)

	case "snapshot":
		// POST /api/vms/{id}/snapshot - create snapshot
		if r.Method == http.MethodPost {
			result, err := s.vmMgr.CreateSnapshot(vmID)
			if err != nil {
				s.jsonError(w, "Failed to create snapshot: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{
				"status":   "success",
				"message":  "Snapshot created",
				"snapshot": result,
			})
			return
		}
		// GET /api/vms/{id}/snapshot - list snapshots
		if r.Method == http.MethodGet {
			snapshots, err := s.vmMgr.ListSnapshots(vmID)
			if err != nil {
				s.jsonError(w, "Failed to list snapshots: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{
				"snapshots": snapshots,
			})
			return
		}
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)

	case "snapshots":
		// Handle /api/vms/{id}/snapshots/{snapshotId} routes
		if len(parts) < 3 {
			s.jsonError(w, "Snapshot ID required", http.StatusBadRequest)
			return
		}
		snapshotID := parts[2]

		// DELETE /api/vms/{id}/snapshots/{snapshotId} - delete snapshot
		if r.Method == http.MethodDelete {
			if err := s.vmMgr.DeleteSnapshot(vmID, snapshotID); err != nil {
				s.jsonError(w, "Failed to delete snapshot: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{
				"status":  "success",
				"message": "Snapshot deleted",
			})
			return
		}

		// POST /api/vms/{id}/snapshots/{snapshotId}/restore - restore snapshot
		if r.Method == http.MethodPost {
			subaction := ""
			if len(parts) > 3 {
				subaction = parts[3]
			}
			if subaction != "restore" {
				s.jsonError(w, "Invalid action", http.StatusBadRequest)
				return
			}
			if err := s.vmMgr.RestoreSnapshot(vmID, snapshotID); err != nil {
				s.jsonError(w, "Failed to restore snapshot: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{
				"status":  "success",
				"message": "VM restored from snapshot",
			})
			return
		}

		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)

	case "duplicate":
		// POST /api/vms/{id}/duplicate - duplicate VM
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		newVM, err := s.vmMgr.DuplicateVM(vmID, req.Name)
		if err != nil {
			s.jsonError(w, "Failed to duplicate VM: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(newVM.ID, "info", "VM created by duplicating "+vmID)
		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"vm":     newVM,
		})

	case "export":
		// POST /api/vms/{id}/export - export VM as .fcrack archive
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		archivePath, err := s.vmMgr.ExportVM(vmID)
		if err != nil {
			s.jsonError(w, "Failed to export VM: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get just the filename for the download URL
		filename := filepath.Base(archivePath)
		s.db.AddVMLog(vmID, "info", "VM exported to "+filename)

		s.jsonResponse(w, map[string]interface{}{
			"status":       "success",
			"archive_path": archivePath,
			"filename":     filename,
			"download_url": "/api/vms/export/" + filename,
		})

	case "disks":
		// Handle /api/vms/{id}/disks routes
		if len(parts) < 3 {
			// GET /api/vms/{id}/disks - list disks
			// POST /api/vms/{id}/disks - attach new disk
			if r.Method == http.MethodGet {
				disks, err := s.vmMgr.ListDisks(vmID)
				if err != nil {
					s.jsonError(w, "Failed to list disks: "+err.Error(), http.StatusInternalServerError)
					return
				}
				s.jsonResponse(w, map[string]interface{}{
					"disks": disks,
				})
				return
			}

			if r.Method == http.MethodPost {
				var req struct {
					Name       string `json:"name"`
					SizeMB     int64  `json:"size_mb"`
					MountPoint string `json:"mount_point"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					s.jsonError(w, "Invalid request", http.StatusBadRequest)
					return
				}

				if req.Name == "" {
					s.jsonError(w, "Disk name is required", http.StatusBadRequest)
					return
				}
				if req.SizeMB <= 0 {
					s.jsonError(w, "Disk size must be positive (in MB)", http.StatusBadRequest)
					return
				}
				if req.MountPoint == "" {
					s.jsonError(w, "Mount point is required (e.g., /mnt/data)", http.StatusBadRequest)
					return
				}

				disk, err := s.vmMgr.AttachDisk(vmID, req.Name, req.SizeMB, req.MountPoint)
				if err != nil {
					s.jsonError(w, "Failed to attach disk: "+err.Error(), http.StatusInternalServerError)
					return
				}

				s.jsonResponse(w, map[string]interface{}{
					"status": "success",
					"disk":   disk,
				})
				return
			}

			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Handle /api/vms/{id}/disks/{diskId} routes
		diskID := parts[2]

		// DELETE /api/vms/{id}/disks/{diskId} - detach disk
		if r.Method == http.MethodDelete {
			if err := s.vmMgr.DetachDisk(vmID, diskID); err != nil {
				s.jsonError(w, "Failed to detach disk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{
				"status":  "success",
				"message": "Disk detached",
			})
			return
		}

		// GET /api/vms/{id}/disks/{diskId} - get disk info
		if r.Method == http.MethodGet {
			disk, err := s.db.GetVMDisk(diskID)
			if err != nil {
				s.jsonError(w, "Failed to get disk: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if disk == nil {
				s.jsonError(w, "Disk not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, disk)
			return
		}

		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)

	case "":
		switch r.Method {
		case http.MethodGet:
			vmObj, err := s.db.GetVM(vmID)
			if err != nil {
				s.jsonError(w, "Failed to get VM", http.StatusInternalServerError)
				return
			}
			if vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, vmObj)

		case http.MethodPut:
			var req struct {
				Name         string  `json:"name"`
				VCPU         int     `json:"vcpu"`
				MemoryMB     int     `json:"memory_mb"`
				KernelArgs   string  `json:"kernel_args"`
				NetworkID    *string `json:"network_id"`    // Pointer to distinguish between "not provided" and "set to empty"
				DNSServers   *string `json:"dns_servers"`   // Pointer to allow clearing
				SnapshotType *string `json:"snapshot_type"` // Pointer to allow clearing
				Autorun      *bool   `json:"autorun"`       // Pointer to allow explicit true/false
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			vmObj, err := s.db.GetVM(vmID)
			if err != nil || vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}

			if vmObj.Status == "running" {
				s.jsonError(w, "Cannot modify running VM", http.StatusBadRequest)
				return
			}

			if req.Name != "" {
				vmObj.Name = req.Name
			}
			if req.VCPU > 0 {
				vmObj.VCPU = req.VCPU
			}
			if req.MemoryMB > 0 {
				vmObj.MemoryMB = req.MemoryMB
			}
			if req.KernelArgs != "" {
				vmObj.KernelArgs = req.KernelArgs
			}
			if req.DNSServers != nil {
				vmObj.DNSServers = *req.DNSServers
			}
			if req.SnapshotType != nil {
				vmObj.SnapshotType = *req.SnapshotType
			}
			if req.Autorun != nil {
				vmObj.Autorun = *req.Autorun
			}

			// Handle network change
			if req.NetworkID != nil {
				newNetworkID := *req.NetworkID
				if newNetworkID != vmObj.NetworkID {
					if newNetworkID == "" {
						// Remove network - strip IP config from kernel args
						vmObj.NetworkID = ""
						vmObj.TapDevice = ""
						vmObj.MacAddress = ""
						vmObj.IPAddress = ""
						// Remove ip= parameter from kernel args
						vmObj.KernelArgs = buildKernelArgs(vmObj.KernelArgs, "", "")
					} else {
						// Validate new network exists
						net, err := s.db.GetNetwork(newNetworkID)
						if err != nil || net == nil {
							s.jsonError(w, "Network not found", http.StatusBadRequest)
							return
						}
						// Generate new network config for VM
						vmObj.NetworkID = newNetworkID
						vmObj.TapDevice = network.GenerateTAPName(vmID)
						vmObj.MacAddress = network.GenerateMAC(vmID)

						// Allocate IP
						existingVMs, _ := s.db.GetVMsByNetwork(newNetworkID)
						usedIPs := make([]string, 0, len(existingVMs))
						for _, v := range existingVMs {
							if v.IPAddress != "" && v.ID != vmID {
								usedIPs = append(usedIPs, v.IPAddress)
							}
						}
						ip, err := network.AllocateIP(net.Subnet, net.Gateway, usedIPs)
						if err != nil {
							s.jsonError(w, "Failed to allocate IP: "+err.Error(), http.StatusInternalServerError)
							return
						}
						vmObj.IPAddress = ip

						// Update kernel args with new IP configuration
						vmObj.KernelArgs = buildKernelArgs(vmObj.KernelArgs, ip, net.Gateway)
					}
				}
			}

			if err := s.db.UpdateVM(vmObj); err != nil {
				s.jsonError(w, "Failed to update VM", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"status": "success", "vm": vmObj})

		case http.MethodDelete:
			vmObj, err := s.db.GetVM(vmID)
			if err != nil || vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}

			if vmObj.Status == "running" {
				s.vmMgr.StopVM(vmID)
			}

			if err := s.db.DeleteVM(vmID); err != nil {
				s.jsonError(w, "Failed to delete VM", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Unknown action", http.StatusBadRequest)
	}
}

// Network handlers
func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		networks, err := s.db.ListNetworks()
		if err != nil {
			s.jsonError(w, "Failed to list networks", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"networks": networks})

	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			Subnet    string `json:"subnet"`
			Gateway   string `json:"gateway"`
			DHCPStart string `json:"dhcp_start"`
			DHCPEnd   string `json:"dhcp_end"`
			EnableNAT bool   `json:"enable_nat"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" || req.Subnet == "" {
			s.jsonError(w, "Name and subnet are required", http.StatusBadRequest)
			return
		}

		// Validate subnet
		if err := network.ValidateSubnet(req.Subnet); err != nil {
			s.jsonError(w, "Invalid subnet: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Parse subnet if gateway not provided
		if req.Gateway == "" {
			_, gw, _, _, err := network.ParseCIDR(req.Subnet)
			if err != nil {
				s.jsonError(w, "Failed to parse subnet", http.StatusBadRequest)
				return
			}
			req.Gateway = gw
		}

		netID := generateID()
		bridgeName := network.GenerateBridgeName(netID)

		netObj := &database.Network{
			ID:         netID,
			Name:       req.Name,
			BridgeName: bridgeName,
			Subnet:     req.Subnet,
			Gateway:    req.Gateway,
			DHCPStart:  req.DHCPStart,
			DHCPEnd:    req.DHCPEnd,
			EnableNAT:  req.EnableNAT,
			Status:     "inactive",
		}

		if err := s.db.CreateNetwork(netObj); err != nil {
			s.jsonError(w, "Failed to create network: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":  "success",
			"network": netObj,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/networks/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		s.jsonError(w, "Network ID required", http.StatusBadRequest)
		return
	}

	netID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "activate":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		netObj, err := s.db.GetNetwork(netID)
		if err != nil || netObj == nil {
			s.jsonError(w, "Network not found", http.StatusNotFound)
			return
		}

		// Create bridge
		if err := s.netMgr.CreateBridge(netObj.BridgeName); err != nil {
			s.jsonError(w, "Failed to create bridge: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Set IP on bridge
		netmask, _ := network.SubnetToNetmask(netObj.Subnet)
		if err := s.netMgr.SetInterfaceIP(netObj.BridgeName, netObj.Gateway, netmask); err != nil {
			s.jsonError(w, "Failed to set bridge IP: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Bring bridge up
		if err := s.netMgr.SetInterfaceUp(netObj.BridgeName); err != nil {
			s.jsonError(w, "Failed to bring bridge up: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Enable NAT if requested
		if netObj.EnableNAT {
			defaultIface, _ := network.GetDefaultInterface()
			s.netMgr.SetupNAT(netObj.Gateway, netObj.Subnet, defaultIface)
		}

		netObj.Status = "active"
		s.db.UpdateNetworkStatus(netID, "active")

		s.jsonResponse(w, map[string]string{"status": "success", "message": "Network activated"})

	case "deactivate":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		netObj, err := s.db.GetNetwork(netID)
		if err != nil || netObj == nil {
			s.jsonError(w, "Network not found", http.StatusNotFound)
			return
		}

		// Check for running VMs
		vms, _ := s.db.GetVMsByNetwork(netID)
		for _, v := range vms {
			if v.Status == "running" {
				s.jsonError(w, "Cannot deactivate network with running VMs", http.StatusBadRequest)
				return
			}
		}

		// Delete bridge
		s.netMgr.DeleteBridge(netObj.BridgeName)

		netObj.Status = "inactive"
		s.db.UpdateNetworkStatus(netID, "inactive")

		s.jsonResponse(w, map[string]string{"status": "success", "message": "Network deactivated"})

	case "vms":
		vms, err := s.db.GetVMsByNetwork(netID)
		if err != nil {
			s.jsonError(w, "Failed to get VMs", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"vms": vms})

	case "":
		switch r.Method {
		case http.MethodGet:
			netObj, err := s.db.GetNetwork(netID)
			if err != nil {
				s.jsonError(w, "Failed to get network", http.StatusInternalServerError)
				return
			}
			if netObj == nil {
				s.jsonError(w, "Network not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, netObj)

		case http.MethodDelete:
			netObj, err := s.db.GetNetwork(netID)
			if err != nil || netObj == nil {
				s.jsonError(w, "Network not found", http.StatusNotFound)
				return
			}

			// Check for VMs using this network
			vms, _ := s.db.GetVMsByNetwork(netID)
			if len(vms) > 0 {
				s.jsonError(w, "Cannot delete network with attached VMs", http.StatusBadRequest)
				return
			}

			// Cleanup bridge if active
			if netObj.Status == "active" {
				s.netMgr.DeleteBridge(netObj.BridgeName)
			}

			if err := s.db.DeleteNetwork(netID); err != nil {
				s.jsonError(w, "Failed to delete network", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Unknown action", http.StatusBadRequest)
	}
}

// Kernel handlers
func (s *Server) handleKernels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		kernels, err := s.db.ListKernelImages()
		if err != nil {
			s.jsonError(w, "Failed to list kernels", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"kernels": kernels})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleKernel(w http.ResponseWriter, r *http.Request) {
	kernelID := strings.TrimPrefix(r.URL.Path, "/api/kernels/")
	parts := strings.Split(kernelID, "/")
	kernelID = parts[0]

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "default":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.db.SetDefaultKernel(kernelID); err != nil {
			s.jsonError(w, "Failed to set default kernel", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success"})

	case "":
		switch r.Method {
		case http.MethodGet:
			kernel, err := s.db.GetKernelImage(kernelID)
			if err != nil || kernel == nil {
				s.jsonError(w, "Kernel not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, kernel)

		case http.MethodDelete:
			kernel, err := s.db.GetKernelImage(kernelID)
			if err != nil || kernel == nil {
				s.jsonError(w, "Kernel not found", http.StatusNotFound)
				return
			}

			// Delete file
			s.kernelMgr.DeleteKernel(kernel.Name)

			if err := s.db.DeleteKernelImage(kernelID); err != nil {
				s.jsonError(w, "Failed to delete kernel", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Unknown action", http.StatusBadRequest)
	}
}

func (s *Server) handleKernelDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL          string `json:"url"`
		Name         string `json:"name"`
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		req.URL = kernel.DefaultKernelURL
	}
	if req.Name == "" {
		req.Name = "vmlinux"
	}
	if req.Version == "" {
		req.Version = "5.10"
	}
	if req.Architecture == "" {
		req.Architecture = "x86_64"
	}

	// Download in background
	go func() {
		path, err := s.kernelMgr.DownloadKernel(req.URL, req.Name)
		if err != nil {
			s.logger("Failed to download kernel: %v", err)
			return
		}

		size, _ := s.kernelMgr.GetFileSize(path)
		checksum, _ := s.kernelMgr.CalculateChecksum(path)

		kernelID := generateID()
		kernelImg := &database.KernelImage{
			ID:           kernelID,
			Name:         req.Name,
			Version:      req.Version,
			Architecture: req.Architecture,
			Path:         path,
			Size:         size,
			Checksum:     checksum,
		}

		if err := s.db.CreateKernelImage(kernelImg); err != nil {
			s.logger("Failed to save kernel to database: %v", err)
		}
	}()

	s.jsonResponse(w, map[string]string{
		"status":       "success",
		"message":      "Download started",
		"progress_key": "kernel-" + req.Name,
	})
}

// RootFS handlers
func (s *Server) handleRootFSList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rootfsList, err := s.db.ListRootFS()
		if err != nil {
			s.jsonError(w, "Failed to list rootfs", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"rootfs": rootfsList})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRootFS(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/rootfs/")
	parts := strings.Split(path, "/")
	rootfsID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	if rootfsID == "" {
		s.jsonError(w, "RootFS ID required", http.StatusBadRequest)
		return
	}

	// Handle actions
	switch action {
	case "duplicate":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRootFSDuplicate(w, r, rootfsID)
		return

	case "rename":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRootFSRename(w, r, rootfsID)
		return
	}

	// Default handlers (no action)
	switch r.Method {
	case http.MethodGet:
		rootfs, err := s.db.GetRootFS(rootfsID)
		if err != nil || rootfs == nil {
			s.jsonError(w, "RootFS not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, rootfs)

	case http.MethodDelete:
		rootfs, err := s.db.GetRootFS(rootfsID)
		if err != nil || rootfs == nil {
			s.jsonError(w, "RootFS not found", http.StatusNotFound)
			return
		}

		s.kernelMgr.DeleteRootFS(rootfs.Name)

		if err := s.db.DeleteRootFS(rootfsID); err != nil {
			s.jsonError(w, "Failed to delete rootfs", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success"})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRootFSDuplicate(w http.ResponseWriter, r *http.Request, rootfsID string) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Get source rootfs
	srcRootfs, err := s.db.GetRootFS(rootfsID)
	if err != nil || srcRootfs == nil {
		s.jsonError(w, "RootFS not found", http.StatusNotFound)
		return
	}

	// Create destination filename
	destFilename := req.Name
	if !strings.HasSuffix(destFilename, ".ext4") && !strings.HasSuffix(destFilename, ".img") && !strings.HasSuffix(destFilename, ".raw") {
		destFilename += ".ext4"
	}
	destPath := s.kernelMgr.GetRootFSDir() + "/" + destFilename

	// Check if destination already exists
	if _, err := os.Stat(destPath); err == nil {
		s.jsonError(w, "A rootfs with this name already exists", http.StatusConflict)
		return
	}

	// Copy the file
	srcFile, err := os.Open(srcRootfs.Path)
	if err != nil {
		s.jsonError(w, "Failed to open source rootfs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		s.jsonError(w, "Failed to create destination file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	written, err := io.Copy(destFile, srcFile)
	destFile.Close()
	if err != nil {
		os.Remove(destPath)
		s.jsonError(w, "Failed to copy rootfs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create database entry
	newID := generateID()
	newRootfs := &database.RootFS{
		ID:        newID,
		Name:      req.Name,
		Path:      destPath,
		Size:      written,
		Format:    srcRootfs.Format,
		BaseImage: srcRootfs.Name,
	}

	if err := s.db.CreateRootFS(newRootfs); err != nil {
		os.Remove(destPath)
		s.jsonError(w, "Failed to save rootfs to database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Duplicated rootfs %s to %s", srcRootfs.Name, req.Name)
	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"rootfs": newRootfs,
	})
}

func (s *Server) handleRootFSRename(w http.ResponseWriter, r *http.Request, rootfsID string) {
	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Get source rootfs
	rootfs, err := s.db.GetRootFS(rootfsID)
	if err != nil || rootfs == nil {
		s.jsonError(w, "RootFS not found", http.StatusNotFound)
		return
	}

	// Create new filename
	newFilename := req.Name
	if !strings.HasSuffix(newFilename, ".ext4") && !strings.HasSuffix(newFilename, ".img") && !strings.HasSuffix(newFilename, ".raw") {
		newFilename += ".ext4"
	}
	newPath := s.kernelMgr.GetRootFSDir() + "/" + newFilename

	// Check if destination already exists (and is not the same file)
	if newPath != rootfs.Path {
		if _, err := os.Stat(newPath); err == nil {
			s.jsonError(w, "A rootfs with this name already exists", http.StatusConflict)
			return
		}

		// Rename the file
		if err := os.Rename(rootfs.Path, newPath); err != nil {
			s.jsonError(w, "Failed to rename rootfs file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Update database entry
	oldName := rootfs.Name
	rootfs.Name = req.Name
	rootfs.Path = newPath

	if err := s.db.UpdateRootFS(rootfs); err != nil {
		// Try to revert the file rename
		if newPath != rootfs.Path {
			os.Rename(newPath, rootfs.Path)
		}
		s.jsonError(w, "Failed to update database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Renamed rootfs %s to %s", oldName, req.Name)
	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"rootfs": rootfs,
	})
}

func (s *Server) handleRootFSDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		req.URL = kernel.DefaultRootFSURL
	}
	if req.Name == "" {
		req.Name = "ubuntu-22.04.ext4"
	}

	// Download in background
	go func() {
		path, err := s.kernelMgr.DownloadRootFS(req.URL, req.Name)
		if err != nil {
			s.logger("Failed to download rootfs: %v", err)
			return
		}

		size, _ := s.kernelMgr.GetFileSize(path)
		checksum, _ := s.kernelMgr.CalculateChecksum(path)
		info, _ := s.kernelMgr.GetRootFSInfo(path)

		format := "ext4"
		if f, ok := info["format"].(string); ok {
			format = f
		}

		rootfsID := generateID()
		rootfs := &database.RootFS{
			ID:       rootfsID,
			Name:     req.Name,
			Path:     path,
			Size:     size,
			Format:   format,
			Checksum: checksum,
		}

		if err := s.db.CreateRootFS(rootfs); err != nil {
			s.logger("Failed to save rootfs to database: %v", err)
		}
	}()

	s.jsonResponse(w, map[string]string{
		"status":       "success",
		"message":      "Download started",
		"progress_key": "rootfs-" + req.Name,
	})
}

func (s *Server) handleRootFSCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name   string `json:"name"`
		SizeMB int64  `json:"size_mb"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}
	if req.SizeMB <= 0 {
		req.SizeMB = 1024 // Default 1GB
	}

	path, err := s.kernelMgr.CreateRootFS(req.Name, req.SizeMB)
	if err != nil {
		s.jsonError(w, "Failed to create rootfs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:     rootfsID,
		Name:   req.Name,
		Path:   path,
		Size:   req.SizeMB * 1024 * 1024,
		Format: "raw",
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		s.jsonError(w, "Failed to save rootfs to database", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"rootfs": rootfs,
	})
}

func (s *Server) handleRootFSUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form with a max memory of 32MB (rest will be written to temp files)
	// This allows streaming of large files without loading them entirely into memory
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.jsonError(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get the name from the form
	name := r.FormValue("name")
	if name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Determine the rootfs directory from kernel manager
	rootfsDir := s.kernelMgr.GetRootFSDir()

	// Sanitize filename and create destination path
	destFilename := name
	if !strings.HasSuffix(destFilename, ".ext4") && !strings.HasSuffix(destFilename, ".img") && !strings.HasSuffix(destFilename, ".raw") {
		destFilename += ".ext4"
	}
	destPath := rootfsDir + "/" + destFilename

	// Check if file already exists
	if _, err := os.Stat(destPath); err == nil {
		s.jsonError(w, "A rootfs with this name already exists", http.StatusConflict)
		return
	}

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		s.jsonError(w, "Failed to create destination file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Stream copy from uploaded file to destination
	written, err := io.Copy(destFile, file)
	destFile.Close()
	if err != nil {
		os.Remove(destPath)
		s.jsonError(w, "Failed to save uploaded file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Uploaded rootfs: %s (%d bytes from %s)", name, written, header.Filename)

	// Create database entry
	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:     rootfsID,
		Name:   name,
		Path:   destPath,
		Size:   written,
		Format: "ext4",
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		os.Remove(destPath)
		s.jsonError(w, "Failed to save rootfs to database: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"rootfs": rootfs,
	})
}

// User handlers
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := s.db.ListUsers()
		if err != nil {
			s.jsonError(w, "Failed to list users", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"users": users})

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Email    string `json:"email"`
			Role     string `json:"role"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			s.jsonError(w, "Username and password required", http.StatusBadRequest)
			return
		}

		if req.Role == "" {
			req.Role = "user"
		}

		hash := sha256.Sum256([]byte(req.Password))
		user := &database.User{
			Username:     req.Username,
			PasswordHash: hex.EncodeToString(hash[:]),
			Email:        req.Email,
			Role:         req.Role,
			Active:       true,
		}

		if err := s.db.CreateUser(user); err != nil {
			s.jsonError(w, "Failed to create user: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"user":   user,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	userIDStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	parts := strings.Split(userIDStr, "/")
	userIDStr = parts[0]

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		s.jsonError(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "password":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		hash := sha256.Sum256([]byte(req.Password))
		if err := s.db.UpdateUserPassword(userID, hex.EncodeToString(hash[:])); err != nil {
			s.jsonError(w, "Failed to update password", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success"})

	case "":
		switch r.Method {
		case http.MethodGet:
			user, err := s.db.GetUser(userID)
			if err != nil || user == nil {
				s.jsonError(w, "User not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, user)

		case http.MethodPut:
			var req struct {
				Email  string `json:"email"`
				Role   string `json:"role"`
				Active bool   `json:"active"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			user, err := s.db.GetUser(userID)
			if err != nil || user == nil {
				s.jsonError(w, "User not found", http.StatusNotFound)
				return
			}

			user.Email = req.Email
			if req.Role != "" {
				user.Role = req.Role
			}
			user.Active = req.Active

			if err := s.db.UpdateUser(user); err != nil {
				s.jsonError(w, "Failed to update user", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		case http.MethodDelete:
			if err := s.db.DeleteUser(userID); err != nil {
				s.jsonError(w, "Failed to delete user", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Unknown action", http.StatusBadRequest)
	}
}

// Group handlers
func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		groups, err := s.db.ListGroups()
		if err != nil {
			s.jsonError(w, "Failed to list groups", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"groups": groups})

	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Permissions string `json:"permissions"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		// Default permissions if not specified
		if req.Permissions == "" {
			req.Permissions = "start,stop,console"
		}

		groupID := generateID()
		group := &database.Group{
			ID:          groupID,
			Name:        req.Name,
			Description: req.Description,
			Permissions: req.Permissions,
		}

		if err := s.db.CreateGroup(group); err != nil {
			s.jsonError(w, "Failed to create group: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"group":  group,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/groups/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		s.jsonError(w, "Group ID required", http.StatusBadRequest)
		return
	}

	groupID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "members":
		s.handleGroupMembers(w, r, groupID, parts)

	case "vms":
		s.handleGroupVMs(w, r, groupID, parts)

	case "":
		switch r.Method {
		case http.MethodGet:
			group, err := s.db.GetGroup(groupID)
			if err != nil {
				s.jsonError(w, "Failed to get group", http.StatusInternalServerError)
				return
			}
			if group == nil {
				s.jsonError(w, "Group not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, group)

		case http.MethodPut:
			var req struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Permissions string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			group, err := s.db.GetGroup(groupID)
			if err != nil || group == nil {
				s.jsonError(w, "Group not found", http.StatusNotFound)
				return
			}

			if req.Name != "" {
				group.Name = req.Name
			}
			if req.Description != "" {
				group.Description = req.Description
			}
			if req.Permissions != "" {
				group.Permissions = req.Permissions
			}

			if err := s.db.UpdateGroup(group); err != nil {
				s.jsonError(w, "Failed to update group", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"status": "success", "group": group})

		case http.MethodDelete:
			if err := s.db.DeleteGroup(groupID); err != nil {
				s.jsonError(w, "Failed to delete group", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	default:
		s.jsonError(w, "Unknown action", http.StatusBadRequest)
	}
}

func (s *Server) handleGroupMembers(w http.ResponseWriter, r *http.Request, groupID string, parts []string) {
	// GET /api/groups/{id}/members - list members
	// POST /api/groups/{id}/members - add member
	// DELETE /api/groups/{id}/members/{userId} - remove member

	if len(parts) < 3 {
		// List or add members
		switch r.Method {
		case http.MethodGet:
			members, err := s.db.ListGroupMembers(groupID)
			if err != nil {
				s.jsonError(w, "Failed to list members", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"members": members})

		case http.MethodPost:
			var req struct {
				UserID int `json:"user_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.UserID <= 0 {
				s.jsonError(w, "User ID is required", http.StatusBadRequest)
				return
			}

			// Verify user exists
			user, err := s.db.GetUser(req.UserID)
			if err != nil || user == nil {
				s.jsonError(w, "User not found", http.StatusBadRequest)
				return
			}

			if err := s.db.AddGroupMember(groupID, req.UserID); err != nil {
				s.jsonError(w, "Failed to add member: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]string{"status": "success", "message": "Member added"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Remove member: DELETE /api/groups/{id}/members/{userId}
	if r.Method != http.MethodDelete {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, err := strconv.Atoi(parts[2])
	if err != nil {
		s.jsonError(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := s.db.RemoveGroupMember(groupID, userID); err != nil {
		s.jsonError(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "success", "message": "Member removed"})
}

func (s *Server) handleGroupVMs(w http.ResponseWriter, r *http.Request, groupID string, parts []string) {
	// GET /api/groups/{id}/vms - list VMs
	// POST /api/groups/{id}/vms - add VM
	// DELETE /api/groups/{id}/vms/{vmId} - remove VM

	if len(parts) < 3 {
		// List or add VMs
		switch r.Method {
		case http.MethodGet:
			vms, err := s.db.ListGroupVMs(groupID)
			if err != nil {
				s.jsonError(w, "Failed to list VMs", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"vms": vms})

		case http.MethodPost:
			var req struct {
				VMID string `json:"vm_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.VMID == "" {
				s.jsonError(w, "VM ID is required", http.StatusBadRequest)
				return
			}

			// Verify VM exists
			vm, err := s.db.GetVM(req.VMID)
			if err != nil || vm == nil {
				s.jsonError(w, "VM not found", http.StatusBadRequest)
				return
			}

			if err := s.db.AddGroupVM(groupID, req.VMID); err != nil {
				s.jsonError(w, "Failed to add VM: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]string{"status": "success", "message": "VM added to group"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Remove VM: DELETE /api/groups/{id}/vms/{vmId}
	if r.Method != http.MethodDelete {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	vmID := parts[2]
	if err := s.db.RemoveGroupVM(groupID, vmID); err != nil {
		s.jsonError(w, "Failed to remove VM", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "success", "message": "VM removed from group"})
}

// Logs handler
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	logs, err := s.db.GetRecentLogs(limit)
	if err != nil {
		s.jsonError(w, "Failed to get logs", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, map[string]interface{}{"logs": logs})
}

func (s *Server) handleVMLogs(w http.ResponseWriter, r *http.Request) {
	vmID := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if vmID == "" {
		s.jsonError(w, "VM ID required", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	logs, err := s.db.GetVMLogs(vmID, limit)
	if err != nil {
		s.jsonError(w, "Failed to get logs", http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, map[string]interface{}{"logs": logs})
}

// Download progress handler
func (s *Server) handleDownloadProgress(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/downloads/")
	if key == "" {
		s.jsonError(w, "Progress key required", http.StatusBadRequest)
		return
	}

	progress := s.kernelMgr.GetDownloadProgress(key)
	if progress == nil {
		s.jsonResponse(w, map[string]interface{}{
			"status": "not_found",
		})
		return
	}

	s.jsonResponse(w, progress)
}

// System status handler
func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := make(map[string]interface{})

	// FireCrackManager version
	status["firecrackmanager"] = map[string]interface{}{
		"version":    version.Version,
		"build_date": version.BuildDate,
		"git_commit": version.GitCommit,
	}

	// Firecracker version
	fcVersion := "not installed"
	fcPath := "/usr/sbin/firecracker"
	if _, err := os.Stat(fcPath); err == nil {
		out, err := exec.Command(fcPath, "--version").Output()
		if err == nil {
			fcVersion = strings.TrimSpace(string(out))
			// Parse version from output like "Firecracker v1.10.0"
			if parts := strings.Fields(fcVersion); len(parts) >= 2 {
				fcVersion = parts[1]
			}
		}
	}
	status["firecracker"] = map[string]interface{}{
		"version":   fcVersion,
		"path":      fcPath,
		"installed": fcVersion != "not installed",
	}

	// System info
	var memInfo runtime.MemStats
	runtime.ReadMemStats(&memInfo)

	hostname, _ := os.Hostname()
	status["system"] = map[string]interface{}{
		"hostname":     hostname,
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"go_version":   runtime.Version(),
		"num_cpu":      runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
		"memory_alloc": memInfo.Alloc,
		"memory_sys":   memInfo.Sys,
	}

	// KVM status
	kvmAvailable := false
	if _, err := os.Stat("/dev/kvm"); err == nil {
		kvmAvailable = true
	}
	status["kvm"] = map[string]interface{}{
		"available": kvmAvailable,
		"path":      "/dev/kvm",
	}

	// Uptime (process start time approximation)
	status["uptime_seconds"] = time.Since(startTime).Seconds()

	s.jsonResponse(w, status)
}

// Firecracker version check handler
func (s *Server) handleFirecrackerCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get cached version info from updater
	cache := s.updater.GetCache()

	result := map[string]interface{}{
		"current_version":  cache.CurrentVersion,
		"latest_version":   cache.LatestVersion,
		"update_available": cache.UpdateAvailable,
		"checked_at":       cache.CheckedAt,
	}

	if cache.Error != "" {
		result["error"] = cache.Error
	}

	s.jsonResponse(w, result)
}

// Firecracker upgrade handler
func (s *Server) handleFirecrackerUpgrade(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if any VMs are running
	vms, err := s.db.ListVMs()
	if err != nil {
		s.jsonError(w, "Failed to check running VMs", http.StatusInternalServerError)
		return
	}

	for _, vmObj := range vms {
		if vmObj.Status == "running" {
			s.jsonError(w, "Cannot upgrade while VMs are running. Please stop all VMs first.", http.StatusBadRequest)
			return
		}
	}

	// Perform upgrade in background
	go func() {
		s.logger("Starting Firecracker upgrade...")

		setupInst := setup.NewSetup(s.logger)
		if err := setupInst.UpgradeFirecracker(); err != nil {
			s.logger("Firecracker upgrade failed: %v", err)
			return
		}

		s.logger("Firecracker upgrade completed successfully")

		// Invalidate cache to trigger re-check with new version
		s.updater.InvalidateCache()
	}()

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Firecracker upgrade started",
	})
}

// Ping handler to check if an IP address is reachable
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract IP from URL: /api/ping/{ip}
	path := strings.TrimPrefix(r.URL.Path, "/api/ping/")
	ipStr := strings.TrimSuffix(path, "/")

	if ipStr == "" {
		s.jsonError(w, "IP address required", http.StatusBadRequest)
		return
	}

	// Parse and validate IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		s.jsonError(w, "Invalid IP address format", http.StatusBadRequest)
		return
	}

	// Perform ICMP ping with 1 second timeout
	reachable := ping(ipStr, time.Second)

	s.jsonResponse(w, map[string]interface{}{
		"ip":        ipStr,
		"reachable": reachable,
	})
}

// ping sends an ICMP echo request to the specified IP and returns true if reachable
func ping(addr string, timeout time.Duration) bool {
	// Use a simple TCP connection attempt as a fallback method
	// Try to connect to common ports with timeout
	ports := []string{"22", "80", "443"}

	// First try ICMP ping
	if icmpPing(addr, timeout) {
		return true
	}

	// Fallback: try TCP connection to common ports
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", addr+":"+port, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

// icmpPing attempts an ICMP echo request
func icmpPing(addr string, timeout time.Duration) bool {
	// Listen for ICMP replies using privileged socket (requires root)
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	// Resolve destination
	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return false
	}

	// Create ICMP message with unique ID
	id := int(time.Now().UnixNano() & 0xffff)
	seq := 1

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("FCMPING"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	// Send ICMP echo request
	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return false
	}

	// Wait for reply
	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			return false
		}

		// Parse reply - protocol 1 is ICMP
		rm, err := icmp.ParseMessage(1, reply[:n])
		if err != nil {
			continue
		}

		// Check if it's an echo reply from our target
		if rm.Type == ipv4.ICMPTypeEchoReply {
			if peer.String() == dst.String() {
				if echo, ok := rm.Body.(*icmp.Echo); ok {
					if echo.ID == id && echo.Seq == seq {
						return true
					}
				}
			}
		}
	}
}

// Process start time for uptime calculation
var startTime = time.Now()

// WebSocket upgrader for console connections
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for local use
	},
}

// handleVMConsole handles WebSocket connections for VM console access
func (s *Server) handleVMConsole(w http.ResponseWriter, r *http.Request) {
	// Check authentication via session cookie
	session := s.getSession(r)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract VM ID from URL: /api/vms/console/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/vms/console/")
	vmID := strings.TrimSuffix(path, "/")

	if vmID == "" {
		http.Error(w, "VM ID required", http.StatusBadRequest)
		return
	}

	// Check if VM exists and is running
	if !s.vmMgr.IsRunning(vmID) {
		http.Error(w, "VM is not running", http.StatusBadRequest)
		return
	}

	// Get console I/O streams
	consoleIn, consoleOut, err := s.vmMgr.GetConsoleIO(vmID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Upgrade to WebSocket
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	s.logger("Console connected for VM %s", vmID)

	// Create done channel for cleanup
	done := make(chan struct{})

	// Goroutine to read from VM console and send to WebSocket
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := consoleOut.Read(buf)
			if err != nil {
				if err != io.EOF {
					s.logger("Console read error for VM %s: %v", vmID, err)
				}
				return
			}
			if n > 0 {
				if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					s.logger("WebSocket write error for VM %s: %v", vmID, err)
					return
				}
			}
		}
	}()

	// Read from WebSocket and write to VM console
	for {
		select {
		case <-done:
			return
		default:
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					s.logger("WebSocket read error for VM %s: %v", vmID, err)
				}
				return
			}
			if _, err := consoleIn.Write(message); err != nil {
				s.logger("Console write error for VM %s: %v", vmID, err)
				return
			}
		}
	}
}

// handleVMImport handles importing a .fcrack archive to create a new VM
func (s *Server) handleVMImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form with a max memory of 64MB (rest will be written to temp files)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		s.jsonError(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get the name and kernel_id from the form
	name := r.FormValue("name")
	if name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	kernelID := r.FormValue("kernel_id")
	if kernelID == "" {
		s.jsonError(w, "Kernel ID is required", http.StatusBadRequest)
		return
	}

	// Verify kernel exists
	kernelImg, err := s.db.GetKernelImage(kernelID)
	if err != nil || kernelImg == nil {
		s.jsonError(w, "Kernel not found", http.StatusBadRequest)
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Verify file extension
	if !strings.HasSuffix(header.Filename, ".fcrack") {
		s.jsonError(w, "Invalid file format. Expected .fcrack archive", http.StatusBadRequest)
		return
	}

	// Save to temp file
	tempFile, err := os.CreateTemp("", "fcm-import-*.fcrack")
	if err != nil {
		s.jsonError(w, "Failed to create temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	written, err := io.Copy(tempFile, file)
	tempFile.Close()
	if err != nil {
		s.jsonError(w, "Failed to save uploaded file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Uploaded .fcrack archive: %s (%d bytes from %s)", name, written, header.Filename)

	// Import the VM
	newVM, err := s.vmMgr.ImportVM(tempPath, name, kernelID)
	if err != nil {
		s.jsonError(w, "Failed to import VM: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.db.AddVMLog(newVM.ID, "info", "VM imported from "+header.Filename)
	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"vm":     newVM,
	})
}

// handleVMExportDownload serves .fcrack files for download
func (s *Server) handleVMExportDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract filename from URL: /api/vms/export/{filename}
	filename := strings.TrimPrefix(r.URL.Path, "/api/vms/export/")
	filename = strings.TrimSuffix(filename, "/")

	if filename == "" {
		s.jsonError(w, "Filename required", http.StatusBadRequest)
		return
	}

	// Security check: ensure filename doesn't contain path separators
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		s.jsonError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Verify file extension
	if !strings.HasSuffix(filename, ".fcrack") {
		s.jsonError(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	// Build full path
	exportPath := s.vmMgr.GetExportPath(filename)

	// Check if file exists
	fileInfo, err := os.Stat(exportPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.jsonError(w, "Export file not found", http.StatusNotFound)
			return
		}
		s.jsonError(w, "Failed to access export file", http.StatusInternalServerError)
		return
	}

	// Open file
	file, err := os.Open(exportPath)
	if err != nil {
		s.jsonError(w, "Failed to open export file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set headers for download
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	// Stream the file
	io.Copy(w, file)
}

// Helper functions
func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func generateID() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

// buildKernelArgs constructs kernel arguments with network configuration if needed
// Format: ip=<client-ip>:<server-ip>:<gateway>:<netmask>:<hostname>:<device>:<autoconf>
func buildKernelArgs(baseArgs, ipAddress, gateway string) string {
	defaultArgs := "console=ttyS0 reboot=k panic=1 pci=off"

	// Start with base args or default
	args := baseArgs
	if args == "" {
		args = defaultArgs
	}

	// Remove any existing ip= parameter first
	parts := strings.Fields(args)
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		if !strings.HasPrefix(p, "ip=") {
			filtered = append(filtered, p)
		}
	}
	args = strings.Join(filtered, " ")

	// Add IP configuration if we have an IP address
	if ipAddress != "" && gateway != "" {
		// Format: ip=<client-ip>::<gateway>:<netmask>::eth0:off
		ipConfig := "ip=" + ipAddress + "::" + gateway + ":255.255.255.0::eth0:off"
		args = args + " " + ipConfig
	}

	return args
}

// CleanupSessions periodically removes expired sessions
func (s *Server) CleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.db.CleanExpiredSessions()

		// Clean session cache
		s.sessionMu.Lock()
		now := time.Now()
		for id, sess := range s.sessionCache {
			if now.After(sess.ExpiresAt) {
				delete(s.sessionCache, id)
			}
		}
		s.sessionMu.Unlock()
	}
}

// InitDefaultAdmin creates the default admin user if no users exist
func (s *Server) InitDefaultAdmin() error {
	count, err := s.db.UserCount()
	if err != nil {
		return err
	}

	if count == 0 {
		hash := sha256.Sum256([]byte("admin"))
		user := &database.User{
			Username:     "admin",
			PasswordHash: hex.EncodeToString(hash[:]),
			Email:        "",
			Role:         "admin",
			Active:       true,
		}
		if err := s.db.CreateUser(user); err != nil {
			return err
		}
		s.logger("Created default admin user (username: admin, password: admin)")
	}
	return nil
}
