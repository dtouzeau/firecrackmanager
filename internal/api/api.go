package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/hostnet"
	"firecrackmanager/internal/kernel"
	"firecrackmanager/internal/kernelbuilder"
	"firecrackmanager/internal/kernelupdater"
	"firecrackmanager/internal/ldap"
	"firecrackmanager/internal/network"
	"firecrackmanager/internal/proxyconfig"
	"firecrackmanager/internal/setup"
	"firecrackmanager/internal/store"
	"firecrackmanager/internal/updater"
	"firecrackmanager/internal/version"
	"firecrackmanager/internal/vm"

	"github.com/gorilla/websocket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// UpgradeProgress tracks the progress of a Firecracker upgrade
type UpgradeProgress struct {
	Status         string   `json:"status"`          // idle, running, completed, error
	Step           int      `json:"step"`            // Current step number
	TotalSteps     int      `json:"total_steps"`     // Total number of steps
	CurrentTask    string   `json:"current_task"`    // Description of current task
	Logs           []string `json:"logs"`            // Log messages
	Error          string   `json:"error,omitempty"` // Error message if failed
	StartedAt      string   `json:"started_at,omitempty"`
	CompletedAt    string   `json:"completed_at,omitempty"`
	CurrentVersion string   `json:"current_version,omitempty"`
	TargetVersion  string   `json:"target_version,omitempty"`
}

type Server struct {
	db                          *database.DB
	vmMgr                       *vm.Manager
	netMgr                      *network.Manager
	kernelMgr                   *kernel.Manager
	mux                         *http.ServeMux
	sessionMu                   sync.RWMutex
	sessionCache                map[string]*database.Session
	logger                      func(string, ...interface{})
	updater                     *updater.Updater
	kernelUpdater               *kernelupdater.KernelUpdater
	migrationSrv                *vm.MigrationServer
	dataDir                     string
	hostNetMgr                  *hostnet.Manager
	enableHostNetworkManagement bool
	builderDir                  string
	store                       *store.Store
	rootfsScanner               RootFSScanner
	appliancesScanner           AppliancesScanner
	upgradeProgress             *UpgradeProgress
	upgradeProgressMu           sync.RWMutex
	ldapClient                  *ldap.Client
	ldapClientMu                sync.RWMutex
	kernelBuilder               *kernelbuilder.Builder
}

// RootFSScanner interface for triggering rootfs scans
type RootFSScanner interface {
	TriggerScan()
}

// AppliancesScanner interface for scanning exported VMs
type AppliancesScanner interface {
	TriggerScan()
	ScanSync()
	GetCached() interface{}
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
		builderDir:   "/home/Builder", // default
	}
	s.registerRoutes()
	return s
}

// SetBuilderDir sets the directory used for building Debian images
func (s *Server) SetBuilderDir(dir string) {
	s.builderDir = dir
}

// SetRootFSScanner sets the rootfs scanner for triggering scans after conversions
func (s *Server) SetRootFSScanner(scanner RootFSScanner) {
	s.rootfsScanner = scanner
}

// SetKernelUpdater sets the kernel updater for kernel version management
func (s *Server) SetKernelUpdater(ku *kernelupdater.KernelUpdater) {
	s.kernelUpdater = ku
}

// SetAppliancesScanner sets the appliances scanner for exported VMs cache
func (s *Server) SetAppliancesScanner(scanner AppliancesScanner) {
	s.appliancesScanner = scanner
}

// SetKernelBuilder sets the kernel builder for compiling custom kernels
func (s *Server) SetKernelBuilder(kb *kernelbuilder.Builder) {
	s.kernelBuilder = kb
}

// GetBuilderDir returns the current builder directory
func (s *Server) GetBuilderDir() string {
	if s.builderDir == "" {
		return "/home/Builder"
	}
	return s.builderDir
}

// handleBuilderDir returns the configured builder directory
func (s *Server) handleBuilderDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.jsonResponse(w, map[string]string{
		"builder_dir": s.GetBuilderDir(),
	})
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
	s.mux.HandleFunc("/api/vms/search", s.requireAuth(s.handleVMSearch))
	s.mux.HandleFunc("/api/vms/import", s.requireAuth(s.handleVMImport))
	s.mux.HandleFunc("/api/vms/export/", s.requireAuth(s.handleVMExportDownload))
	s.mux.HandleFunc("/api/vms/", s.requireAuth(s.handleVM))

	// VM Groups routes (admin only for management, auth for viewing)
	s.mux.HandleFunc("/api/vmgroups", s.requireAuth(s.handleVMGroups))
	s.mux.HandleFunc("/api/vmgroups/", s.requireAuth(s.handleVMGroup))

	// Network routes (requires networks permission)
	s.mux.HandleFunc("/api/networks", s.requirePermission("networks", s.handleNetworks))
	s.mux.HandleFunc("/api/networks/", s.requirePermission("networks", s.handleNetwork))
	s.mux.HandleFunc("/api/interfaces", s.requirePermission("networks", s.handlePhysicalInterfaces))

	// Kernel routes (requires images permission)
	s.mux.HandleFunc("/api/kernels", s.requirePermission("images", s.handleKernels))
	s.mux.HandleFunc("/api/kernels/", s.requirePermission("images", s.handleKernel))
	s.mux.HandleFunc("/api/kernels/download", s.requirePermission("images", s.handleKernelDownload))
	s.mux.HandleFunc("/api/kernels/rescan-virtio", s.requireAdmin(s.handleKernelRescanVirtio))
	s.mux.HandleFunc("/api/kernels/build", s.requireAdmin(s.handleKernelBuild))
	s.mux.HandleFunc("/api/kernels/build/", s.requireAuth(s.handleKernelBuildProgress))

	// RootFS routes (requires images permission)
	s.mux.HandleFunc("/api/rootfs", s.requirePermission("images", s.handleRootFSList))
	s.mux.HandleFunc("/api/rootfs/", s.requirePermission("images", s.handleRootFS))
	s.mux.HandleFunc("/api/rootfs/download", s.requirePermission("images", s.handleRootFSDownload))
	s.mux.HandleFunc("/api/rootfs/create", s.requirePermission("images", s.handleRootFSCreate))
	s.mux.HandleFunc("/api/rootfs/upload", s.requirePermission("images", s.handleRootFSUpload))
	s.mux.HandleFunc("/api/rootfs/extend/", s.requirePermission("images", s.handleRootFSExtend))
	s.mux.HandleFunc("/api/rootfs/convert-qemu", s.requirePermission("images", s.handleQemuConvert))

	// User routes (admin only)
	s.mux.HandleFunc("/api/users", s.requireAdmin(s.handleUsers))
	s.mux.HandleFunc("/api/users/", s.requireAdmin(s.handleUser))

	// Current user account route (any authenticated user)
	s.mux.HandleFunc("/api/account", s.requireAuth(s.handleAccount))
	s.mux.HandleFunc("/api/account/password", s.requireAuth(s.handleAccountPassword))

	// Group routes (admin only)
	s.mux.HandleFunc("/api/groups", s.requireAdmin(s.handleGroups))
	s.mux.HandleFunc("/api/groups/", s.requireAdmin(s.handleGroup))

	// Logs route
	s.mux.HandleFunc("/api/logs", s.requireAuth(s.handleLogs))
	s.mux.HandleFunc("/api/logs/", s.requireAuth(s.handleVMLogs))

	// Download progress
	s.mux.HandleFunc("/api/downloads/", s.requireAuth(s.handleDownloadProgress))

	// Operation progress (for async operations like VM duplication)
	s.mux.HandleFunc("/api/operations/", s.requireAuth(s.handleOperationProgress))

	// System status and Firecracker management
	s.mux.HandleFunc("/api/system/status", s.requireAuth(s.handleSystemStatus))
	s.mux.HandleFunc("/api/system/firecracker/check", s.requireAuth(s.handleFirecrackerCheck))
	s.mux.HandleFunc("/api/system/firecracker/upgrade", s.requireAdmin(s.handleFirecrackerUpgrade))
	s.mux.HandleFunc("/api/system/firecracker/upgrade/progress", s.requireAuth(s.handleFirecrackerUpgradeProgress))
	s.mux.HandleFunc("/api/system/jailer", s.requireAdmin(s.handleJailerConfig))

	// Kernel update management
	s.mux.HandleFunc("/api/system/kernels/check", s.requireAuth(s.handleKernelUpdateCheck))
	s.mux.HandleFunc("/api/system/kernels/download", s.requireAdmin(s.handleKernelUpdateDownload))
	s.mux.HandleFunc("/api/system/kernels/download/", s.requireAuth(s.handleKernelDownloadProgress))

	// Ping endpoint for checking VM reachability
	s.mux.HandleFunc("/api/ping/", s.requireAuth(s.handlePing))

	// Port scan endpoint
	s.mux.HandleFunc("/api/scan-ports/", s.requireAuth(s.handleScanPorts))

	// WebSocket console endpoint
	s.mux.HandleFunc("/api/vms/console/", s.handleVMConsole)

	// Registry/Container image routes
	// Docker registry routes (requires images permission)
	s.mux.HandleFunc("/api/registry/search", s.requirePermission("images", s.handleRegistrySearch))
	s.mux.HandleFunc("/api/registry/convert", s.requirePermission("images", s.handleRegistryConvert))
	s.mux.HandleFunc("/api/registry/convert/", s.requirePermission("images", s.handleRegistryConversionStatus))
	s.mux.HandleFunc("/api/registry/jobs", s.requirePermission("images", s.handleRegistryJobs))

	// Docker Compose routes (requires images permission)
	s.mux.HandleFunc("/api/compose/services", s.requirePermission("images", s.handleComposeServices))
	s.mux.HandleFunc("/api/compose/convert", s.requirePermission("images", s.handleComposeConvert))
	s.mux.HandleFunc("/api/compose/upload", s.requirePermission("images", s.handleComposeUpload))

	// Data disk creation (requires images permission)
	s.mux.HandleFunc("/api/rootfs/create-data-disk", s.requirePermission("images", s.handleCreateDataDisk))

	// Debian image builder
	s.mux.HandleFunc("/api/rootfs/build-debian", s.requireAdmin(s.handleBuildDebianImage))
	s.mux.HandleFunc("/api/rootfs/build-debian/progress", s.requireAuth(s.handleBuildDebianProgress))
	s.mux.HandleFunc("/api/system/builder-dir", s.requireAuth(s.handleBuilderDir))

	// Proxy configuration (admin only)
	s.mux.HandleFunc("/api/system/proxy", s.requireAdmin(s.handleProxyConfig))
	s.mux.HandleFunc("/api/system/proxy/test", s.requireAdmin(s.handleProxyTest))

	// QEMU utils status and installation (admin only for install)
	s.mux.HandleFunc("/api/system/qemu-utils", s.requireAuth(s.handleQemuUtilsStatus))
	s.mux.HandleFunc("/api/system/qemu-utils/install", s.requireAdmin(s.handleQemuUtilsInstall))

	// Migration routes (admin only)
	s.mux.HandleFunc("/api/migration/keys", s.requireAdmin(s.handleMigrationKeys))
	s.mux.HandleFunc("/api/migration/keys/", s.requireAdmin(s.handleMigrationKey))
	s.mux.HandleFunc("/api/migration/server", s.requireAdmin(s.handleMigrationServer))
	s.mux.HandleFunc("/api/migration/send", s.requireAdmin(s.handleMigrationSend))
	s.mux.HandleFunc("/api/migration/status", s.requireAuth(s.handleMigrationStatus))

	// Appliances routes (exported VMs)
	s.mux.HandleFunc("/api/appliances", s.requireAuth(s.handleAppliances))
	s.mux.HandleFunc("/api/appliances/restore/", s.requireAuth(s.handleApplianceRestore))
	s.mux.HandleFunc("/api/appliances/", s.requireAuth(s.handleAppliance))

	// Store routes (appliance store)
	s.mux.HandleFunc("/api/store", s.requireAuth(s.handleStore))
	s.mux.HandleFunc("/api/store/download/", s.requireAuth(s.handleStoreDownload))
	s.mux.HandleFunc("/api/store/progress/", s.requireAuth(s.handleStoreProgress))
	s.mux.HandleFunc("/api/store/refresh", s.requireAuth(s.handleStoreRefresh))

	// Host network management routes (admin only)
	s.registerHostNetRoutes()

	// LDAP/Active Directory routes (admin only)
	s.mux.HandleFunc("/api/system/ldap", s.requireAdmin(s.handleLDAPConfig))
	s.mux.HandleFunc("/api/system/ldap/test", s.requireAdmin(s.handleLDAPTest))
	s.mux.HandleFunc("/api/system/ldap/groups", s.requireAdmin(s.handleLDAPGroups))
	s.mux.HandleFunc("/api/system/ldap/group-members", s.requireAdmin(s.handleLDAPGroupMemberCount))
	s.mux.HandleFunc("/api/ldap/group-mappings", s.requireAdmin(s.handleLDAPGroupMappings))
	s.mux.HandleFunc("/api/ldap/group-mappings/", s.requireAdmin(s.handleLDAPGroupMapping))
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

// requirePermission creates middleware that checks if user has a specific permission
func (s *Server) requirePermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := s.getSession(r)
		if session == nil {
			s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Admins have all permissions
		if session.Role == "admin" {
			s.db.ExtendSession(session.ID, 24*time.Hour)
			next(w, r)
			return
		}
		// Check if user has the required permission from their groups
		perms := s.db.GetUserPermissions(session.UserID, session.Role)
		if !perms[permission] && !perms["admin"] {
			s.jsonError(w, "Forbidden: requires "+permission+" permission", http.StatusForbidden)
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

	var user *database.User
	var err error

	// First try to find local user
	user, err = s.db.GetUserByUsername(req.Username)

	if user != nil {
		// User exists locally
		if user.LDAPUser {
			// LDAP user - authenticate via LDAP
			ldapUser, ldapErr := s.authenticateLDAP(req.Username, req.Password)
			if ldapErr != nil {
				s.logger("LDAP authentication failed for user %s: %v", req.Username, ldapErr)
				s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}
			// Check if AD user has privileges
			if !s.hasADUserPrivileges(ldapUser) {
				s.logger("AD user %s has no privileges - login denied", req.Username)
				s.jsonError(w, "Access denied: your account is not a member of any privileged group", http.StatusForbidden)
				return
			}
			// Update user info from LDAP
			s.updateUserFromLDAP(user, ldapUser)
		} else {
			// Local user - verify password hash
			hash := sha256.Sum256([]byte(req.Password))
			if user.PasswordHash != hex.EncodeToString(hash[:]) {
				s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}
		}
	} else {
		// User doesn't exist locally - try LDAP authentication
		ldapUser, ldapErr := s.authenticateLDAP(req.Username, req.Password)
		if ldapErr != nil {
			s.jsonError(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Check if AD user has privileges before creating account
		if !s.hasADUserPrivileges(ldapUser) {
			s.logger("AD user %s has no privileges - login denied", req.Username)
			s.jsonError(w, "Access denied: your account is not a member of any privileged group", http.StatusForbidden)
			return
		}

		// Create local user from LDAP
		user, err = s.createUserFromLDAP(ldapUser)
		if err != nil {
			s.logger("Failed to create local user from LDAP: %v", err)
			s.jsonError(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
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

// authenticateLDAP attempts to authenticate a user via LDAP
func (s *Server) authenticateLDAP(username, password string) (*ldap.ADUser, error) {
	// Check if LDAP is enabled
	ldapConfig, err := s.db.GetLDAPConfig()
	if err != nil || ldapConfig == nil || !ldapConfig.Enabled {
		return nil, fmt.Errorf("LDAP not enabled")
	}

	client, err := s.getLDAPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP client: %w", err)
	}

	return client.AuthenticateUser(username, password)
}

// createUserFromLDAP creates a local user based on LDAP authentication
func (s *Server) createUserFromLDAP(ldapUser *ldap.ADUser) (*database.User, error) {
	// Determine role based on group mappings
	role := "user"
	var groupID string

	mappings, err := s.db.ListLDAPGroupMappings()
	if err == nil {
		for _, mapping := range mappings {
			for _, userGroup := range ldapUser.Groups {
				if strings.EqualFold(userGroup, mapping.GroupDN) {
					if mapping.LocalRole == "admin" {
						role = "admin"
						break
					} else if mapping.LocalRole == "group" {
						role = "user"
						groupID = mapping.LocalGroupID
					}
				}
			}
			if role == "admin" {
				break
			}
		}
	}

	user, err := s.db.CreateOrUpdateLDAPUser(ldapUser.SAMAccountName, role, ldapUser.DN)
	if err != nil {
		return nil, err
	}

	// Add to group if specified by LDAP group mapping
	if groupID != "" && user.ID > 0 {
		s.db.AddGroupMember(groupID, user.ID)
	}

	// Add user to any imported AD groups they belong to
	s.syncUserADGroupMembership(user.ID, ldapUser.Groups)

	s.logger("Created/updated LDAP user: %s (role: %s)", user.Username, role)
	return user, nil
}

// updateUserFromLDAP updates an existing user's role based on LDAP groups
func (s *Server) updateUserFromLDAP(user *database.User, ldapUser *ldap.ADUser) {
	// Update role based on group mappings
	mappings, err := s.db.ListLDAPGroupMappings()
	if err != nil {
		return
	}

	newRole := "user"
	var groupID string

	for _, mapping := range mappings {
		for _, userGroup := range ldapUser.Groups {
			if strings.EqualFold(userGroup, mapping.GroupDN) {
				if mapping.LocalRole == "admin" {
					newRole = "admin"
					break
				} else if mapping.LocalRole == "group" {
					groupID = mapping.LocalGroupID
				}
			}
		}
		if newRole == "admin" {
			break
		}
	}

	// Update role if changed
	if user.Role != newRole {
		user.Role = newRole
		s.db.UpdateUser(user)
		s.logger("Updated LDAP user role: %s -> %s", user.Username, newRole)
	}

	// Update group membership from mapping
	if groupID != "" && user.ID > 0 {
		s.db.AddGroupMember(groupID, user.ID)
	}

	// Sync user with imported AD groups they belong to
	s.syncUserADGroupMembership(user.ID, ldapUser.Groups)
}

// syncUserADGroupMembership adds a user to any imported AD groups they belong to
func (s *Server) syncUserADGroupMembership(userID int, adGroups []string) {
	if userID <= 0 || len(adGroups) == 0 {
		return
	}

	// Check each AD group the user belongs to
	for _, adGroupDN := range adGroups {
		// Check if this AD group DN exists as a local group (imported AD group)
		group, err := s.db.GetGroupByName(adGroupDN)
		if err != nil || group == nil {
			continue
		}

		// Add user to this group
		if err := s.db.AddGroupMember(group.ID, userID); err != nil {
			s.logger("Failed to add user %d to AD group %s: %v", userID, group.ID, err)
		} else {
			s.logger("Added user %d to imported AD group: %s", userID, adGroupDN)
		}
	}
}

// hasADUserPrivileges checks if an AD user belongs to any privileged group
// (either via LDAP group mappings or imported AD groups)
func (s *Server) hasADUserPrivileges(ldapUser *ldap.ADUser) bool {
	if ldapUser == nil || len(ldapUser.Groups) == 0 {
		return false
	}

	// Check LDAP group mappings
	mappings, err := s.db.ListLDAPGroupMappings()
	if err == nil && len(mappings) > 0 {
		for _, mapping := range mappings {
			for _, userGroup := range ldapUser.Groups {
				if strings.EqualFold(userGroup, mapping.GroupDN) {
					return true
				}
			}
		}
	}

	// Check imported AD groups (groups with DN as name)
	for _, adGroupDN := range ldapUser.Groups {
		group, err := s.db.GetGroupByName(adGroupDN)
		if err == nil && group != nil {
			return true
		}
	}

	return false
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
		// Get session for access control
		sess := s.getSession(r)
		if sess == nil {
			s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Filter VMs based on user role and group membership
		vms, err := s.db.GetUserAccessibleVMs(sess.UserID, sess.Role)
		if err != nil {
			s.jsonError(w, "Failed to list VMs", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"vms": vms})

	case http.MethodPost:
		var req struct {
			Name                 string `json:"name"`
			Description          string `json:"description"`
			VCPU                 int    `json:"vcpu"`
			MemoryMB             int    `json:"memory_mb"`
			KernelID             string `json:"kernel_id"`
			RootFSID             string `json:"rootfs_id"`
			KernelArgs           string `json:"kernel_args"`
			NetworkID            string `json:"network_id"`
			DNSServers           string `json:"dns_servers"`
			SnapshotType         string `json:"snapshot_type"`
			DataDiskID           string `json:"data_disk_id"`
			RootPassword         string `json:"root_password"`
			HotplugMemoryEnabled bool   `json:"hotplug_memory_enabled"`
			HotplugMemoryTotalMB int    `json:"hotplug_memory_total_mb"`
			HotplugMemoryBlockMB int    `json:"hotplug_memory_block_mb"`
			HotplugMemorySlotMB  int    `json:"hotplug_memory_slot_mb"`
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

		// Set hotplug defaults
		hotplugBlockMB := req.HotplugMemoryBlockMB
		if hotplugBlockMB <= 0 {
			hotplugBlockMB = 2
		}
		hotplugSlotMB := req.HotplugMemorySlotMB
		if hotplugSlotMB <= 0 {
			hotplugSlotMB = 128
		}

		vmObj := &database.VM{
			ID:                   vmID,
			Name:                 req.Name,
			Description:          req.Description,
			VCPU:                 req.VCPU,
			MemoryMB:             req.MemoryMB,
			KernelPath:           kernelImg.Path,
			RootFSPath:           rootfs.Path,
			KernelArgs:           req.KernelArgs,
			DNSServers:           req.DNSServers,
			SnapshotType:         req.SnapshotType,
			Status:               "stopped",
			HotplugMemoryEnabled: req.HotplugMemoryEnabled,
			HotplugMemoryTotalMB: req.HotplugMemoryTotalMB,
			HotplugMemoryBlockMB: hotplugBlockMB,
			HotplugMemorySlotMB:  hotplugSlotMB,
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
				vmObj.KernelArgs = "console=ttyS0,115200n8 reboot=k panic=1"
			}
		}

		if err := s.db.CreateVM(vmObj); err != nil {
			s.jsonError(w, "Failed to create VM: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(vmID, "info", "VM created")

		// Set root password if specified
		if req.RootPassword != "" {
			if err := setRootPassword(rootfs.Path, req.RootPassword); err != nil {
				s.logger("Warning: Failed to set root password: %v", err)
				s.db.AddVMLog(vmID, "warning", "Failed to set root password: "+err.Error())
			} else {
				s.db.AddVMLog(vmID, "info", "Root password set")
			}
		}

		// Attach data disk if specified
		if req.DataDiskID != "" {
			dataDisk, err := s.db.GetRootFS(req.DataDiskID)
			if err != nil || dataDisk == nil {
				s.logger("Warning: Data disk %s not found, skipping attachment", req.DataDiskID)
			} else {
				vmDisk := &database.VMDisk{
					ID:         generateID(),
					VMID:       vmID,
					Name:       dataDisk.Name,
					Path:       dataDisk.Path,
					SizeMB:     dataDisk.Size / (1024 * 1024),
					Format:     dataDisk.Format,
					MountPoint: "/mnt/data",
					DriveID:    "data",
					IsReadOnly: false,
				}
				if err := s.db.CreateVMDisk(vmDisk); err != nil {
					s.logger("Warning: Failed to attach data disk: %v", err)
				} else {
					s.db.AddVMLog(vmID, "info", "Data disk attached: "+dataDisk.Name)
				}
			}
		}

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

	// Get session for access control
	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Helper to check VM access with specific permission
	checkAccess := func(permission string) bool {
		canAccess, err := s.db.CanUserAccessVM(sess.UserID, sess.Role, vmID, permission)
		if err != nil || !canAccess {
			return false
		}
		return true
	}

	switch action {
	case "start":
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkAccess("start") {
			s.jsonError(w, "Access denied: no permission to start this VM", http.StatusForbidden)
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
		if !checkAccess("stop") {
			s.jsonError(w, "Access denied: no permission to stop this VM", http.StatusForbidden)
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
		if !checkAccess("stop") {
			s.jsonError(w, "Access denied: no permission to stop this VM", http.StatusForbidden)
			return
		}
		if err := s.vmMgr.ForceStopVM(vmID); err != nil {
			s.jsonError(w, "Failed to force stop VM: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": "success", "message": "VM force stopped"})

	case "status":
		// Any permission grants read access to status
		if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") {
			s.jsonError(w, "Access denied: no permission to view this VM", http.StatusForbidden)
			return
		}
		status, err := s.vmMgr.GetVMStatus(vmID)
		if err != nil {
			s.jsonError(w, "Failed to get status: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]string{"status": status})

	case "info":
		// Any permission grants read access to info
		if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") {
			s.jsonError(w, "Access denied: no permission to view this VM", http.StatusForbidden)
			return
		}
		info, err := s.vmMgr.GetVMInfo(vmID)
		if err != nil {
			s.jsonError(w, "Failed to get info: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, info)

	case "metrics":
		// Any permission grants read access to metrics
		if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") {
			s.jsonError(w, "Access denied: no permission to view this VM", http.StatusForbidden)
			return
		}
		metrics, err := s.vmMgr.GetVMMetrics(vmID)
		if err != nil {
			s.jsonError(w, "Failed to get metrics: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, metrics)

	case "metrics-history":
		// GET /api/vms/{id}/metrics-history?period=realtime|hour|day|week|month
		if r.Method != http.MethodGet {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Any permission grants read access to metrics
		if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") {
			s.jsonError(w, "Access denied: no permission to view this VM", http.StatusForbidden)
			return
		}

		period := r.URL.Query().Get("period")
		if period == "" {
			period = "realtime"
		}

		var metrics []*database.VMMetric
		var err error

		switch period {
		case "realtime":
			// Last 10 minutes, raw data from vm_metrics
			since := time.Now().Add(-10 * time.Minute)
			metrics, err = s.db.GetVMMetrics(vmID, since, 60)

		case "hour":
			// Last hour, raw data from vm_metrics
			since := time.Now().Add(-1 * time.Hour)
			metrics, err = s.db.GetVMMetrics(vmID, since, 360)

		case "day":
			// Last 24 hours - use 10-minute compressed data + recent raw data
			since := time.Now().Add(-24 * time.Hour)
			oneHourAgo := time.Now().Add(-1 * time.Hour)

			// Get compressed 10-minute data for older period
			compressed, err1 := s.db.GetVMMetrics10Min(vmID, since)
			if err1 != nil {
				compressed = []*database.VMMetric{}
			}

			// Get raw data for the last hour (not yet compressed)
			raw, err2 := s.db.GetVMMetricsAggregated(vmID, oneHourAgo, 10)
			if err2 != nil {
				raw = []*database.VMMetric{}
			}

			// Combine: compressed older data + aggregated recent data
			metrics = append(compressed, raw...)

		case "week":
			// Last 7 days - use hourly compressed data + recent 10-min data
			since := time.Now().Add(-7 * 24 * time.Hour)
			oneDayAgo := time.Now().Add(-24 * time.Hour)

			// Get compressed hourly data for older period
			compressed, err1 := s.db.GetVMMetricsHourly(vmID, since)
			if err1 != nil {
				compressed = []*database.VMMetric{}
			}

			// Get 10-minute data for the last day (not yet compressed to hourly)
			recent, err2 := s.db.GetVMMetrics10Min(vmID, oneDayAgo)
			if err2 != nil {
				recent = []*database.VMMetric{}
			}

			metrics = append(compressed, recent...)

		case "month":
			// Last 30 days - use 14-hour compressed data + recent hourly data
			since := time.Now().Add(-30 * 24 * time.Hour)
			oneWeekAgo := time.Now().Add(-7 * 24 * time.Hour)

			// Get compressed 14-hour data for older period
			compressed, err1 := s.db.GetVMMetricsDaily(vmID, since)
			if err1 != nil {
				compressed = []*database.VMMetric{}
			}

			// Get hourly data for the last week (not yet compressed to 14-hour)
			recent, err2 := s.db.GetVMMetricsHourly(vmID, oneWeekAgo)
			if err2 != nil {
				recent = []*database.VMMetric{}
			}

			metrics = append(compressed, recent...)

		default:
			s.jsonError(w, "Invalid period. Use: realtime, hour, day, week, month", http.StatusBadRequest)
			return
		}

		if err != nil {
			s.jsonError(w, "Failed to get metrics history: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Ensure metrics is never null in JSON (empty array instead)
		if metrics == nil {
			metrics = []*database.VMMetric{}
		}

		s.jsonResponse(w, map[string]interface{}{
			"period":  period,
			"metrics": metrics,
		})

	case "snapshot":
		// Check snapshot permission
		if !checkAccess("snapshot") {
			s.jsonError(w, "Access denied: no permission for snapshots on this VM", http.StatusForbidden)
			return
		}
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
		// Check snapshot permission
		if !checkAccess("snapshot") {
			s.jsonError(w, "Access denied: no permission for snapshots on this VM", http.StatusForbidden)
			return
		}
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
		// POST /api/vms/{id}/duplicate - duplicate VM (async with progress)
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

		// Start async duplication
		opKey, err := s.vmMgr.DuplicateVMAsync(vmID, req.Name)
		if err != nil {
			s.jsonError(w, "Failed to start VM duplication: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":       "started",
			"progress_key": opKey,
		})

	case "export":
		// POST /api/vms/{id}/export - export VM as .fcrack archive
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request body for optional description
		var exportReq struct {
			Description string `json:"description"`
		}
		if r.Body != nil {
			json.NewDecoder(r.Body).Decode(&exportReq)
		}

		// Generate operation key for progress tracking
		opKey := fmt.Sprintf("export-%s-%d", vmID, time.Now().UnixNano())

		// Capture user ID for ownership and description
		ownerID := sess.UserID
		exportDescription := exportReq.Description

		// Initialize progress
		s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
			Status:  "starting",
			Stage:   "Preparing export...",
			Percent: 0,
		})

		// Run export in background
		go func() {
			// Auto-shrink rootfs before export
			s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
				Status:  "shrinking",
				Stage:   "Shrinking rootfs...",
				Percent: 0,
			})
			s.logger("Shrinking rootfs before export...")
			if err := s.vmMgr.ShrinkRootFS(vmID); err != nil {
				s.logger("Warning: failed to shrink rootfs: %v", err)
				// Continue with export even if shrink fails
			}

			archivePath, err := s.vmMgr.ExportVMWithProgress(vmID, opKey, exportDescription)
			if err != nil {
				s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
					Status: "error",
					Stage:  "Export failed",
					Error:  err.Error(),
				})
				return
			}

			// Get just the filename for the download URL
			filename := filepath.Base(archivePath)
			s.db.AddVMLog(vmID, "info", "VM exported to "+filename)

			// Set appliance owner
			if err := s.db.SetApplianceOwner(filename, ownerID); err != nil {
				s.logger("Warning: failed to set appliance owner: %v", err)
			}

			// Trigger appliances cache refresh
			if s.appliancesScanner != nil {
				s.appliancesScanner.TriggerScan()
			}

			s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
				Status:     "completed",
				Stage:      "Export completed",
				Percent:    100,
				ResultID:   filename,
				ResultName: "/api/vms/export/" + filename,
			})
		}()

		s.jsonResponse(w, map[string]interface{}{
			"status":       "started",
			"progress_key": opKey,
			"vm_id":        vmID,
		})

	case "shrink":
		// POST /api/vms/{id}/shrink - shrink VM rootfs
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := s.vmMgr.ShrinkRootFS(vmID); err != nil {
			s.jsonError(w, "Failed to shrink rootfs: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":  "success",
			"message": "RootFS shrunk successfully",
		})

	case "install-ssh":
		// POST /api/vms/{id}/install-ssh - install OpenSSH server in VM rootfs
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get VM to check status and get rootfs path
		vm, err := s.db.GetVM(vmID)
		if err != nil || vm == nil {
			s.jsonError(w, "VM not found", http.StatusNotFound)
			return
		}

		// Check if VM is running and stop it
		wasRunning := vm.Status == "running"
		if wasRunning {
			s.db.AddVMLog(vmID, "info", "Stopping VM to install SSH server")
			if err := s.vmMgr.StopVM(vmID); err != nil {
				s.jsonError(w, "Failed to stop VM: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.db.AddVMLog(vmID, "info", "VM stopped for SSH installation")
		}

		s.db.AddVMLog(vmID, "info", "Starting OpenSSH server installation")

		// Install SSH in rootfs
		if err := s.installSSHInRootFS(vm.RootFSPath, vmID); err != nil {
			s.db.AddVMLog(vmID, "error", "SSH installation failed: "+err.Error())
			s.jsonError(w, "Failed to install SSH: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(vmID, "info", "OpenSSH server installed successfully")

		// Trigger rootfs rescan to update SSH status
		if s.rootfsScanner != nil {
			s.rootfsScanner.TriggerScan()
			s.db.AddVMLog(vmID, "info", "RootFS rescan triggered after SSH installation")
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":      "success",
			"message":     "OpenSSH server installed successfully",
			"was_running": wasRunning,
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

		// Check for /api/vms/{id}/disks/{diskId}/expand
		if len(parts) >= 4 && parts[3] == "expand" {
			// POST /api/vms/{id}/disks/{diskId}/expand - expand disk
			if r.Method != http.MethodPost {
				s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			var req struct {
				NewSizeMB int64 `json:"new_size_mb"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.NewSizeMB <= 0 {
				s.jsonError(w, "New size must be positive (in MB)", http.StatusBadRequest)
				return
			}

			if err := s.vmMgr.ExpandDisk(vmID, diskID, req.NewSizeMB); err != nil {
				s.jsonError(w, "Failed to expand disk: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]interface{}{
				"status":      "success",
				"message":     "Disk expanded",
				"new_size_mb": req.NewSizeMB,
			})
			return
		}

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

	case "networks":
		// Handle /api/vms/{id}/networks routes for multiple network interfaces
		if len(parts) < 3 {
			// GET /api/vms/{id}/networks - list VM network interfaces
			// POST /api/vms/{id}/networks - attach new network interface
			if r.Method == http.MethodGet {
				vmNetworks, err := s.db.ListVMNetworks(vmID)
				if err != nil {
					s.jsonError(w, "Failed to list networks: "+err.Error(), http.StatusInternalServerError)
					return
				}

				// Enrich with network names
				type enrichedNetwork struct {
					*database.VMNetwork
					NetworkName string `json:"network_name"`
				}
				enriched := make([]enrichedNetwork, 0, len(vmNetworks))
				for _, vmNet := range vmNetworks {
					en := enrichedNetwork{VMNetwork: vmNet}
					if net, err := s.db.GetNetwork(vmNet.NetworkID); err == nil && net != nil {
						en.NetworkName = net.Name
					}
					enriched = append(enriched, en)
				}

				s.jsonResponse(w, map[string]interface{}{
					"networks": enriched,
				})
				return
			}

			if r.Method == http.MethodPost {
				// Check if VM is running
				vmObj, err := s.db.GetVM(vmID)
				if err != nil || vmObj == nil {
					s.jsonError(w, "VM not found", http.StatusNotFound)
					return
				}
				if vmObj.Status == "running" {
					s.jsonError(w, "Cannot modify networks while VM is running", http.StatusBadRequest)
					return
				}

				var req struct {
					NetworkID string `json:"network_id"`
					IPAddress string `json:"ip_address"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					s.jsonError(w, "Invalid request", http.StatusBadRequest)
					return
				}

				if req.NetworkID == "" {
					s.jsonError(w, "Network ID is required", http.StatusBadRequest)
					return
				}

				// Verify network exists
				net, err := s.db.GetNetwork(req.NetworkID)
				if err != nil || net == nil {
					s.jsonError(w, "Network not found", http.StatusNotFound)
					return
				}

				// Get next interface index
				ifaceIndex, err := s.db.GetNextIfaceIndex(vmID)
				if err != nil {
					s.jsonError(w, "Failed to get interface index: "+err.Error(), http.StatusInternalServerError)
					return
				}

				// Generate MAC address and TAP device name
				macAddress := s.vmMgr.GenerateMAC()
				tapDevice := fmt.Sprintf("fc%s-%d", vmID[:8], ifaceIndex)

				vmNetwork := &database.VMNetwork{
					ID:         generateID(),
					VMID:       vmID,
					NetworkID:  req.NetworkID,
					IfaceIndex: ifaceIndex,
					MacAddress: macAddress,
					IPAddress:  req.IPAddress,
					TapDevice:  tapDevice,
				}

				if err := s.db.CreateVMNetwork(vmNetwork); err != nil {
					s.jsonError(w, "Failed to create network interface: "+err.Error(), http.StatusInternalServerError)
					return
				}

				s.db.AddVMLog(vmID, "info", fmt.Sprintf("Added network interface eth%d on network %s", ifaceIndex, net.Name))
				s.jsonResponse(w, map[string]interface{}{
					"status":  "success",
					"network": vmNetwork,
				})
				return
			}

			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Handle /api/vms/{id}/networks/{netId} routes
		netID := parts[2]

		// DELETE /api/vms/{id}/networks/{netId} - remove network interface
		if r.Method == http.MethodDelete {
			// Check if VM is running
			vmObj, err := s.db.GetVM(vmID)
			if err != nil || vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}
			if vmObj.Status == "running" {
				s.jsonError(w, "Cannot modify networks while VM is running", http.StatusBadRequest)
				return
			}

			vmNet, err := s.db.GetVMNetwork(netID)
			if err != nil || vmNet == nil {
				s.jsonError(w, "Network interface not found", http.StatusNotFound)
				return
			}

			if err := s.db.DeleteVMNetwork(netID); err != nil {
				s.jsonError(w, "Failed to remove network interface: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.db.AddVMLog(vmID, "info", fmt.Sprintf("Removed network interface eth%d", vmNet.IfaceIndex))
			s.jsonResponse(w, map[string]string{
				"status":  "success",
				"message": "Network interface removed",
			})
			return
		}

		// PUT /api/vms/{id}/networks/{netId} - update network interface
		if r.Method == http.MethodPut {
			// Check if VM is running
			vmObj, err := s.db.GetVM(vmID)
			if err != nil || vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}
			if vmObj.Status == "running" {
				s.jsonError(w, "Cannot modify networks while VM is running", http.StatusBadRequest)
				return
			}

			vmNet, err := s.db.GetVMNetwork(netID)
			if err != nil || vmNet == nil {
				s.jsonError(w, "Network interface not found", http.StatusNotFound)
				return
			}

			var req struct {
				NetworkID string `json:"network_id"`
				IPAddress string `json:"ip_address"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.NetworkID != "" {
				// Verify network exists
				net, err := s.db.GetNetwork(req.NetworkID)
				if err != nil || net == nil {
					s.jsonError(w, "Network not found", http.StatusNotFound)
					return
				}
				vmNet.NetworkID = req.NetworkID
				// Update TAP device name if network changed
				vmNet.TapDevice = fmt.Sprintf("fc%s-%d", vmID[:8], vmNet.IfaceIndex)
			}
			vmNet.IPAddress = req.IPAddress

			if err := s.db.UpdateVMNetwork(vmNet); err != nil {
				s.jsonError(w, "Failed to update network interface: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.db.AddVMLog(vmID, "info", fmt.Sprintf("Updated network interface eth%d", vmNet.IfaceIndex))
			s.jsonResponse(w, map[string]interface{}{
				"status":  "success",
				"network": vmNet,
			})
			return
		}

		// GET /api/vms/{id}/networks/{netId} - get network interface info
		if r.Method == http.MethodGet {
			vmNet, err := s.db.GetVMNetwork(netID)
			if err != nil {
				s.jsonError(w, "Failed to get network interface: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if vmNet == nil {
				s.jsonError(w, "Network interface not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, vmNet)
			return
		}

		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)

	case "password":
		// POST /api/vms/{id}/password - change root password
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

		if req.Password == "" {
			s.jsonError(w, "Password is required", http.StatusBadRequest)
			return
		}

		// Get VM to check status and get rootfs path
		vmObj, err := s.db.GetVM(vmID)
		if err != nil || vmObj == nil {
			s.jsonError(w, "VM not found", http.StatusNotFound)
			return
		}

		if vmObj.Status == "running" {
			s.jsonError(w, "Cannot change password while VM is running", http.StatusBadRequest)
			return
		}

		if vmObj.RootFSPath == "" {
			s.jsonError(w, "VM has no root filesystem configured", http.StatusBadRequest)
			return
		}

		// Set the root password
		if err := setRootPassword(vmObj.RootFSPath, req.Password); err != nil {
			s.jsonError(w, "Failed to set root password: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(vmID, "info", "Root password changed")
		s.jsonResponse(w, map[string]string{
			"status":  "success",
			"message": "Root password changed",
		})

	case "expand-rootfs":
		// POST /api/vms/{id}/expand-rootfs - expand root filesystem
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			NewSizeMB int64 `json:"new_size_mb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.NewSizeMB <= 0 {
			s.jsonError(w, "New size must be positive (in MB)", http.StatusBadRequest)
			return
		}

		if err := s.vmMgr.ExpandRootFS(vmID, req.NewSizeMB); err != nil {
			s.jsonError(w, "Failed to expand rootfs: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":      "success",
			"message":     "RootFS expanded",
			"new_size_mb": req.NewSizeMB,
		})

	case "":
		switch r.Method {
		case http.MethodGet:
			// Any permission grants read access
			if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") {
				s.jsonError(w, "Access denied: no permission to view this VM", http.StatusForbidden)
				return
			}
			vmObj, err := s.db.GetVM(vmID)
			if err != nil {
				s.jsonError(w, "Failed to get VM", http.StatusInternalServerError)
				return
			}
			if vmObj == nil {
				s.jsonError(w, "VM not found", http.StatusNotFound)
				return
			}

			// Enrich with kernel info
			type enrichedVM struct {
				*database.VM
				KernelID   string `json:"kernel_id,omitempty"`
				KernelName string `json:"kernel_name,omitempty"`
			}
			enriched := enrichedVM{VM: vmObj}
			if vmObj.KernelPath != "" {
				if kernel, err := s.db.GetKernelByPath(vmObj.KernelPath); err == nil && kernel != nil {
					enriched.KernelID = kernel.ID
					enriched.KernelName = kernel.Name
				}
			}
			s.jsonResponse(w, enriched)

		case http.MethodPut:
			// Edit permission required for modification
			if !checkAccess("edit") {
				s.jsonError(w, "Access denied: no permission to edit this VM", http.StatusForbidden)
				return
			}
			var req struct {
				Name         string  `json:"name"`
				Description  *string `json:"description"` // Pointer to allow clearing
				VCPU         int     `json:"vcpu"`
				MemoryMB     int     `json:"memory_mb"`
				KernelID     string  `json:"kernel_id"` // Kernel image ID to switch kernel
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
			if req.Description != nil {
				vmObj.Description = *req.Description
			}
			if req.VCPU > 0 {
				vmObj.VCPU = req.VCPU
			}
			if req.MemoryMB > 0 {
				vmObj.MemoryMB = req.MemoryMB
			}
			// Handle kernel change
			if req.KernelID != "" {
				kernel, err := s.db.GetKernelImage(req.KernelID)
				if err != nil || kernel == nil {
					s.jsonError(w, "Kernel not found", http.StatusBadRequest)
					return
				}
				vmObj.KernelPath = kernel.Path
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
			// Only admins can delete VMs
			if sess.Role != "admin" {
				s.jsonError(w, "Access denied: only admins can delete VMs", http.StatusForbidden)
				return
			}
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
			// Delete VM metrics history
			if err := s.db.DeleteVMMetrics(vmID); err != nil {
				s.logger("Warning: failed to delete VM metrics for %s: %v", vmID, err)
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	case "change-ip":
		// POST /api/vms/{id}/change-ip - change VM IP address
		if r.Method != http.MethodPost {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var req struct {
			IPAddress string `json:"ip_address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.IPAddress == "" {
			s.jsonError(w, "IP address is required", http.StatusBadRequest)
			return
		}

		// Validate IP format
		if net.ParseIP(req.IPAddress) == nil {
			s.jsonError(w, "Invalid IP address format", http.StatusBadRequest)
			return
		}

		// Get the VM
		vmObj, err := s.db.GetVM(vmID)
		if err != nil || vmObj == nil {
			s.jsonError(w, "VM not found", http.StatusNotFound)
			return
		}

		// Check if VM has a network
		if vmObj.NetworkID == "" {
			s.jsonError(w, "VM is not connected to a network", http.StatusBadRequest)
			return
		}

		// Get network to validate IP is in range
		netObj, err := s.db.GetNetwork(vmObj.NetworkID)
		if err != nil || netObj == nil {
			s.jsonError(w, "Network not found", http.StatusNotFound)
			return
		}

		// Verify IP is in the network subnet
		_, ipNet, err := net.ParseCIDR(netObj.Subnet)
		if err != nil {
			s.jsonError(w, "Invalid network subnet", http.StatusInternalServerError)
			return
		}

		reqIP := net.ParseIP(req.IPAddress)
		if !ipNet.Contains(reqIP) {
			s.jsonError(w, "IP address is not in the network subnet", http.StatusBadRequest)
			return
		}

		// Check if IP is already in use by another VM
		vms, err := s.db.GetVMsByNetwork(vmObj.NetworkID)
		if err != nil {
			s.jsonError(w, "Failed to check IP availability", http.StatusInternalServerError)
			return
		}

		for _, vm := range vms {
			if vm.ID != vmID && vm.IPAddress == req.IPAddress {
				s.jsonError(w, "IP address is already in use by another VM", http.StatusConflict)
				return
			}
		}

		// Check if IP is the gateway
		if req.IPAddress == netObj.Gateway {
			s.jsonError(w, "Cannot use gateway IP address", http.StatusBadRequest)
			return
		}

		// Store whether VM was running
		wasRunning := vmObj.Status == "running"

		// If VM is running, stop it first
		if wasRunning {
			if err := s.vmMgr.StopVM(vmID); err != nil {
				s.logger("Warning: failed to stop VM for IP change: %v", err)
			}
			// Wait a bit for VM to stop
			time.Sleep(2 * time.Second)
		}

		// Update the VM IP address
		oldIP := vmObj.IPAddress
		vmObj.IPAddress = req.IPAddress
		// Update kernel args with new IP configuration
		vmObj.KernelArgs = buildKernelArgs(vmObj.KernelArgs, req.IPAddress, netObj.Gateway)

		if err := s.db.UpdateVM(vmObj); err != nil {
			s.jsonError(w, "Failed to update VM", http.StatusInternalServerError)
			return
		}

		s.db.AddVMLog(vmID, "info", fmt.Sprintf("IP address changed from %s to %s", oldIP, req.IPAddress))

		// If VM was running, restart it
		if wasRunning {
			if err := s.vmMgr.StartVM(vmID); err != nil {
				s.db.AddVMLog(vmID, "error", "Failed to restart VM after IP change: "+err.Error())
				s.jsonError(w, "IP changed but failed to restart VM: "+err.Error(), http.StatusInternalServerError)
				return
			}
			s.db.AddVMLog(vmID, "info", "VM restarted with new IP address")
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":     "success",
			"ip_address": req.IPAddress,
			"restarted":  wasRunning,
		})

	case "memory-hotplug":
		// Memory hotplug status and control
		// GET /api/vms/{id}/memory-hotplug - Get memory hotplug status
		// PATCH /api/vms/{id}/memory-hotplug - Adjust hotplugged memory (runtime)
		// PUT /api/vms/{id}/memory-hotplug - Configure memory hotplug (pre-boot)

		// Any permission grants read access
		if !checkAccess("start") && !checkAccess("stop") && !checkAccess("console") && !checkAccess("edit") {
			s.jsonError(w, "Access denied: no permission to access this VM", http.StatusForbidden)
			return
		}

		vmObj, err := s.db.GetVM(vmID)
		if err != nil || vmObj == nil {
			s.jsonError(w, "VM not found", http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get memory hotplug status from running VM
			if vmObj.Status != "running" {
				// Return config from database if not running
				s.jsonResponse(w, map[string]interface{}{
					"enabled":       vmObj.HotplugMemoryEnabled,
					"total_size_mb": vmObj.HotplugMemoryTotalMB,
					"block_size_mb": vmObj.HotplugMemoryBlockMB,
					"slot_size_mb":  vmObj.HotplugMemorySlotMB,
					"running":       false,
				})
				return
			}

			status, err := s.vmMgr.GetMemoryHotplugStatus(vmID)
			if err != nil {
				s.jsonError(w, "Failed to get memory hotplug status: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]interface{}{
				"enabled":            vmObj.HotplugMemoryEnabled,
				"total_size_mib":     status.TotalSizeMib,
				"block_size_mib":     status.BlockSizeMib,
				"slot_size_mib":      status.SlotSizeMib,
				"plugged_size_mib":   status.PluggedSizeMib,
				"requested_size_mib": status.RequestedSizeMib,
				"running":            true,
			})

		case http.MethodPatch:
			// Adjust memory at runtime (VM must be running with hotplug enabled)
			if !checkAccess("edit") {
				s.jsonError(w, "Access denied: no permission to modify this VM", http.StatusForbidden)
				return
			}

			if vmObj.Status != "running" {
				s.jsonError(w, "VM must be running to adjust memory at runtime", http.StatusBadRequest)
				return
			}

			if !vmObj.HotplugMemoryEnabled {
				s.jsonError(w, "Memory hotplug is not enabled for this VM", http.StatusBadRequest)
				return
			}

			var req struct {
				RequestedSizeMib int `json:"requested_size_mib"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.RequestedSizeMib <= 0 {
				s.jsonError(w, "requested_size_mib must be positive", http.StatusBadRequest)
				return
			}

			if err := s.vmMgr.AdjustHotplugMemory(vmID, req.RequestedSizeMib); err != nil {
				s.jsonError(w, "Failed to adjust memory: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.db.AddVMLog(vmID, "info", fmt.Sprintf("Memory hotplug adjusted to %d MiB", req.RequestedSizeMib))
			s.jsonResponse(w, map[string]interface{}{
				"status":             "success",
				"message":            "Memory adjusted",
				"requested_size_mib": req.RequestedSizeMib,
			})

		case http.MethodPut:
			// Configure memory hotplug (VM must be stopped)
			if !checkAccess("edit") {
				s.jsonError(w, "Access denied: no permission to modify this VM", http.StatusForbidden)
				return
			}

			if vmObj.Status == "running" {
				s.jsonError(w, "Cannot configure memory hotplug while VM is running", http.StatusBadRequest)
				return
			}

			var req struct {
				Enabled     bool `json:"enabled"`
				TotalSizeMB int  `json:"total_size_mb"`
				BlockSizeMB int  `json:"block_size_mb"`
				SlotSizeMB  int  `json:"slot_size_mb"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			// Validate configuration
			if req.Enabled {
				if req.TotalSizeMB <= 0 {
					s.jsonError(w, "total_size_mb must be positive when enabling hotplug", http.StatusBadRequest)
					return
				}
				if req.TotalSizeMB <= vmObj.MemoryMB {
					s.jsonError(w, "total_size_mb must be greater than base memory", http.StatusBadRequest)
					return
				}
				// Set defaults if not provided
				if req.BlockSizeMB <= 0 {
					req.BlockSizeMB = 2 // Default 2 MiB block size
				}
				if req.SlotSizeMB <= 0 {
					req.SlotSizeMB = 128 // Default 128 MiB slot size
				}
				// Validate block size is power of 2 and >= 2
				if req.BlockSizeMB < 2 || (req.BlockSizeMB&(req.BlockSizeMB-1)) != 0 {
					s.jsonError(w, "block_size_mb must be a power of 2 and >= 2", http.StatusBadRequest)
					return
				}
			}

			// Update VM configuration
			vmObj.HotplugMemoryEnabled = req.Enabled
			vmObj.HotplugMemoryTotalMB = req.TotalSizeMB
			vmObj.HotplugMemoryBlockMB = req.BlockSizeMB
			vmObj.HotplugMemorySlotMB = req.SlotSizeMB

			if err := s.db.UpdateVM(vmObj); err != nil {
				s.jsonError(w, "Failed to update VM", http.StatusInternalServerError)
				return
			}

			action := "disabled"
			if req.Enabled {
				action = fmt.Sprintf("enabled (total: %d MiB, block: %d MiB, slot: %d MiB)",
					req.TotalSizeMB, req.BlockSizeMB, req.SlotSizeMB)
			}
			s.db.AddVMLog(vmID, "info", "Memory hotplug "+action)

			s.jsonResponse(w, map[string]interface{}{
				"status":        "success",
				"enabled":       vmObj.HotplugMemoryEnabled,
				"total_size_mb": vmObj.HotplugMemoryTotalMB,
				"block_size_mb": vmObj.HotplugMemoryBlockMB,
				"slot_size_mb":  vmObj.HotplugMemorySlotMB,
			})

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
			Name          string `json:"name"`
			Subnet        string `json:"subnet"`
			Gateway       string `json:"gateway"`
			DHCPStart     string `json:"dhcp_start"`
			DHCPEnd       string `json:"dhcp_end"`
			EnableNAT     bool   `json:"enable_nat"`
			OutInterface  string `json:"out_interface"`
			MTU           int    `json:"mtu"`
			STP           bool   `json:"stp"`
			BlockExternal bool   `json:"block_external"`
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

		// Default MTU
		if req.MTU == 0 {
			req.MTU = 1500
		}

		netID := generateID()
		bridgeName := network.GenerateBridgeName(netID)

		netObj := &database.Network{
			ID:            netID,
			Name:          req.Name,
			BridgeName:    bridgeName,
			Subnet:        req.Subnet,
			Gateway:       req.Gateway,
			DHCPStart:     req.DHCPStart,
			DHCPEnd:       req.DHCPEnd,
			EnableNAT:     req.EnableNAT,
			OutInterface:  req.OutInterface,
			MTU:           req.MTU,
			STP:           req.STP,
			BlockExternal: req.BlockExternal,
			Status:        "inactive",
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

	case "bridge":
		netObj, err := s.db.GetNetwork(netID)
		if err != nil || netObj == nil {
			s.jsonError(w, "Network not found", http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get bridge info
			bridgeInfo, err := s.netMgr.GetBridgeInfo(netObj.BridgeName)
			if err != nil {
				// Bridge may not exist yet
				s.jsonResponse(w, map[string]interface{}{
					"name":       netObj.BridgeName,
					"exists":     false,
					"is_up":      false,
					"mtu":        netObj.MTU,
					"stp":        netObj.STP,
					"interfaces": []string{},
				})
				return
			}
			bridgeInfo.MTU = netObj.MTU // Use configured MTU
			s.jsonResponse(w, map[string]interface{}{
				"name":       bridgeInfo.Name,
				"exists":     true,
				"is_up":      bridgeInfo.IsUp,
				"mtu":        bridgeInfo.MTU,
				"stp":        bridgeInfo.STP,
				"ip_address": bridgeInfo.IPAddress,
				"interfaces": bridgeInfo.Interfaces,
			})

		case http.MethodPut:
			// Update bridge settings
			var req struct {
				MTU int  `json:"mtu"`
				STP bool `json:"stp"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			// Update in database
			if req.MTU > 0 {
				netObj.MTU = req.MTU
			}
			netObj.STP = req.STP
			if err := s.db.UpdateNetwork(netObj); err != nil {
				s.jsonError(w, "Failed to update network", http.StatusInternalServerError)
				return
			}

			// Apply to running bridge if active
			if netObj.Status == "active" {
				if req.MTU > 0 {
					s.netMgr.SetBridgeMTU(netObj.BridgeName, req.MTU)
				}
				s.netMgr.SetBridgeSTP(netObj.BridgeName, req.STP)
			}

			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	case "firewall":
		s.handleNetworkFirewall(w, r, netID)
		return

	case "interfaces":
		// List available physical interfaces for NAT
		if r.Method != http.MethodGet {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		interfaces, err := network.ListPhysicalInterfaces()
		if err != nil {
			s.jsonError(w, "Failed to list interfaces", http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{"interfaces": interfaces})

	case "available-ips":
		// List available (free) IP addresses in the network
		if r.Method != http.MethodGet {
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		netObj, err := s.db.GetNetwork(netID)
		if err != nil || netObj == nil {
			s.jsonError(w, "Network not found", http.StatusNotFound)
			return
		}

		// Parse subnet to get available IPs
		availableIPs, err := s.getAvailableIPsInNetwork(netObj)
		if err != nil {
			s.jsonError(w, "Failed to calculate available IPs: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{"available_ips": availableIPs})

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

// handleNetworkFirewall handles firewall rule management for a network
func (s *Server) handleNetworkFirewall(w http.ResponseWriter, r *http.Request, networkID string) {
	netObj, err := s.db.GetNetwork(networkID)
	if err != nil || netObj == nil {
		s.jsonError(w, "Network not found", http.StatusNotFound)
		return
	}

	// Check for rule ID in path
	path := strings.TrimPrefix(r.URL.Path, "/api/networks/"+networkID+"/firewall")
	path = strings.TrimPrefix(path, "/")
	ruleID := ""
	if path != "" {
		ruleID = path
	}

	switch r.Method {
	case http.MethodGet:
		if ruleID != "" {
			// Get single rule
			rule, err := s.db.GetFirewallRule(ruleID)
			if err != nil || rule == nil {
				s.jsonError(w, "Rule not found", http.StatusNotFound)
				return
			}
			s.jsonResponse(w, rule)
		} else {
			// List all rules for network
			rules, err := s.db.ListFirewallRules(networkID)
			if err != nil {
				s.jsonError(w, "Failed to list firewall rules", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{
				"rules":          rules,
				"block_external": netObj.BlockExternal,
			})
		}

	case http.MethodPost:
		var req struct {
			RuleType    string `json:"rule_type"` // source_ip, port_forward, port_allow
			SourceIP    string `json:"source_ip"` // For source_ip rules
			DestIP      string `json:"dest_ip"`   // VM IP for port_forward
			HostPort    int    `json:"host_port"` // External port for port_forward
			DestPort    int    `json:"dest_port"` // Destination port
			Protocol    string `json:"protocol"`  // tcp, udp, all
			Description string `json:"description"`
			Priority    int    `json:"priority"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.RuleType == "" {
			s.jsonError(w, "Rule type is required", http.StatusBadRequest)
			return
		}

		// Validate based on rule type
		switch req.RuleType {
		case "source_ip":
			if req.SourceIP == "" {
				s.jsonError(w, "Source IP is required for source_ip rules", http.StatusBadRequest)
				return
			}
		case "port_forward":
			if req.DestIP == "" || req.HostPort == 0 || req.DestPort == 0 {
				s.jsonError(w, "dest_ip, host_port, and dest_port are required for port_forward rules", http.StatusBadRequest)
				return
			}
		case "port_allow":
			if req.DestPort == 0 {
				s.jsonError(w, "dest_port is required for port_allow rules", http.StatusBadRequest)
				return
			}
		default:
			s.jsonError(w, "Invalid rule type", http.StatusBadRequest)
			return
		}

		if req.Protocol == "" {
			req.Protocol = "tcp"
		}
		if req.Priority == 0 {
			req.Priority = 100
		}

		rule := &database.FirewallRule{
			ID:          generateID(),
			NetworkID:   networkID,
			RuleType:    req.RuleType,
			SourceIP:    req.SourceIP,
			DestIP:      req.DestIP,
			HostPort:    req.HostPort,
			DestPort:    req.DestPort,
			Protocol:    req.Protocol,
			Action:      "allow",
			Description: req.Description,
			Enabled:     true,
			Priority:    req.Priority,
		}

		if err := s.db.CreateFirewallRule(rule); err != nil {
			s.jsonError(w, "Failed to create firewall rule: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"rule":   rule,
		})

	case http.MethodPut:
		if ruleID == "" {
			// Update network block_external setting
			var req struct {
				BlockExternal bool `json:"block_external"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}
			netObj.BlockExternal = req.BlockExternal
			if err := s.db.UpdateNetwork(netObj); err != nil {
				s.jsonError(w, "Failed to update network", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})
			return
		}

		// Update specific rule
		rule, err := s.db.GetFirewallRule(ruleID)
		if err != nil || rule == nil {
			s.jsonError(w, "Rule not found", http.StatusNotFound)
			return
		}

		var req struct {
			Enabled     *bool  `json:"enabled"`
			Description string `json:"description"`
			Priority    int    `json:"priority"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Enabled != nil {
			rule.Enabled = *req.Enabled
		}
		if req.Description != "" {
			rule.Description = req.Description
		}
		if req.Priority > 0 {
			rule.Priority = req.Priority
		}

		if err := s.db.UpdateFirewallRule(rule); err != nil {
			s.jsonError(w, "Failed to update firewall rule", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"rule":   rule,
		})

	case http.MethodDelete:
		if ruleID == "" {
			s.jsonError(w, "Rule ID required", http.StatusBadRequest)
			return
		}

		if err := s.db.DeleteFirewallRule(ruleID); err != nil {
			s.jsonError(w, "Failed to delete firewall rule", http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]string{"status": "success"})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePhysicalInterfaces returns list of physical interfaces for NAT configuration
func (s *Server) handlePhysicalInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	interfaces, err := network.ListPhysicalInterfaces()
	if err != nil {
		s.jsonError(w, "Failed to list interfaces", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{"interfaces": interfaces})
}

// VM Search handler
func (s *Server) handleVMSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session for access control
	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	params := &database.VMSearchParams{}

	if r.Method == http.MethodGet {
		// Parse query parameters
		params.Query = r.URL.Query().Get("q")
		if params.Query == "" {
			params.Query = r.URL.Query().Get("query") // Also accept "query" param
		}
		params.Name = r.URL.Query().Get("name")
		params.IPAddress = r.URL.Query().Get("ip")
		params.OS = r.URL.Query().Get("os")
		params.Status = r.URL.Query().Get("status")
		params.NetworkID = r.URL.Query().Get("network_id")
		params.RootFSID = r.URL.Query().Get("rootfs_id")
		params.KernelID = r.URL.Query().Get("kernel_id")
		params.VMGroupID = r.URL.Query().Get("vm_group_id")
		params.GroupID = r.URL.Query().Get("group_id")
	} else {
		// Parse JSON body
		if err := json.NewDecoder(r.Body).Decode(params); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}
	}

	// Get all VMs matching the search criteria
	allVMs, err := s.db.SearchVMs(params)
	if err != nil {
		s.jsonError(w, "Search failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Filter VMs based on user access (unless admin)
	var vms []*database.VM
	if sess.Role == "admin" {
		vms = allVMs
	} else {
		// Get list of VM IDs the user can access
		accessibleVMs, err := s.db.GetUserAccessibleVMs(sess.UserID, sess.Role)
		if err != nil {
			s.jsonError(w, "Failed to check access", http.StatusInternalServerError)
			return
		}
		accessibleIDs := make(map[string]bool)
		for _, v := range accessibleVMs {
			accessibleIDs[v.ID] = true
		}
		// Filter search results
		for _, vm := range allVMs {
			if accessibleIDs[vm.ID] {
				vms = append(vms, vm)
			}
		}
	}

	// Enrich results with additional info
	type enrichedVM struct {
		*database.VM
		RootFSName  string              `json:"rootfs_name,omitempty"`
		OSRelease   string              `json:"os_release,omitempty"`
		KernelName  string              `json:"kernel_name,omitempty"`
		NetworkName string              `json:"network_name,omitempty"`
		VMGroups    []*database.VMGroup `json:"vm_groups,omitempty"`
	}

	results := make([]enrichedVM, 0, len(vms))
	for _, vm := range vms {
		enriched := enrichedVM{VM: vm}

		// Get rootfs info
		if vm.RootFSPath != "" {
			if rootfs, err := s.db.GetRootFSByPath(vm.RootFSPath); err == nil && rootfs != nil {
				enriched.RootFSName = rootfs.Name
				enriched.OSRelease = rootfs.OSRelease
			}
		}

		// Get kernel info
		if vm.KernelPath != "" {
			if kernel, err := s.db.GetKernelByPath(vm.KernelPath); err == nil && kernel != nil {
				enriched.KernelName = kernel.Name
			}
		}

		// Get network info
		if vm.NetworkID != "" {
			if net, err := s.db.GetNetwork(vm.NetworkID); err == nil && net != nil {
				enriched.NetworkName = net.Name
			}
		}

		// Get VM groups
		if groups, err := s.db.GetVMGroups(vm.ID); err == nil {
			enriched.VMGroups = groups
		}

		results = append(results, enriched)
	}

	s.jsonResponse(w, map[string]interface{}{
		"vms":   results,
		"count": len(results),
	})
}

// VM Groups handlers
func (s *Server) handleVMGroups(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)

	switch r.Method {
	case http.MethodGet:
		groups, err := s.db.ListVMGroups()
		if err != nil {
			s.jsonError(w, "Failed to list VM groups", http.StatusInternalServerError)
			return
		}

		// Enrich with VM count
		type groupWithCount struct {
			*database.VMGroup
			VMCount int `json:"vm_count"`
		}

		result := make([]groupWithCount, 0, len(groups))
		for _, g := range groups {
			count, _ := s.db.CountVMsInGroup(g.ID)
			result = append(result, groupWithCount{VMGroup: g, VMCount: count})
		}

		s.jsonResponse(w, map[string]interface{}{"vm_groups": result})

	case http.MethodPost:
		// Only admins can create VM groups
		if session == nil || session.Role != "admin" {
			s.jsonError(w, "Admin access required", http.StatusForbidden)
			return
		}

		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Color       string `json:"color"`
			Autorun     bool   `json:"autorun"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		if req.Color == "" {
			req.Color = "#6366f1" // Default purple
		}

		group := &database.VMGroup{
			ID:          generateID(),
			Name:        req.Name,
			Description: req.Description,
			Color:       req.Color,
			Autorun:     req.Autorun,
		}

		if err := s.db.CreateVMGroup(group); err != nil {
			s.jsonError(w, "Failed to create VM group: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"status":   "success",
			"vm_group": group,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVMGroup(w http.ResponseWriter, r *http.Request) {
	session := s.getSession(r)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/vmgroups/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		s.jsonError(w, "VM Group ID required", http.StatusBadRequest)
		return
	}

	groupID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch action {
	case "vms":
		// Get or manage VMs in this group
		switch r.Method {
		case http.MethodGet:
			vms, err := s.db.GetVMsInGroup(groupID)
			if err != nil {
				s.jsonError(w, "Failed to get VMs", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"vms": vms})

		case http.MethodPost:
			// Add VM to group (admin only)
			if session == nil || session.Role != "admin" {
				s.jsonError(w, "Admin access required", http.StatusForbidden)
				return
			}
			var req struct {
				VMID string `json:"vm_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}
			if err := s.db.AddVMToGroup(groupID, req.VMID); err != nil {
				s.jsonError(w, "Failed to add VM to group", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		case http.MethodDelete:
			// Remove VM from group (admin only)
			if session == nil || session.Role != "admin" {
				s.jsonError(w, "Admin access required", http.StatusForbidden)
				return
			}
			vmID := r.URL.Query().Get("vm_id")
			if vmID == "" {
				s.jsonError(w, "vm_id required", http.StatusBadRequest)
				return
			}
			if err := s.db.RemoveVMFromGroup(groupID, vmID); err != nil {
				s.jsonError(w, "Failed to remove VM from group", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	case "permissions":
		// Manage permissions (admin only)
		if session == nil || session.Role != "admin" {
			s.jsonError(w, "Admin access required", http.StatusForbidden)
			return
		}

		switch r.Method {
		case http.MethodGet:
			perms, err := s.db.GetVMGroupPermissions(groupID)
			if err != nil {
				s.jsonError(w, "Failed to get permissions", http.StatusInternalServerError)
				return
			}

			// Enrich with group names
			type permWithName struct {
				*database.VMGroupPermission
				GroupName string `json:"group_name"`
			}
			result := make([]permWithName, 0, len(perms))
			for _, p := range perms {
				name := ""
				if g, err := s.db.GetGroup(p.GroupID); err == nil && g != nil {
					name = g.Name
				}
				result = append(result, permWithName{VMGroupPermission: p, GroupName: name})
			}

			s.jsonResponse(w, map[string]interface{}{"permissions": result})

		case http.MethodPost:
			var req struct {
				GroupID     string `json:"group_id"`
				Permissions string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}
			if req.GroupID == "" {
				s.jsonError(w, "group_id required", http.StatusBadRequest)
				return
			}
			if err := s.db.AddVMGroupPermission(groupID, req.GroupID, req.Permissions); err != nil {
				s.jsonError(w, "Failed to add permission", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		case http.MethodDelete:
			userGroupID := r.URL.Query().Get("group_id")
			if userGroupID == "" {
				s.jsonError(w, "group_id required", http.StatusBadRequest)
				return
			}
			if err := s.db.RemoveVMGroupPermission(groupID, userGroupID); err != nil {
				s.jsonError(w, "Failed to remove permission", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]string{"status": "success"})

		default:
			s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		}

	case "":
		// Direct operations on the group
		switch r.Method {
		case http.MethodGet:
			group, err := s.db.GetVMGroup(groupID)
			if err != nil || group == nil {
				s.jsonError(w, "VM group not found", http.StatusNotFound)
				return
			}

			// Get VM count and permissions
			vmCount, _ := s.db.CountVMsInGroup(groupID)
			perms, _ := s.db.GetVMGroupPermissions(groupID)

			s.jsonResponse(w, map[string]interface{}{
				"vm_group":    group,
				"vm_count":    vmCount,
				"permissions": perms,
			})

		case http.MethodPut:
			// Update group (admin only)
			if session == nil || session.Role != "admin" {
				s.jsonError(w, "Admin access required", http.StatusForbidden)
				return
			}

			group, err := s.db.GetVMGroup(groupID)
			if err != nil || group == nil {
				s.jsonError(w, "VM group not found", http.StatusNotFound)
				return
			}

			var req struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Color       string `json:"color"`
				Autorun     *bool  `json:"autorun"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.Name != "" {
				group.Name = req.Name
			}
			if req.Description != "" {
				group.Description = req.Description
			}
			if req.Color != "" {
				group.Color = req.Color
			}
			if req.Autorun != nil {
				group.Autorun = *req.Autorun
			}

			if err := s.db.UpdateVMGroup(group); err != nil {
				s.jsonError(w, "Failed to update VM group", http.StatusInternalServerError)
				return
			}
			s.jsonResponse(w, map[string]interface{}{"status": "success", "vm_group": group})

		case http.MethodDelete:
			// Delete group (admin only)
			if session == nil || session.Role != "admin" {
				s.jsonError(w, "Admin access required", http.StatusForbidden)
				return
			}

			if err := s.db.DeleteVMGroup(groupID); err != nil {
				s.jsonError(w, "Failed to delete VM group", http.StatusInternalServerError)
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

		// Check for virtio support
		virtioSupport := kernel.CheckVirtioSupport(path)
		if !virtioSupport {
			s.logger("Warning: Kernel %s may not have proper virtio support", req.Name)
		}

		kernelID := generateID()
		kernelImg := &database.KernelImage{
			ID:            kernelID,
			Name:          req.Name,
			Version:       req.Version,
			Architecture:  req.Architecture,
			Path:          path,
			Size:          size,
			Checksum:      checksum,
			VirtioSupport: virtioSupport,
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

// handleKernelRescanVirtio re-checks virtio support for all existing kernels
func (s *Server) handleKernelRescanVirtio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	kernels, err := s.db.ListKernelImages()
	if err != nil {
		s.jsonError(w, "Failed to list kernels", http.StatusInternalServerError)
		return
	}

	updated := 0
	results := make([]map[string]interface{}, 0, len(kernels))

	for _, k := range kernels {
		hasVirtio := kernel.CheckVirtioSupport(k.Path)
		if hasVirtio != k.VirtioSupport {
			if err := s.db.UpdateKernelVirtioSupport(k.ID, hasVirtio); err != nil {
				s.logger("Failed to update virtio support for kernel %s: %v", k.Name, err)
			} else {
				updated++
			}
		}
		results = append(results, map[string]interface{}{
			"id":             k.ID,
			"name":           k.Name,
			"virtio_support": hasVirtio,
			"changed":        hasVirtio != k.VirtioSupport,
		})
	}

	s.jsonResponse(w, map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("Rescanned %d kernels, %d updated", len(kernels), updated),
		"results": results,
	})
}

// handleKernelBuild starts or gets status of a kernel build
func (s *Server) handleKernelBuild(w http.ResponseWriter, r *http.Request) {
	if s.kernelBuilder == nil {
		s.jsonError(w, "Kernel builder not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get current build status
		if progress := s.kernelBuilder.GetActiveBuild(); progress != nil {
			s.jsonResponse(w, map[string]interface{}{
				"building": true,
				"progress": progress,
			})
		} else {
			s.jsonResponse(w, map[string]interface{}{
				"building": false,
				"versions": s.kernelBuilder.GetSupportedVersions(),
			})
		}

	case http.MethodPost:
		// Start a new build
		if s.kernelBuilder.IsBuilding() {
			s.jsonError(w, "A build is already in progress", http.StatusConflict)
			return
		}

		var req struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Default to 6.1 if no version specified
			req.Version = "6.1"
		}

		// Validate version
		validVersion := false
		for _, v := range s.kernelBuilder.GetSupportedVersions() {
			if v == req.Version {
				validVersion = true
				break
			}
		}
		if !validVersion {
			s.jsonError(w, fmt.Sprintf("Unsupported kernel version: %s", req.Version), http.StatusBadRequest)
			return
		}

		progress, err := s.kernelBuilder.StartBuild(req.Version)
		if err != nil {
			s.jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.logger("Started kernel build: version=%s, id=%s", req.Version, progress.ID)
		s.jsonResponse(w, map[string]interface{}{
			"status":   "started",
			"build_id": progress.ID,
			"version":  req.Version,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleKernelBuildProgress returns progress of a specific build
func (s *Server) handleKernelBuildProgress(w http.ResponseWriter, r *http.Request) {
	if s.kernelBuilder == nil {
		s.jsonError(w, "Kernel builder not configured", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract build ID from path: /api/kernels/build/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/kernels/build/")
	buildID := strings.TrimSuffix(path, "/")

	if buildID == "" || buildID == "status" {
		// Return active build status
		if progress := s.kernelBuilder.GetActiveBuild(); progress != nil {
			s.jsonResponse(w, progress)
		} else {
			s.jsonResponse(w, map[string]interface{}{
				"building": false,
			})
		}
		return
	}

	progress := s.kernelBuilder.GetBuildProgress(buildID)
	if progress == nil {
		s.jsonError(w, "Build not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, progress)
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

		// Build response with VM usage information
		type rootfsWithUsage struct {
			*database.RootFS
			UsedByVMs []map[string]string `json:"used_by_vms"`
		}

		result := make([]rootfsWithUsage, 0, len(rootfsList))
		for _, rootfs := range rootfsList {
			entry := rootfsWithUsage{RootFS: rootfs, UsedByVMs: []map[string]string{}}
			vms, err := s.db.GetVMsByRootFSPath(rootfs.Path)
			if err == nil && len(vms) > 0 {
				for _, vm := range vms {
					entry.UsedByVMs = append(entry.UsedByVMs, map[string]string{
						"id":     vm.ID,
						"name":   vm.Name,
						"status": vm.Status,
					})
				}
			}
			result = append(result, entry)
		}

		s.jsonResponse(w, map[string]interface{}{"rootfs": result})

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

// handleAccount returns the current user's account information with groups and accessible VMs
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user details
	user, err := s.db.GetUser(sess.UserID)
	if err != nil || user == nil {
		s.jsonError(w, "User not found", http.StatusNotFound)
		return
	}

	// Get user's groups
	groups, err := s.db.GetUserGroups(sess.UserID)
	if err != nil {
		groups = []*database.Group{}
	}

	// Build response with groups and their VMs
	type groupWithVMs struct {
		*database.Group
		Permissions []string            `json:"permissions_list"`
		VMs         []*database.GroupVM `json:"vms"`
	}

	groupsWithVMs := make([]groupWithVMs, 0, len(groups))
	allVMIDs := make(map[string]bool)

	for _, g := range groups {
		gvms, err := s.db.ListGroupVMs(g.ID)
		if err != nil {
			gvms = []*database.GroupVM{}
		}

		// Track all VM IDs for this user
		for _, gvm := range gvms {
			allVMIDs[gvm.VMID] = true
		}

		// Parse permissions string into list
		permList := []string{}
		if g.Permissions != "" {
			permList = strings.Split(g.Permissions, ",")
		}

		groupsWithVMs = append(groupsWithVMs, groupWithVMs{
			Group:       g,
			Permissions: permList,
			VMs:         gvms,
		})
	}

	// Get full VM details for all accessible VMs
	type vmInfo struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		IPAddress string `json:"ip_address"`
		VCPU      int    `json:"vcpu"`
		MemoryMB  int    `json:"memory_mb"`
	}

	accessibleVMs := make([]vmInfo, 0)

	// If admin, they have access to all VMs
	if user.Role == "admin" {
		vms, err := s.db.ListVMs()
		if err == nil {
			for _, vm := range vms {
				accessibleVMs = append(accessibleVMs, vmInfo{
					ID:        vm.ID,
					Name:      vm.Name,
					Status:    vm.Status,
					IPAddress: vm.IPAddress,
					VCPU:      vm.VCPU,
					MemoryMB:  vm.MemoryMB,
				})
			}
		}
	} else {
		// For regular users, only show VMs from their groups
		for vmID := range allVMIDs {
			vm, err := s.db.GetVM(vmID)
			if err == nil && vm != nil {
				accessibleVMs = append(accessibleVMs, vmInfo{
					ID:        vm.ID,
					Name:      vm.Name,
					Status:    vm.Status,
					IPAddress: vm.IPAddress,
					VCPU:      vm.VCPU,
					MemoryMB:  vm.MemoryMB,
				})
			}
		}
	}

	s.jsonResponse(w, map[string]interface{}{
		"user": map[string]interface{}{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"role":       user.Role,
			"active":     user.Active,
			"ldap_user":  user.LDAPUser,
			"created_at": user.CreatedAt,
		},
		"groups":         groupsWithVMs,
		"accessible_vms": accessibleVMs,
		"is_admin":       user.Role == "admin",
	})
}

// handleAccountPassword changes the current user's password
func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.NewPassword == "" {
		s.jsonError(w, "New password is required", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 4 {
		s.jsonError(w, "Password must be at least 4 characters", http.StatusBadRequest)
		return
	}

	// Verify current password
	user, err := s.db.GetUser(sess.UserID)
	if err != nil || user == nil {
		s.jsonError(w, "User not found", http.StatusNotFound)
		return
	}

	currentHash := sha256.Sum256([]byte(req.CurrentPassword))
	if hex.EncodeToString(currentHash[:]) != user.PasswordHash {
		s.jsonError(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}

	// Update password
	newHash := sha256.Sum256([]byte(req.NewPassword))
	if err := s.db.UpdateUserPassword(sess.UserID, hex.EncodeToString(newHash[:])); err != nil {
		s.jsonError(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]string{"status": "success", "message": "Password changed successfully"})
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

// Operation progress handler for async operations (VM duplication, etc.)
func (s *Server) handleOperationProgress(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/operations/")
	if key == "" {
		s.jsonError(w, "Operation key required", http.StatusBadRequest)
		return
	}

	progress := s.vmMgr.GetOperationProgress(key)
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
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"go_version":    runtime.Version(),
		"num_cpu":       runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
		"memory_alloc":  memInfo.Alloc,
		"memory_sys":    memInfo.Sys,
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

	// Real system CPU and memory stats
	cpuPercent, cpuCores := getSystemCPU()
	memUsedMB, memTotalMB, memPercent := getSystemMemory()

	status["cpu_percent"] = cpuPercent
	status["cpu_cores"] = cpuCores
	status["mem_used_mb"] = memUsedMB
	status["mem_total_mb"] = memTotalMB
	status["mem_percent"] = memPercent

	// Disk usage for data directory
	diskUsedGB, diskTotalGB, diskPercent := getDiskUsage(s.dataDir)
	status["disk_used_gb"] = diskUsedGB
	status["disk_total_gb"] = diskTotalGB
	status["disk_percent"] = diskPercent
	status["data_dir"] = s.dataDir

	s.jsonResponse(w, status)
}

// getSystemCPU returns CPU usage percentage and core count
func getSystemCPU() (float64, int) {
	cores := runtime.NumCPU()

	// Read /proc/stat for CPU usage
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, cores
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0, cores
	}

	// Parse first line: cpu user nice system idle iowait irq softirq
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, cores
	}

	var user, nice, system, idle, iowait int64
	fmt.Sscanf(fields[1], "%d", &user)
	fmt.Sscanf(fields[2], "%d", &nice)
	fmt.Sscanf(fields[3], "%d", &system)
	fmt.Sscanf(fields[4], "%d", &idle)
	if len(fields) > 5 {
		fmt.Sscanf(fields[5], "%d", &iowait)
	}

	total := user + nice + system + idle + iowait
	if total == 0 {
		return 0, cores
	}

	// Calculate percentage (non-idle)
	idlePercent := float64(idle+iowait) / float64(total) * 100
	cpuPercent := 100 - idlePercent

	return cpuPercent, cores
}

// getSystemMemory returns used MB, total MB, and percentage
func getSystemMemory() (int64, int64, float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}

	var memTotal, memFree, buffers, cached, sReclaimable int64

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var val int64
		fmt.Sscanf(fields[1], "%d", &val)

		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemFree:":
			memFree = val
		case "Buffers:":
			buffers = val
		case "Cached:":
			cached = val
		case "SReclaimable:":
			sReclaimable = val
		}
	}

	// Available memory = Free + Buffers + Cached + SReclaimable
	memAvailable := memFree + buffers + cached + sReclaimable
	memUsed := memTotal - memAvailable

	// Convert from KB to MB
	memTotalMB := memTotal / 1024
	memUsedMB := memUsed / 1024

	var memPercent float64
	if memTotal > 0 {
		memPercent = float64(memUsed) / float64(memTotal) * 100
	}

	return memUsedMB, memTotalMB, memPercent
}

// getDiskUsage returns disk usage for a given path (used GB, total GB, percentage)
func getDiskUsage(path string) (float64, float64, float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}

	// Calculate sizes in bytes
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)
	usedBytes := totalBytes - freeBytes

	// Convert to GB
	totalGB := float64(totalBytes) / (1024 * 1024 * 1024)
	usedGB := float64(usedBytes) / (1024 * 1024 * 1024)

	var percent float64
	if totalBytes > 0 {
		percent = float64(usedBytes) / float64(totalBytes) * 100
	}

	return usedGB, totalGB, percent
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

	// Check if upgrade is already in progress
	s.upgradeProgressMu.RLock()
	if s.upgradeProgress != nil && s.upgradeProgress.Status == "running" {
		s.upgradeProgressMu.RUnlock()
		s.jsonError(w, "Upgrade already in progress", http.StatusConflict)
		return
	}
	s.upgradeProgressMu.RUnlock()

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

	// Initialize progress tracking
	s.upgradeProgressMu.Lock()
	s.upgradeProgress = &UpgradeProgress{
		Status:     "running",
		Step:       0,
		TotalSteps: 5,
		Logs:       make([]string, 0),
		StartedAt:  time.Now().Format(time.RFC3339),
	}
	s.upgradeProgressMu.Unlock()

	// Progress callback function
	progressCallback := func(step int, task string, logMsg string) {
		s.upgradeProgressMu.Lock()
		if s.upgradeProgress != nil {
			s.upgradeProgress.Step = step
			s.upgradeProgress.CurrentTask = task
			if logMsg != "" {
				s.upgradeProgress.Logs = append(s.upgradeProgress.Logs, logMsg)
			}
		}
		s.upgradeProgressMu.Unlock()
		s.logger("%s", logMsg)
	}

	// Version callback for tracking versions
	versionCallback := func(current, target string) {
		s.upgradeProgressMu.Lock()
		if s.upgradeProgress != nil {
			s.upgradeProgress.CurrentVersion = current
			s.upgradeProgress.TargetVersion = target
		}
		s.upgradeProgressMu.Unlock()
	}

	// Perform upgrade in background
	go func() {
		progressCallback(1, "Checking for updates", "Starting Firecracker upgrade...")

		setupInst := setup.NewSetup(s.logger)
		if err := setupInst.UpgradeFirecrackerWithProgress(progressCallback, versionCallback); err != nil {
			s.upgradeProgressMu.Lock()
			if s.upgradeProgress != nil {
				s.upgradeProgress.Status = "error"
				s.upgradeProgress.Error = err.Error()
				s.upgradeProgress.CompletedAt = time.Now().Format(time.RFC3339)
				s.upgradeProgress.Logs = append(s.upgradeProgress.Logs, fmt.Sprintf("Error: %v", err))
			}
			s.upgradeProgressMu.Unlock()
			s.logger("Firecracker upgrade failed: %v", err)
			return
		}

		s.upgradeProgressMu.Lock()
		if s.upgradeProgress != nil {
			s.upgradeProgress.Status = "completed"
			s.upgradeProgress.Step = s.upgradeProgress.TotalSteps
			s.upgradeProgress.CurrentTask = "Upgrade completed"
			s.upgradeProgress.CompletedAt = time.Now().Format(time.RFC3339)
			s.upgradeProgress.Logs = append(s.upgradeProgress.Logs, "Firecracker upgrade completed successfully")
		}
		s.upgradeProgressMu.Unlock()

		s.logger("Firecracker upgrade completed successfully")

		// Invalidate cache to trigger re-check with new version
		s.updater.InvalidateCache()
	}()

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Firecracker upgrade started",
	})
}

// handleFirecrackerUpgradeProgress returns the current upgrade progress
func (s *Server) handleFirecrackerUpgradeProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.upgradeProgressMu.RLock()
	progress := s.upgradeProgress
	s.upgradeProgressMu.RUnlock()

	if progress == nil {
		s.jsonResponse(w, &UpgradeProgress{
			Status:     "idle",
			Step:       0,
			TotalSteps: 5,
			Logs:       []string{},
		})
		return
	}

	s.jsonResponse(w, progress)
}

// handleJailerConfig handles GET/PUT for jailer configuration
func (s *Server) handleJailerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return current jailer config
		config := s.vmMgr.GetJailerConfig()
		available := s.vmMgr.IsJailerAvailable()

		s.jsonResponse(w, map[string]interface{}{
			"config":    config,
			"available": available,
		})

	case http.MethodPut:
		// Update jailer config
		var config vm.JailerConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			s.jsonError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validate config
		if config.Enabled {
			// Check if jailer binary exists
			jailerPath := config.JailerPath
			if jailerPath == "" {
				jailerPath = vm.JailerBinary
			}
			if _, err := os.Stat(jailerPath); err != nil {
				s.jsonError(w, fmt.Sprintf("Jailer binary not found at %s", jailerPath), http.StatusBadRequest)
				return
			}

			// Validate UID/GID
			if config.UID < 0 || config.GID < 0 {
				s.jsonError(w, "Invalid UID/GID", http.StatusBadRequest)
				return
			}

			// Ensure chroot base directory exists or can be created
			if config.ChrootBase == "" {
				config.ChrootBase = vm.DefaultJailerChrootBase
			}
			if err := os.MkdirAll(config.ChrootBase, 0755); err != nil {
				s.jsonError(w, fmt.Sprintf("Cannot create chroot base directory: %v", err), http.StatusBadRequest)
				return
			}

			// Validate cgroup version
			if config.CgroupVer != 1 && config.CgroupVer != 2 {
				config.CgroupVer = 2 // Default to cgroup v2
			}
		}

		// Apply config
		s.vmMgr.SetJailerConfig(&config)

		s.logger("Jailer configuration updated: enabled=%v, chroot=%s, uid=%d, gid=%d",
			config.Enabled, config.ChrootBase, config.UID, config.GID)

		s.jsonResponse(w, map[string]interface{}{
			"status":  "success",
			"message": "Jailer configuration updated",
			"config":  config,
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProxyTest tests the proxy connection by making a request through the proxy
func (s *Server) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create HTTP client with current proxy settings
	client, err := proxyconfig.NewHTTPClient(30 * time.Second)
	if err != nil {
		s.jsonResponse(w, map[string]interface{}{
			"success": false,
			"error":   "Failed to create HTTP client: " + err.Error(),
		})
		return
	}

	// Try to reach a known test endpoint
	testURL := "https://api.github.com/zen"
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		s.jsonResponse(w, map[string]interface{}{
			"success": false,
			"error":   "Failed to create request: " + err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		s.jsonResponse(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		s.jsonResponse(w, map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Unexpected status code: %d", resp.StatusCode),
		})
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Proxy connection test successful",
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

	// Check for debug parameter
	debug := r.URL.Query().Get("debug") == "1"

	// Perform ICMP ping with 2 second timeout
	reachable, debugInfo := pingWithDebug(ipStr, 2*time.Second)

	response := map[string]interface{}{
		"ip":        ipStr,
		"reachable": reachable,
	}
	if debug {
		response["debug"] = debugInfo
	}

	s.jsonResponse(w, response)
}

// handleScanPorts performs a quick TCP port scan on an IP address
func (s *Server) handleScanPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract IP from URL: /api/scan-ports/{ip}
	path := strings.TrimPrefix(r.URL.Path, "/api/scan-ports/")
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

	// Common ports to scan
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 2375, 2376, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
		8080, 8443, 8888, 9000, 9090, 9200, 27017,
	}

	// Scan ports concurrently with timeout
	openPorts := scanPortsConcurrent(ipStr, commonPorts, 500*time.Millisecond)

	s.jsonResponse(w, map[string]interface{}{
		"ip":    ipStr,
		"ports": openPorts,
	})
}

// scanPortsConcurrent scans multiple ports concurrently and returns open ports
func scanPortsConcurrent(ip string, ports []int, timeout time.Duration) []int {
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrency to avoid overwhelming the target
	semaphore := make(chan struct{}, 20)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			addr := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	// Sort the open ports
	sort.Ints(openPorts)
	return openPorts
}

// ping sends an ICMP echo request to the specified IP and returns true if reachable
func ping(addr string, timeout time.Duration) bool {
	reachable, _ := pingWithDebug(addr, timeout)
	return reachable
}

// pingWithDebug performs ping and returns debug information
func pingWithDebug(addr string, timeout time.Duration) (bool, map[string]interface{}) {
	debug := make(map[string]interface{})

	// First try using system ping command (most reliable)
	systemResult, systemErr, systemOut := systemPingDebug(addr, timeout)
	debug["system_ping"] = map[string]interface{}{
		"success": systemResult,
		"error":   systemErr,
		"output":  systemOut,
	}
	if systemResult {
		return true, debug
	}

	// Fallback: try ICMP ping using raw socket
	icmpResult := icmpPing(addr, timeout)
	debug["icmp_ping"] = icmpResult
	if icmpResult {
		return true, debug
	}

	// Last resort: try TCP connection to common ports
	ports := []string{"22", "80", "443"}
	tcpResults := make(map[string]bool)
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", addr+":"+port, timeout)
		if err == nil {
			conn.Close()
			tcpResults[port] = true
			debug["tcp_ports"] = tcpResults
			return true, debug
		}
		tcpResults[port] = false
	}
	debug["tcp_ports"] = tcpResults

	return false, debug
}

// systemPing uses the system ping command which is the most reliable method
func systemPing(addr string, timeout time.Duration) bool {
	result, _, _ := systemPingDebug(addr, timeout)
	return result
}

// systemPingDebug uses the system ping command and returns debug info
func systemPingDebug(addr string, timeout time.Duration) (bool, string, string) {
	// Use ping with count=1 and timeout in seconds
	timeoutSecs := int(timeout.Seconds())
	if timeoutSecs < 1 {
		timeoutSecs = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer cancel()

	// Use full path to ping binary
	cmd := exec.CommandContext(ctx, "/usr/bin/ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSecs), addr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err.Error(), string(output)
	}
	return true, "", string(output)
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
			// Compare IPs by parsing peer address
			// peer.String() returns just the IP for ICMP connections
			peerIP := net.ParseIP(peer.String())
			if peerIP != nil && peerIP.Equal(dst.IP) {
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

	// Check console permission
	canAccess, err := s.db.CanUserAccessVM(session.UserID, session.Role, vmID, "console")
	if err != nil || !canAccess {
		http.Error(w, "Access denied: no permission to access console for this VM", http.StatusForbidden)
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
	defaultArgs := "console=ttyS0,115200n8 reboot=k panic=1"

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

// setRootPassword sets the root password in a rootfs image by mounting it and modifying /etc/shadow
func setRootPassword(rootfsPath, password string) error {
	// Create temporary mount point
	mountPoint, err := os.MkdirTemp("", "rootfs-passwd-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mountPoint)

	// Mount the rootfs
	mountCmd := exec.Command("mount", "-o", "loop", rootfsPath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mount failed: %v: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	// Ensure root user exists in /etc/passwd
	if err := ensureRootUserExists(mountPoint); err != nil {
		return fmt.Errorf("failed to ensure root user exists: %v", err)
	}

	// Generate password hash using openssl
	// Use SHA-512 ($6$) which is widely supported
	saltBytes := make([]byte, 8)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)[:8]

	opensslCmd := exec.Command("openssl", "passwd", "-6", "-salt", salt, password)
	hashOutput, err := opensslCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to generate password hash: %v", err)
	}
	passwordHash := strings.TrimSpace(string(hashOutput))

	// Read /etc/shadow
	shadowPath := filepath.Join(mountPoint, "etc", "shadow")
	shadowData, err := os.ReadFile(shadowPath)
	if err != nil {
		// If shadow doesn't exist, try to create it
		if os.IsNotExist(err) {
			// Create shadow file with root entry
			shadowContent := fmt.Sprintf("root:%s:19000:0:99999:7:::\n", passwordHash)
			if err := os.WriteFile(shadowPath, []byte(shadowContent), 0640); err != nil {
				return fmt.Errorf("failed to create shadow file: %v", err)
			}
			return nil
		}
		return fmt.Errorf("failed to read shadow file: %v", err)
	}

	// Parse and update shadow file
	lines := strings.Split(string(shadowData), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "root:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				parts[1] = passwordHash
				// Ensure all required shadow fields exist (9 fields total)
				// Format: username:password:lastchange:min:max:warn:inactive:expire:reserved
				for len(parts) < 9 {
					parts = append(parts, "")
				}
				// Set reasonable defaults if fields are empty
				if parts[2] == "" {
					parts[2] = "19000" // last password change (days since epoch)
				}
				if parts[3] == "" {
					parts[3] = "0" // min days between password changes
				}
				if parts[4] == "" {
					parts[4] = "99999" // max days password is valid
				}
				if parts[5] == "" {
					parts[5] = "7" // days before expiry to warn
				}
				// parts[6], parts[7], parts[8] can remain empty (inactive, expire, reserved)
				lines[i] = strings.Join(parts, ":")
				found = true
				break
			}
		}
	}

	if !found {
		// Add root entry if not found
		rootLine := fmt.Sprintf("root:%s:19000:0:99999:7:::", passwordHash)
		lines = append([]string{rootLine}, lines...)
	}

	// Write updated shadow file
	newShadow := strings.Join(lines, "\n")
	if err := os.WriteFile(shadowPath, []byte(newShadow), 0640); err != nil {
		return fmt.Errorf("failed to write shadow file: %v", err)
	}

	return nil
}

// ensureRootUserExists checks if root user exists in /etc/passwd and /etc/group,
// and creates them if they don't exist
func ensureRootUserExists(mountPoint string) error {
	// Ensure /etc directory exists
	etcPath := filepath.Join(mountPoint, "etc")
	if err := os.MkdirAll(etcPath, 0755); err != nil {
		return fmt.Errorf("failed to create /etc: %v", err)
	}

	// Check and fix /etc/passwd
	passwdPath := filepath.Join(mountPoint, "etc", "passwd")
	passwdData, err := os.ReadFile(passwdPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create passwd file with root entry
			passwdContent := "root:x:0:0:root:/root:/bin/sh\n"
			if err := os.WriteFile(passwdPath, []byte(passwdContent), 0644); err != nil {
				return fmt.Errorf("failed to create passwd file: %v", err)
			}
			passwdData = []byte(passwdContent)
		} else {
			return fmt.Errorf("failed to read passwd file: %v", err)
		}
	}

	// Check if root exists in passwd
	rootInPasswd := false
	passwdLines := strings.Split(string(passwdData), "\n")
	for _, line := range passwdLines {
		if strings.HasPrefix(line, "root:") {
			rootInPasswd = true
			break
		}
	}

	if !rootInPasswd {
		// Add root entry to passwd
		rootLine := "root:x:0:0:root:/root:/bin/sh"
		passwdLines = append([]string{rootLine}, passwdLines...)
		newPasswd := strings.Join(passwdLines, "\n")
		// Ensure file ends with newline
		if !strings.HasSuffix(newPasswd, "\n") {
			newPasswd += "\n"
		}
		if err := os.WriteFile(passwdPath, []byte(newPasswd), 0644); err != nil {
			return fmt.Errorf("failed to update passwd file: %v", err)
		}
	}

	// Check and fix /etc/group
	groupPath := filepath.Join(mountPoint, "etc", "group")
	groupData, err := os.ReadFile(groupPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create group file with root entry
			groupContent := "root:x:0:\n"
			if err := os.WriteFile(groupPath, []byte(groupContent), 0644); err != nil {
				return fmt.Errorf("failed to create group file: %v", err)
			}
			groupData = []byte(groupContent)
		} else {
			return fmt.Errorf("failed to read group file: %v", err)
		}
	}

	// Check if root group exists
	rootInGroup := false
	groupLines := strings.Split(string(groupData), "\n")
	for _, line := range groupLines {
		if strings.HasPrefix(line, "root:") {
			rootInGroup = true
			break
		}
	}

	if !rootInGroup {
		// Add root group entry
		rootLine := "root:x:0:"
		groupLines = append([]string{rootLine}, groupLines...)
		newGroup := strings.Join(groupLines, "\n")
		// Ensure file ends with newline
		if !strings.HasSuffix(newGroup, "\n") {
			newGroup += "\n"
		}
		if err := os.WriteFile(groupPath, []byte(newGroup), 0644); err != nil {
			return fmt.Errorf("failed to update group file: %v", err)
		}
	}

	// Ensure /root directory exists
	rootHome := filepath.Join(mountPoint, "root")
	if err := os.MkdirAll(rootHome, 0700); err != nil {
		return fmt.Errorf("failed to create /root directory: %v", err)
	}

	// Ensure /etc/shadow exists (even if empty, for password to be set)
	shadowPath := filepath.Join(mountPoint, "etc", "shadow")
	if _, err := os.Stat(shadowPath); os.IsNotExist(err) {
		// Create empty shadow file with proper permissions
		if err := os.WriteFile(shadowPath, []byte(""), 0640); err != nil {
			return fmt.Errorf("failed to create shadow file: %v", err)
		}
	}

	return nil
}

// SetDataDir sets the data directory for migration server
func (s *Server) SetDataDir(dataDir string) {
	s.dataDir = dataDir
}

// SetStore sets the store manager
func (s *Server) SetStore(st *store.Store) {
	s.store = st
}

// Migration API handlers

// handleMigrationKeys handles GET/POST /api/migration/keys
func (s *Server) handleMigrationKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// List all migration keys
		keys, err := s.db.ListMigrationKeys()
		if err != nil {
			s.jsonError(w, "Failed to list keys: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Don't expose the actual key hashes
		safeKeys := make([]map[string]interface{}, len(keys))
		for i, k := range keys {
			safeKeys[i] = map[string]interface{}{
				"id":           k.ID,
				"name":         k.Name,
				"description":  k.Description,
				"allow_push":   k.AllowPush,
				"allow_pull":   k.AllowPull,
				"created_at":   k.CreatedAt,
				"last_used_at": k.LastUsedAt,
			}
		}
		s.jsonResponse(w, map[string]interface{}{"keys": safeKeys})

	case http.MethodPost:
		// Create a new migration key
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			AllowPush   bool   `json:"allow_push"`
			AllowPull   bool   `json:"allow_pull"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			s.jsonError(w, "Name is required", http.StatusBadRequest)
			return
		}

		// Check if name already exists
		existing, _ := s.db.GetMigrationKeyByName(req.Name)
		if existing != nil {
			s.jsonError(w, "Key with this name already exists", http.StatusConflict)
			return
		}

		// Generate random key
		keyBytes := make([]byte, 32)
		if _, err := cryptoRandRead(keyBytes); err != nil {
			s.jsonError(w, "Failed to generate key", http.StatusInternalServerError)
			return
		}
		rawKey := hex.EncodeToString(keyBytes)

		// Hash the key for storage
		keyHash := hashSHA256(rawKey)

		// Generate ID
		idBytes := make([]byte, 8)
		cryptoRandRead(idBytes)
		keyID := hex.EncodeToString(idBytes)

		key := &database.MigrationKey{
			ID:          keyID,
			Name:        req.Name,
			KeyHash:     keyHash,
			Description: req.Description,
			AllowPush:   req.AllowPush,
			AllowPull:   req.AllowPull,
		}

		if err := s.db.CreateMigrationKey(key); err != nil {
			s.jsonError(w, "Failed to create key: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.logger("Created migration key: %s", req.Name)

		// Return the raw key (only shown once)
		s.jsonResponse(w, map[string]interface{}{
			"status": "success",
			"key": map[string]interface{}{
				"id":          key.ID,
				"name":        key.Name,
				"key":         rawKey, // Only returned once at creation
				"description": key.Description,
				"allow_push":  key.AllowPush,
				"allow_pull":  key.AllowPull,
			},
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMigrationKey handles GET/DELETE /api/migration/keys/{id}
func (s *Server) handleMigrationKey(w http.ResponseWriter, r *http.Request) {
	// Extract key ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/migration/keys/")
	keyID := strings.Split(path, "/")[0]

	if keyID == "" {
		s.jsonError(w, "Key ID is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		key, err := s.db.GetMigrationKey(keyID)
		if err != nil {
			s.jsonError(w, "Failed to get key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if key == nil {
			s.jsonError(w, "Key not found", http.StatusNotFound)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"id":           key.ID,
			"name":         key.Name,
			"description":  key.Description,
			"allow_push":   key.AllowPush,
			"allow_pull":   key.AllowPull,
			"created_at":   key.CreatedAt,
			"last_used_at": key.LastUsedAt,
		})

	case http.MethodDelete:
		if err := s.db.DeleteMigrationKey(keyID); err != nil {
			s.jsonError(w, "Failed to delete key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.logger("Deleted migration key: %s", keyID)
		s.jsonResponse(w, map[string]string{"status": "success"})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMigrationServer handles POST /api/migration/server (start/stop)
func (s *Server) handleMigrationServer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Get server status
		running := false
		port := 0
		if s.migrationSrv != nil {
			running = s.migrationSrv.IsRunning()
			port = s.migrationSrv.GetPort()
		}
		s.jsonResponse(w, map[string]interface{}{
			"running": running,
			"port":    port,
		})

	case http.MethodPost:
		var req struct {
			Action string `json:"action"` // "start" or "stop"
			Port   int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request", http.StatusBadRequest)
			return
		}

		switch req.Action {
		case "start":
			if s.migrationSrv != nil && s.migrationSrv.IsRunning() {
				s.jsonError(w, "Migration server already running", http.StatusBadRequest)
				return
			}

			port := req.Port
			if port == 0 {
				port = 9090 // Default port
			}

			s.migrationSrv = vm.NewMigrationServer(port, s.dataDir, s.db, s.vmMgr, s.logger)
			if err := s.migrationSrv.Start(); err != nil {
				s.jsonError(w, "Failed to start migration server: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]interface{}{
				"status":  "success",
				"message": fmt.Sprintf("Migration server started on port %d", port),
				"port":    port,
			})

		case "stop":
			if s.migrationSrv == nil || !s.migrationSrv.IsRunning() {
				s.jsonError(w, "Migration server not running", http.StatusBadRequest)
				return
			}

			if err := s.migrationSrv.Stop(); err != nil {
				s.jsonError(w, "Failed to stop migration server: "+err.Error(), http.StatusInternalServerError)
				return
			}

			s.jsonResponse(w, map[string]string{
				"status":  "success",
				"message": "Migration server stopped",
			})

		default:
			s.jsonError(w, "Invalid action (use 'start' or 'stop')", http.StatusBadRequest)
		}

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleMigrationSend handles POST /api/migration/send
func (s *Server) handleMigrationSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		VMID       string `json:"vm_id"`
		RemoteHost string `json:"remote_host"`
		RemotePort int    `json:"remote_port"`
		Key        string `json:"key"`
		Compress   bool   `json:"compress"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.VMID == "" {
		s.jsonError(w, "VM ID is required", http.StatusBadRequest)
		return
	}
	if req.RemoteHost == "" {
		s.jsonError(w, "Remote host is required", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		s.jsonError(w, "Migration key is required", http.StatusBadRequest)
		return
	}

	port := req.RemotePort
	if port == 0 {
		port = 9090
	}

	// Start migration in background
	go func() {
		err := s.vmMgr.MigrateVM(req.VMID, req.RemoteHost, port, req.Key, req.Compress, nil)
		if err != nil {
			s.logger("Migration failed: %v", err)
		}
	}()

	s.jsonResponse(w, map[string]string{
		"status":  "success",
		"message": "Migration started",
	})
}

// handleMigrationStatus handles GET /api/migration/status
func (s *Server) handleMigrationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var migrations []*vm.MigrationStatus
	if s.migrationSrv != nil {
		migrations = s.migrationSrv.GetMigrations()
	}

	s.jsonResponse(w, map[string]interface{}{
		"migrations": migrations,
	})
}

// Helper functions for crypto
func cryptoRandRead(b []byte) (int, error) {
	return io.ReadFull(cryptoRandReader, b)
}

var cryptoRandReader = func() io.Reader {
	return rand.Reader
}()

func hashSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// getAvailableIPsInNetwork returns a list of available (unused) IP addresses in a network
func (s *Server) getAvailableIPsInNetwork(netObj *database.Network) ([]string, error) {
	// Parse the subnet CIDR
	_, ipNet, err := net.ParseCIDR(netObj.Subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %v", err)
	}

	// Get used IPs in this network
	vms, err := s.db.GetVMsByNetwork(netObj.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VMs: %v", err)
	}

	usedIPs := make(map[string]bool)
	// Mark gateway as used
	usedIPs[netObj.Gateway] = true
	// Mark all VM IPs as used
	for _, vm := range vms {
		if vm.IPAddress != "" {
			usedIPs[vm.IPAddress] = true
		}
	}

	// Generate available IPs (limit to reasonable range)
	var availableIPs []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	// Skip network address and start from first usable
	for i := 0; i < 4; i++ {
		ip = incrementIP(ip)
	}

	// Generate up to 254 IPs (typical /24 network)
	for i := 0; i < 250; i++ {
		if !ipNet.Contains(ip) {
			break
		}

		ipStr := ip.String()
		if !usedIPs[ipStr] {
			availableIPs = append(availableIPs, ipStr)
		}

		ip = incrementIP(ip)
		if ip == nil {
			break
		}
	}

	return availableIPs, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(result) - 1; i >= 0; i-- {
		result[i]++
		if result[i] != 0 {
			return result
		}
	}
	return nil
}

// ApplianceInfo represents an exported VM appliance file
type ApplianceInfo struct {
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	ExportedDate string `json:"exported_date"`
	VMName       string `json:"vm_name"`
	Description  string `json:"description,omitempty"`
	OwnerID      int    `json:"owner_id,omitempty"`
	OwnerName    string `json:"owner_name,omitempty"`
	CanWrite     bool   `json:"can_write"`
	IsOwner      bool   `json:"is_owner"`
}

// handleAppliances handles GET /api/appliances - list all exported VM appliances
func (s *Server) handleAppliances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session for access control
	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var appliances []ApplianceInfo
	var existingFiles []string

	// Try to use cached data if available
	if s.appliancesScanner != nil {
		cached := s.appliancesScanner.GetCached()
		if cached != nil {
			// Type assert to access the cache data
			if cacheMap, ok := cached.(interface{ GetAppliances() []interface{} }); ok {
				_ = cacheMap // Handle interface
			}
			// Use reflection-free approach: marshal and unmarshal
			cacheJSON, _ := json.Marshal(cached)
			var cacheData struct {
				Appliances []struct {
					Filename     string `json:"filename"`
					Size         int64  `json:"size"`
					ExportedDate string `json:"exported_date"`
					VMName       string `json:"vm_name"`
					Description  string `json:"description"`
					OwnerID      int    `json:"owner_id"`
					OwnerName    string `json:"owner_name"`
				} `json:"appliances"`
				ScannedAt string `json:"scanned_at"`
			}
			if err := json.Unmarshal(cacheJSON, &cacheData); err == nil && len(cacheData.Appliances) > 0 {
				// Filter based on user access and add access control info
				for _, app := range cacheData.Appliances {
					existingFiles = append(existingFiles, app.Filename)

					canAccess, canWrite, isOwner := s.db.CanUserAccessAppliance(app.Filename, sess.UserID, sess.Role)
					if !canAccess {
						continue
					}

					appliances = append(appliances, ApplianceInfo{
						Filename:     app.Filename,
						Size:         app.Size,
						ExportedDate: app.ExportedDate,
						VMName:       app.VMName,
						Description:  app.Description,
						OwnerID:      app.OwnerID,
						OwnerName:    app.OwnerName,
						CanWrite:     canWrite,
						IsOwner:      isOwner,
					})
				}

				// Cleanup orphan privileges (async)
				go func() {
					if deleted, err := s.db.CleanupOrphanAppliancePrivileges(existingFiles); err == nil && deleted > 0 {
						s.logger("Cleaned up %d orphan appliance privileges", deleted)
					}
				}()

				s.jsonResponse(w, map[string]interface{}{
					"appliances": appliances,
					"count":      len(appliances),
					"cached":     true,
					"scanned_at": cacheData.ScannedAt,
				})
				return
			}
		}
	}

	// Fallback: scan directly if cache is not available
	dataDir := s.vmMgr.GetDataDir()
	files, err := os.ReadDir(dataDir)
	if err != nil {
		s.jsonError(w, "Failed to read data directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".fcrack") {
			continue
		}

		filename := file.Name()
		existingFiles = append(existingFiles, filename)

		canAccess, canWrite, isOwner := s.db.CanUserAccessAppliance(filename, sess.UserID, sess.Role)
		if !canAccess {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		baseName := strings.TrimSuffix(filename, ".fcrack")
		vmName := baseName
		exportedDate := info.ModTime().Format("2006-01-02 15:04:05")

		if len(baseName) > 16 {
			datePart := baseName[len(baseName)-15:]
			if len(datePart) == 15 && datePart[8] == '-' {
				if t, err := time.Parse("20060102-150405", datePart); err == nil {
					exportedDate = t.Format("2006-01-02 15:04:05")
					vmName = baseName[:len(baseName)-16]
				}
			}
		}

		vmName = strings.ReplaceAll(vmName, "_", " ")

		ownerID, _ := s.db.GetApplianceOwner(filename)
		ownerName := ""
		if ownerID > 0 {
			if owner, err := s.db.GetUser(ownerID); err == nil && owner != nil {
				ownerName = owner.Username
			}
		}

		description := s.vmMgr.GetApplianceDescription(filename)

		appliances = append(appliances, ApplianceInfo{
			Filename:     filename,
			Size:         info.Size(),
			ExportedDate: exportedDate,
			VMName:       vmName,
			Description:  description,
			OwnerID:      ownerID,
			OwnerName:    ownerName,
			CanWrite:     canWrite,
			IsOwner:      isOwner,
		})
	}

	// Cleanup orphan privileges (async)
	go func() {
		if deleted, err := s.db.CleanupOrphanAppliancePrivileges(existingFiles); err == nil && deleted > 0 {
			s.logger("Cleaned up %d orphan appliance privileges", deleted)
		}
	}()

	// Sort by date descending (most recent first)
	sort.Slice(appliances, func(i, j int) bool {
		return appliances[i].ExportedDate > appliances[j].ExportedDate
	})

	s.jsonResponse(w, map[string]interface{}{
		"appliances": appliances,
		"count":      len(appliances),
		"cached":     false,
	})
}

// handleAppliance handles individual appliance operations
// DELETE /api/appliances/{filename} - delete an appliance
// GET /api/appliances/{filename} - download an appliance
// handleApplianceRestore handles POST /api/appliances/restore/{filename} - restore appliance to a new VM
func (s *Server) handleApplianceRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session for access control
	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract filename from path
	filename := strings.TrimPrefix(r.URL.Path, "/api/appliances/restore/")
	filename = strings.TrimSuffix(filename, "/")

	if filename == "" {
		s.jsonError(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Security check: ensure filename doesn't contain path traversal
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		s.jsonError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Ensure it's a .fcrack file
	if !strings.HasSuffix(filename, ".fcrack") {
		s.jsonError(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(s.vmMgr.GetDataDir(), filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		s.jsonError(w, "Appliance not found", http.StatusNotFound)
		return
	}

	// Check user access
	canAccess, _, _ := s.db.CanUserAccessAppliance(filename, sess.UserID, sess.Role)
	if !canAccess {
		s.jsonError(w, "Access denied", http.StatusForbidden)
		return
	}

	// Parse request body for VM name, kernel, and optional disk expansion
	var req struct {
		Name         string `json:"name"`
		KernelID     string `json:"kernel_id"`
		ExpandDiskGB int    `json:"expand_disk_gb"` // Optional: expand disk to this size in GB after restore
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		s.jsonError(w, "Name is required", http.StatusBadRequest)
		return
	}

	if req.KernelID == "" {
		s.jsonError(w, "Kernel ID is required", http.StatusBadRequest)
		return
	}

	// Verify kernel exists
	kernelImg, err := s.db.GetKernelImage(req.KernelID)
	if err != nil || kernelImg == nil {
		s.jsonError(w, "Kernel not found", http.StatusBadRequest)
		return
	}

	// Generate operation key for progress tracking
	opKey := fmt.Sprintf("restore-%s-%d", filename, time.Now().UnixNano())

	// Initialize progress
	s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
		Status:  "starting",
		Stage:   "Preparing restore...",
		Percent: 0,
	})

	// Capture expand disk size for use in goroutine
	expandDiskGB := req.ExpandDiskGB

	// Run import in background
	go func() {
		newVM, err := s.vmMgr.ImportVMWithProgress(filePath, req.Name, req.KernelID, opKey)
		if err != nil {
			s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
				Status: "error",
				Stage:  "Restore failed",
				Error:  err.Error(),
			})
			return
		}

		s.db.AddVMLog(newVM.ID, "info", "VM restored from appliance "+filename)
		s.logger("Restored appliance %s as VM %s (%s)", filename, req.Name, newVM.ID)

		// Expand disk if requested
		if expandDiskGB > 0 {
			s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
				Status:  "expanding",
				Stage:   fmt.Sprintf("Expanding disk to %d GB...", expandDiskGB),
				Percent: 90,
			})

			expandSizeMB := int64(expandDiskGB) * 1024
			if err := s.vmMgr.ExpandRootFS(newVM.ID, expandSizeMB); err != nil {
				s.logger("Warning: failed to expand disk for VM %s: %v", newVM.ID, err)
				s.db.AddVMLog(newVM.ID, "warning", fmt.Sprintf("Failed to expand disk to %d GB: %v", expandDiskGB, err))
				// Continue anyway - VM was created successfully
			} else {
				s.db.AddVMLog(newVM.ID, "info", fmt.Sprintf("Disk expanded to %d GB", expandDiskGB))
				s.logger("Expanded disk for VM %s to %d GB", newVM.ID, expandDiskGB)
			}
		}

		s.vmMgr.SetOperationProgress(opKey, &vm.OperationProgress{
			Status:     "completed",
			Stage:      "Restore completed",
			Percent:    100,
			ResultID:   newVM.ID,
			ResultName: newVM.Name,
		})
	}()

	s.jsonResponse(w, map[string]interface{}{
		"status":       "started",
		"progress_key": opKey,
	})
}

// GET /api/appliances/{filename}/privileges - list privileges
// POST /api/appliances/{filename}/privileges - add privilege
// DELETE /api/appliances/{filename}/privileges/{type}/{id} - remove privilege
func (s *Server) handleAppliance(w http.ResponseWriter, r *http.Request) {
	// Get session for access control
	sess := s.getSession(r)
	if sess == nil {
		s.jsonError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract filename and action from path
	path := strings.TrimPrefix(r.URL.Path, "/api/appliances/")
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	filename := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	// URL decode the filename
	if decoded, err := url.PathUnescape(filename); err == nil {
		filename = decoded
	}

	if filename == "" {
		s.jsonError(w, "Filename is required", http.StatusBadRequest)
		return
	}

	// Security check: ensure filename doesn't contain path traversal
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		s.jsonError(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Ensure it's a .fcrack file
	if !strings.HasSuffix(filename, ".fcrack") {
		s.jsonError(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(s.vmMgr.GetDataDir(), filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		s.jsonError(w, "Appliance not found", http.StatusNotFound)
		return
	}

	// Check user access
	canAccess, canWrite, isOwner := s.db.CanUserAccessAppliance(filename, sess.UserID, sess.Role)

	// Handle privilege management routes
	if action == "privileges" {
		s.handleAppliancePrivileges(w, r, filename, sess, isOwner, parts)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Download the appliance file - requires read access
		if !canAccess {
			s.jsonError(w, "Access denied", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		http.ServeFile(w, r, filePath)

	case http.MethodDelete:
		// Delete the appliance file - requires write access
		if !canWrite {
			s.jsonError(w, "Access denied: write permission required", http.StatusForbidden)
			return
		}

		if err := os.Remove(filePath); err != nil {
			s.jsonError(w, "Failed to delete appliance: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete associated privileges
		if err := s.db.DeleteAppliancePrivileges(filename); err != nil {
			s.logger("Warning: failed to delete appliance privileges: %v", err)
		}

		// Refresh appliances cache synchronously so the response includes fresh data
		if s.appliancesScanner != nil {
			s.appliancesScanner.ScanSync()
		}

		s.logger("Deleted appliance: %s", filename)
		s.jsonResponse(w, map[string]interface{}{
			"success": true,
			"message": "Appliance deleted successfully",
		})

	case http.MethodPut:
		// Update appliance description - requires write access
		if !canWrite {
			s.jsonError(w, "Access denied: write permission required", http.StatusForbidden)
			return
		}

		var req struct {
			Description string `json:"description"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if err := s.vmMgr.UpdateApplianceDescription(filename, req.Description); err != nil {
			s.jsonError(w, "Failed to update description: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.logger("Updated description for appliance: %s", filename)
		s.jsonResponse(w, map[string]interface{}{
			"success": true,
			"message": "Description updated successfully",
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAppliancePrivileges manages privileges for an appliance
func (s *Server) handleAppliancePrivileges(w http.ResponseWriter, r *http.Request, filename string, sess *database.Session, isOwner bool, parts []string) {
	// Only owner or admin can manage privileges
	if !isOwner && sess.Role != "admin" {
		s.jsonError(w, "Access denied: only owner can manage privileges", http.StatusForbidden)
		return
	}

	ownerID, _ := s.db.GetApplianceOwner(filename)
	if ownerID == 0 {
		ownerID = sess.UserID // Fallback to current user if no owner set
	}

	switch r.Method {
	case http.MethodGet:
		// List privileges
		privileges, err := s.db.GetAppliancePrivileges(filename)
		if err != nil {
			s.jsonError(w, "Failed to get privileges: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"privileges": privileges,
			"owner_id":   ownerID,
		})

	case http.MethodPost:
		// Add privilege
		var req struct {
			UserID   *int    `json:"user_id"`
			GroupID  *string `json:"group_id"`
			CanRead  bool    `json:"can_read"`
			CanWrite bool    `json:"can_write"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.UserID == nil && req.GroupID == nil {
			s.jsonError(w, "Either user_id or group_id is required", http.StatusBadRequest)
			return
		}

		if req.UserID != nil && req.GroupID != nil {
			s.jsonError(w, "Cannot specify both user_id and group_id", http.StatusBadRequest)
			return
		}

		if req.UserID != nil {
			if err := s.db.AddApplianceUserPrivilege(filename, ownerID, *req.UserID, req.CanRead, req.CanWrite); err != nil {
				s.jsonError(w, "Failed to add privilege: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			if err := s.db.AddApplianceGroupPrivilege(filename, ownerID, *req.GroupID, req.CanRead, req.CanWrite); err != nil {
				s.jsonError(w, "Failed to add privilege: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		s.jsonResponse(w, map[string]interface{}{
			"success": true,
			"message": "Privilege added successfully",
		})

	case http.MethodDelete:
		// Remove privilege: DELETE /api/appliances/{filename}/privileges/user/{id} or /group/{id}
		if len(parts) < 4 {
			s.jsonError(w, "Invalid path: expected /privileges/user/{id} or /privileges/group/{id}", http.StatusBadRequest)
			return
		}

		privType := parts[2] // "user" or "group"
		privID := parts[3]

		switch privType {
		case "user":
			userID, err := strconv.Atoi(privID)
			if err != nil {
				s.jsonError(w, "Invalid user ID", http.StatusBadRequest)
				return
			}
			if err := s.db.RemoveApplianceUserPrivilege(filename, userID); err != nil {
				s.jsonError(w, "Failed to remove privilege: "+err.Error(), http.StatusInternalServerError)
				return
			}
		case "group":
			if err := s.db.RemoveApplianceGroupPrivilege(filename, privID); err != nil {
				s.jsonError(w, "Failed to remove privilege: "+err.Error(), http.StatusInternalServerError)
				return
			}
		default:
			s.jsonError(w, "Invalid privilege type: expected 'user' or 'group'", http.StatusBadRequest)
			return
		}

		s.jsonResponse(w, map[string]interface{}{
			"success": true,
			"message": "Privilege removed successfully",
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Store API handlers

// handleStore handles GET /api/store - list store catalog
func (s *Server) handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.jsonError(w, "Store not initialized", http.StatusServiceUnavailable)
		return
	}

	catalog := s.store.GetCatalog()
	lastFetch := s.store.GetLastFetch()

	s.jsonResponse(w, map[string]interface{}{
		"appliances":  catalog,
		"last_update": lastFetch.Format(time.RFC3339),
		"count":       len(catalog),
	})
}

// handleStoreDownload handles POST /api/store/download/{name} - start download
func (s *Server) handleStoreDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.jsonError(w, "Store not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract appliance name from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/store/download/")
	name := strings.TrimSuffix(path, "/")
	if name == "" {
		s.jsonError(w, "Appliance name required", http.StatusBadRequest)
		return
	}

	// Start download
	key, err := s.store.StartDownload(name)
	if err != nil {
		s.jsonError(w, "Failed to start download: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.logger("Store download started: %s (key: %s)", name, key)

	s.jsonResponse(w, map[string]interface{}{
		"success": true,
		"key":     key,
		"message": "Download started",
	})
}

// handleStoreProgress handles GET /api/store/progress/{key} - get download progress
func (s *Server) handleStoreProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.jsonError(w, "Store not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract progress key from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/store/progress/")
	key := strings.TrimSuffix(path, "/")
	if key == "" {
		s.jsonError(w, "Progress key required", http.StatusBadRequest)
		return
	}

	progress := s.store.GetDownloadProgress(key)
	if progress == nil {
		s.jsonError(w, "Download not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, progress)
}

// handleStoreRefresh handles POST /api/store/refresh - force catalog refresh
func (s *Server) handleStoreRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.store == nil {
		s.jsonError(w, "Store not initialized", http.StatusServiceUnavailable)
		return
	}

	s.store.RefreshCatalog()

	s.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Catalog refresh initiated",
	})
}

// Kernel Update Handlers

// handleKernelUpdateCheck handles GET /api/system/kernels/check
// Returns kernel update status and available versions
func (s *Server) handleKernelUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Force refresh check
		if s.kernelUpdater == nil {
			s.jsonError(w, "Kernel updater not initialized", http.StatusServiceUnavailable)
			return
		}
		go s.kernelUpdater.CheckForUpdates()
		s.jsonResponse(w, map[string]interface{}{
			"status":  "checking",
			"message": "Kernel version check initiated",
		})
		return
	}

	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.kernelUpdater == nil {
		s.jsonError(w, "Kernel updater not initialized", http.StatusServiceUnavailable)
		return
	}

	// Get cached version info from kernel updater
	cache := s.kernelUpdater.GetCache()

	result := map[string]interface{}{
		"installed_kernels":   cache.InstalledKernels,
		"available_kernels":   cache.AvailableKernels,
		"update_available":    cache.UpdateAvailable,
		"latest_version":      cache.LatestVersion,
		"current_max_version": cache.CurrentMaxVersion,
		"checked_at":          cache.CheckedAt,
	}

	if cache.Error != "" {
		result["error"] = cache.Error
	}

	s.jsonResponse(w, result)
}

// handleKernelUpdateDownload handles POST /api/system/kernels/download
// Starts downloading a specific kernel version
func (s *Server) handleKernelUpdateDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.kernelUpdater == nil {
		s.jsonError(w, "Kernel updater not initialized", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Version == "" {
		s.jsonError(w, "Version is required", http.StatusBadRequest)
		return
	}

	// Start download
	jobID, err := s.kernelUpdater.DownloadKernel(req.Version)
	if err != nil {
		s.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"status":  "started",
		"job_id":  jobID,
		"message": "Kernel download started",
	})
}

// handleKernelDownloadProgress handles GET /api/system/kernels/download/{jobID}
// Returns download progress for a kernel download job
func (s *Server) handleKernelDownloadProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.kernelUpdater == nil {
		s.jsonError(w, "Kernel updater not initialized", http.StatusServiceUnavailable)
		return
	}

	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/system/kernels/download/")
	jobID := strings.TrimSuffix(path, "/")

	if jobID == "" {
		s.jsonError(w, "Job ID is required", http.StatusBadRequest)
		return
	}

	progress := s.kernelUpdater.GetDownloadProgress(jobID)
	if progress == nil {
		s.jsonError(w, "Download job not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, progress)
}

// installSSHInRootFS installs OpenSSH server into a rootfs image
func (s *Server) installSSHInRootFS(rootfsPath, vmID string) error {
	// Create temporary mount point
	mountPoint, err := os.MkdirTemp("", "ssh-install-*")
	if err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	// Mount the rootfs
	s.db.AddVMLog(vmID, "info", "Mounting rootfs for SSH installation")
	cmd := exec.Command("mount", "-o", "loop", rootfsPath, mountPoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to mount rootfs: %v - %s", err, string(output))
	}
	defer func() {
		exec.Command("umount", "-l", mountPoint).Run()
	}()

	// Detect distribution and package manager
	osRelease := ""
	if data, err := os.ReadFile(filepath.Join(mountPoint, "etc/os-release")); err == nil {
		osRelease = string(data)
	}

	// Bind mount required filesystems for chroot
	for _, mount := range []struct {
		src, dst, fstype, opts string
	}{
		{"/proc", filepath.Join(mountPoint, "proc"), "proc", ""},
		{"/sys", filepath.Join(mountPoint, "sys"), "sysfs", ""},
		{"/dev", filepath.Join(mountPoint, "dev"), "", "bind"},
	} {
		os.MkdirAll(mount.dst, 0755)
		var mountCmd *exec.Cmd
		if mount.opts == "bind" {
			mountCmd = exec.Command("mount", "--bind", mount.src, mount.dst)
		} else {
			mountCmd = exec.Command("mount", "-t", mount.fstype, mount.fstype, mount.dst)
		}
		mountCmd.Run()
		defer exec.Command("umount", "-l", mount.dst).Run()
	}

	// Copy resolv.conf for network access
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		os.WriteFile(filepath.Join(mountPoint, "etc/resolv.conf"), data, 0644)
	}

	var installCmd *exec.Cmd
	var pkgManager string

	// Determine package manager and install command
	if strings.Contains(osRelease, "Debian") || strings.Contains(osRelease, "Ubuntu") ||
		fileExists(filepath.Join(mountPoint, "usr/bin/apt-get")) {
		pkgManager = "apt"
		s.db.AddVMLog(vmID, "info", "Detected Debian/Ubuntu system, using apt")

		// Update package lists first
		s.db.AddVMLog(vmID, "info", "Updating package lists...")
		updateCmd := exec.Command("chroot", mountPoint, "apt-get", "update", "-qq")
		updateCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if output, err := updateCmd.CombinedOutput(); err != nil {
			s.db.AddVMLog(vmID, "warning", "apt-get update warning: "+string(output))
		}

		installCmd = exec.Command("chroot", mountPoint, "apt-get", "install", "-y", "-qq", "openssh-server")
		installCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	} else if strings.Contains(osRelease, "Alpine") ||
		fileExists(filepath.Join(mountPoint, "sbin/apk")) {
		pkgManager = "apk"
		s.db.AddVMLog(vmID, "info", "Detected Alpine system, using apk")
		installCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "openssh-server")

	} else if strings.Contains(osRelease, "CentOS") || strings.Contains(osRelease, "Red Hat") ||
		strings.Contains(osRelease, "Fedora") ||
		fileExists(filepath.Join(mountPoint, "usr/bin/dnf")) {
		pkgManager = "dnf"
		s.db.AddVMLog(vmID, "info", "Detected RHEL/CentOS/Fedora system, using dnf")
		installCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "openssh-server")

	} else if fileExists(filepath.Join(mountPoint, "usr/bin/yum")) {
		pkgManager = "yum"
		s.db.AddVMLog(vmID, "info", "Detected RHEL/CentOS system, using yum")
		installCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "openssh-server")

	} else {
		return fmt.Errorf("unsupported distribution: could not detect package manager")
	}

	// Run installation
	s.db.AddVMLog(vmID, "info", fmt.Sprintf("Installing OpenSSH server using %s...", pkgManager))
	output, err = installCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install openssh-server: %v - %s", err, string(output))
	}

	// Install haveged for entropy (prevents systemd-random-seed.service hang)
	s.db.AddVMLog(vmID, "info", "Installing haveged for entropy...")
	var havegedCmd *exec.Cmd
	switch pkgManager {
	case "apt":
		havegedCmd = exec.Command("chroot", mountPoint, "apt-get", "install", "-y", "-qq", "haveged")
		havegedCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	case "apk":
		havegedCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "haveged")
	case "dnf":
		havegedCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "haveged")
	case "yum":
		havegedCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "haveged")
	}
	if havegedCmd != nil {
		if output, err := havegedCmd.CombinedOutput(); err != nil {
			s.db.AddVMLog(vmID, "warning", "haveged installation warning: "+string(output))
		}
	}

	// Pre-seed the random seed file to prevent boot hang
	randomSeedDir := filepath.Join(mountPoint, "var/lib/systemd")
	os.MkdirAll(randomSeedDir, 0755)
	randomSeedFile := filepath.Join(randomSeedDir, "random-seed")
	randomData := make([]byte, 512)
	if _, err := rand.Read(randomData); err == nil {
		os.WriteFile(randomSeedFile, randomData, 0600)
		s.db.AddVMLog(vmID, "info", "Pre-seeded random-seed file for faster boot")
	}

	// Enable SSH and haveged services if systemd is present
	if fileExists(filepath.Join(mountPoint, "usr/lib/systemd/systemd")) ||
		fileExists(filepath.Join(mountPoint, "lib/systemd/systemd")) {
		s.db.AddVMLog(vmID, "info", "Enabling SSH and haveged services in systemd")
		exec.Command("chroot", mountPoint, "systemctl", "enable", "ssh").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "sshd").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "haveged").Run()
	}

	// For Alpine, enable OpenRC services
	if pkgManager == "apk" {
		s.db.AddVMLog(vmID, "info", "Enabling SSH and haveged services in OpenRC")
		exec.Command("chroot", mountPoint, "rc-update", "add", "sshd", "default").Run()
		exec.Command("chroot", mountPoint, "rc-update", "add", "haveged", "default").Run()
	}

	// Generate host keys if they don't exist
	sshKeyDir := filepath.Join(mountPoint, "etc/ssh")
	if _, err := os.Stat(filepath.Join(sshKeyDir, "ssh_host_rsa_key")); os.IsNotExist(err) {
		s.db.AddVMLog(vmID, "info", "Generating SSH host keys")
		exec.Command("chroot", mountPoint, "ssh-keygen", "-A").Run()
	}

	// Ensure sshd_config allows password authentication
	sshdConfig := filepath.Join(sshKeyDir, "sshd_config")
	if data, err := os.ReadFile(sshdConfig); err == nil {
		config := string(data)
		modified := false

		// Enable password authentication
		if strings.Contains(config, "#PasswordAuthentication") {
			config = strings.ReplaceAll(config, "#PasswordAuthentication no", "PasswordAuthentication yes")
			config = strings.ReplaceAll(config, "#PasswordAuthentication yes", "PasswordAuthentication yes")
			modified = true
		}

		// Enable root login (for initial access)
		if strings.Contains(config, "#PermitRootLogin") {
			config = strings.ReplaceAll(config, "#PermitRootLogin prohibit-password", "PermitRootLogin yes")
			config = strings.ReplaceAll(config, "#PermitRootLogin yes", "PermitRootLogin yes")
			modified = true
		}

		if modified {
			os.WriteFile(sshdConfig, []byte(config), 0644)
			s.db.AddVMLog(vmID, "info", "Updated sshd_config to allow password authentication")
		}
	}

	s.db.AddVMLog(vmID, "info", "OpenSSH server installation completed")
	return nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// getLDAPClient returns the current LDAP client, creating one if needed
func (s *Server) getLDAPClient() (*ldap.Client, error) {
	s.ldapClientMu.RLock()
	if s.ldapClient != nil {
		client := s.ldapClient
		s.ldapClientMu.RUnlock()
		return client, nil
	}
	s.ldapClientMu.RUnlock()

	// Need to create client
	s.ldapClientMu.Lock()
	defer s.ldapClientMu.Unlock()

	// Double-check after acquiring write lock
	if s.ldapClient != nil {
		return s.ldapClient, nil
	}

	config, err := s.db.GetLDAPConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP config: %w", err)
	}

	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("LDAP is not enabled")
	}

	ldapConfig := &ldap.Config{
		Enabled:         config.Enabled,
		Server:          config.Server,
		Port:            config.Port,
		UseSSL:          config.UseSSL,
		UseStartTLS:     config.UseStartTLS,
		SkipVerify:      config.SkipVerify,
		BindDN:          config.BindDN,
		BindPassword:    config.BindPassword,
		BaseDN:          config.BaseDN,
		UserSearchBase:  config.UserSearchBase,
		UserFilter:      config.UserFilter,
		GroupSearchBase: config.GroupSearchBase,
		GroupFilter:     config.GroupFilter,
	}

	s.ldapClient = ldap.NewClient(ldapConfig, s.logger)
	return s.ldapClient, nil
}

// refreshLDAPClient forces recreation of the LDAP client (after config change)
func (s *Server) refreshLDAPClient() {
	s.ldapClientMu.Lock()
	defer s.ldapClientMu.Unlock()
	s.ldapClient = nil
}

// handleLDAPConfig handles GET/PUT for LDAP configuration
func (s *Server) handleLDAPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getLDAPConfigHandler(w, r)
	case http.MethodPut:
		s.updateLDAPConfigHandler(w, r)
	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getLDAPConfigHandler(w http.ResponseWriter, r *http.Request) {
	config, err := s.db.GetLDAPConfig()
	if err != nil {
		s.jsonError(w, "Failed to get LDAP config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if config == nil {
		// Return default config
		config = &database.LDAPConfig{
			Enabled:     false,
			Port:        389,
			UseSSL:      false,
			UseStartTLS: false,
			SkipVerify:  true,
			UserFilter:  "(&(objectClass=user)(sAMAccountName=%s))",
			GroupFilter: "(objectClass=group)",
		}
	}

	// Don't return the password
	config.BindPassword = ""

	s.jsonResponse(w, config)
}

// deriveBaseDNFromUsername extracts domain from user@domain.tld and converts to DC=domain,DC=tld
func deriveBaseDNFromUsername(username string) string {
	atIndex := strings.Index(username, "@")
	if atIndex == -1 {
		return ""
	}
	domain := username[atIndex+1:]
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	dcParts := make([]string, len(parts))
	for i, p := range parts {
		dcParts[i] = "DC=" + p
	}
	return strings.Join(dcParts, ",")
}

func (s *Server) updateLDAPConfigHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled      bool   `json:"enabled"`
		Server       string `json:"server"`
		Port         int    `json:"port"`
		UseSSL       bool   `json:"use_ssl"`
		UseStartTLS  bool   `json:"use_starttls"`
		SkipVerify   bool   `json:"skip_verify"`
		BindDN       string `json:"bind_dn"` // user@domain.tld format
		BindPassword string `json:"bind_password"`
		BaseDN       string `json:"base_dn"` // Optional, auto-derived from BindDN
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate
	if req.Enabled {
		if req.Server == "" {
			s.jsonError(w, "Server is required", http.StatusBadRequest)
			return
		}
		if req.Port <= 0 {
			req.Port = 389
		}
		if req.BindDN == "" {
			s.jsonError(w, "Service account username is required", http.StatusBadRequest)
			return
		}
		// Validate user@domain.tld format
		if !strings.Contains(req.BindDN, "@") {
			s.jsonError(w, "Service account must be in user@domain.tld format", http.StatusBadRequest)
			return
		}
	}

	// Get existing config to preserve password if not provided
	existingConfig, _ := s.db.GetLDAPConfig()
	if req.BindPassword == "" && existingConfig != nil {
		req.BindPassword = existingConfig.BindPassword
	}

	// Auto-derive Base DN from username domain if not provided
	baseDN := req.BaseDN
	if baseDN == "" && req.BindDN != "" {
		baseDN = deriveBaseDNFromUsername(req.BindDN)
	}

	config := &database.LDAPConfig{
		Enabled:         req.Enabled,
		Server:          req.Server,
		Port:            req.Port,
		UseSSL:          req.UseSSL,
		UseStartTLS:     req.UseStartTLS,
		SkipVerify:      req.SkipVerify,
		BindDN:          req.BindDN,
		BindPassword:    req.BindPassword,
		BaseDN:          baseDN,
		UserSearchBase:  baseDN, // Use BaseDN for user searches
		UserFilter:      "(&(objectClass=user)(sAMAccountName=%s))",
		GroupSearchBase: baseDN, // Use BaseDN for group searches
		GroupFilter:     "(objectClass=group)",
	}

	if err := s.db.SaveLDAPConfig(config); err != nil {
		s.jsonError(w, "Failed to save LDAP config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Refresh LDAP client
	s.refreshLDAPClient()

	s.logger("LDAP configuration updated, enabled=%v server=%s", config.Enabled, config.Server)
	s.jsonResponse(w, map[string]string{"status": "success"})
}

// handleLDAPTest tests the LDAP connection
func (s *Server) handleLDAPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Option to test with provided config (before saving)
	var req struct {
		Server       string `json:"server"`
		Port         int    `json:"port"`
		UseSSL       bool   `json:"use_ssl"`
		UseStartTLS  bool   `json:"use_starttls"`
		SkipVerify   bool   `json:"skip_verify"`
		BindDN       string `json:"bind_dn"` // user@domain.tld format
		BindPassword string `json:"bind_password"`
		BaseDN       string `json:"base_dn"` // Optional, auto-derived
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get existing password if not provided
	if req.BindPassword == "" {
		existingConfig, _ := s.db.GetLDAPConfig()
		if existingConfig != nil {
			req.BindPassword = existingConfig.BindPassword
		}
	}

	if req.Server == "" {
		s.jsonError(w, "Server is required", http.StatusBadRequest)
		return
	}

	if req.Port <= 0 {
		req.Port = 389
	}

	// Auto-derive Base DN from username domain if not provided
	baseDN := req.BaseDN
	if baseDN == "" && req.BindDN != "" {
		baseDN = deriveBaseDNFromUsername(req.BindDN)
	}

	testConfig := &ldap.Config{
		Enabled:      true,
		Server:       req.Server,
		Port:         req.Port,
		UseSSL:       req.UseSSL,
		UseStartTLS:  req.UseStartTLS,
		SkipVerify:   req.SkipVerify,
		BindDN:       req.BindDN,
		BindPassword: req.BindPassword,
		BaseDN:       baseDN,
	}

	client := ldap.NewClient(testConfig, s.logger)
	if err := client.TestConnection(); err != nil {
		s.jsonResponse(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Connection successful",
	})
}

// handleLDAPGroups searches for AD groups
func (s *Server) handleLDAPGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	client, err := s.getLDAPClient()
	if err != nil {
		s.jsonError(w, "LDAP not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	groups, err := client.SearchGroups(query, limit)
	if err != nil {
		s.jsonError(w, "Failed to search groups: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, groups)
}

// handleLDAPGroupMemberCount returns the member count or list for an AD group
func (s *Server) handleLDAPGroupMemberCount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	groupDN := r.URL.Query().Get("dn")
	if groupDN == "" {
		s.jsonError(w, "Group DN is required", http.StatusBadRequest)
		return
	}

	client, err := s.getLDAPClient()
	if err != nil {
		s.jsonError(w, "LDAP not available: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// If list=true, return full member list; otherwise just count
	if r.URL.Query().Get("list") == "true" {
		members, err := client.GetGroupMembers(groupDN)
		if err != nil {
			s.jsonError(w, "Failed to get members: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.jsonResponse(w, map[string]interface{}{
			"count":   len(members),
			"members": members,
		})
		return
	}

	count, err := client.GetGroupMemberCount(groupDN)
	if err != nil {
		s.jsonError(w, "Failed to get member count: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]int{"count": count})
}

// handleLDAPGroupMappings handles GET/POST for group mappings
func (s *Server) handleLDAPGroupMappings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listLDAPGroupMappings(w, r)
	case http.MethodPost:
		s.createLDAPGroupMapping(w, r)
	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listLDAPGroupMappings(w http.ResponseWriter, r *http.Request) {
	mappings, err := s.db.ListLDAPGroupMappings()
	if err != nil {
		s.jsonError(w, "Failed to list group mappings: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, mappings)
}

func (s *Server) createLDAPGroupMapping(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupDN      string `json:"group_dn"`
		GroupName    string `json:"group_name"`
		LocalRole    string `json:"local_role"`
		LocalGroupID string `json:"local_group_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.GroupDN == "" {
		s.jsonError(w, "Group DN is required", http.StatusBadRequest)
		return
	}

	if req.LocalRole == "" {
		req.LocalRole = "user"
	}

	// Validate role
	validRoles := map[string]bool{"admin": true, "user": true, "group": true}
	if !validRoles[req.LocalRole] {
		s.jsonError(w, "Invalid role, must be: admin, user, or group", http.StatusBadRequest)
		return
	}

	if req.LocalRole == "group" && req.LocalGroupID == "" {
		s.jsonError(w, "Local group ID is required when role is 'group'", http.StatusBadRequest)
		return
	}

	mapping := &database.LDAPGroupMapping{
		ID:           generateID(),
		GroupDN:      req.GroupDN,
		GroupName:    req.GroupName,
		LocalRole:    req.LocalRole,
		LocalGroupID: req.LocalGroupID,
	}

	if err := s.db.CreateLDAPGroupMapping(mapping); err != nil {
		s.jsonError(w, "Failed to create mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Created LDAP group mapping: %s -> %s", req.GroupDN, req.LocalRole)
	s.jsonResponse(w, mapping)
}

// handleLDAPGroupMapping handles GET/PUT/DELETE for a specific group mapping
func (s *Server) handleLDAPGroupMapping(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/ldap/group-mappings/")
	if id == "" {
		s.jsonError(w, "Mapping ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getLDAPGroupMapping(w, r, id)
	case http.MethodPut:
		s.updateLDAPGroupMapping(w, r, id)
	case http.MethodDelete:
		s.deleteLDAPGroupMapping(w, r, id)
	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) getLDAPGroupMapping(w http.ResponseWriter, r *http.Request, id string) {
	mapping, err := s.db.GetLDAPGroupMapping(id)
	if err != nil {
		s.jsonError(w, "Failed to get mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if mapping == nil {
		s.jsonError(w, "Mapping not found", http.StatusNotFound)
		return
	}
	s.jsonResponse(w, mapping)
}

func (s *Server) updateLDAPGroupMapping(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		GroupDN      string `json:"group_dn"`
		GroupName    string `json:"group_name"`
		LocalRole    string `json:"local_role"`
		LocalGroupID string `json:"local_group_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}

	mapping, err := s.db.GetLDAPGroupMapping(id)
	if err != nil {
		s.jsonError(w, "Failed to get mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if mapping == nil {
		s.jsonError(w, "Mapping not found", http.StatusNotFound)
		return
	}

	if req.GroupDN != "" {
		mapping.GroupDN = req.GroupDN
	}
	if req.GroupName != "" {
		mapping.GroupName = req.GroupName
	}
	if req.LocalRole != "" {
		validRoles := map[string]bool{"admin": true, "user": true, "group": true}
		if !validRoles[req.LocalRole] {
			s.jsonError(w, "Invalid role, must be: admin, user, or group", http.StatusBadRequest)
			return
		}
		mapping.LocalRole = req.LocalRole
	}
	mapping.LocalGroupID = req.LocalGroupID

	if mapping.LocalRole == "group" && mapping.LocalGroupID == "" {
		s.jsonError(w, "Local group ID is required when role is 'group'", http.StatusBadRequest)
		return
	}

	if err := s.db.UpdateLDAPGroupMapping(mapping); err != nil {
		s.jsonError(w, "Failed to update mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Updated LDAP group mapping: %s", id)
	s.jsonResponse(w, mapping)
}

func (s *Server) deleteLDAPGroupMapping(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.db.DeleteLDAPGroupMapping(id); err != nil {
		s.jsonError(w, "Failed to delete mapping: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("Deleted LDAP group mapping: %s", id)
	s.jsonResponse(w, map[string]string{"status": "success"})
}
