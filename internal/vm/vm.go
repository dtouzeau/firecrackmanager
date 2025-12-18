package vm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/md5"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/network"
)

const (
	FirecrackerBinary = "/usr/sbin/firecracker"
	JailerBinary      = "/usr/sbin/jailer"
	DefaultVCPU       = 1
	DefaultMemoryMB   = 512
	DefaultKernelArgs = "console=ttyS0,115200n8 reboot=k panic=1"

	// InternalKernelArgs contains kernel arguments that are always added internally
	// but hidden from the web console and API. These are essential for Firecracker operation.
	// - pci=off: Firecracker doesn't emulate PCI
	// - random.trust_cpu=on: Trust CPU's hardware RNG (RDRAND/RDSEED) for entropy
	// - random.trust_bootloader=on: Trust entropy passed from bootloader
	// - rng_core.default_quality=1000: High quality rating for hardware RNG to speed up entropy init
	InternalKernelArgs = "pci=off random.trust_cpu=on random.trust_bootloader=on rng_core.default_quality=1000"

	// FirecrackerHypervisorArg is appended to kernel args to allow VMs to detect
	// they are running in a Firecracker environment. Guest can check via:
	//   grep -q "fcm.hypervisor=firecracker" /proc/cmdline
	// Or read the value:
	//   cat /proc/cmdline | grep -oP 'fcm\.hypervisor=\K\w+'
	FirecrackerHypervisorArg = "fcm.hypervisor=firecracker fcm.managed=true"

	// Jailer defaults
	DefaultJailerChrootBase = "/srv/jailer"
	DefaultJailerUID        = 1000
	DefaultJailerGID        = 1000
)

// JailerConfig holds configuration for Firecracker jailer
type JailerConfig struct {
	Enabled        bool   `json:"enabled"`
	JailerPath     string `json:"jailer_path"`
	ChrootBase     string `json:"chroot_base"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	CgroupVer      int    `json:"cgroup_version"` // 1 or 2
	Daemonize      bool   `json:"daemonize"`
	NewPidNS       bool   `json:"new_pid_ns"`
	NetNS          string `json:"netns"` // Optional network namespace path
	ResourceLimits struct {
		Fsize  int64 `json:"fsize"`   // Max file size (0 = unlimited)
		NoFile int   `json:"no_file"` // Max open files (0 = default)
	} `json:"resource_limits"`
}

// buildKernelArgs constructs the final kernel arguments by combining user-provided
// args (or defaults) with internal system parameters and hypervisor detection args.
// Internal args (pci=off, random.trust_cpu=on) are always added but hidden from UI/API.
// This ensures VMs can always detect they are running in a Firecracker environment.
func buildKernelArgs(userArgs string) string {
	baseArgs := userArgs
	if baseArgs == "" {
		baseArgs = DefaultKernelArgs
	}
	// Always append internal args (hidden from UI) and hypervisor detection args
	return baseArgs + " " + InternalKernelArgs + " " + FirecrackerHypervisorArg
}

// Firecracker API structures
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
}

type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type MachineConfig struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMib int  `json:"mem_size_mib"`
	Smt        bool `json:"smt,omitempty"`
}

type NetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac,omitempty"`
	HostDevName string `json:"host_dev_name"`
}

type InstanceActionInfo struct {
	ActionType string `json:"action_type"` // InstanceStart, FlushMetrics, SendCtrlAltDel
}

type VMConfig struct {
	BootSource        BootSource         `json:"boot-source"`
	Drives            []Drive            `json:"drives"`
	MachineConfig     MachineConfig      `json:"machine-config"`
	NetworkInterfaces []NetworkInterface `json:"network-interfaces,omitempty"`
}

// Manager handles VM lifecycle
// OperationProgress tracks progress of long-running operations like VM duplication
type OperationProgress struct {
	Status     string  `json:"status"`  // "starting", "copying", "completed", "error"
	Stage      string  `json:"stage"`   // Current stage description
	Total      int64   `json:"total"`   // Total bytes to copy
	Copied     int64   `json:"copied"`  // Bytes copied so far
	Percent    float64 `json:"percent"` // Progress percentage
	Error      string  `json:"error,omitempty"`
	ResultID   string  `json:"result_id,omitempty"`   // ID of created resource (e.g., new VM ID)
	ResultName string  `json:"result_name,omitempty"` // Name of created resource
}

type Manager struct {
	db            *database.DB
	netMgr        *network.Manager
	dataDir       string
	socketDir     string
	mu            sync.RWMutex
	runningVMs    map[string]*runningVM
	logger        func(string, ...interface{})
	metricsCancel context.CancelFunc
	jailerConfig  *JailerConfig
	// Operation progress tracking
	opMu       sync.RWMutex
	operations map[string]*OperationProgress
}

type runningVM struct {
	cmd        *exec.Cmd
	socketPath string
	tapFD      int
	cancel     context.CancelFunc
	// Console I/O
	consoleIn  io.WriteCloser
	consoleOut io.ReadCloser
	// Jailer info
	jailed        bool
	jailPath      string // Path to jail root directory
	jailerPidFile string // Path to jailer PID file
}

func NewManager(db *database.DB, netMgr *network.Manager, dataDir string, logger func(string, ...interface{})) (*Manager, error) {
	socketDir := filepath.Join(dataDir, "sockets")
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Check firecracker binary exists
	if _, err := os.Stat(FirecrackerBinary); err != nil {
		return nil, fmt.Errorf("firecracker binary not found at %s: %w", FirecrackerBinary, err)
	}

	m := &Manager{
		db:         db,
		netMgr:     netMgr,
		dataDir:    dataDir,
		socketDir:  socketDir,
		runningVMs: make(map[string]*runningVM),
		logger:     logger,
		jailerConfig: &JailerConfig{
			Enabled:    false,
			JailerPath: JailerBinary,
			ChrootBase: DefaultJailerChrootBase,
			UID:        DefaultJailerUID,
			GID:        DefaultJailerGID,
			CgroupVer:  2,
			Daemonize:  false,
			NewPidNS:   true,
		},
		operations: make(map[string]*OperationProgress),
	}

	// Start metrics collector
	m.StartMetricsCollector(10 * time.Second)

	return m, nil
}

// SetJailerConfig updates the jailer configuration
func (m *Manager) SetJailerConfig(config *JailerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jailerConfig = config
	if config.Enabled {
		m.logger("Jailer enabled: chroot=%s, uid=%d, gid=%d", config.ChrootBase, config.UID, config.GID)
	}
}

// GetJailerConfig returns the current jailer configuration
func (m *Manager) GetJailerConfig() *JailerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.jailerConfig
}

// IsJailerAvailable checks if the jailer binary is available
func (m *Manager) IsJailerAvailable() bool {
	jailerPath := JailerBinary
	if m.jailerConfig != nil && m.jailerConfig.JailerPath != "" {
		jailerPath = m.jailerConfig.JailerPath
	}
	_, err := os.Stat(jailerPath)
	return err == nil
}

// jailInfo contains information about a jail environment
type jailInfo struct {
	jailID     string            // Unique jail identifier (VM ID)
	jailRoot   string            // Full path to jail root: <chroot_base>/firecracker/<id>/root
	jailBase   string            // Path to jail base: <chroot_base>/firecracker/<id>
	socketPath string            // Socket path inside jail (relative to jailRoot)
	kernelPath string            // Kernel path inside jail
	rootfsPath string            // RootFS path inside jail
	diskPaths  map[string]string // Additional disk paths inside jail
}

// setupJail creates the jail environment for a VM
func (m *Manager) setupJail(vm *database.VM) (*jailInfo, error) {
	config := m.jailerConfig
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("jailer not enabled")
	}

	// Create jail directory structure: <chroot_base>/firecracker/<vm_id>/root
	jailBase := filepath.Join(config.ChrootBase, "firecracker", vm.ID)
	jailRoot := filepath.Join(jailBase, "root")

	// Clean up any existing jail
	os.RemoveAll(jailBase)

	// Create directories
	if err := os.MkdirAll(jailRoot, 0755); err != nil {
		return nil, fmt.Errorf("failed to create jail root: %w", err)
	}

	// Create device directories
	devDir := filepath.Join(jailRoot, "dev", "net")
	if err := os.MkdirAll(devDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create dev directory: %w", err)
	}

	info := &jailInfo{
		jailID:    vm.ID,
		jailBase:  jailBase,
		jailRoot:  jailRoot,
		diskPaths: make(map[string]string),
	}

	// Hard link kernel to jail
	kernelName := filepath.Base(vm.KernelPath)
	jailKernelPath := filepath.Join(jailRoot, kernelName)
	if err := os.Link(vm.KernelPath, jailKernelPath); err != nil {
		// Try copy if hard link fails (cross-device)
		if err := copyFile(vm.KernelPath, jailKernelPath); err != nil {
			return nil, fmt.Errorf("failed to link/copy kernel to jail: %w", err)
		}
	}
	info.kernelPath = "/" + kernelName

	// Hard link rootfs to jail
	rootfsName := filepath.Base(vm.RootFSPath)
	jailRootfsPath := filepath.Join(jailRoot, rootfsName)
	if err := os.Link(vm.RootFSPath, jailRootfsPath); err != nil {
		// Try copy if hard link fails (cross-device)
		if err := copyFile(vm.RootFSPath, jailRootfsPath); err != nil {
			return nil, fmt.Errorf("failed to link/copy rootfs to jail: %w", err)
		}
	}
	info.rootfsPath = "/" + rootfsName

	// Hard link additional disks
	additionalDisks, err := m.db.ListVMDisks(vm.ID)
	if err == nil {
		for _, disk := range additionalDisks {
			diskName := filepath.Base(disk.Path)
			jailDiskPath := filepath.Join(jailRoot, diskName)
			if err := os.Link(disk.Path, jailDiskPath); err != nil {
				if err := copyFile(disk.Path, jailDiskPath); err != nil {
					m.logger("Warning: failed to link disk %s to jail: %v", disk.Path, err)
					continue
				}
			}
			info.diskPaths[disk.DriveID] = "/" + diskName
		}
	}

	// Socket will be created at jailRoot/run/firecracker.socket
	runDir := filepath.Join(jailRoot, "run")
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create run directory: %w", err)
	}
	info.socketPath = "/run/firecracker.socket"

	// Change ownership of jail to jailer UID/GID
	if err := chownRecursive(jailBase, config.UID, config.GID); err != nil {
		m.logger("Warning: failed to chown jail directory: %v", err)
	}

	m.logger("Jail created for VM %s at %s", vm.ID, jailRoot)
	return info, nil
}

// cleanupJail removes the jail environment for a VM
func (m *Manager) cleanupJail(vmID string) error {
	if m.jailerConfig == nil {
		return nil
	}

	jailBase := filepath.Join(m.jailerConfig.ChrootBase, "firecracker", vmID)
	if _, err := os.Stat(jailBase); os.IsNotExist(err) {
		return nil // Already cleaned up
	}

	if err := os.RemoveAll(jailBase); err != nil {
		return fmt.Errorf("failed to remove jail: %w", err)
	}

	m.logger("Jail cleaned up for VM %s", vmID)
	return nil
}

// chownRecursive changes ownership of a directory recursively
func chownRecursive(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, uid, gid)
	})
}

// buildJailerArgs constructs the jailer command line arguments
func (m *Manager) buildJailerArgs(vm *database.VM, jailInfo *jailInfo) []string {
	config := m.jailerConfig

	args := []string{
		"--id", vm.ID,
		"--exec-file", FirecrackerBinary,
		"--uid", fmt.Sprintf("%d", config.UID),
		"--gid", fmt.Sprintf("%d", config.GID),
		"--chroot-base-dir", config.ChrootBase,
	}

	// Cgroup version
	if config.CgroupVer > 0 {
		args = append(args, "--cgroup-version", fmt.Sprintf("%d", config.CgroupVer))
	}

	// Daemonize
	if config.Daemonize {
		args = append(args, "--daemonize")
	}

	// New PID namespace
	if config.NewPidNS {
		args = append(args, "--new-pid-ns")
	}

	// Network namespace
	if config.NetNS != "" {
		args = append(args, "--netns", config.NetNS)
	}

	// Resource limits
	if config.ResourceLimits.Fsize > 0 {
		args = append(args, "--resource-limit", fmt.Sprintf("fsize=%d", config.ResourceLimits.Fsize))
	}
	if config.ResourceLimits.NoFile > 0 {
		args = append(args, "--resource-limit", fmt.Sprintf("no-file=%d", config.ResourceLimits.NoFile))
	}

	// Separator for firecracker args
	args = append(args, "--")

	// Firecracker args (socket path is relative to jail root)
	args = append(args, "--api-sock", jailInfo.socketPath)

	return args
}

// StartMetricsCollector starts a goroutine that collects metrics for running VMs
func (m *Manager) StartMetricsCollector(interval time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	m.metricsCancel = cancel

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.collectAllMetrics()
			}
		}
	}()

	m.logger("Metrics collector started (interval: %v)", interval)
}

// StopMetricsCollector stops the metrics collection goroutine
func (m *Manager) StopMetricsCollector() {
	if m.metricsCancel != nil {
		m.metricsCancel()
	}
}

// collectAllMetrics collects metrics for all running VMs
func (m *Manager) collectAllMetrics() {
	m.mu.RLock()
	vmIDs := make([]string, 0, len(m.runningVMs))
	for vmID := range m.runningVMs {
		vmIDs = append(vmIDs, vmID)
	}
	m.mu.RUnlock()

	for _, vmID := range vmIDs {
		metrics, err := m.GetVMMetrics(vmID)
		if err != nil {
			continue
		}

		if metrics["status"] == "running" {
			cpuPercent, _ := metrics["cpu_percent"].(float64)
			memPercent, _ := metrics["mem_percent"].(float64)
			memUsedMB, _ := metrics["mem_used_mb"].(int64)
			if memUsedInt, ok := metrics["mem_used_mb"].(int); ok {
				memUsedMB = int64(memUsedInt)
			}

			if err := m.db.SaveVMMetric(vmID, cpuPercent, memPercent, memUsedMB); err != nil {
				m.logger("Failed to save metrics for VM %s: %v", vmID, err)
			}
		}
	}
}

// StartVM starts a virtual machine with retry logic for resilience
func (m *Manager) StartVM(vmID string) error {
	return m.StartVMWithRetry(vmID, 3, 2*time.Second)
}

// StartVMWithRetry starts a VM with configurable retry logic
func (m *Manager) StartVMWithRetry(vmID string, maxRetries int, initialDelay time.Duration) error {
	var lastErr error
	delay := initialDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := m.startVMInternal(vmID)
		if err == nil {
			if attempt > 1 {
				m.logger("VM %s started successfully on attempt %d", vmID, attempt)
			}
			return nil
		}

		lastErr = err
		m.logger("VM %s start attempt %d/%d failed: %v", vmID, attempt, maxRetries, err)

		// Log the failure to VM logs
		m.db.AddVMLog(vmID, "warning", fmt.Sprintf("Start attempt %d/%d failed: %v", attempt, maxRetries, err))

		if attempt < maxRetries {
			// Cleanup any partial resources before retry
			m.cleanupFailedStart(vmID)

			m.logger("Retrying VM %s start in %v...", vmID, delay)
			time.Sleep(delay)
			delay *= 2 // Exponential backoff
			if delay > 10*time.Second {
				delay = 10 * time.Second // Cap at 10 seconds
			}
		}
	}

	// Update VM status to error after all retries failed
	if vm, err := m.db.GetVM(vmID); err == nil && vm != nil {
		vm.Status = "error"
		vm.ErrorMessage = fmt.Sprintf("Failed to start after %d attempts: %v", maxRetries, lastErr)
		m.db.UpdateVM(vm)
		m.db.AddVMLog(vmID, "error", vm.ErrorMessage)
	}

	return fmt.Errorf("failed to start VM after %d attempts: %w", maxRetries, lastErr)
}

// cleanupFailedStart cleans up resources from a failed start attempt
func (m *Manager) cleanupFailedStart(vmID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get VM info
	vm, err := m.db.GetVM(vmID)
	if err != nil || vm == nil {
		return
	}

	// Clean up socket
	socketPath := filepath.Join(m.socketDir, fmt.Sprintf("%s.sock", vmID))
	os.Remove(socketPath)

	// Clean up TAP devices from vm_networks table
	vmNetworks, err := m.db.ListVMNetworks(vmID)
	if err == nil && len(vmNetworks) > 0 {
		for _, vmNet := range vmNetworks {
			if vmNet.TapDevice != "" {
				// Remove from bridge first
				if net, netErr := m.db.GetNetwork(vmNet.NetworkID); netErr == nil && net != nil {
					m.netMgr.RemoveInterfaceFromBridge(net.BridgeName, vmNet.TapDevice)
				}
				m.netMgr.DeleteTAP(vmNet.TapDevice)
			}
		}
	}

	// Fallback: Clean up legacy single TAP device if configured
	if vm.TapDevice != "" {
		// Remove from bridge first
		if vm.NetworkID != "" {
			if net, err := m.db.GetNetwork(vm.NetworkID); err == nil && net != nil {
				m.netMgr.RemoveInterfaceFromBridge(net.BridgeName, vm.TapDevice)
			}
		}
		m.netMgr.DeleteTAP(vm.TapDevice)
	}

	// Remove from running VMs if partially tracked
	if rv, ok := m.runningVMs[vmID]; ok {
		if rv.cancel != nil {
			rv.cancel()
		}
		if rv.cmd != nil && rv.cmd.Process != nil {
			syscall.Kill(-rv.cmd.Process.Pid, syscall.SIGKILL)
			rv.cmd.Wait()
		}
		delete(m.runningVMs, vmID)
	}

	// Give kernel time to clean up resources
	time.Sleep(200 * time.Millisecond)
}

// startVMInternal is the internal VM start implementation
func (m *Manager) startVMInternal(vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear realtime metrics so charts start fresh
	if err := m.db.ClearVMRealtimeMetrics(vmID); err != nil {
		m.logger("Warning: failed to clear realtime metrics for VM %s: %v", vmID, err)
	}

	m.db.AddVMLog(vmID, "info", "Starting VM startup sequence...")

	// Check if already running
	if _, running := m.runningVMs[vmID]; running {
		m.db.AddVMLog(vmID, "error", "VM is already running")
		return fmt.Errorf("VM %s is already running", vmID)
	}

	// Get VM from database
	m.db.AddVMLog(vmID, "info", "Loading VM configuration from database")
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to get VM from database: %v", err))
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		m.db.AddVMLog(vmID, "error", "VM not found in database")
		return fmt.Errorf("VM %s not found", vmID)
	}
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM config: %d vCPUs, %d MB RAM, kernel=%s", vm.VCPU, vm.MemoryMB, filepath.Base(vm.KernelPath)))

	// Verify kernel and rootfs exist
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Checking kernel: %s", vm.KernelPath))
	if _, err := os.Stat(vm.KernelPath); err != nil {
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Kernel not found: %s", vm.KernelPath))
		return fmt.Errorf("kernel not found: %s", vm.KernelPath)
	}
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Checking rootfs: %s", vm.RootFSPath))
	if _, err := os.Stat(vm.RootFSPath); err != nil {
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("RootFS not found: %s", vm.RootFSPath))
		return fmt.Errorf("rootfs not found: %s", vm.RootFSPath)
	}

	// Update DNS configuration in rootfs if DNS servers are specified
	if vm.DNSServers != "" {
		m.db.AddVMLog(vmID, "info", fmt.Sprintf("Updating DNS configuration: %s", vm.DNSServers))
		if err := m.updateRootFSDNS(vm.RootFSPath, vm.DNSServers); err != nil {
			m.db.AddVMLog(vmID, "warning", fmt.Sprintf("Failed to update DNS in rootfs: %v", err))
			m.logger("Warning: failed to update DNS in rootfs: %v", err)
		}
	}

	// Seed entropy to rootfs to prevent getrandom() blocking
	m.db.AddVMLog(vmID, "info", "Seeding entropy to rootfs")
	if err := m.seedEntropyToRootFS(vm.RootFSPath); err != nil {
		m.db.AddVMLog(vmID, "warning", fmt.Sprintf("Failed to seed entropy to rootfs: %v", err))
		m.logger("Warning: failed to seed entropy to rootfs: %v", err)
	}

	// Determine if we should use jailer
	useJailer := m.jailerConfig != nil && m.jailerConfig.Enabled && m.IsJailerAvailable()

	var jailEnv *jailInfo
	var socketPath string
	var actualSocketPath string // The path we'll use to connect

	if useJailer {
		m.db.AddVMLog(vmID, "info", "Setting up jailed environment")
		// Setup jail environment
		var err error
		jailEnv, err = m.setupJail(vm)
		if err != nil {
			m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to setup jail: %v", err))
			return fmt.Errorf("failed to setup jail: %w", err)
		}
		// Socket path inside jail (relative)
		socketPath = jailEnv.socketPath
		// Actual socket path on host for API calls
		actualSocketPath = filepath.Join(jailEnv.jailRoot, "run", "firecracker.socket")
		m.db.AddVMLog(vmID, "info", "Starting VM in jailed mode")
		m.logger("Starting VM %s in jailed mode", vmID)
	} else {
		// Create socket path in regular socket directory
		socketPath = filepath.Join(m.socketDir, fmt.Sprintf("%s.sock", vmID))
		actualSocketPath = socketPath
		// Remove old socket if exists
		os.Remove(socketPath)
		m.db.AddVMLog(vmID, "info", "Starting VM in standard mode (no jailer)")
	}

	// Get VM networks from the new vm_networks table
	vmNetworks, err := m.db.ListVMNetworks(vmID)
	if err != nil {
		m.db.AddVMLog(vmID, "warning", fmt.Sprintf("Failed to list VM networks: %v", err))
		vmNetworks = nil
	}

	// Fallback to legacy single-network fields if no vm_networks entries exist
	if len(vmNetworks) == 0 && vm.NetworkID != "" && vm.TapDevice != "" {
		vmNetworks = []*database.VMNetwork{{
			ID:         "legacy",
			VMID:       vmID,
			NetworkID:  vm.NetworkID,
			IfaceIndex: 0,
			MacAddress: vm.MacAddress,
			IPAddress:  vm.IPAddress,
			TapDevice:  vm.TapDevice,
		}}
	}

	// Create TAP devices for each network interface
	var createdTAPs []string
	if len(vmNetworks) > 0 {
		m.db.AddVMLog(vmID, "info", fmt.Sprintf("Setting up %d network interface(s)", len(vmNetworks)))

		for _, vmNet := range vmNetworks {
			m.db.AddVMLog(vmID, "info", fmt.Sprintf("Setting up network eth%d: TAP=%s, NetworkID=%s", vmNet.IfaceIndex, vmNet.TapDevice, vmNet.NetworkID))

			// Pre-cleanup: ensure no stale TAP device exists
			m.netMgr.DeleteTAP(vmNet.TapDevice)
			time.Sleep(100 * time.Millisecond) // Give kernel time to clean up

			_, err := m.netMgr.CreateTAP(vmNet.TapDevice)
			if err != nil {
				m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to create TAP device %s: %v", vmNet.TapDevice, err))
				// Cleanup already created TAPs
				for _, tap := range createdTAPs {
					m.netMgr.DeleteTAP(tap)
				}
				if useJailer {
					m.cleanupJail(vmID)
				}
				return fmt.Errorf("failed to create TAP device %s: %w", vmNet.TapDevice, err)
			}
			createdTAPs = append(createdTAPs, vmNet.TapDevice)
			m.db.AddVMLog(vmID, "info", fmt.Sprintf("TAP device %s created", vmNet.TapDevice))

			// Bring TAP device up with retry
			tapUp := false
			for i := 0; i < 3; i++ {
				if err := m.netMgr.SetInterfaceUp(vmNet.TapDevice); err != nil {
					if i == 2 {
						m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to bring TAP device %s up after 3 attempts: %v", vmNet.TapDevice, err))
						// Cleanup all created TAPs
						for _, tap := range createdTAPs {
							m.netMgr.DeleteTAP(tap)
						}
						if useJailer {
							m.cleanupJail(vmID)
						}
						return fmt.Errorf("failed to bring TAP device %s up after 3 attempts: %w", vmNet.TapDevice, err)
					}
					m.db.AddVMLog(vmID, "warning", fmt.Sprintf("TAP device %s up attempt %d failed, retrying...", vmNet.TapDevice, i+1))
					time.Sleep(100 * time.Millisecond)
					continue
				}
				tapUp = true
				break
			}
			if tapUp {
				m.db.AddVMLog(vmID, "info", fmt.Sprintf("TAP device %s is up", vmNet.TapDevice))
			}

			// Add TAP to bridge
			net, err := m.db.GetNetwork(vmNet.NetworkID)
			if err == nil && net != nil {
				if err := m.netMgr.AddInterfaceToBridge(net.BridgeName, vmNet.TapDevice); err != nil {
					m.db.AddVMLog(vmID, "warning", fmt.Sprintf("Failed to add TAP %s to bridge %s: %v", vmNet.TapDevice, net.BridgeName, err))
					m.logger("Warning: failed to add TAP %s to bridge %s: %v", vmNet.TapDevice, net.BridgeName, err)
				} else {
					m.db.AddVMLog(vmID, "info", fmt.Sprintf("TAP device %s added to bridge %s", vmNet.TapDevice, net.BridgeName))
				}
			}
		}
	} else {
		m.db.AddVMLog(vmID, "info", "No network configured for this VM")
	}

	// Create context for process management
	ctx, cancel := context.WithCancel(context.Background())

	// Build command based on jailer mode
	m.db.AddVMLog(vmID, "info", "Building Firecracker command")
	var cmd *exec.Cmd
	if useJailer {
		jailerPath := m.jailerConfig.JailerPath
		if jailerPath == "" {
			jailerPath = JailerBinary
		}
		args := m.buildJailerArgs(vm, jailEnv)
		cmd = exec.CommandContext(ctx, jailerPath, args...)
		m.db.AddVMLog(vmID, "info", fmt.Sprintf("Jailer command: %s", jailerPath))
		m.logger("Jailer command: %s %v", jailerPath, args)
	} else {
		cmd = exec.CommandContext(ctx, FirecrackerBinary,
			"--api-sock", socketPath,
		)
		m.db.AddVMLog(vmID, "info", fmt.Sprintf("Firecracker command: %s --api-sock %s", FirecrackerBinary, socketPath))
	}

	// Set process group for proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Create pipes for console I/O
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to create stdin pipe: %v", err))
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		stdinPipe.Close()
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to create stdout pipe: %v", err))
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Combine stderr with stdout for console output
	cmd.Stderr = cmd.Stdout

	// Start the process
	m.db.AddVMLog(vmID, "info", "Starting Firecracker process...")
	if err := cmd.Start(); err != nil {
		cancel()
		stdinPipe.Close()
		stdoutPipe.Close()
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to start Firecracker process: %v", err))
		return fmt.Errorf("failed to start firecracker: %w", err)
	}
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Firecracker process started with PID %d", cmd.Process.Pid))

	// Wait for socket to be available (increased timeout for jailer)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Waiting for Firecracker socket: %s", actualSocketPath))
	socketTimeout := 10 * time.Second
	if useJailer {
		socketTimeout = 15 * time.Second
	}
	if err := m.waitForSocket(actualSocketPath, socketTimeout); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(actualSocketPath)
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Firecracker socket not ready after %v: %v", socketTimeout, err))
		return fmt.Errorf("firecracker socket not ready: %w", err)
	}
	m.db.AddVMLog(vmID, "info", "Firecracker socket is ready")

	// Configure the VM via API
	m.db.AddVMLog(vmID, "info", "Configuring VM via Firecracker API...")
	var configErr error
	if useJailer {
		configErr = m.configureVMJailed(actualSocketPath, vm, jailEnv)
	} else {
		configErr = m.configureVM(actualSocketPath, vm)
	}
	if configErr != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(actualSocketPath)
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to configure VM: %v", configErr))
		return fmt.Errorf("failed to configure VM: %w", configErr)
	}
	m.db.AddVMLog(vmID, "info", "VM configuration applied successfully")

	// Seed entropy before starting to prevent getrandom() blocking in guest
	m.db.AddVMLog(vmID, "info", "Seeding entropy via Firecracker API")
	m.seedEntropy(actualSocketPath)

	// Start the instance
	m.db.AddVMLog(vmID, "info", "Starting VM instance...")
	if err := m.startInstance(actualSocketPath); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(actualSocketPath)
		for _, tap := range createdTAPs {
			m.netMgr.DeleteTAP(tap)
		}
		if useJailer {
			m.cleanupJail(vmID)
		}
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Failed to start VM instance: %v", err))
		return fmt.Errorf("failed to start instance: %w", err)
	}
	m.db.AddVMLog(vmID, "info", "VM instance started successfully")

	// Track running VM
	rv := &runningVM{
		cmd:        cmd,
		socketPath: actualSocketPath,
		tapFD:      -1,
		cancel:     cancel,
		consoleIn:  stdinPipe,
		consoleOut: stdoutPipe,
		jailed:     useJailer,
	}
	if useJailer {
		rv.jailPath = jailEnv.jailBase
	}
	m.runningVMs[vmID] = rv

	// Update database
	vm.Status = "running"
	vm.PID = cmd.Process.Pid
	vm.SocketPath = actualSocketPath
	vm.ErrorMessage = ""
	if err := m.db.UpdateVM(vm); err != nil {
		m.logger("Failed to update VM status: %v", err)
	}

	// Log event
	modeStr := "standard"
	if useJailer {
		modeStr = "jailed"
	}
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM startup complete - PID %d (%s mode)", cmd.Process.Pid, modeStr))

	// Start goroutine to monitor process
	go m.monitorProcess(vmID, cmd, cancel)

	return nil
}

// StopVM stops a virtual machine
func (m *Manager) StopVM(vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rv, ok := m.runningVMs[vmID]
	if !ok {
		// Try to get from database and check PID
		vm, err := m.db.GetVM(vmID)
		if err != nil {
			return fmt.Errorf("failed to get VM: %w", err)
		}
		if vm == nil {
			return fmt.Errorf("VM %s not found", vmID)
		}
		if vm.Status == "stopped" {
			return nil
		}
		// Try to kill by PID if we have one
		if vm.PID > 0 {
			syscall.Kill(vm.PID, syscall.SIGTERM)
			time.Sleep(100 * time.Millisecond)
			syscall.Kill(vm.PID, syscall.SIGKILL)
		}
		vm.Status = "stopped"
		vm.PID = 0
		m.db.UpdateVM(vm)
		return nil
	}

	// Send graceful shutdown signal via API
	m.sendCtrlAltDel(rv.socketPath)

	// Wait briefly for graceful shutdown
	time.Sleep(2 * time.Second)

	// Cancel context and terminate process
	rv.cancel()

	// Give process time to exit gracefully
	done := make(chan struct{})
	go func() {
		rv.cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Process exited
	case <-time.After(5 * time.Second):
		// Force kill
		if rv.cmd.Process != nil {
			syscall.Kill(-rv.cmd.Process.Pid, syscall.SIGKILL)
		}
	}

	// Cleanup
	m.cleanupVM(vmID, rv)

	return nil
}

// ForceStopVM forcefully terminates a VM
func (m *Manager) ForceStopVM(vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rv, ok := m.runningVMs[vmID]
	if !ok {
		vm, _ := m.db.GetVM(vmID)
		if vm != nil && vm.PID > 0 {
			syscall.Kill(vm.PID, syscall.SIGKILL)
			vm.Status = "stopped"
			vm.PID = 0
			m.db.UpdateVM(vm)
		}
		return nil
	}

	rv.cancel()
	if rv.cmd.Process != nil {
		syscall.Kill(-rv.cmd.Process.Pid, syscall.SIGKILL)
	}

	m.cleanupVM(vmID, rv)
	return nil
}

func (m *Manager) cleanupVM(vmID string, rv *runningVM) {
	// Get VM info
	vm, _ := m.db.GetVM(vmID)

	// Delete TAP device
	if vm != nil && vm.TapDevice != "" {
		if vm.NetworkID != "" {
			net, _ := m.db.GetNetwork(vm.NetworkID)
			if net != nil {
				m.netMgr.RemoveInterfaceFromBridge(net.BridgeName, vm.TapDevice)
			}
		}
		m.netMgr.DeleteTAP(vm.TapDevice)
	}

	// Remove socket
	os.Remove(rv.socketPath)

	// Cleanup jail if VM was jailed
	if rv.jailed && rv.jailPath != "" {
		if err := os.RemoveAll(rv.jailPath); err != nil {
			m.logger("Warning: failed to cleanup jail for VM %s: %v", vmID, err)
		} else {
			m.logger("Cleaned up jail for VM %s", vmID)
		}
	}

	// Remove from tracking
	delete(m.runningVMs, vmID)

	// Update database
	if vm != nil {
		vm.Status = "stopped"
		vm.PID = 0
		m.db.UpdateVM(vm)
		if rv.jailed {
			m.db.AddVMLog(vmID, "info", "VM stopped (jailed mode)")
		} else {
			m.db.AddVMLog(vmID, "info", "VM stopped")
		}
	}
}

func (m *Manager) monitorProcess(vmID string, cmd *exec.Cmd, cancel context.CancelFunc) {
	err := cmd.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	rv, ok := m.runningVMs[vmID]
	if !ok {
		return
	}

	// Process exited, cleanup
	vm, _ := m.db.GetVM(vmID)

	// Clean up TAP device
	if vm != nil && vm.TapDevice != "" {
		if vm.NetworkID != "" {
			net, _ := m.db.GetNetwork(vm.NetworkID)
			if net != nil {
				m.netMgr.RemoveInterfaceFromBridge(net.BridgeName, vm.TapDevice)
			}
		}
		m.netMgr.DeleteTAP(vm.TapDevice)
	}

	os.Remove(rv.socketPath)

	// Cleanup jail if VM was jailed
	if rv.jailed && rv.jailPath != "" {
		if err := os.RemoveAll(rv.jailPath); err != nil {
			m.logger("Warning: failed to cleanup jail for VM %s: %v", vmID, err)
		}
	}

	delete(m.runningVMs, vmID)

	// Update status
	modeStr := ""
	if rv.jailed {
		modeStr = " (jailed mode)"
	}
	if vm != nil {
		if err != nil {
			vm.Status = "error"
			vm.ErrorMessage = err.Error()
			m.db.AddVMLog(vmID, "error", fmt.Sprintf("VM exited with error%s: %v", modeStr, err))
		} else {
			vm.Status = "stopped"
			m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM process exited%s", modeStr))
		}
		vm.PID = 0
		m.db.UpdateVM(vm)
	}
}

func (m *Manager) waitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket")
}

func (m *Manager) configureVM(socketPath string, vm *database.VM) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Configure boot source with hypervisor detection args
	m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Setting boot source: kernel=%s", filepath.Base(vm.KernelPath)))
	bootSource := BootSource{
		KernelImagePath: vm.KernelPath,
		BootArgs:        buildKernelArgs(vm.KernelArgs),
	}

	if err := m.apiPut(client, "/boot-source", bootSource); err != nil {
		m.db.AddVMLog(vm.ID, "error", fmt.Sprintf("Failed to set boot source: %v", err))
		return fmt.Errorf("failed to set boot source: %w", err)
	}
	m.db.AddVMLog(vm.ID, "info", "Boot source configured")

	// Configure root drive
	m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Setting root drive: %s", filepath.Base(vm.RootFSPath)))
	rootDrive := Drive{
		DriveID:      "rootfs",
		PathOnHost:   vm.RootFSPath,
		IsRootDevice: true,
		IsReadOnly:   false,
	}
	if err := m.apiPut(client, "/drives/rootfs", rootDrive); err != nil {
		m.db.AddVMLog(vm.ID, "error", fmt.Sprintf("Failed to set root drive: %v", err))
		return fmt.Errorf("failed to set root drive: %w", err)
	}
	m.db.AddVMLog(vm.ID, "info", "Root drive configured")

	// Configure additional attached disks
	additionalDisks, err := m.db.ListVMDisks(vm.ID)
	if err != nil {
		m.db.AddVMLog(vm.ID, "warning", fmt.Sprintf("Failed to list VM disks: %v", err))
		m.logger("Warning: failed to list VM disks: %v", err)
	} else if len(additionalDisks) > 0 {
		m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Attaching %d additional disk(s)", len(additionalDisks)))
		for _, disk := range additionalDisks {
			// Verify disk file exists
			if _, err := os.Stat(disk.Path); err != nil {
				m.db.AddVMLog(vm.ID, "warning", fmt.Sprintf("Disk file not found, skipping: %s", disk.Path))
				m.logger("Warning: disk file not found, skipping: %s", disk.Path)
				continue
			}
			additionalDrive := Drive{
				DriveID:      disk.DriveID,
				PathOnHost:   disk.Path,
				IsRootDevice: false,
				IsReadOnly:   disk.IsReadOnly,
			}
			if err := m.apiPut(client, "/drives/"+disk.DriveID, additionalDrive); err != nil {
				m.db.AddVMLog(vm.ID, "warning", fmt.Sprintf("Failed to attach disk %s: %v", disk.Name, err))
				m.logger("Warning: failed to attach disk %s: %v", disk.Name, err)
			} else {
				m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Attached disk %s at %s", disk.Name, disk.MountPoint))
				m.logger("Attached disk %s (%s) at %s", disk.Name, disk.DriveID, disk.MountPoint)
			}
		}
	}

	// Configure machine
	m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Setting machine config: %d vCPUs, %d MB RAM", vm.VCPU, vm.MemoryMB))
	machineConfig := MachineConfig{
		VCPUCount:  vm.VCPU,
		MemSizeMib: vm.MemoryMB,
	}
	if err := m.apiPut(client, "/machine-config", machineConfig); err != nil {
		m.db.AddVMLog(vm.ID, "error", fmt.Sprintf("Failed to set machine config: %v", err))
		return fmt.Errorf("failed to set machine config: %w", err)
	}
	m.db.AddVMLog(vm.ID, "info", "Machine config applied")

	// Configure network interfaces from vm_networks table
	vmNetworks, err := m.db.ListVMNetworks(vm.ID)
	if err != nil {
		m.db.AddVMLog(vm.ID, "warning", fmt.Sprintf("Failed to list VM networks: %v", err))
		vmNetworks = nil
	}

	// Fallback to legacy single-network fields if no vm_networks entries exist
	if len(vmNetworks) == 0 && vm.NetworkID != "" && vm.TapDevice != "" {
		vmNetworks = []*database.VMNetwork{{
			ID:         "legacy",
			VMID:       vm.ID,
			NetworkID:  vm.NetworkID,
			IfaceIndex: 0,
			MacAddress: vm.MacAddress,
			IPAddress:  vm.IPAddress,
			TapDevice:  vm.TapDevice,
		}}
	}

	// Configure each network interface
	for _, vmNet := range vmNetworks {
		ifaceName := fmt.Sprintf("eth%d", vmNet.IfaceIndex)
		m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Setting network interface %s: TAP=%s, MAC=%s", ifaceName, vmNet.TapDevice, vmNet.MacAddress))
		netIface := NetworkInterface{
			IfaceID:     ifaceName,
			GuestMAC:    vmNet.MacAddress,
			HostDevName: vmNet.TapDevice,
		}
		if err := m.apiPut(client, "/network-interfaces/"+ifaceName, netIface); err != nil {
			m.db.AddVMLog(vm.ID, "error", fmt.Sprintf("Failed to set network interface %s: %v", ifaceName, err))
			return fmt.Errorf("failed to set network interface %s: %w", ifaceName, err)
		}
		m.db.AddVMLog(vm.ID, "info", fmt.Sprintf("Network interface %s configured", ifaceName))
	}

	return nil
}

// configureVMJailed configures a VM using jailed paths
func (m *Manager) configureVMJailed(socketPath string, vm *database.VM, jail *jailInfo) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Configure boot source with jailed kernel path
	bootSource := BootSource{
		KernelImagePath: jail.kernelPath, // Path inside jail
		BootArgs:        buildKernelArgs(vm.KernelArgs),
	}

	if err := m.apiPut(client, "/boot-source", bootSource); err != nil {
		return fmt.Errorf("failed to set boot source: %w", err)
	}

	// Configure root drive with jailed rootfs path
	rootDrive := Drive{
		DriveID:      "rootfs",
		PathOnHost:   jail.rootfsPath, // Path inside jail
		IsRootDevice: true,
		IsReadOnly:   false,
	}
	if err := m.apiPut(client, "/drives/rootfs", rootDrive); err != nil {
		return fmt.Errorf("failed to set root drive: %w", err)
	}

	// Configure additional attached disks with jailed paths
	for driveID, jailedPath := range jail.diskPaths {
		additionalDrive := Drive{
			DriveID:      driveID,
			PathOnHost:   jailedPath, // Path inside jail
			IsRootDevice: false,
			IsReadOnly:   false,
		}
		if err := m.apiPut(client, "/drives/"+driveID, additionalDrive); err != nil {
			m.logger("Warning: failed to attach disk %s: %v", driveID, err)
		}
	}

	// Configure machine
	machineConfig := MachineConfig{
		VCPUCount:  vm.VCPU,
		MemSizeMib: vm.MemoryMB,
	}
	if err := m.apiPut(client, "/machine-config", machineConfig); err != nil {
		return fmt.Errorf("failed to set machine config: %w", err)
	}

	// Configure network interfaces from vm_networks table
	vmNetworks, err := m.db.ListVMNetworks(vm.ID)
	if err != nil {
		vmNetworks = nil
	}

	// Fallback to legacy single-network fields if no vm_networks entries exist
	if len(vmNetworks) == 0 && vm.NetworkID != "" && vm.TapDevice != "" {
		vmNetworks = []*database.VMNetwork{{
			ID:         "legacy",
			VMID:       vm.ID,
			NetworkID:  vm.NetworkID,
			IfaceIndex: 0,
			MacAddress: vm.MacAddress,
			IPAddress:  vm.IPAddress,
			TapDevice:  vm.TapDevice,
		}}
	}

	// Configure each network interface
	for _, vmNet := range vmNetworks {
		ifaceName := fmt.Sprintf("eth%d", vmNet.IfaceIndex)
		netIface := NetworkInterface{
			IfaceID:     ifaceName,
			GuestMAC:    vmNet.MacAddress,
			HostDevName: vmNet.TapDevice,
		}
		if err := m.apiPut(client, "/network-interfaces/"+ifaceName, netIface); err != nil {
			return fmt.Errorf("failed to set network interface %s: %w", ifaceName, err)
		}
	}

	return nil
}

func (m *Manager) startInstance(socketPath string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	action := InstanceActionInfo{
		ActionType: "InstanceStart",
	}
	return m.apiPut(client, "/actions", action)
}

// seedEntropy injects random entropy into the VM before boot.
// First tries Firecracker's entropy API, then falls back to seeding the rootfs directly.
func (m *Manager) seedEntropy(socketPath string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Generate 512 bytes of random entropy from host
	entropy := make([]byte, 512)
	if _, err := cryptoRand.Read(entropy); err != nil {
		return fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Firecracker expects base64-encoded entropy
	entropyReq := struct {
		Seed string `json:"seed"`
	}{
		Seed: base64.StdEncoding.EncodeToString(entropy),
	}

	if err := m.apiPut(client, "/entropy", entropyReq); err != nil {
		// Log but don't fail - entropy seeding is optional in older Firecracker versions
		m.logger("Warning: failed to seed entropy via API (may not be supported): %v", err)
	}

	return nil
}

// seedEntropyToRootFS seeds entropy directly to the rootfs by mounting it temporarily.
// It creates a wrapper init script that seeds /dev/urandom BEFORE the real init starts.
func (m *Manager) seedEntropyToRootFS(rootfsPath string) error {
	// Create temporary mount point
	mountPoint, err := os.MkdirTemp("", "fcm-entropy-")
	if err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	// Mount the rootfs
	cmd := exec.Command("mount", "-o", "loop", rootfsPath, mountPoint)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %v: %s", err, string(output))
	}
	defer func() {
		exec.Command("umount", mountPoint).Run()
	}()

	// Generate entropy (use more bytes for better seeding)
	entropy := make([]byte, 4096)
	if _, err := cryptoRand.Read(entropy); err != nil {
		return fmt.Errorf("failed to generate entropy: %w", err)
	}

	// Write entropy to multiple locations
	// 1. systemd random-seed
	randomSeedDir := filepath.Join(mountPoint, "var", "lib", "systemd")
	os.MkdirAll(randomSeedDir, 0755)
	os.WriteFile(filepath.Join(randomSeedDir, "random-seed"), entropy[:512], 0600)

	// 2. Write to a file that our init wrapper will read
	os.WriteFile(filepath.Join(mountPoint, "etc", ".fcm-entropy"), entropy, 0600)

	// 3. Create a wrapper init script that seeds entropy BEFORE real init starts
	// This runs as PID 1 first, seeds entropy, then execs the real init
	wrapperScript := `#!/bin/sh
# FCM entropy seeder - runs before real init
# Seed entropy immediately
if [ -f /etc/.fcm-entropy ]; then
    cat /etc/.fcm-entropy > /dev/urandom 2>/dev/null
    cat /etc/.fcm-entropy > /dev/random 2>/dev/null
    rm -f /etc/.fcm-entropy
fi
# Also seed from random-seed if available
if [ -f /var/lib/systemd/random-seed ]; then
    cat /var/lib/systemd/random-seed > /dev/urandom 2>/dev/null
fi
# Execute the real init
if [ -x /sbin/init.real ]; then
    exec /sbin/init.real "$@"
elif [ -x /lib/systemd/systemd ]; then
    exec /lib/systemd/systemd "$@"
elif [ -x /usr/lib/systemd/systemd ]; then
    exec /usr/lib/systemd/systemd "$@"
else
    exec /sbin/init.real "$@"
fi
`
	// Check if init wrapper is already installed
	initPath := filepath.Join(mountPoint, "sbin", "init")
	initRealPath := filepath.Join(mountPoint, "sbin", "init.real")

	// If init.real doesn't exist, we need to set up the wrapper
	if _, err := os.Stat(initRealPath); os.IsNotExist(err) {
		// Check what init currently is
		initInfo, err := os.Lstat(initPath)
		if err != nil {
			m.logger("Warning: cannot stat /sbin/init: %v", err)
			return nil
		}

		if initInfo.Mode()&os.ModeSymlink != 0 {
			// init is a symlink - read the target and update wrapper
			target, err := os.Readlink(initPath)
			if err != nil {
				m.logger("Warning: cannot read init symlink: %v", err)
				return nil
			}
			// Remove the symlink
			os.Remove(initPath)
			// Create init.real pointing to the same target
			os.Symlink(target, initRealPath)
		} else {
			// init is a real file - rename it
			if err := os.Rename(initPath, initRealPath); err != nil {
				m.logger("Warning: cannot rename init: %v", err)
				return nil
			}
		}

		// Write our wrapper as /sbin/init
		if err := os.WriteFile(initPath, []byte(wrapperScript), 0755); err != nil {
			m.logger("Warning: cannot write init wrapper: %v", err)
			// Try to restore
			os.Rename(initRealPath, initPath)
			return nil
		}
	} else {
		// Wrapper already installed, just refresh the entropy file
		m.logger("Init wrapper already installed, refreshing entropy")
	}

	// Fix BusyBox symlink issue: if init.real is a symlink to busybox,
	// BusyBox uses argv[0] to determine the applet, so "init.real" won't work.
	// We need to replace the symlink with a wrapper script that calls "busybox init"
	if fixed, err := m.fixBusyboxInitSymlink(mountPoint); err != nil {
		m.logger("Warning: failed to fix busybox init symlink: %v", err)
	} else if fixed {
		m.logger("Applied BusyBox init fix for rootfs")
	}

	// Fix missing OpenRC issue: if inittab references openrc but it's not installed,
	// replace inittab with a BusyBox-compatible version
	if fixed, err := m.fixMissingOpenRC(mountPoint); err != nil {
		m.logger("Warning: failed to fix missing OpenRC: %v", err)
	} else if fixed {
		m.logger("Applied BusyBox inittab fix (OpenRC not installed)")
	}

	// Fix securetty: ensure ttyS0 is allowed for root login (Firecracker serial console)
	if fixed, err := m.fixSecuretty(mountPoint); err != nil {
		m.logger("Warning: failed to fix securetty: %v", err)
	} else if fixed {
		m.logger("Added ttyS0 to securetty for serial console root login")
	}

	return nil
}

// fixBusyboxInitSymlink fixes the issue where init.real is a symlink to busybox.
// BusyBox uses argv[0] to determine which applet to run, so when called as "init.real"
// it doesn't recognize the applet name. This function replaces the symlink with a
// wrapper script that explicitly calls "busybox init".
// Returns (fixed bool, err error) where fixed indicates if a fix was applied.
func (m *Manager) fixBusyboxInitSymlink(mountPoint string) (bool, error) {
	initRealPath := filepath.Join(mountPoint, "sbin", "init.real")

	// Check if init.real exists
	info, err := os.Lstat(initRealPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // No init.real, nothing to fix
		}
		return false, err
	}

	// Only fix if it's a symlink
	if info.Mode()&os.ModeSymlink == 0 {
		return false, nil // Not a symlink, nothing to fix
	}

	// Read the symlink target
	target, err := os.Readlink(initRealPath)
	if err != nil {
		return false, err
	}

	// Check if it points to busybox (either /bin/busybox or ../bin/busybox etc)
	if !strings.Contains(target, "busybox") {
		return false, nil // Not pointing to busybox, nothing to fix
	}

	m.logger("Fixing BusyBox init symlink: %s -> %s", initRealPath, target)

	// Determine the busybox path to use in the wrapper script
	busyboxPath := target
	if !filepath.IsAbs(target) {
		// Convert relative path to absolute for the wrapper script
		busyboxPath = filepath.Join("/sbin", target)
		// Simplify the path
		busyboxPath = filepath.Clean(busyboxPath)
	}

	// Create a wrapper script that explicitly calls busybox init
	wrapperScript := fmt.Sprintf(`#!/bin/sh
exec %s init "$@"
`, busyboxPath)

	// Remove the symlink
	if err := os.Remove(initRealPath); err != nil {
		return false, fmt.Errorf("failed to remove symlink: %w", err)
	}

	// Write the wrapper script
	if err := os.WriteFile(initRealPath, []byte(wrapperScript), 0755); err != nil {
		// Try to restore the symlink on failure
		os.Symlink(target, initRealPath)
		return false, fmt.Errorf("failed to write wrapper script: %w", err)
	}

	m.logger("Fixed BusyBox init symlink with wrapper script")
	return true, nil
}

// fixMissingOpenRC fixes the issue where inittab references OpenRC but it's not installed.
// This is common in minimal Alpine images. We replace the inittab with a BusyBox-compatible
// version that doesn't require OpenRC.
// Returns (fixed bool, err error) where fixed indicates if a fix was applied.
func (m *Manager) fixMissingOpenRC(mountPoint string) (bool, error) {
	inittabPath := filepath.Join(mountPoint, "etc", "inittab")
	openrcPath := filepath.Join(mountPoint, "sbin", "openrc")

	// Check if inittab exists
	inittabData, err := os.ReadFile(inittabPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // No inittab, nothing to fix
		}
		return false, err
	}

	// Check if inittab references openrc
	if !strings.Contains(string(inittabData), "/sbin/openrc") {
		return false, nil // Doesn't reference openrc, nothing to fix
	}

	// Check if openrc exists
	if _, err := os.Stat(openrcPath); err == nil {
		return false, nil // OpenRC is installed, nothing to fix
	}

	m.logger("Detected inittab referencing OpenRC but OpenRC is not installed, applying fix")

	// Backup original inittab
	backupPath := inittabPath + ".openrc-backup"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		os.WriteFile(backupPath, inittabData, 0644)
	}

	// Create BusyBox-compatible inittab
	busyboxInittab := `# /etc/inittab - BusyBox init configuration (auto-generated by FCM)
# OpenRC was not found, using BusyBox init instead

# System initialization
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sysfs /sys
::sysinit:/bin/mount -o remount,rw /
::sysinit:/bin/mkdir -p /dev/pts /dev/shm /run
::sysinit:/bin/mount -t devpts devpts /dev/pts
::sysinit:/bin/mount -t tmpfs tmpfs /dev/shm
::sysinit:/bin/mount -t tmpfs tmpfs /run
::sysinit:/bin/hostname -F /etc/hostname 2>/dev/null
::sysinit:/sbin/ifconfig lo 127.0.0.1 up

# Mount all filesystems from fstab
::sysinit:/bin/mount -a 2>/dev/null

# Start system logging if available
::sysinit:/sbin/syslogd -C 2>/dev/null
::sysinit:/sbin/klogd 2>/dev/null

# Network is configured via kernel command line
::sysinit:/sbin/ifconfig eth0 up 2>/dev/null

# Start services in /etc/init.d/
::wait:/bin/sh -c 'for s in /etc/init.d/S* /etc/init.d/*; do [ -x "$s" ] && "$s" start 2>/dev/null; done'

# Getty on serial console (Firecracker uses ttyS0)
ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100

# Virtual terminals (optional, may not work in Firecracker)
#tty1::respawn:/sbin/getty 38400 tty1

# Handle Ctrl+Alt+Del
::ctrlaltdel:/sbin/reboot

# Shutdown procedures
::shutdown:/bin/sh -c 'for s in /etc/init.d/*; do [ -x "$s" ] && "$s" stop 2>/dev/null; done'
::shutdown:/bin/umount -a -r 2>/dev/null
::shutdown:/sbin/swapoff -a 2>/dev/null
`

	// Write the new inittab
	if err := os.WriteFile(inittabPath, []byte(busyboxInittab), 0644); err != nil {
		return false, fmt.Errorf("failed to write inittab: %w", err)
	}

	m.logger("Replaced inittab with BusyBox-compatible version")
	return true, nil
}

// fixSecuretty ensures ttyS0 is in /etc/securetty so root can login via serial console.
// Firecracker uses ttyS0 for the serial console, and many Linux distributions restrict
// root login to terminals listed in securetty.
// Returns (fixed bool, err error) where fixed indicates if a fix was applied.
func (m *Manager) fixSecuretty(mountPoint string) (bool, error) {
	securettyPath := filepath.Join(mountPoint, "etc", "securetty")

	// Check if securetty exists
	data, err := os.ReadFile(securettyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // No securetty, root can login from anywhere
		}
		return false, err
	}

	// Check if ttyS0 is already in the file
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "ttyS0" {
			return false, nil // Already has ttyS0
		}
	}

	// Add ttyS0 to securetty
	m.logger("Adding ttyS0 to /etc/securetty for serial console root login")

	// Append ttyS0 to the file
	newData := string(data)
	if !strings.HasSuffix(newData, "\n") {
		newData += "\n"
	}
	newData += "ttyS0\n"

	if err := os.WriteFile(securettyPath, []byte(newData), 0644); err != nil {
		return false, fmt.Errorf("failed to write securetty: %w", err)
	}

	return true, nil
}

func (m *Manager) sendCtrlAltDel(socketPath string) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	action := InstanceActionInfo{
		ActionType: "SendCtrlAltDel",
	}
	return m.apiPut(client, "/actions", action)
}

func (m *Manager) apiPut(client *http.Client, path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, "http://localhost"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetVMStatus returns the current status of a VM
func (m *Manager) GetVMStatus(vmID string) (string, error) {
	m.mu.RLock()
	_, running := m.runningVMs[vmID]
	m.mu.RUnlock()

	if running {
		return "running", nil
	}

	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return "", err
	}
	if vm == nil {
		return "", fmt.Errorf("VM not found")
	}

	// Verify process is actually running if status says running
	if vm.Status == "running" && vm.PID > 0 {
		if err := syscall.Kill(vm.PID, 0); err != nil {
			vm.Status = "stopped"
			vm.PID = 0
			m.db.UpdateVM(vm)
		}
	}

	return vm.Status, nil
}

// IsRunning checks if a VM is currently running
func (m *Manager) IsRunning(vmID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.runningVMs[vmID]
	return ok
}

// GetRunningVMs returns list of running VM IDs
func (m *Manager) GetRunningVMs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ids []string
	for id := range m.runningVMs {
		ids = append(ids, id)
	}
	return ids
}

// SyncVMStatus synchronizes database status with actual process state
func (m *Manager) SyncVMStatus() error {
	vms, err := m.db.ListVMs()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, vm := range vms {
		if vm.Status == "running" {
			// Check if process is still alive
			if vm.PID > 0 {
				if err := syscall.Kill(vm.PID, 0); err != nil {
					// Process is dead
					vm.Status = "stopped"
					vm.PID = 0
					m.db.UpdateVM(vm)
					m.db.AddVMLog(vm.ID, "warning", "VM process found dead, status corrected")
				} else {
					// Check if we're tracking it
					if _, ok := m.runningVMs[vm.ID]; !ok {
						// Not tracking but process exists - mark as error
						vm.Status = "error"
						vm.ErrorMessage = "Orphaned process"
						m.db.UpdateVM(vm)
					}
				}
			} else {
				vm.Status = "stopped"
				m.db.UpdateVM(vm)
			}
		}
	}

	return nil
}

// StopAllVMs stops all running VMs (for shutdown)
func (m *Manager) StopAllVMs() {
	m.mu.Lock()
	ids := make([]string, 0, len(m.runningVMs))
	for id := range m.runningVMs {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.logger("Stopping VM %s for shutdown", id)
		m.StopVM(id)
	}
}

// GetVMInfo returns detailed information about a running VM
func (m *Manager) GetVMInfo(vmID string) (map[string]interface{}, error) {
	m.mu.RLock()
	rv, running := m.runningVMs[vmID]
	m.mu.RUnlock()

	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, fmt.Errorf("VM not found")
	}

	info := map[string]interface{}{
		"id":            vm.ID,
		"name":          vm.Name,
		"description":   vm.Description,
		"vcpu":          vm.VCPU,
		"memory_mb":     vm.MemoryMB,
		"status":        vm.Status,
		"pid":           vm.PID,
		"kernel_path":   vm.KernelPath,
		"rootfs_path":   vm.RootFSPath,
		"kernel_args":   vm.KernelArgs,
		"network_id":    vm.NetworkID,
		"mac_address":   vm.MacAddress,
		"ip_address":    vm.IPAddress,
		"tap_device":    vm.TapDevice,
		"dns_servers":   vm.DNSServers,
		"created_at":    vm.CreatedAt,
		"updated_at":    vm.UpdatedAt,
		"error_message": vm.ErrorMessage,
	}

	if running {
		info["socket_path"] = rv.socketPath
		info["running"] = true
	} else {
		info["running"] = false
	}

	// Add disk information
	diskInfo := m.getDiskInfo(vm.RootFSPath)
	for k, v := range diskInfo {
		info[k] = v
	}

	// Add attached disks info
	attachedDisks, err := m.db.ListVMDisks(vmID)
	if err == nil && len(attachedDisks) > 0 {
		disksInfo := make([]map[string]interface{}, 0, len(attachedDisks))
		for _, disk := range attachedDisks {
			diskEntry := map[string]interface{}{
				"id":          disk.ID,
				"name":        disk.Name,
				"mount_point": disk.MountPoint,
				"drive_id":    disk.DriveID,
				"size_mb":     disk.SizeMB,
				"format":      disk.Format,
				"is_readonly": disk.IsReadOnly,
			}
			// Get actual file size
			if fileInfo, err := os.Stat(disk.Path); err == nil {
				diskEntry["file_size"] = fileInfo.Size()
			}
			disksInfo = append(disksInfo, diskEntry)
		}
		info["attached_disks"] = disksInfo
	}

	return info, nil
}

// getDiskInfo retrieves disk information for a rootfs path
func (m *Manager) getDiskInfo(rootfsPath string) map[string]interface{} {
	diskInfo := make(map[string]interface{})

	// Get file size on disk
	if fileInfo, err := os.Stat(rootfsPath); err == nil {
		diskInfo["disk_size"] = fileInfo.Size()
		diskInfo["disk_size_mb"] = fileInfo.Size() / (1024 * 1024)
		diskInfo["disk_size_human"] = formatBytes(fileInfo.Size())
	}

	// Get rootfs metadata from database
	if rootfs, err := m.db.GetRootFSByPath(rootfsPath); err == nil && rootfs != nil {
		if rootfs.OSRelease != "" {
			diskInfo["os_release"] = rootfs.OSRelease
		}
		if rootfs.InitSystem != "" {
			diskInfo["init_system"] = rootfs.InitSystem
		}
		if rootfs.DiskType != "" {
			diskInfo["disk_type"] = rootfs.DiskType
		}
	}

	return diskInfo
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetVMMetrics returns CPU and memory metrics for a VM
func (m *Manager) GetVMMetrics(vmID string) (map[string]interface{}, error) {
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, fmt.Errorf("VM not found")
	}

	metrics := map[string]interface{}{
		"vm_id":       vmID,
		"vm_name":     vm.Name,
		"status":      vm.Status,
		"vcpu":        vm.VCPU,
		"memory_mb":   vm.MemoryMB,
		"cpu_percent": 0.0,
		"mem_percent": 0.0,
		"mem_used_mb": 0,
		"uptime":      "",
	}

	// Only get process metrics if VM is running
	if vm.Status != "running" || vm.PID == 0 {
		return metrics, nil
	}

	// Read CPU stats from /proc/{pid}/stat
	statPath := fmt.Sprintf("/proc/%d/stat", vm.PID)
	statData, err := os.ReadFile(statPath)
	if err == nil {
		fields := strings.Fields(string(statData))
		if len(fields) >= 22 {
			// Get uptime
			uptimePath := "/proc/uptime"
			uptimeData, err := os.ReadFile(uptimePath)
			if err == nil {
				var systemUptime float64
				fmt.Sscanf(string(uptimeData), "%f", &systemUptime)

				// Field 21 is starttime (in clock ticks)
				var starttime uint64
				fmt.Sscanf(fields[21], "%d", &starttime)
				clkTck := float64(100) // Usually 100 Hz
				processStartSec := float64(starttime) / clkTck
				processUptime := systemUptime - processStartSec

				if processUptime > 0 {
					hours := int(processUptime) / 3600
					minutes := (int(processUptime) % 3600) / 60
					seconds := int(processUptime) % 60
					if hours > 0 {
						metrics["uptime"] = fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
					} else if minutes > 0 {
						metrics["uptime"] = fmt.Sprintf("%dm %ds", minutes, seconds)
					} else {
						metrics["uptime"] = fmt.Sprintf("%ds", seconds)
					}
				}

				// Calculate CPU percentage (utime + stime) / uptime
				// Normalize by number of vCPUs to get 0-100% range
				var utime, stime uint64
				fmt.Sscanf(fields[13], "%d", &utime)
				fmt.Sscanf(fields[14], "%d", &stime)
				totalTime := float64(utime+stime) / clkTck
				if processUptime > 0 {
					cpuPercent := (totalTime / processUptime) * 100.0
					// Normalize by vCPU count (e.g., 4 vCPUs can use up to 400% raw)
					if vm.VCPU > 0 {
						cpuPercent = cpuPercent / float64(vm.VCPU)
					}
					metrics["cpu_percent"] = math.Round(cpuPercent*100) / 100
				}
			}
		}
	}

	// Read memory stats from /proc/{pid}/status
	statusPath := fmt.Sprintf("/proc/%d/status", vm.PID)
	statusData, err := os.ReadFile(statusPath)
	if err == nil {
		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					var rssKB int64
					fmt.Sscanf(fields[1], "%d", &rssKB)
					memUsedMB := rssKB / 1024
					metrics["mem_used_mb"] = memUsedMB
					if vm.MemoryMB > 0 {
						memPercent := (float64(memUsedMB) / float64(vm.MemoryMB)) * 100.0
						metrics["mem_percent"] = math.Round(memPercent*100) / 100
					}
				}
				break
			}
		}
	}

	return metrics, nil
}

// Cleanup releases all resources
func (m *Manager) Cleanup() {
	m.StopAllVMs()

	// Clean up sockets directory
	entries, _ := os.ReadDir(m.socketDir)
	for _, entry := range entries {
		os.Remove(filepath.Join(m.socketDir, entry.Name()))
	}
}

// GetConsoleIO returns the console input/output streams for a running VM
func (m *Manager) GetConsoleIO(vmID string) (io.WriteCloser, io.ReadCloser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rv, ok := m.runningVMs[vmID]
	if !ok {
		return nil, nil, fmt.Errorf("VM %s is not running", vmID)
	}

	return rv.consoleIn, rv.consoleOut, nil
}

// WriteToConsole writes data to the VM's console input
func (m *Manager) WriteToConsole(vmID string, data []byte) error {
	m.mu.RLock()
	rv, ok := m.runningVMs[vmID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("VM %s is not running", vmID)
	}

	if rv.consoleIn == nil {
		return fmt.Errorf("console input not available")
	}

	_, err := rv.consoleIn.Write(data)
	return err
}

// SnapshotCreate structure for Firecracker snapshot API
type SnapshotCreate struct {
	SnapshotType string `json:"snapshot_type"` // Full or Diff
	SnapshotPath string `json:"snapshot_path"`
	MemFilePath  string `json:"mem_file_path"`
}

// SnapshotResult contains the paths to the created snapshot files
type SnapshotResult struct {
	SnapshotPath string `json:"snapshot_path"`
	MemFilePath  string `json:"mem_file_path"`
	CreatedAt    string `json:"created_at"`
}

// SnapshotInfo contains detailed information about a snapshot
type SnapshotInfo struct {
	ID           string `json:"id"`            // Timestamp-based ID
	SnapshotPath string `json:"snapshot_path"` // Path to vmstate file
	MemFilePath  string `json:"mem_file_path"` // Path to memory file
	CreatedAt    string `json:"created_at"`    // Human-readable timestamp
	StateSize    int64  `json:"state_size"`    // Size of vmstate file in bytes
	MemSize      int64  `json:"mem_size"`      // Size of memory file in bytes
}

// SnapshotLoad structure for Firecracker snapshot load API
type SnapshotLoad struct {
	SnapshotPath        string `json:"snapshot_path"`
	MemFilePath         string `json:"mem_file_path,omitempty"`
	EnableDiffSnapshots bool   `json:"enable_diff_snapshots,omitempty"`
	ResumeVM            bool   `json:"resume_vm,omitempty"`
}

// VMState structure for Firecracker VM state API
type VMState struct {
	State string `json:"state"` // Paused or Resumed
}

// CreateSnapshot creates a snapshot of a running VM
func (m *Manager) CreateSnapshot(vmID string) (*SnapshotResult, error) {
	m.mu.RLock()
	rv, ok := m.runningVMs[vmID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("VM %s is not running", vmID)
	}

	// Get VM from database
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return nil, fmt.Errorf("VM %s not found", vmID)
	}

	// Get snapshot type (default to Full if not configured)
	snapshotType := vm.SnapshotType
	if snapshotType == "" {
		snapshotType = "Full"
	}

	// Generate snapshot filenames with timestamp
	timestamp := time.Now().Format("20060102-150405")
	rootfsDir := filepath.Dir(vm.RootFSPath)
	snapshotPath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", vmID, timestamp))
	memFilePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", vmID, timestamp))

	// Create HTTP client for Unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", rv.socketPath)
			},
		},
		Timeout: 60 * time.Second, // Longer timeout for snapshots
	}

	// First, pause the VM
	m.logger("Pausing VM %s for snapshot...", vmID)
	if err := m.setVMState(client, "Paused"); err != nil {
		return nil, fmt.Errorf("failed to pause VM: %w", err)
	}

	// Create snapshot request
	snapshotReq := SnapshotCreate{
		SnapshotType: snapshotType,
		SnapshotPath: snapshotPath,
		MemFilePath:  memFilePath,
	}

	data, err := json.Marshal(snapshotReq)
	if err != nil {
		// Resume VM before returning error
		m.setVMState(client, "Resumed")
		return nil, fmt.Errorf("failed to marshal snapshot request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, "http://localhost/snapshot/create", bytes.NewReader(data))
	if err != nil {
		// Resume VM before returning error
		m.setVMState(client, "Resumed")
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Resume VM before returning error
		m.setVMState(client, "Resumed")
		return nil, fmt.Errorf("failed to create snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		// Resume VM before returning error
		m.setVMState(client, "Resumed")
		return nil, fmt.Errorf("snapshot API error %d: %s", resp.StatusCode, string(body))
	}

	// Resume the VM after snapshot
	m.logger("Resuming VM %s after snapshot...", vmID)
	if err := m.setVMState(client, "Resumed"); err != nil {
		m.logger("Warning: failed to resume VM after snapshot: %v", err)
	}

	m.logger("Created snapshot for VM %s: %s", vmID, snapshotPath)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Snapshot created: %s", snapshotPath))

	return &SnapshotResult{
		SnapshotPath: snapshotPath,
		MemFilePath:  memFilePath,
		CreatedAt:    timestamp,
	}, nil
}

// setVMState pauses or resumes the VM
func (m *Manager) setVMState(client *http.Client, state string) error {
	vmState := VMState{State: state}
	data, err := json.Marshal(vmState)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPatch, "http://localhost/vm", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("VM state API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListSnapshots returns all snapshots for a VM
func (m *Manager) ListSnapshots(vmID string) ([]*SnapshotInfo, error) {
	// Get VM from database
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return nil, fmt.Errorf("VM %s not found", vmID)
	}

	// Get the rootfs directory where snapshots are stored
	rootfsDir := filepath.Dir(vm.RootFSPath)

	// Find all vmstate snapshot files for this VM
	pattern := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-*.fc", vmID))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %w", err)
	}

	var snapshots []*SnapshotInfo
	for _, vmstatePath := range matches {
		// Extract timestamp from filename
		// Format: snapshot-{vmID}-vmstate-{timestamp}.fc
		basename := filepath.Base(vmstatePath)
		prefix := fmt.Sprintf("snapshot-%s-vmstate-", vmID)
		suffix := ".fc"
		if !strings.HasPrefix(basename, prefix) || !strings.HasSuffix(basename, suffix) {
			continue
		}
		timestamp := strings.TrimSuffix(strings.TrimPrefix(basename, prefix), suffix)

		// Construct memory file path
		memFilePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", vmID, timestamp))

		// Get file sizes
		var stateSize, memSize int64
		if info, err := os.Stat(vmstatePath); err == nil {
			stateSize = info.Size()
		}
		if info, err := os.Stat(memFilePath); err == nil {
			memSize = info.Size()
		}

		// Parse timestamp for display
		createdAt := timestamp
		if t, err := time.Parse("20060102-150405", timestamp); err == nil {
			createdAt = t.Format("2006-01-02 15:04:05")
		}

		snapshots = append(snapshots, &SnapshotInfo{
			ID:           timestamp,
			SnapshotPath: vmstatePath,
			MemFilePath:  memFilePath,
			CreatedAt:    createdAt,
			StateSize:    stateSize,
			MemSize:      memSize,
		})
	}

	// Sort by timestamp (newest first)
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].ID > snapshots[j].ID
	})

	return snapshots, nil
}

// DeleteSnapshot deletes a specific snapshot for a VM
func (m *Manager) DeleteSnapshot(vmID, snapshotID string) error {
	// Get VM from database
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}

	// Validate snapshot ID format (should be a timestamp)
	if _, err := time.Parse("20060102-150405", snapshotID); err != nil {
		return fmt.Errorf("invalid snapshot ID format")
	}

	// Get the rootfs directory where snapshots are stored
	rootfsDir := filepath.Dir(vm.RootFSPath)

	// Construct file paths
	vmstatePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", vmID, snapshotID))
	memFilePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", vmID, snapshotID))

	// Check if vmstate file exists
	if _, err := os.Stat(vmstatePath); os.IsNotExist(err) {
		return fmt.Errorf("snapshot %s not found", snapshotID)
	}

	// Delete vmstate file
	if err := os.Remove(vmstatePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete vmstate file: %w", err)
	}

	// Delete memory file
	if err := os.Remove(memFilePath); err != nil && !os.IsNotExist(err) {
		m.logger("Warning: failed to delete memory file %s: %v", memFilePath, err)
	}

	m.logger("Deleted snapshot %s for VM %s", snapshotID, vmID)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Snapshot deleted: %s", snapshotID))

	return nil
}

// RestoreSnapshot restores a VM from a specific snapshot
// Note: Firecracker requires starting a new VM instance to restore from snapshot
// This function will stop the current VM if running and start a new one from the snapshot
func (m *Manager) RestoreSnapshot(vmID, snapshotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get VM from database
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}

	// Validate snapshot ID format
	if _, err := time.Parse("20060102-150405", snapshotID); err != nil {
		return fmt.Errorf("invalid snapshot ID format")
	}

	// Get the rootfs directory where snapshots are stored
	rootfsDir := filepath.Dir(vm.RootFSPath)

	// Construct file paths
	vmstatePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", vmID, snapshotID))
	memFilePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", vmID, snapshotID))

	// Check if snapshot files exist
	if _, err := os.Stat(vmstatePath); os.IsNotExist(err) {
		return fmt.Errorf("snapshot vmstate file not found: %s", snapshotID)
	}
	if _, err := os.Stat(memFilePath); os.IsNotExist(err) {
		return fmt.Errorf("snapshot memory file not found: %s", snapshotID)
	}

	// Stop VM if running (unlock temporarily for ForceStopVM)
	if rv, isRunning := m.runningVMs[vmID]; isRunning {
		m.logger("Stopping VM %s before restore...", vmID)
		// Kill process directly without releasing lock
		if rv.cmd != nil && rv.cmd.Process != nil {
			syscall.Kill(-rv.cmd.Process.Pid, syscall.SIGKILL)
			rv.cmd.Wait()
		}
		if rv.cancel != nil {
			rv.cancel()
		}
		// Cleanup TAP device
		if vm.TapDevice != "" {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		// Remove socket
		os.Remove(rv.socketPath)
		delete(m.runningVMs, vmID)
		// Wait a moment for cleanup
		time.Sleep(500 * time.Millisecond)
	}

	// Start VM from snapshot
	m.logger("Restoring VM %s from snapshot %s...", vmID, snapshotID)

	// Create socket path
	socketPath := filepath.Join(m.socketDir, fmt.Sprintf("%s.sock", vmID))
	os.Remove(socketPath) // Remove old socket if exists

	// Create context for process management
	ctx, cancel := context.WithCancel(context.Background())

	// Start firecracker process
	cmd := exec.CommandContext(ctx, FirecrackerBinary, "--api-sock", socketPath)

	// Set process group for proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Create pipes for console I/O
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		stdinPipe.Close()
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Combine stderr with stdout for console output
	cmd.Stderr = cmd.Stdout

	// Start the process
	if err := cmd.Start(); err != nil {
		cancel()
		stdinPipe.Close()
		stdoutPipe.Close()
		return fmt.Errorf("failed to start firecracker: %w", err)
	}

	// Wait for socket to be available
	if err := m.waitForSocket(socketPath, 5*time.Second); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("firecracker socket not ready: %w", err)
	}

	// Create HTTP client for Unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	// Load snapshot
	snapshotLoad := SnapshotLoad{
		SnapshotPath:        vmstatePath,
		MemFilePath:         memFilePath,
		EnableDiffSnapshots: vm.SnapshotType == "Diff",
		ResumeVM:            true,
	}

	data, err := json.Marshal(snapshotLoad)
	if err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		stdinPipe.Close()
		stdoutPipe.Close()
		return fmt.Errorf("failed to marshal snapshot load request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, "http://localhost/snapshot/load", bytes.NewReader(data))
	if err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		stdinPipe.Close()
		stdoutPipe.Close()
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		stdinPipe.Close()
		stdoutPipe.Close()
		return fmt.Errorf("failed to load snapshot: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		stdinPipe.Close()
		stdoutPipe.Close()
		return fmt.Errorf("snapshot load API error %d: %s", resp.StatusCode, string(body))
	}

	// Register running VM
	m.runningVMs[vmID] = &runningVM{
		cmd:        cmd,
		socketPath: socketPath,
		tapFD:      -1,
		cancel:     cancel,
		consoleIn:  stdinPipe,
		consoleOut: stdoutPipe,
	}

	// Update database
	vm.Status = "running"
	vm.PID = cmd.Process.Pid
	vm.SocketPath = socketPath
	vm.ErrorMessage = ""
	if err := m.db.UpdateVM(vm); err != nil {
		m.logger("Failed to update VM status: %v", err)
	}

	// Log event
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM restored from snapshot %s (PID: %d)", snapshotID, cmd.Process.Pid))

	// Start goroutine to monitor process
	go m.monitorProcess(vmID, cmd, cancel)

	m.logger("VM %s restored from snapshot %s (PID: %d)", vmID, snapshotID, cmd.Process.Pid)

	return nil
}

// updateRootFSDNS mounts the rootfs and updates /etc/resolv.conf with the specified DNS servers
func (m *Manager) updateRootFSDNS(rootfsPath, dnsServers string) error {
	if dnsServers == "" {
		return nil
	}

	// Create a temporary mount point
	mountPoint, err := os.MkdirTemp("", "rootfs-mount-*")
	if err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	// Mount the rootfs image
	// First try to mount as ext4
	mountCmd := exec.Command("mount", "-o", "loop", rootfsPath, mountPoint)
	if err := mountCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %w", err)
	}

	// Ensure we unmount on return
	defer func() {
		umountCmd := exec.Command("umount", mountPoint)
		if err := umountCmd.Run(); err != nil {
			m.logger("Warning: failed to unmount rootfs: %v", err)
		}
	}()

	// Build resolv.conf content
	var content strings.Builder
	content.WriteString("# DNS configuration managed by FireCrackManager\n")
	content.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n")

	// Parse comma-separated DNS servers
	servers := strings.Split(dnsServers, ",")
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server != "" {
			// Validate it looks like an IP address
			if net.ParseIP(server) != nil {
				content.WriteString("nameserver " + server + "\n")
			} else {
				m.logger("Warning: invalid DNS server IP: %s", server)
			}
		}
	}

	// Write resolv.conf
	resolvPath := filepath.Join(mountPoint, "etc", "resolv.conf")

	// Ensure /etc directory exists
	etcDir := filepath.Join(mountPoint, "etc")
	if _, err := os.Stat(etcDir); os.IsNotExist(err) {
		if err := os.MkdirAll(etcDir, 0755); err != nil {
			return fmt.Errorf("failed to create /etc directory: %w", err)
		}
	}

	// Write the file
	if err := os.WriteFile(resolvPath, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %w", err)
	}

	m.logger("Updated DNS configuration in rootfs: %s", dnsServers)
	return nil
}

// VMExportManifest contains metadata for the exported VM
type VMExportManifest struct {
	Version      string            `json:"version"`
	ExportedAt   string            `json:"exported_at"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	VCPU         int               `json:"vcpu"`
	MemoryMB     int               `json:"memory_mb"`
	KernelArgs   string            `json:"kernel_args"`
	DNSServers   string            `json:"dns_servers"`
	SnapshotType string            `json:"snapshot_type"`
	RootFSName   string            `json:"rootfs_name"`
	RootFSSize   int64             `json:"rootfs_size"`
	Snapshots    []SnapshotInfo    `json:"snapshots,omitempty"`
	Checksum     map[string]string `json:"checksums"`
}

// SetOperationProgress sets or updates operation progress
func (m *Manager) SetOperationProgress(key string, progress *OperationProgress) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.operations[key] = progress
}

// GetOperationProgress returns current operation progress
func (m *Manager) GetOperationProgress(key string) *OperationProgress {
	m.opMu.RLock()
	defer m.opMu.RUnlock()
	if p, ok := m.operations[key]; ok {
		return &OperationProgress{
			Status:     p.Status,
			Stage:      p.Stage,
			Total:      p.Total,
			Copied:     p.Copied,
			Percent:    p.Percent,
			Error:      p.Error,
			ResultID:   p.ResultID,
			ResultName: p.ResultName,
		}
	}
	return nil
}

// DeleteOperationProgress removes an operation progress entry
func (m *Manager) DeleteOperationProgress(key string) {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	delete(m.operations, key)
}

// copyFileWithProgress copies a file and reports progress to the given operation key
func (m *Manager) copyFileWithProgress(src, dst, opKey string, baseProgress int64) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy in chunks and update progress
	buf := make([]byte, 1024*1024) // 1MB buffer
	var copied int64

	for {
		n, readErr := srcFile.Read(buf)
		if n > 0 {
			_, writeErr := dstFile.Write(buf[:n])
			if writeErr != nil {
				return writeErr
			}
			copied += int64(n)

			// Update progress
			m.opMu.Lock()
			if op, ok := m.operations[opKey]; ok {
				op.Copied = baseProgress + copied
				if op.Total > 0 {
					op.Percent = float64(op.Copied) / float64(op.Total) * 100
				}
			}
			m.opMu.Unlock()
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	// Preserve permissions
	return os.Chmod(dst, srcInfo.Mode())
}

// DuplicateVMAsync starts VM duplication in the background and returns the operation key
func (m *Manager) DuplicateVMAsync(vmID, newName string) (string, error) {
	// Get original VM
	origVM, err := m.db.GetVM(vmID)
	if err != nil {
		return "", fmt.Errorf("failed to get VM: %w", err)
	}
	if origVM == nil {
		return "", fmt.Errorf("VM %s not found", vmID)
	}

	// Check if VM is running
	m.mu.RLock()
	_, isRunning := m.runningVMs[vmID]
	m.mu.RUnlock()
	if isRunning {
		return "", fmt.Errorf("cannot duplicate a running VM, please stop it first")
	}

	// Check if name already exists
	existingVM, _ := m.db.GetVMByName(newName)
	if existingVM != nil {
		return "", fmt.Errorf("VM with name '%s' already exists", newName)
	}

	// Generate operation key
	opKey := fmt.Sprintf("duplicate-vm-%s", generateVMID()[:8])

	// Calculate total size to copy
	var totalSize int64
	if info, err := os.Stat(origVM.RootFSPath); err == nil {
		totalSize = info.Size()
	}

	// Add snapshot sizes
	snapshots, _ := m.ListSnapshots(vmID)
	for _, snap := range snapshots {
		if info, err := os.Stat(snap.SnapshotPath); err == nil {
			totalSize += info.Size()
		}
		if info, err := os.Stat(snap.MemFilePath); err == nil {
			totalSize += info.Size()
		}
	}

	// Initialize progress
	m.SetOperationProgress(opKey, &OperationProgress{
		Status:  "starting",
		Stage:   "Initializing duplication...",
		Total:   totalSize,
		Copied:  0,
		Percent: 0,
	})

	// Run duplication in background
	go func() {
		newID := generateVMID()
		rootfsDir := filepath.Dir(origVM.RootFSPath)
		rootfsExt := filepath.Ext(origVM.RootFSPath)
		newRootFSPath := filepath.Join(rootfsDir, fmt.Sprintf("%s%s", newID, rootfsExt))

		// Update progress for rootfs copy
		m.opMu.Lock()
		if op, ok := m.operations[opKey]; ok {
			op.Status = "copying"
			op.Stage = "Copying root filesystem..."
		}
		m.opMu.Unlock()

		m.logger("Duplicating rootfs from %s to %s...", origVM.RootFSPath, newRootFSPath)
		if err := m.copyFileWithProgress(origVM.RootFSPath, newRootFSPath, opKey, 0); err != nil {
			m.opMu.Lock()
			if op, ok := m.operations[opKey]; ok {
				op.Status = "error"
				op.Error = fmt.Sprintf("Failed to copy rootfs: %v", err)
			}
			m.opMu.Unlock()
			return
		}

		// Get current progress for base
		var currentCopied int64
		m.opMu.RLock()
		if op, ok := m.operations[opKey]; ok {
			currentCopied = op.Copied
		}
		m.opMu.RUnlock()

		// Copy snapshots if any
		for i, snap := range snapshots {
			m.opMu.Lock()
			if op, ok := m.operations[opKey]; ok {
				op.Stage = fmt.Sprintf("Copying snapshot %d of %d...", i+1, len(snapshots))
			}
			m.opMu.Unlock()

			// Copy vmstate file
			newVmstatePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", newID, snap.ID))
			if err := m.copyFileWithProgress(snap.SnapshotPath, newVmstatePath, opKey, currentCopied); err != nil {
				m.logger("Warning: failed to copy snapshot vmstate: %v", err)
			}

			// Update currentCopied
			m.opMu.RLock()
			if op, ok := m.operations[opKey]; ok {
				currentCopied = op.Copied
			}
			m.opMu.RUnlock()

			// Copy memory file
			newMemPath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", newID, snap.ID))
			if err := m.copyFileWithProgress(snap.MemFilePath, newMemPath, opKey, currentCopied); err != nil {
				m.logger("Warning: failed to copy snapshot memfile: %v", err)
			}

			// Update currentCopied
			m.opMu.RLock()
			if op, ok := m.operations[opKey]; ok {
				currentCopied = op.Copied
			}
			m.opMu.RUnlock()
		}

		// Create new VM record
		m.opMu.Lock()
		if op, ok := m.operations[opKey]; ok {
			op.Stage = "Creating VM record..."
		}
		m.opMu.Unlock()

		newVM := &database.VM{
			ID:           newID,
			Name:         newName,
			VCPU:         origVM.VCPU,
			MemoryMB:     origVM.MemoryMB,
			KernelPath:   origVM.KernelPath,
			RootFSPath:   newRootFSPath,
			KernelArgs:   origVM.KernelArgs,
			DNSServers:   origVM.DNSServers,
			SnapshotType: origVM.SnapshotType,
			Status:       "stopped",
		}

		if err := m.db.CreateVM(newVM); err != nil {
			os.Remove(newRootFSPath)
			m.opMu.Lock()
			if op, ok := m.operations[opKey]; ok {
				op.Status = "error"
				op.Error = fmt.Sprintf("Failed to create VM record: %v", err)
			}
			m.opMu.Unlock()
			return
		}

		m.logger("Duplicated VM %s as %s (%s)", vmID, newName, newID)
		m.db.AddVMLog(newID, "info", fmt.Sprintf("VM duplicated from %s", origVM.Name))

		// Mark as completed
		m.opMu.Lock()
		if op, ok := m.operations[opKey]; ok {
			op.Status = "completed"
			op.Stage = "Duplication complete"
			op.Percent = 100
			op.Copied = op.Total
			op.ResultID = newID
			op.ResultName = newName
		}
		m.opMu.Unlock()
	}()

	return opKey, nil
}

// DuplicateVM creates a copy of an existing VM with a new name (synchronous version)
func (m *Manager) DuplicateVM(vmID, newName string) (*database.VM, error) {
	// Get original VM
	origVM, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM: %w", err)
	}
	if origVM == nil {
		return nil, fmt.Errorf("VM %s not found", vmID)
	}

	// Check if VM is running
	m.mu.RLock()
	_, isRunning := m.runningVMs[vmID]
	m.mu.RUnlock()
	if isRunning {
		return nil, fmt.Errorf("cannot duplicate a running VM, please stop it first")
	}

	// Check if name already exists
	existingVM, _ := m.db.GetVMByName(newName)
	if existingVM != nil {
		return nil, fmt.Errorf("VM with name '%s' already exists", newName)
	}

	// Generate new VM ID
	newID := generateVMID()

	// Copy rootfs
	rootfsDir := filepath.Dir(origVM.RootFSPath)
	rootfsExt := filepath.Ext(origVM.RootFSPath)
	newRootFSPath := filepath.Join(rootfsDir, fmt.Sprintf("%s%s", newID, rootfsExt))

	m.logger("Duplicating rootfs from %s to %s...", origVM.RootFSPath, newRootFSPath)
	if err := copyFile(origVM.RootFSPath, newRootFSPath); err != nil {
		return nil, fmt.Errorf("failed to copy rootfs: %w", err)
	}

	// Copy snapshots if any
	snapshots, _ := m.ListSnapshots(vmID)
	for _, snap := range snapshots {
		// Copy vmstate file
		newVmstatePath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", newID, snap.ID))
		if err := copyFile(snap.SnapshotPath, newVmstatePath); err != nil {
			m.logger("Warning: failed to copy snapshot vmstate: %v", err)
		}
		// Copy memory file
		newMemPath := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", newID, snap.ID))
		if err := copyFile(snap.MemFilePath, newMemPath); err != nil {
			m.logger("Warning: failed to copy snapshot memfile: %v", err)
		}
	}

	// Create new VM record
	newVM := &database.VM{
		ID:           newID,
		Name:         newName,
		VCPU:         origVM.VCPU,
		MemoryMB:     origVM.MemoryMB,
		KernelPath:   origVM.KernelPath, // Use same kernel
		RootFSPath:   newRootFSPath,
		KernelArgs:   origVM.KernelArgs,
		DNSServers:   origVM.DNSServers,
		SnapshotType: origVM.SnapshotType,
		Status:       "stopped",
	}

	// Note: Network is not duplicated - user must configure manually
	// This prevents IP conflicts

	if err := m.db.CreateVM(newVM); err != nil {
		// Cleanup on failure
		os.Remove(newRootFSPath)
		return nil, fmt.Errorf("failed to create VM record: %w", err)
	}

	m.logger("Duplicated VM %s as %s (%s)", vmID, newName, newID)
	m.db.AddVMLog(newID, "info", fmt.Sprintf("VM duplicated from %s", origVM.Name))

	return newVM, nil
}

// GenerateMAC generates a unique locally administered MAC address
func (m *Manager) GenerateMAC() string {
	// Generate random bytes for the last 3 octets
	randomBytes := make([]byte, 3)
	cryptoRand.Read(randomBytes)

	// Locally administered, unicast MAC
	// Format: AA:FC:00:XX:XX:XX (custom Firecracker prefix)
	return fmt.Sprintf("AA:FC:00:%02X:%02X:%02X",
		randomBytes[0],
		randomBytes[1],
		randomBytes[2])
}

// ExportVM creates a .fcrack archive containing the VM configuration, rootfs, and snapshots
func (m *Manager) ExportVM(vmID string) (string, error) {
	return m.ExportVMWithProgress(vmID, "", "")
}

// ExportVMWithProgress creates a .fcrack archive with progress tracking
func (m *Manager) ExportVMWithProgress(vmID, opKey, description string) (string, error) {
	// Helper to update progress
	updateProgress := func(stage string, copied, total int64) {
		if opKey == "" {
			return
		}
		percent := float64(0)
		if total > 0 {
			percent = float64(copied) / float64(total) * 100
		}
		m.SetOperationProgress(opKey, &OperationProgress{
			Status:  "exporting",
			Stage:   stage,
			Total:   total,
			Copied:  copied,
			Percent: percent,
		})
	}

	// Get VM
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return "", fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return "", fmt.Errorf("VM %s not found", vmID)
	}

	// Check if VM is running
	m.mu.RLock()
	_, isRunning := m.runningVMs[vmID]
	m.mu.RUnlock()
	if isRunning {
		return "", fmt.Errorf("cannot export a running VM, please stop it first")
	}

	updateProgress("Preparing export...", 0, 100)

	// Create export filename
	safeName := strings.ReplaceAll(vm.Name, " ", "_")
	safeName = strings.ReplaceAll(safeName, "/", "_")
	timestamp := time.Now().Format("20060102-150405")
	exportPath := filepath.Join(m.dataDir, fmt.Sprintf("%s-%s.fcrack", safeName, timestamp))

	m.logger("Exporting VM %s to %s...", vmID, exportPath)

	// Create the archive file
	archiveFile, err := os.Create(exportPath)
	if err != nil {
		return "", fmt.Errorf("failed to create archive: %w", err)
	}
	defer archiveFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(archiveFile)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	checksums := make(map[string]string)

	// Get rootfs info
	rootfsInfo, err := os.Stat(vm.RootFSPath)
	if err != nil {
		return "", fmt.Errorf("rootfs not found: %w", err)
	}

	// Calculate total size for progress
	totalSize := rootfsInfo.Size()
	snapshots, _ := m.ListSnapshots(vmID)
	for _, snap := range snapshots {
		if info, err := os.Stat(snap.SnapshotPath); err == nil {
			totalSize += info.Size()
		}
		if info, err := os.Stat(snap.MemFilePath); err == nil {
			totalSize += info.Size()
		}
	}

	var copiedSize int64

	// Add rootfs to archive with progress
	updateProgress("Exporting rootfs...", copiedSize, totalSize)
	rootfsName := "rootfs" + filepath.Ext(vm.RootFSPath)
	checksum, err := addFileToTarWithProgress(tarWriter, vm.RootFSPath, rootfsName, func(written int64) {
		updateProgress("Exporting rootfs...", copiedSize+written, totalSize)
	})
	if err != nil {
		os.Remove(exportPath)
		return "", fmt.Errorf("failed to add rootfs to archive: %w", err)
	}
	checksums[rootfsName] = checksum
	copiedSize += rootfsInfo.Size()

	// Add snapshots to archive
	var snapshotInfos []SnapshotInfo
	for i, snap := range snapshots {
		updateProgress(fmt.Sprintf("Exporting snapshot %d/%d...", i+1, len(snapshots)), copiedSize, totalSize)

		// Add vmstate
		vmstateName := fmt.Sprintf("snapshots/vmstate-%s.fc", snap.ID)
		vmstateInfo, _ := os.Stat(snap.SnapshotPath)
		checksum, err := addFileToTarWithProgress(tarWriter, snap.SnapshotPath, vmstateName, func(written int64) {
			updateProgress(fmt.Sprintf("Exporting snapshot %d/%d...", i+1, len(snapshots)), copiedSize+written, totalSize)
		})
		if err != nil {
			m.logger("Warning: failed to add snapshot vmstate: %v", err)
			continue
		}
		checksums[vmstateName] = checksum
		if vmstateInfo != nil {
			copiedSize += vmstateInfo.Size()
		}

		// Add memfile
		memfileName := fmt.Sprintf("snapshots/memfile-%s.fc", snap.ID)
		memfileInfo, _ := os.Stat(snap.MemFilePath)
		checksum, err = addFileToTarWithProgress(tarWriter, snap.MemFilePath, memfileName, func(written int64) {
			updateProgress(fmt.Sprintf("Exporting snapshot %d/%d...", i+1, len(snapshots)), copiedSize+written, totalSize)
		})
		if err != nil {
			m.logger("Warning: failed to add snapshot memfile: %v", err)
			continue
		}
		checksums[memfileName] = checksum
		if memfileInfo != nil {
			copiedSize += memfileInfo.Size()
		}

		snapshotInfos = append(snapshotInfos, *snap)
	}

	updateProgress("Creating manifest...", totalSize, totalSize)

	// Use provided description or fall back to VM description
	exportDescription := description
	if exportDescription == "" {
		exportDescription = vm.Description
	}

	// Create manifest
	manifest := VMExportManifest{
		Version:      "1.0",
		ExportedAt:   time.Now().Format(time.RFC3339),
		Name:         vm.Name,
		Description:  exportDescription,
		VCPU:         vm.VCPU,
		MemoryMB:     vm.MemoryMB,
		KernelArgs:   vm.KernelArgs,
		DNSServers:   vm.DNSServers,
		SnapshotType: vm.SnapshotType,
		RootFSName:   rootfsName,
		RootFSSize:   rootfsInfo.Size(),
		Snapshots:    snapshotInfos,
		Checksum:     checksums,
	}

	// Add manifest to archive
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		os.Remove(exportPath)
		return "", fmt.Errorf("failed to create manifest: %w", err)
	}

	header := &tar.Header{
		Name:    "manifest.json",
		Mode:    0644,
		Size:    int64(len(manifestData)),
		ModTime: time.Now(),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		os.Remove(exportPath)
		return "", fmt.Errorf("failed to write manifest header: %w", err)
	}
	if _, err := tarWriter.Write(manifestData); err != nil {
		os.Remove(exportPath)
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	m.logger("VM %s exported successfully to %s", vmID, exportPath)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM exported to %s", filepath.Base(exportPath)))

	return exportPath, nil
}

// ImportVM imports a VM from a .fcrack archive
func (m *Manager) ImportVM(archivePath, newName, kernelID string) (*database.VM, error) {
	m.logger("Importing VM from %s...", archivePath)

	// Open archive
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Temp directory for extraction
	tempDir, err := os.MkdirTemp("", "fcrack-import-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract all files
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}

		targetPath := filepath.Join(tempDir, header.Name)

		// Create directories as needed
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directory: %w", err)
		}

		// Extract file
		outFile, err := os.Create(targetPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(outFile, tarReader); err != nil {
			outFile.Close()
			return nil, fmt.Errorf("failed to extract file: %w", err)
		}
		outFile.Close()
	}

	// Read manifest
	manifestPath := filepath.Join(tempDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest not found in archive")
	}

	var manifest VMExportManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	// Determine VM name
	vmName := newName
	if vmName == "" {
		vmName = manifest.Name
	}

	// Check if name already exists and append suffix if needed
	baseName := vmName
	suffix := 1
	for {
		existingVM, _ := m.db.GetVMByName(vmName)
		if existingVM == nil {
			break
		}
		vmName = fmt.Sprintf("%s-%d", baseName, suffix)
		suffix++
	}

	// Get kernel
	var kernelPath string
	if kernelID != "" {
		kernel, err := m.db.GetKernelImage(kernelID)
		if err != nil || kernel == nil {
			return nil, fmt.Errorf("kernel %s not found", kernelID)
		}
		kernelPath = kernel.Path
	} else {
		// Use default kernel
		kernel, err := m.db.GetDefaultKernel()
		if err != nil || kernel == nil {
			return nil, fmt.Errorf("no default kernel available, please specify a kernel_id")
		}
		kernelPath = kernel.Path
	}

	// Generate new VM ID
	newID := generateVMID()

	// Move rootfs to final location
	rootfsDir := filepath.Join(m.dataDir, "rootfs")
	rootfsExt := filepath.Ext(manifest.RootFSName)
	newRootFSPath := filepath.Join(rootfsDir, fmt.Sprintf("%s%s", newID, rootfsExt))

	srcRootFS := filepath.Join(tempDir, manifest.RootFSName)

	// Verify checksum if available
	if expectedChecksum, ok := manifest.Checksum[manifest.RootFSName]; ok {
		actualChecksum, err := calculateMD5(srcRootFS)
		if err != nil {
			m.logger("Warning: could not verify rootfs checksum: %v", err)
		} else if actualChecksum != expectedChecksum {
			return nil, fmt.Errorf("rootfs checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
		}
	}

	// Copy rootfs to destination
	if err := copyFile(srcRootFS, newRootFSPath); err != nil {
		return nil, fmt.Errorf("failed to copy rootfs: %w", err)
	}

	// Copy snapshots
	snapshotsDir := filepath.Join(tempDir, "snapshots")
	for _, snap := range manifest.Snapshots {
		// Copy vmstate
		srcVmstate := filepath.Join(snapshotsDir, fmt.Sprintf("vmstate-%s.fc", snap.ID))
		dstVmstate := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", newID, snap.ID))
		if err := copyFile(srcVmstate, dstVmstate); err != nil {
			m.logger("Warning: failed to copy snapshot vmstate: %v", err)
		}

		// Copy memfile
		srcMemfile := filepath.Join(snapshotsDir, fmt.Sprintf("memfile-%s.fc", snap.ID))
		dstMemfile := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", newID, snap.ID))
		if err := copyFile(srcMemfile, dstMemfile); err != nil {
			m.logger("Warning: failed to copy snapshot memfile: %v", err)
		}
	}

	// Create VM record
	newVM := &database.VM{
		ID:           newID,
		Name:         vmName,
		Description:  manifest.Description,
		VCPU:         manifest.VCPU,
		MemoryMB:     manifest.MemoryMB,
		KernelPath:   kernelPath,
		RootFSPath:   newRootFSPath,
		KernelArgs:   manifest.KernelArgs,
		DNSServers:   manifest.DNSServers,
		SnapshotType: manifest.SnapshotType,
		Status:       "stopped",
	}

	if err := m.db.CreateVM(newVM); err != nil {
		// Cleanup on failure
		os.Remove(newRootFSPath)
		return nil, fmt.Errorf("failed to create VM record: %w", err)
	}

	m.logger("Imported VM %s from %s", vmName, filepath.Base(archivePath))
	m.db.AddVMLog(newID, "info", fmt.Sprintf("VM imported from %s", filepath.Base(archivePath)))

	return newVM, nil
}

// ImportVMWithProgress imports a VM from a .fcrack archive with progress tracking
func (m *Manager) ImportVMWithProgress(archivePath, newName, kernelID, progressKey string) (*database.VM, error) {
	m.logger("Importing VM from %s with progress tracking...", archivePath)

	// Get archive file size for progress calculation
	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat archive: %w", err)
	}
	totalSize := archiveInfo.Size()

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "starting",
		Stage:   "Opening archive...",
		Percent: 0,
	})

	// Open archive
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close()

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "extracting",
		Stage:   "Decompressing archive...",
		Percent: 5,
	})

	// Create gzip reader
	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Temp directory for extraction
	tempDir, err := os.MkdirTemp("", "fcrack-import-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "extracting",
		Stage:   "Extracting files...",
		Percent: 10,
	})

	// Extract all files with progress
	var extractedSize int64
	fileCount := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}

		targetPath := filepath.Join(tempDir, header.Name)

		// Create directories as needed
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create parent directory: %w", err)
		}

		// Extract file
		outFile, err := os.Create(targetPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file: %w", err)
		}

		written, err := io.Copy(outFile, tarReader)
		outFile.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to extract file: %w", err)
		}

		extractedSize += written
		fileCount++

		// Update progress (10-60% for extraction)
		progress := 10.0 + float64(extractedSize)/float64(totalSize)*50.0
		if progress > 60.0 {
			progress = 60.0
		}
		m.SetOperationProgress(progressKey, &OperationProgress{
			Status:  "extracting",
			Stage:   fmt.Sprintf("Extracting files... (%d files)", fileCount),
			Percent: progress,
		})
	}

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "processing",
		Stage:   "Reading manifest...",
		Percent: 65,
	})

	// Read manifest
	manifestPath := filepath.Join(tempDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("manifest not found in archive")
	}

	var manifest VMExportManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	// Determine VM name
	vmName := newName
	if vmName == "" {
		vmName = manifest.Name
	}

	// Check if name already exists and append suffix if needed
	baseName := vmName
	suffix := 1
	for {
		existingVM, _ := m.db.GetVMByName(vmName)
		if existingVM == nil {
			break
		}
		vmName = fmt.Sprintf("%s-%d", baseName, suffix)
		suffix++
	}

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "processing",
		Stage:   "Verifying kernel...",
		Percent: 70,
	})

	// Get kernel
	var kernelPath string
	if kernelID != "" {
		kernel, err := m.db.GetKernelImage(kernelID)
		if err != nil || kernel == nil {
			return nil, fmt.Errorf("kernel %s not found", kernelID)
		}
		kernelPath = kernel.Path
	} else {
		kernel, err := m.db.GetDefaultKernel()
		if err != nil || kernel == nil {
			return nil, fmt.Errorf("no default kernel available, please specify a kernel_id")
		}
		kernelPath = kernel.Path
	}

	// Generate new VM ID
	newID := generateVMID()

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "copying",
		Stage:   "Copying rootfs...",
		Percent: 75,
	})

	// Move rootfs to final location
	rootfsDir := filepath.Join(m.dataDir, "rootfs")
	rootfsExt := filepath.Ext(manifest.RootFSName)
	newRootFSPath := filepath.Join(rootfsDir, fmt.Sprintf("%s%s", newID, rootfsExt))

	srcRootFS := filepath.Join(tempDir, manifest.RootFSName)

	// Verify checksum if available
	if expectedChecksum, ok := manifest.Checksum[manifest.RootFSName]; ok {
		m.SetOperationProgress(progressKey, &OperationProgress{
			Status:  "verifying",
			Stage:   "Verifying checksum...",
			Percent: 80,
		})
		actualChecksum, err := calculateMD5(srcRootFS)
		if err != nil {
			m.logger("Warning: could not verify rootfs checksum: %v", err)
		} else if actualChecksum != expectedChecksum {
			return nil, fmt.Errorf("rootfs checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
		}
	}

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "copying",
		Stage:   "Copying rootfs to destination...",
		Percent: 85,
	})

	// Copy rootfs to destination
	if err := copyFile(srcRootFS, newRootFSPath); err != nil {
		return nil, fmt.Errorf("failed to copy rootfs: %w", err)
	}

	// Copy snapshots
	if len(manifest.Snapshots) > 0 {
		m.SetOperationProgress(progressKey, &OperationProgress{
			Status:  "copying",
			Stage:   "Copying snapshots...",
			Percent: 90,
		})

		snapshotsDir := filepath.Join(tempDir, "snapshots")
		for _, snap := range manifest.Snapshots {
			srcVmstate := filepath.Join(snapshotsDir, fmt.Sprintf("vmstate-%s.fc", snap.ID))
			dstVmstate := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-vmstate-%s.fc", newID, snap.ID))
			if err := copyFile(srcVmstate, dstVmstate); err != nil {
				m.logger("Warning: failed to copy snapshot vmstate: %v", err)
			}

			srcMemfile := filepath.Join(snapshotsDir, fmt.Sprintf("memfile-%s.fc", snap.ID))
			dstMemfile := filepath.Join(rootfsDir, fmt.Sprintf("snapshot-%s-memfile-%s.fc", newID, snap.ID))
			if err := copyFile(srcMemfile, dstMemfile); err != nil {
				m.logger("Warning: failed to copy snapshot memfile: %v", err)
			}
		}
	}

	m.SetOperationProgress(progressKey, &OperationProgress{
		Status:  "finalizing",
		Stage:   "Creating VM record...",
		Percent: 95,
	})

	// Create VM record
	newVM := &database.VM{
		ID:           newID,
		Name:         vmName,
		Description:  manifest.Description,
		VCPU:         manifest.VCPU,
		MemoryMB:     manifest.MemoryMB,
		KernelPath:   kernelPath,
		RootFSPath:   newRootFSPath,
		KernelArgs:   manifest.KernelArgs,
		DNSServers:   manifest.DNSServers,
		SnapshotType: manifest.SnapshotType,
		Status:       "stopped",
	}

	if err := m.db.CreateVM(newVM); err != nil {
		os.Remove(newRootFSPath)
		return nil, fmt.Errorf("failed to create VM record: %w", err)
	}

	m.logger("Imported VM %s from %s", vmName, filepath.Base(archivePath))
	m.db.AddVMLog(newID, "info", fmt.Sprintf("VM imported from %s", filepath.Base(archivePath)))

	return newVM, nil
}

// GetExportPath returns the path to an exported .fcrack file
func (m *Manager) GetExportPath(filename string) string {
	return filepath.Join(m.dataDir, filename)
}

// ReadApplianceManifest reads the manifest from a .fcrack archive
func (m *Manager) ReadApplianceManifest(filename string) (*VMExportManifest, error) {
	archivePath := filepath.Join(m.dataDir, filename)

	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open archive: %w", err)
	}
	defer archiveFile.Close()

	gzReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}

		if header.Name == "manifest.json" {
			manifestData, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest: %w", err)
			}

			var manifest VMExportManifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				return nil, fmt.Errorf("invalid manifest: %w", err)
			}
			return &manifest, nil
		}
	}

	return nil, fmt.Errorf("manifest not found in archive")
}

// ApplianceMetadata stores metadata for appliances in a separate file for fast access
type ApplianceMetadata struct {
	Descriptions map[string]string `json:"descriptions"`
}

// getApplianceMetadataPath returns the path to the appliance metadata file
func (m *Manager) getApplianceMetadataPath() string {
	return filepath.Join(m.dataDir, "appliance-metadata.json")
}

// loadApplianceMetadata loads the appliance metadata from disk
func (m *Manager) loadApplianceMetadata() (*ApplianceMetadata, error) {
	metaPath := m.getApplianceMetadataPath()
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ApplianceMetadata{Descriptions: make(map[string]string)}, nil
		}
		return nil, err
	}

	var meta ApplianceMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	if meta.Descriptions == nil {
		meta.Descriptions = make(map[string]string)
	}
	return &meta, nil
}

// saveApplianceMetadata saves the appliance metadata to disk
func (m *Manager) saveApplianceMetadata(meta *ApplianceMetadata) error {
	metaPath := m.getApplianceMetadataPath()
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, data, 0644)
}

// GetApplianceDescription gets the description for an appliance (checks metadata file first, then archive)
func (m *Manager) GetApplianceDescription(filename string) string {
	// First check metadata file (fast)
	meta, err := m.loadApplianceMetadata()
	if err == nil {
		if desc, ok := meta.Descriptions[filename]; ok {
			return desc
		}
	}

	// Fall back to reading from archive manifest (slower)
	manifest, err := m.ReadApplianceManifest(filename)
	if err == nil && manifest != nil {
		return manifest.Description
	}

	return ""
}

// UpdateApplianceDescription updates the description in the metadata file (fast, no archive rewrite)
func (m *Manager) UpdateApplianceDescription(filename, description string) error {
	// Verify the appliance file exists
	archivePath := filepath.Join(m.dataDir, filename)
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("appliance not found: %s", filename)
	}

	// Load existing metadata
	meta, err := m.loadApplianceMetadata()
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	// Update description
	if description == "" {
		delete(meta.Descriptions, filename)
	} else {
		meta.Descriptions[filename] = description
	}

	// Save metadata
	if err := m.saveApplianceMetadata(meta); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	m.logger("Updated description for appliance %s", filename)
	return nil
}

// AttachDisk creates a new disk, formats it with ext4, and prepares it for VM attachment
func (m *Manager) AttachDisk(vmID, name string, sizeMB int64, mountPoint string) (*database.VMDisk, error) {
	// Get VM to verify it exists and is stopped
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return nil, fmt.Errorf("VM %s not found", vmID)
	}
	if vm.Status == "running" {
		return nil, fmt.Errorf("cannot attach disk to running VM, please stop it first")
	}

	// Validate mount point
	if mountPoint == "" || !strings.HasPrefix(mountPoint, "/") {
		return nil, fmt.Errorf("mount point must be an absolute path (e.g., /mnt/data)")
	}
	if mountPoint == "/" || mountPoint == "/root" || mountPoint == "/etc" || mountPoint == "/var" || mountPoint == "/usr" {
		return nil, fmt.Errorf("cannot use system mount point: %s", mountPoint)
	}

	// Generate disk ID and get next drive ID
	diskID := generateVMID()
	driveID, err := m.db.GetNextDriveID(vmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get next drive ID: %w", err)
	}

	// Create disk directory
	diskDir := filepath.Join(m.dataDir, "disks")
	if err := os.MkdirAll(diskDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create disk directory: %w", err)
	}

	// Create disk file path
	diskPath := filepath.Join(diskDir, fmt.Sprintf("%s-%s.img", vmID, diskID[:8]))

	// Create the raw disk image
	m.logger("Creating disk image: %s (%d MB)", diskPath, sizeMB)
	if err := m.createDiskImage(diskPath, sizeMB); err != nil {
		return nil, fmt.Errorf("failed to create disk image: %w", err)
	}

	// Format the disk with ext4
	m.logger("Formatting disk with ext4...")
	if err := m.formatDiskExt4(diskPath); err != nil {
		os.Remove(diskPath)
		return nil, fmt.Errorf("failed to format disk: %w", err)
	}

	// Update fstab in the rootfs
	m.logger("Updating fstab in rootfs...")
	if err := m.updateFstab(vm.RootFSPath, driveID, mountPoint); err != nil {
		os.Remove(diskPath)
		return nil, fmt.Errorf("failed to update fstab: %w", err)
	}

	// Create mount point in rootfs
	m.logger("Creating mount point %s in rootfs...", mountPoint)
	if err := m.createMountPoint(vm.RootFSPath, mountPoint); err != nil {
		os.Remove(diskPath)
		return nil, fmt.Errorf("failed to create mount point: %w", err)
	}

	// Create database record
	disk := &database.VMDisk{
		ID:         diskID,
		VMID:       vmID,
		Name:       name,
		Path:       diskPath,
		SizeMB:     sizeMB,
		Format:     "ext4",
		MountPoint: mountPoint,
		DriveID:    driveID,
		IsReadOnly: false,
	}

	if err := m.db.CreateVMDisk(disk); err != nil {
		os.Remove(diskPath)
		return nil, fmt.Errorf("failed to create disk record: %w", err)
	}

	m.logger("Disk %s attached to VM %s at %s", name, vm.Name, mountPoint)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Disk %s (%d MB) attached at %s", name, sizeMB, mountPoint))

	return disk, nil
}

// createDiskImage creates a raw disk image of specified size
func (m *Manager) createDiskImage(path string, sizeMB int64) error {
	// Use dd to create a sparse file
	cmd := exec.Command("dd", "if=/dev/zero", "of="+path, "bs=1M", "count=0", fmt.Sprintf("seek=%d", sizeMB))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dd failed: %s: %w", string(output), err)
	}
	return nil
}

// formatDiskExt4 formats the disk image with ext4 filesystem
func (m *Manager) formatDiskExt4(path string) error {
	// Use mkfs.ext4 to format the disk
	cmd := exec.Command("mkfs.ext4", "-F", "-q", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %s: %w", string(output), err)
	}
	return nil
}

// updateFstab adds an entry to /etc/fstab in the rootfs
func (m *Manager) updateFstab(rootfsPath, driveID, mountPoint string) error {
	// Create a temporary directory to mount the rootfs
	tmpMount, err := os.MkdirTemp("", "fcm-rootfs-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpMount)

	// Mount the rootfs
	cmd := exec.Command("mount", "-o", "loop", rootfsPath, tmpMount)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %s: %w", string(output), err)
	}
	defer exec.Command("umount", tmpMount).Run()

	// Read current fstab
	fstabPath := filepath.Join(tmpMount, "etc", "fstab")
	content, err := os.ReadFile(fstabPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read fstab: %w", err)
	}

	// Determine device name based on drive ID
	// In Firecracker, drives appear as /dev/vdX where X is b, c, d, etc.
	// drive0 (rootfs) is /dev/vda, drive1 is /dev/vdb, etc.
	driveNum := 0
	fmt.Sscanf(driveID, "drive%d", &driveNum)
	deviceLetter := string(rune('a' + driveNum))
	deviceName := "/dev/vd" + deviceLetter

	// Check if entry already exists
	existingContent := string(content)
	if strings.Contains(existingContent, mountPoint) {
		return nil // Already configured
	}

	// Add fstab entry
	// Format: device mountpoint fs options dump pass
	fstabEntry := fmt.Sprintf("\n# Added by FireCrackManager - %s\n%s\t%s\text4\tdefaults,nofail\t0\t2\n",
		driveID, deviceName, mountPoint)

	newContent := existingContent + fstabEntry

	// Write updated fstab
	if err := os.WriteFile(fstabPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write fstab: %w", err)
	}

	return nil
}

// createMountPoint creates the mount point directory in the rootfs
func (m *Manager) createMountPoint(rootfsPath, mountPoint string) error {
	// Create a temporary directory to mount the rootfs
	tmpMount, err := os.MkdirTemp("", "fcm-rootfs-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpMount)

	// Mount the rootfs
	cmd := exec.Command("mount", "-o", "loop", rootfsPath, tmpMount)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %s: %w", string(output), err)
	}
	defer exec.Command("umount", tmpMount).Run()

	// Create the mount point directory
	fullPath := filepath.Join(tmpMount, mountPoint)
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}

	return nil
}

// ListDisks returns all disks attached to a VM
func (m *Manager) ListDisks(vmID string) ([]*database.VMDisk, error) {
	return m.db.ListVMDisks(vmID)
}

// DetachDisk removes a disk from a VM
func (m *Manager) DetachDisk(vmID, diskID string) error {
	// Get VM to verify it exists and is stopped
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}
	if vm.Status == "running" {
		return fmt.Errorf("cannot detach disk from running VM, please stop it first")
	}

	// Get disk
	disk, err := m.db.GetVMDisk(diskID)
	if err != nil {
		return fmt.Errorf("failed to get disk: %w", err)
	}
	if disk == nil {
		return fmt.Errorf("disk %s not found", diskID)
	}
	if disk.VMID != vmID {
		return fmt.Errorf("disk %s does not belong to VM %s", diskID, vmID)
	}

	// Remove fstab entry
	if err := m.removeFstabEntry(vm.RootFSPath, disk.MountPoint); err != nil {
		m.logger("Warning: failed to remove fstab entry: %v", err)
	}

	// Delete disk file
	if err := os.Remove(disk.Path); err != nil && !os.IsNotExist(err) {
		m.logger("Warning: failed to delete disk file: %v", err)
	}

	// Delete database record
	if err := m.db.DeleteVMDisk(diskID); err != nil {
		return fmt.Errorf("failed to delete disk record: %w", err)
	}

	m.logger("Disk %s detached from VM %s", disk.Name, vm.Name)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Disk %s detached", disk.Name))

	return nil
}

// ExpandDisk expands an attached disk to a new size
func (m *Manager) ExpandDisk(vmID, diskID string, newSizeMB int64) error {
	// Get VM to verify it exists and is stopped
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}
	if vm.Status == "running" {
		return fmt.Errorf("cannot expand disk on running VM, please stop it first")
	}

	// Get disk
	disk, err := m.db.GetVMDisk(diskID)
	if err != nil {
		return fmt.Errorf("failed to get disk: %w", err)
	}
	if disk == nil {
		return fmt.Errorf("disk %s not found", diskID)
	}
	if disk.VMID != vmID {
		return fmt.Errorf("disk %s does not belong to VM %s", diskID, vmID)
	}

	// Validate new size
	if newSizeMB <= disk.SizeMB {
		return fmt.Errorf("new size (%d MB) must be greater than current size (%d MB)", newSizeMB, disk.SizeMB)
	}

	// Expand the disk image file using truncate (pure Go)
	if err := m.expandDiskImage(disk.Path, newSizeMB); err != nil {
		return fmt.Errorf("failed to expand disk image: %w", err)
	}

	// Resize the ext4 filesystem
	if err := m.resizeExt4Filesystem(disk.Path); err != nil {
		return fmt.Errorf("failed to resize filesystem: %w", err)
	}

	// Update database
	oldSize := disk.SizeMB
	disk.SizeMB = newSizeMB
	if err := m.db.UpdateVMDisk(disk); err != nil {
		return fmt.Errorf("failed to update disk record: %w", err)
	}

	m.logger("Disk %s expanded from %d MB to %d MB", disk.Name, oldSize, newSizeMB)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Disk %s expanded from %d MB to %d MB", disk.Name, oldSize, newSizeMB))

	return nil
}

// ExpandRootFS expands the root filesystem of a VM
func (m *Manager) ExpandRootFS(vmID string, newSizeMB int64) error {
	// Get VM to verify it exists and is stopped
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}
	if vm.Status == "running" {
		return fmt.Errorf("cannot expand rootfs on running VM, please stop it first")
	}

	// Get current size
	fileInfo, err := os.Stat(vm.RootFSPath)
	if err != nil {
		return fmt.Errorf("failed to stat rootfs: %w", err)
	}
	currentSizeMB := fileInfo.Size() / (1024 * 1024)

	// Validate new size
	if newSizeMB <= currentSizeMB {
		return fmt.Errorf("new size (%d MB) must be greater than current size (%d MB)", newSizeMB, currentSizeMB)
	}

	// Expand the disk image file
	if err := m.expandDiskImage(vm.RootFSPath, newSizeMB); err != nil {
		return fmt.Errorf("failed to expand rootfs image: %w", err)
	}

	// Resize the ext4 filesystem
	if err := m.resizeExt4Filesystem(vm.RootFSPath); err != nil {
		return fmt.Errorf("failed to resize filesystem: %w", err)
	}

	m.logger("RootFS for VM %s expanded from %d MB to %d MB", vm.Name, currentSizeMB, newSizeMB)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("RootFS expanded from %d MB to %d MB", currentSizeMB, newSizeMB))

	return nil
}

// expandDiskImage expands a disk image file to the new size using pure Go
func (m *Manager) expandDiskImage(path string, newSizeMB int64) error {
	newSizeBytes := newSizeMB * 1024 * 1024

	// Open the file
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open disk image: %w", err)
	}
	defer f.Close()

	// Get current size
	fileInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.Size() >= newSizeBytes {
		return fmt.Errorf("file is already %d bytes, requested %d bytes", fileInfo.Size(), newSizeBytes)
	}

	// Truncate to new size (this creates a sparse file on Linux)
	if err := f.Truncate(newSizeBytes); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}

	return nil
}

// resizeExt4Filesystem resizes the ext4 filesystem to fill the disk image
func (m *Manager) resizeExt4Filesystem(path string) error {
	// Use e2fsck first to check filesystem
	cmd := exec.Command("e2fsck", "-f", "-y", path)
	cmd.Run() // Ignore errors, e2fsck returns non-zero for fixes

	// Use resize2fs to resize the filesystem
	cmd = exec.Command("resize2fs", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs failed: %s: %w", string(output), err)
	}

	return nil
}

// ShrinkRootFS shrinks a VM's rootfs to minimize disk space
// Steps: 1) Check filesystem, 2) Shrink to minimum, 3) Zero free space, 4) Truncate file
func (m *Manager) ShrinkRootFS(vmID string) error {
	// Get VM
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM not found")
	}

	// Check if VM is running
	m.mu.RLock()
	_, isRunning := m.runningVMs[vmID]
	m.mu.RUnlock()
	if isRunning {
		return fmt.Errorf("cannot shrink rootfs of a running VM, please stop it first")
	}

	rootfsPath := vm.RootFSPath
	if rootfsPath == "" {
		return fmt.Errorf("VM has no rootfs configured")
	}

	// Check file exists
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		return fmt.Errorf("rootfs file not found: %s", rootfsPath)
	}

	m.logger("Shrinking rootfs for VM %s: %s", vm.Name, rootfsPath)

	// Get original size
	origInfo, _ := os.Stat(rootfsPath)
	origSize := origInfo.Size()

	// Step 1: Check and fix filesystem
	m.logger("  Running e2fsck...")
	cmd := exec.Command("e2fsck", "-f", "-y", rootfsPath)
	cmd.Run() // Ignore exit code, e2fsck returns non-zero when it fixes things

	// Step 2: Shrink filesystem to minimum size
	m.logger("  Shrinking filesystem to minimum size...")
	cmd = exec.Command("resize2fs", "-M", rootfsPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs -M failed: %s: %w", string(output), err)
	}

	// Step 3: Get the new filesystem size in blocks
	cmd = exec.Command("dumpe2fs", "-h", rootfsPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dumpe2fs failed: %w", err)
	}

	var blockCount, blockSize int64
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Block count:") {
			fmt.Sscanf(line, "Block count: %d", &blockCount)
		}
		if strings.HasPrefix(line, "Block size:") {
			fmt.Sscanf(line, "Block size: %d", &blockSize)
		}
	}

	if blockCount == 0 || blockSize == 0 {
		return fmt.Errorf("could not determine filesystem size")
	}

	// Calculate new file size (filesystem size + small buffer for safety)
	newSize := blockCount * blockSize

	// Step 4: Truncate the file to the new size
	m.logger("  Truncating file from %d to %d bytes...", origSize, newSize)
	if err := os.Truncate(rootfsPath, newSize); err != nil {
		return fmt.Errorf("failed to truncate file: %w", err)
	}

	// Step 5: Try to use zerofree if available (zeros unused blocks for better compression)
	if _, err := exec.LookPath("zerofree"); err == nil {
		m.logger("  Running zerofree to zero unused blocks...")
		cmd = exec.Command("zerofree", rootfsPath)
		cmd.Run() // Ignore errors, zerofree is optional
	}

	// Get final size
	finalInfo, _ := os.Stat(rootfsPath)
	finalSize := finalInfo.Size()
	savedBytes := origSize - finalSize
	savedPct := float64(savedBytes) / float64(origSize) * 100

	m.logger("  Shrink complete: %d -> %d bytes (saved %.1f%%)", origSize, finalSize, savedPct)

	// Log to VM
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("RootFS shrunk: %s -> %s (saved %.1f%%)",
		formatBytes(origSize), formatBytes(finalSize), savedPct))

	return nil
}

// removeFstabEntry removes a mount point entry from fstab
func (m *Manager) removeFstabEntry(rootfsPath, mountPoint string) error {
	// Create a temporary directory to mount the rootfs
	tmpMount, err := os.MkdirTemp("", "fcm-rootfs-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpMount)

	// Mount the rootfs
	cmd := exec.Command("mount", "-o", "loop", rootfsPath, tmpMount)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to mount rootfs: %s: %w", string(output), err)
	}
	defer exec.Command("umount", tmpMount).Run()

	// Read fstab
	fstabPath := filepath.Join(tmpMount, "etc", "fstab")
	content, err := os.ReadFile(fstabPath)
	if err != nil {
		return fmt.Errorf("failed to read fstab: %w", err)
	}

	// Remove lines containing the mount point
	lines := strings.Split(string(content), "\n")
	var newLines []string
	skipNext := false
	for _, line := range lines {
		// Skip comment lines that reference this mount point
		if strings.Contains(line, "FireCrackManager") && skipNext {
			continue
		}
		if strings.Contains(line, mountPoint) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			skipNext = true
			continue
		}
		if strings.HasPrefix(line, "# Added by FireCrackManager") {
			skipNext = true
			continue
		}
		skipNext = false
		newLines = append(newLines, line)
	}

	// Write updated fstab
	if err := os.WriteFile(fstabPath, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to write fstab: %w", err)
	}

	return nil
}

// GetDisksDir returns the path to the disks directory
func (m *Manager) GetDisksDir() string {
	return filepath.Join(m.dataDir, "disks")
}

// GetDataDir returns the path to the data directory
func (m *Manager) GetDataDir() string {
	return m.dataDir
}

// Helper functions

func generateVMID() string {
	h := md5.New()
	h.Write([]byte(time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func addFileToTar(tw *tar.Writer, filePath, name string) (string, error) {
	return addFileToTarWithProgress(tw, filePath, name, nil)
}

// progressWriter wraps a writer and calls a callback with bytes written
type progressWriter struct {
	writer   io.Writer
	written  int64
	callback func(int64)
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.writer.Write(p)
	pw.written += int64(n)
	if pw.callback != nil {
		pw.callback(pw.written)
	}
	return n, err
}

func addFileToTarWithProgress(tw *tar.Writer, filePath, name string, progressCallback func(int64)) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", err
	}

	header := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return "", err
	}

	// Calculate checksum while writing with progress
	hash := md5.New()
	var dest io.Writer = io.MultiWriter(tw, hash)

	if progressCallback != nil {
		dest = &progressWriter{writer: dest, callback: progressCallback}
	}

	if _, err := io.Copy(dest, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// MigrateVM sends a VM to a remote FireCrackManager instance
func (m *Manager) MigrateVM(vmID, remoteHost string, remotePort int, migrationKey string, compress bool, progressCb func(progress float64, bytesSent, bytesTotal int64)) error {
	// Get VM
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}

	// Check if VM is running
	m.mu.RLock()
	_, isRunning := m.runningVMs[vmID]
	m.mu.RUnlock()
	if isRunning {
		return fmt.Errorf("cannot migrate a running VM, please stop it first")
	}

	// Check rootfs exists
	if _, err := os.Stat(vm.RootFSPath); err != nil {
		return fmt.Errorf("rootfs not found: %w", err)
	}

	m.logger("Starting migration of VM '%s' to %s:%d", vm.Name, remoteHost, remotePort)
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("Starting migration to %s:%d", remoteHost, remotePort))

	// Create migration client
	client := NewMigrationClient(remoteHost, remotePort, migrationKey, m.logger)

	// Migrate
	err = client.MigrateVM(
		vm.Name,
		vm.RootFSPath,
		vm.VCPU,
		vm.MemoryMB,
		vm.KernelArgs,
		vm.DNSServers,
		compress,
		progressCb,
	)

	if err != nil {
		m.db.AddVMLog(vmID, "error", fmt.Sprintf("Migration failed: %v", err))
		return fmt.Errorf("migration failed: %w", err)
	}

	m.logger("Migration of VM '%s' completed successfully", vm.Name)
	m.db.AddVMLog(vmID, "info", "Migration completed successfully")

	return nil
}

// ImportMigratedVM imports a VM that was received via migration
func (m *Manager) ImportMigratedVM(vmName, rootfsPath string, vcpu, memoryMB int, kernelArgs, dnsServers string) (*database.VM, error) {
	// Get default kernel
	defaultKernel, err := m.db.GetDefaultKernel()
	if err != nil {
		return nil, fmt.Errorf("failed to get default kernel: %w", err)
	}
	if defaultKernel == nil {
		return nil, fmt.Errorf("no default kernel configured")
	}

	// Generate unique name if needed
	originalName := vmName
	counter := 1
	for {
		existing, err := m.db.GetVMByName(vmName)
		if err != nil {
			return nil, fmt.Errorf("failed to check existing VM: %w", err)
		}
		if existing == nil {
			break
		}
		vmName = fmt.Sprintf("%s-%d", originalName, counter)
		counter++
	}

	// Move rootfs to proper location
	finalRootfsPath := filepath.Join(m.dataDir, "rootfs", fmt.Sprintf("migrated-%s.ext4", generateVMID()))
	if err := os.Rename(rootfsPath, finalRootfsPath); err != nil {
		// Try copy if rename fails (cross-filesystem)
		if err := copyFile(rootfsPath, finalRootfsPath); err != nil {
			return nil, fmt.Errorf("failed to move rootfs: %w", err)
		}
		os.Remove(rootfsPath)
	}

	// Create VM
	vm := &database.VM{
		ID:         generateVMID(),
		Name:       vmName,
		VCPU:       vcpu,
		MemoryMB:   memoryMB,
		KernelPath: defaultKernel.Path,
		RootFSPath: finalRootfsPath,
		KernelArgs: kernelArgs,
		DNSServers: dnsServers,
		Status:     "stopped",
	}

	if err := m.db.CreateVM(vm); err != nil {
		os.Remove(finalRootfsPath)
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	// Register rootfs in database
	rootfsInfo, _ := os.Stat(finalRootfsPath)
	rootfs := &database.RootFS{
		ID:     generateVMID(),
		Name:   fmt.Sprintf("migrated-%s", vmName),
		Path:   finalRootfsPath,
		Size:   rootfsInfo.Size(),
		Format: "ext4",
	}
	m.db.CreateRootFS(rootfs)

	m.logger("Imported migrated VM '%s' (ID: %s)", vmName, vm.ID)
	m.db.AddVMLog(vm.ID, "info", "VM imported via migration")

	return vm, nil
}

// MigrationClient handles outgoing migration connections
type MigrationClient struct {
	host    string
	port    int
	key     string
	logger  func(string, ...interface{})
	timeout time.Duration
}

// NewMigrationClient creates a new migration client
func NewMigrationClient(host string, port int, key string, logger func(string, ...interface{})) *MigrationClient {
	return &MigrationClient{
		host:    host,
		port:    port,
		key:     key,
		logger:  logger,
		timeout: 5 * time.Minute,
	}
}

// MigrateVM sends a VM to a remote server
func (c *MigrationClient) MigrateVM(vmName, rootfsPath string, vcpu, memoryMB int, kernelArgs, dnsServers string, compress bool, progressCb func(float64, int64, int64)) error {
	// Import migration package functionality inline to avoid circular imports
	return migrateVMInternal(c.host, c.port, c.key, vmName, rootfsPath, vcpu, memoryMB, kernelArgs, dnsServers, compress, progressCb, c.logger)
}

// migrateVMInternal handles the actual migration logic
func migrateVMInternal(host string, port int, key, vmName, rootfsPath string, vcpu, memoryMB int, kernelArgs, dnsServers string, compress bool, progressCb func(float64, int64, int64), logger func(string, ...interface{})) error {
	import_crypto_hmac := func(key []byte, message string) string {
		// Inline HMAC-SHA256 implementation
		mac := hmacSHA256(key, []byte(message))
		return hex.EncodeToString(mac)
	}

	// Get file info
	fileInfo, err := os.Stat(rootfsPath)
	if err != nil {
		return fmt.Errorf("failed to stat rootfs: %w", err)
	}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", host, port)
	logger("Connecting to %s...", addr)

	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// Generate nonce
	nonceBytes := make([]byte, 16)
	cryptoRand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	// Generate timestamp
	timestamp := time.Now().Unix()

	// Compute signature
	message := fmt.Sprintf("%d:%s", timestamp, nonce)
	signature := import_crypto_hmac([]byte(key), message)

	// Send auth message
	authPayload := map[string]interface{}{
		"version":   "1.0",
		"timestamp": timestamp,
		"nonce":     nonce,
		"signature": signature,
	}
	authPayloadBytes, _ := json.Marshal(authPayload)

	authMsg := map[string]interface{}{
		"type":    "AUTH",
		"payload": json.RawMessage(authPayloadBytes),
	}
	if err := encoder.Encode(authMsg); err != nil {
		return fmt.Errorf("failed to send auth: %w", err)
	}

	// Read auth response
	var response map[string]interface{}
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if response["type"] != "AUTH_OK" {
		return fmt.Errorf("authentication failed")
	}

	logger("Authenticated successfully")

	// Open and prepare file
	file, err := os.Open(rootfsPath)
	if err != nil {
		return fmt.Errorf("failed to open rootfs: %w", err)
	}
	defer file.Close()

	// Prepare data
	logger("Preparing data for transfer...")
	var dataToSend []byte
	hasher := newSHA256Hasher()

	if compress {
		// Compress the data
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		teeReader := io.TeeReader(file, hasher)
		if _, err := io.Copy(gzWriter, teeReader); err != nil {
			return fmt.Errorf("failed to compress data: %w", err)
		}
		gzWriter.Close()
		dataToSend = buf.Bytes()
	} else {
		// Read uncompressed
		dataToSend, err = io.ReadAll(io.TeeReader(file, hasher))
		if err != nil {
			return fmt.Errorf("failed to read rootfs: %w", err)
		}
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Send migration request
	reqPayload := map[string]interface{}{
		"version":     "1.0",
		"vm_name":     vmName,
		"vcpu":        vcpu,
		"memory_mb":   memoryMB,
		"kernel_args": kernelArgs,
		"dns_servers": dnsServers,
		"rootfs_size": fileInfo.Size(),
		"compressed":  compress,
		"checksum":    checksum,
	}
	reqPayloadBytes, _ := json.Marshal(reqPayload)

	migrateMsg := map[string]interface{}{
		"type":    "MIGRATE",
		"payload": json.RawMessage(reqPayloadBytes),
	}
	if err := encoder.Encode(migrateMsg); err != nil {
		return fmt.Errorf("failed to send migration request: %w", err)
	}

	// Wait for OK
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if response["type"] != "MIGRATE_OK" {
		return fmt.Errorf("migration rejected")
	}

	// Send data in chunks
	chunkSize := 1024 * 1024 // 1MB
	logger("Sending data (%d bytes, compressed: %v)...", len(dataToSend), compress)

	bytesTotal := int64(len(dataToSend))
	var bytesSent int64

	for offset := 0; offset < len(dataToSend); offset += chunkSize {
		end := offset + chunkSize
		if end > len(dataToSend) {
			end = len(dataToSend)
		}

		chunk := dataToSend[offset:end]
		chunkBytes, _ := json.Marshal(chunk)

		chunkMsg := map[string]interface{}{
			"type":    "CHUNK",
			"payload": json.RawMessage(chunkBytes),
		}
		if err := encoder.Encode(chunkMsg); err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}

		// Wait for ACK
		if err := decoder.Decode(&response); err != nil {
			return fmt.Errorf("failed to read chunk ACK: %w", err)
		}

		if response["type"] != "CHUNK_ACK" {
			return fmt.Errorf("unexpected response: %v", response["type"])
		}

		bytesSent += int64(len(chunk))

		if progressCb != nil {
			progressCb(float64(bytesSent)/float64(bytesTotal)*100, bytesSent, bytesTotal)
		}
	}

	// Send done
	doneMsg := map[string]interface{}{
		"type": "DONE",
	}
	if err := encoder.Encode(doneMsg); err != nil {
		return fmt.Errorf("failed to send done: %w", err)
	}

	// Wait for final ACK
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("failed to read final ACK: %w", err)
	}

	if response["type"] == "MIGRATE_FAIL" {
		return fmt.Errorf("migration failed on remote")
	}

	if response["type"] != "DONE_ACK" {
		return fmt.Errorf("unexpected final response: %v", response["type"])
	}

	logger("Migration completed successfully")
	return nil
}

// Crypto helper functions

func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func newSHA256Hasher() interface {
	io.Writer
	Sum([]byte) []byte
} {
	return sha256.New()
}

// MigrationServer handles incoming VM migration connections
type MigrationServer struct {
	listener   net.Listener
	port       int
	dataDir    string
	db         *database.DB
	vmMgr      *Manager
	logger     func(string, ...interface{})
	running    bool
	runMu      sync.Mutex
	migrations map[string]*MigrationStatus
	migMu      sync.RWMutex
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	ID               string     `json:"id"`
	VMID             string     `json:"vm_id,omitempty"`
	VMName           string     `json:"vm_name"`
	Direction        string     `json:"direction"` // "send" or "receive"
	RemoteHost       string     `json:"remote_host"`
	Status           string     `json:"status"` // "pending", "in_progress", "completed", "failed"
	Progress         float64    `json:"progress"`
	BytesTotal       int64      `json:"bytes_total"`
	BytesTransferred int64      `json:"bytes_transferred"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// NewMigrationServer creates a new migration server
func NewMigrationServer(port int, dataDir string, db *database.DB, vmMgr *Manager, logger func(string, ...interface{})) *MigrationServer {
	return &MigrationServer{
		port:       port,
		dataDir:    dataDir,
		db:         db,
		vmMgr:      vmMgr,
		logger:     logger,
		migrations: make(map[string]*MigrationStatus),
	}
}

// Start starts the migration server
func (s *MigrationServer) Start() error {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	if s.running {
		return fmt.Errorf("server already running")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}

	s.listener = listener
	s.running = true

	go s.acceptConnections()

	s.logger("Migration server started on port %d", s.port)
	return nil
}

// Stop stops the migration server
func (s *MigrationServer) Stop() error {
	s.runMu.Lock()
	defer s.runMu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}

	s.logger("Migration server stopped")
	return nil
}

// IsRunning returns whether the server is running
func (s *MigrationServer) IsRunning() bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running
}

// GetPort returns the server port
func (s *MigrationServer) GetPort() int {
	return s.port
}

// GetMigrations returns all migration statuses
func (s *MigrationServer) GetMigrations() []*MigrationStatus {
	s.migMu.RLock()
	defer s.migMu.RUnlock()
	list := make([]*MigrationStatus, 0, len(s.migrations))
	for _, m := range s.migrations {
		list = append(list, m)
	}
	return list
}

func (s *MigrationServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.runMu.Lock()
			running := s.running
			s.runMu.Unlock()
			if !running {
				return
			}
			s.logger("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *MigrationServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	s.logger("Migration connection from %s", remoteAddr)

	// Set read timeout for authentication
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	// Read auth message
	var authMsg map[string]interface{}
	if err := decoder.Decode(&authMsg); err != nil {
		s.logger("Failed to read auth message from %s: %v", remoteAddr, err)
		return
	}

	if authMsg["type"] != "AUTH" {
		s.sendError(encoder, "AUTH_FAIL", "expected AUTH message")
		return
	}

	// Parse auth payload
	payloadBytes, _ := json.Marshal(authMsg["payload"])
	var authPayload struct {
		Version   string `json:"version"`
		Timestamp int64  `json:"timestamp"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(payloadBytes, &authPayload); err != nil {
		s.sendError(encoder, "AUTH_FAIL", "invalid auth payload")
		return
	}

	// Verify authentication
	key := s.verifyAuth(&authPayload)
	if key == nil {
		s.logger("Authentication failed from %s", remoteAddr)
		s.sendError(encoder, "AUTH_FAIL", "authentication failed")
		return
	}

	s.logger("Authenticated connection from %s (key: %s)", remoteAddr, key.Name)

	// Update last used time
	s.db.UpdateMigrationKeyLastUsed(key.ID)

	// Send auth OK
	encoder.Encode(map[string]interface{}{"type": "AUTH_OK"})

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	// Handle migration request
	s.handleMigration(conn, decoder, encoder, key, remoteAddr)
}

func (s *MigrationServer) verifyAuth(auth *struct {
	Version   string `json:"version"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}) *database.MigrationKey {
	// Check version
	if auth.Version != "1.0" {
		return nil
	}

	// Check timestamp (within 5 minutes)
	now := time.Now().Unix()
	if auth.Timestamp < now-300 || auth.Timestamp > now+300 {
		return nil
	}

	// Get all keys and verify signature
	keys, err := s.db.ListMigrationKeys()
	if err != nil {
		return nil
	}

	for _, key := range keys {
		if !key.AllowPush {
			continue
		}

		// Compute expected signature using the stored hash as the key
		message := fmt.Sprintf("%d:%s", auth.Timestamp, auth.Nonce)
		mac := hmac.New(sha256.New, []byte(key.KeyHash))
		mac.Write([]byte(message))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		if hmac.Equal([]byte(auth.Signature), []byte(expectedSig)) {
			return key
		}
	}

	return nil
}

func (s *MigrationServer) handleMigration(conn net.Conn, decoder *json.Decoder, encoder *json.Encoder, key *database.MigrationKey, remoteAddr string) {
	// Read migration request
	var msg map[string]interface{}
	if err := decoder.Decode(&msg); err != nil {
		s.logger("Failed to read migration request: %v", err)
		return
	}

	if msg["type"] != "MIGRATE" {
		s.sendError(encoder, "MIGRATE_FAIL", "expected MIGRATE message")
		return
	}

	// Parse request
	payloadBytes, _ := json.Marshal(msg["payload"])
	var req struct {
		Version    string `json:"version"`
		VMName     string `json:"vm_name"`
		VCPU       int    `json:"vcpu"`
		MemoryMB   int    `json:"memory_mb"`
		KernelArgs string `json:"kernel_args"`
		DNSServers string `json:"dns_servers"`
		RootFSSize int64  `json:"rootfs_size"`
		Compressed bool   `json:"compressed"`
		Checksum   string `json:"checksum"`
	}
	if err := json.Unmarshal(payloadBytes, &req); err != nil {
		s.sendError(encoder, "MIGRATE_FAIL", "invalid migration request")
		return
	}

	s.logger("Receiving VM '%s' from %s (size: %d bytes, compressed: %v)", req.VMName, remoteAddr, req.RootFSSize, req.Compressed)

	// Create migration status
	migrationID := generateVMID()
	status := &MigrationStatus{
		ID:         migrationID,
		VMName:     req.VMName,
		Direction:  "receive",
		RemoteHost: remoteAddr,
		Status:     "in_progress",
		BytesTotal: req.RootFSSize,
		StartedAt:  time.Now(),
	}

	s.migMu.Lock()
	s.migrations[migrationID] = status
	s.migMu.Unlock()

	// Send OK to start receiving
	encoder.Encode(map[string]interface{}{"type": "MIGRATE_OK"})

	// Create temporary file for rootfs
	tmpFile, err := os.CreateTemp(s.dataDir, "migration-*.rootfs")
	if err != nil {
		s.sendError(encoder, "MIGRATE_FAIL", "failed to create temp file")
		status.Status = "failed"
		status.Error = err.Error()
		return
	}
	tmpPath := tmpFile.Name()

	// Receive chunks
	hasher := sha256.New()
	var totalReceived int64

	for {
		var chunkMsg map[string]interface{}
		if err := decoder.Decode(&chunkMsg); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			status.Status = "failed"
			status.Error = "failed to read chunk: " + err.Error()
			return
		}

		msgType := chunkMsg["type"].(string)

		if msgType == "DONE" {
			break
		}

		if msgType != "CHUNK" {
			tmpFile.Close()
			os.Remove(tmpPath)
			status.Status = "failed"
			status.Error = "unexpected message type: " + msgType
			return
		}

		// Decode chunk data (base64 in JSON)
		var chunkData []byte
		payloadBytes, _ := json.Marshal(chunkMsg["payload"])
		if err := json.Unmarshal(payloadBytes, &chunkData); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			status.Status = "failed"
			status.Error = "invalid chunk data"
			return
		}

		// Write to file
		if _, err := tmpFile.Write(chunkData); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			status.Status = "failed"
			status.Error = "failed to write chunk: " + err.Error()
			return
		}

		// Update hash
		hasher.Write(chunkData)
		totalReceived += int64(len(chunkData))

		// Update progress
		status.BytesTransferred = totalReceived
		if status.BytesTotal > 0 {
			status.Progress = float64(totalReceived) / float64(status.BytesTotal) * 100
		}

		// Send ACK
		encoder.Encode(map[string]interface{}{"type": "CHUNK_ACK"})
	}

	tmpFile.Close()

	// Decompress if needed
	finalPath := tmpPath
	if req.Compressed {
		decompressedPath := tmpPath + ".decompressed"
		if err := decompressFile(tmpPath, decompressedPath); err != nil {
			os.Remove(tmpPath)
			s.sendError(encoder, "MIGRATE_FAIL", "decompression failed: "+err.Error())
			status.Status = "failed"
			status.Error = "decompression failed: " + err.Error()
			return
		}
		os.Remove(tmpPath)
		finalPath = decompressedPath
	}

	// Import the VM
	vm, err := s.vmMgr.ImportMigratedVM(req.VMName, finalPath, req.VCPU, req.MemoryMB, req.KernelArgs, req.DNSServers)
	if err != nil {
		os.Remove(finalPath)
		s.sendError(encoder, "MIGRATE_FAIL", err.Error())
		status.Status = "failed"
		status.Error = err.Error()
		return
	}

	// Send done ACK
	encoder.Encode(map[string]interface{}{"type": "DONE_ACK"})

	// Update status
	now := time.Now()
	status.Status = "completed"
	status.VMID = vm.ID
	status.Progress = 100
	status.CompletedAt = &now

	s.logger("Successfully received VM '%s' from %s (ID: %s)", req.VMName, remoteAddr, vm.ID)
}

func (s *MigrationServer) sendError(encoder *json.Encoder, msgType, errMsg string) {
	payload, _ := json.Marshal(map[string]string{"error": errMsg})
	encoder.Encode(map[string]interface{}{
		"type":    msgType,
		"payload": json.RawMessage(payload),
	})
}

func decompressFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	gzReader, err := gzip.NewReader(srcFile)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, gzReader)
	return err
}
