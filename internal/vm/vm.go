package vm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	DefaultVCPU       = 1
	DefaultMemoryMB   = 512
	DefaultKernelArgs = "console=ttyS0 reboot=k panic=1 pci=off"
)

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
type Manager struct {
	db         *database.DB
	netMgr     *network.Manager
	dataDir    string
	socketDir  string
	mu         sync.RWMutex
	runningVMs map[string]*runningVM
	logger     func(string, ...interface{})
}

type runningVM struct {
	cmd        *exec.Cmd
	socketPath string
	tapFD      int
	cancel     context.CancelFunc
	// Console I/O
	consoleIn  io.WriteCloser
	consoleOut io.ReadCloser
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

	return &Manager{
		db:         db,
		netMgr:     netMgr,
		dataDir:    dataDir,
		socketDir:  socketDir,
		runningVMs: make(map[string]*runningVM),
		logger:     logger,
	}, nil
}

// StartVM starts a virtual machine
func (m *Manager) StartVM(vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already running
	if _, running := m.runningVMs[vmID]; running {
		return fmt.Errorf("VM %s is already running", vmID)
	}

	// Get VM from database
	vm, err := m.db.GetVM(vmID)
	if err != nil {
		return fmt.Errorf("failed to get VM: %w", err)
	}
	if vm == nil {
		return fmt.Errorf("VM %s not found", vmID)
	}

	// Verify kernel and rootfs exist
	if _, err := os.Stat(vm.KernelPath); err != nil {
		return fmt.Errorf("kernel not found: %s", vm.KernelPath)
	}
	if _, err := os.Stat(vm.RootFSPath); err != nil {
		return fmt.Errorf("rootfs not found: %s", vm.RootFSPath)
	}

	// Update DNS configuration in rootfs if DNS servers are specified
	if vm.DNSServers != "" {
		if err := m.updateRootFSDNS(vm.RootFSPath, vm.DNSServers); err != nil {
			m.logger("Warning: failed to update DNS in rootfs: %v", err)
		}
	}

	// Create socket path
	socketPath := filepath.Join(m.socketDir, fmt.Sprintf("%s.sock", vmID))

	// Remove old socket if exists
	os.Remove(socketPath)

	// Create TAP device if network is configured
	hasTAP := false
	if vm.NetworkID != "" && vm.TapDevice != "" {
		_, err := m.netMgr.CreateTAP(vm.TapDevice)
		if err != nil {
			return fmt.Errorf("failed to create TAP device: %w", err)
		}
		hasTAP = true

		// Bring TAP device up
		if err := m.netMgr.SetInterfaceUp(vm.TapDevice); err != nil {
			m.netMgr.DeleteTAP(vm.TapDevice)
			return fmt.Errorf("failed to bring TAP device up: %w", err)
		}

		// Add TAP to bridge
		net, err := m.db.GetNetwork(vm.NetworkID)
		if err == nil && net != nil {
			if err := m.netMgr.AddInterfaceToBridge(net.BridgeName, vm.TapDevice); err != nil {
				m.logger("Warning: failed to add TAP to bridge: %v", err)
			}
		}
	}

	// Create context for process management
	ctx, cancel := context.WithCancel(context.Background())

	// Start firecracker process
	cmd := exec.CommandContext(ctx, FirecrackerBinary,
		"--api-sock", socketPath,
	)

	// Set process group for proper cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Create pipes for console I/O
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		stdinPipe.Close()
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Combine stderr with stdout for console output
	cmd.Stderr = cmd.Stdout

	// Start the process
	if err := cmd.Start(); err != nil {
		cancel()
		stdinPipe.Close()
		stdoutPipe.Close()
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("failed to start firecracker: %w", err)
	}

	// Wait for socket to be available
	if err := m.waitForSocket(socketPath, 5*time.Second); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("firecracker socket not ready: %w", err)
	}

	// Configure the VM via API
	if err := m.configureVM(socketPath, vm); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(socketPath)
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("failed to configure VM: %w", err)
	}

	// Start the instance
	if err := m.startInstance(socketPath); err != nil {
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		os.Remove(socketPath)
		if hasTAP {
			m.netMgr.DeleteTAP(vm.TapDevice)
		}
		return fmt.Errorf("failed to start instance: %w", err)
	}

	// Track running VM
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
	m.db.AddVMLog(vmID, "info", fmt.Sprintf("VM started with PID %d", cmd.Process.Pid))

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

	// Remove from tracking
	delete(m.runningVMs, vmID)

	// Update database
	if vm != nil {
		vm.Status = "stopped"
		vm.PID = 0
		m.db.UpdateVM(vm)
		m.db.AddVMLog(vmID, "info", "VM stopped")
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
	delete(m.runningVMs, vmID)

	// Update status
	if vm != nil {
		if err != nil {
			vm.Status = "error"
			vm.ErrorMessage = err.Error()
			m.db.AddVMLog(vmID, "error", fmt.Sprintf("VM exited with error: %v", err))
		} else {
			vm.Status = "stopped"
			m.db.AddVMLog(vmID, "info", "VM process exited")
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

	// Configure boot source
	bootSource := BootSource{
		KernelImagePath: vm.KernelPath,
		BootArgs:        vm.KernelArgs,
	}
	if bootSource.BootArgs == "" {
		bootSource.BootArgs = DefaultKernelArgs
	}

	if err := m.apiPut(client, "/boot-source", bootSource); err != nil {
		return fmt.Errorf("failed to set boot source: %w", err)
	}

	// Configure root drive
	rootDrive := Drive{
		DriveID:      "rootfs",
		PathOnHost:   vm.RootFSPath,
		IsRootDevice: true,
		IsReadOnly:   false,
	}
	if err := m.apiPut(client, "/drives/rootfs", rootDrive); err != nil {
		return fmt.Errorf("failed to set root drive: %w", err)
	}

	// Configure additional attached disks
	additionalDisks, err := m.db.ListVMDisks(vm.ID)
	if err != nil {
		m.logger("Warning: failed to list VM disks: %v", err)
	} else {
		for _, disk := range additionalDisks {
			// Verify disk file exists
			if _, err := os.Stat(disk.Path); err != nil {
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
				m.logger("Warning: failed to attach disk %s: %v", disk.Name, err)
			} else {
				m.logger("Attached disk %s (%s) at %s", disk.Name, disk.DriveID, disk.MountPoint)
			}
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

	// Configure network if enabled
	if vm.NetworkID != "" && vm.TapDevice != "" {
		netIface := NetworkInterface{
			IfaceID:     "eth0",
			GuestMAC:    vm.MacAddress,
			HostDevName: vm.TapDevice,
		}
		if err := m.apiPut(client, "/network-interfaces/eth0", netIface); err != nil {
			return fmt.Errorf("failed to set network interface: %w", err)
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

	return info, nil
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
	SnapshotPath     string `json:"snapshot_path"`
	MemFilePath      string `json:"mem_file_path,omitempty"`
	EnableDiffSnapshots bool `json:"enable_diff_snapshots,omitempty"`
	ResumeVM         bool   `json:"resume_vm,omitempty"`
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

// DuplicateVM creates a copy of an existing VM with a new name
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

// ExportVM creates a .fcrack archive containing the VM configuration, rootfs, and snapshots
func (m *Manager) ExportVM(vmID string) (string, error) {
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

	// Add rootfs to archive
	rootfsName := "rootfs" + filepath.Ext(vm.RootFSPath)
	checksum, err := addFileToTar(tarWriter, vm.RootFSPath, rootfsName)
	if err != nil {
		os.Remove(exportPath)
		return "", fmt.Errorf("failed to add rootfs to archive: %w", err)
	}
	checksums[rootfsName] = checksum

	// Get snapshots
	snapshots, _ := m.ListSnapshots(vmID)
	var snapshotInfos []SnapshotInfo

	// Add snapshots to archive
	for _, snap := range snapshots {
		// Add vmstate
		vmstateName := fmt.Sprintf("snapshots/vmstate-%s.fc", snap.ID)
		checksum, err := addFileToTar(tarWriter, snap.SnapshotPath, vmstateName)
		if err != nil {
			m.logger("Warning: failed to add snapshot vmstate: %v", err)
			continue
		}
		checksums[vmstateName] = checksum

		// Add memfile
		memfileName := fmt.Sprintf("snapshots/memfile-%s.fc", snap.ID)
		checksum, err = addFileToTar(tarWriter, snap.MemFilePath, memfileName)
		if err != nil {
			m.logger("Warning: failed to add snapshot memfile: %v", err)
			continue
		}
		checksums[memfileName] = checksum

		snapshotInfos = append(snapshotInfos, *snap)
	}

	// Create manifest
	manifest := VMExportManifest{
		Version:      "1.0",
		ExportedAt:   time.Now().Format(time.RFC3339),
		Name:         vm.Name,
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

// GetExportPath returns the path to an exported .fcrack file
func (m *Manager) GetExportPath(filename string) string {
	return filepath.Join(m.dataDir, filename)
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

	// Calculate checksum while writing
	hash := md5.New()
	multiWriter := io.MultiWriter(tw, hash)

	if _, err := io.Copy(multiWriter, file); err != nil {
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
