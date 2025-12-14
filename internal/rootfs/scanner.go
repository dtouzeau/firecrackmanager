package rootfs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"firecrackmanager/internal/database"
)

// DiskType represents the type of a root filesystem
type DiskType string

const (
	DiskTypeSystem  DiskType = "system"  // Contains OS (init, kernel modules, etc.)
	DiskTypeData    DiskType = "data"    // Data-only disk
	DiskTypeUnknown DiskType = "unknown" // Could not determine
)

// ScanResult holds the result of scanning a rootfs
type ScanResult struct {
	ID          string    `json:"id"`
	DiskType    DiskType  `json:"disk_type"`
	HasInit     bool      `json:"has_init"`
	HasBinaries bool      `json:"has_binaries"`
	HasEtc      bool      `json:"has_etc"`
	HasLib      bool      `json:"has_lib"`
	InitSystem  string    `json:"init_system,omitempty"` // systemd, openrc, sysvinit, busybox, minimal
	OSRelease   string    `json:"os_release,omitempty"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// Scanner handles background scanning of root filesystems
type Scanner struct {
	db       *database.DB
	dataDir  string
	logger   func(string, ...interface{})
	stopCh   chan struct{}
	wg       sync.WaitGroup
	interval time.Duration
	mu       sync.Mutex
	scanning bool
}

// NewScanner creates a new rootfs scanner
func NewScanner(db *database.DB, dataDir string, logger func(string, ...interface{})) *Scanner {
	return &Scanner{
		db:       db,
		dataDir:  dataDir,
		logger:   logger,
		stopCh:   make(chan struct{}),
		interval: 5 * time.Minute, // Scan every 5 minutes
	}
}

// Start begins the background scanning task
func (s *Scanner) Start() {
	s.wg.Add(1)
	go s.scanLoop()
	s.logger("RootFS scanner started (interval: %v)", s.interval)
}

// Stop stops the background scanning task
func (s *Scanner) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger("RootFS scanner stopped")
}

// scanLoop runs the periodic scanning
func (s *Scanner) scanLoop() {
	defer s.wg.Done()

	// Initial scan on startup
	s.scanAll()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scanAll()
		}
	}
}

// scanAll scans all root filesystems that need scanning
func (s *Scanner) scanAll() {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return
	}
	s.scanning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
	}()

	fsList, err := s.db.ListRootFS()
	if err != nil {
		s.logger("Failed to list rootfs: %v", err)
		return
	}

	for _, fs := range fsList {
		// Skip if already scanned and file hasn't changed
		if fs.DiskType != "" && fs.DiskType != "unknown" {
			// Check if file was modified since last scan
			info, err := os.Stat(fs.Path)
			if err == nil && !info.ModTime().After(fs.ScannedAt) {
				continue
			}
		}

		result := s.ScanRootFS(fs)
		if result.Error == "" {
			fs.DiskType = string(result.DiskType)
			fs.InitSystem = result.InitSystem
			fs.OSRelease = result.OSRelease
			fs.ScannedAt = result.ScannedAt
			if err := s.db.UpdateRootFS(fs); err != nil {
				s.logger("Failed to update rootfs %s: %v", fs.ID, err)
			} else {
				s.logger("Scanned rootfs %s: type=%s, init=%s", fs.Name, result.DiskType, result.InitSystem)
			}
		} else {
			s.logger("Failed to scan rootfs %s: %v", fs.Name, result.Error)
		}
	}
}

// ScanRootFS scans a single root filesystem to determine its type
func (s *Scanner) ScanRootFS(fs *database.RootFS) *ScanResult {
	result := &ScanResult{
		ID:        fs.ID,
		DiskType:  DiskTypeUnknown,
		ScannedAt: time.Now(),
	}

	// Check if file exists
	if _, err := os.Stat(fs.Path); os.IsNotExist(err) {
		result.Error = "file not found"
		return result
	}

	// Create temporary mount point
	mountPoint, err := os.MkdirTemp("", "rootfs-scan-*")
	if err != nil {
		result.Error = fmt.Sprintf("failed to create mount point: %v", err)
		return result
	}
	defer os.RemoveAll(mountPoint)

	// Mount the filesystem (read-only)
	mounted := false

	// Try loop mount for ext4/raw images
	if err := s.mountImage(fs.Path, mountPoint); err != nil {
		result.Error = fmt.Sprintf("failed to mount: %v", err)
		return result
	}
	mounted = true
	defer func() {
		if mounted {
			s.unmount(mountPoint)
		}
	}()

	// Analyze the mounted filesystem
	result.HasInit = s.checkInit(mountPoint)
	result.HasBinaries = s.checkBinaries(mountPoint)
	result.HasEtc = s.checkEtc(mountPoint)
	result.HasLib = s.checkLib(mountPoint)
	result.InitSystem = s.detectInitSystem(mountPoint)
	result.OSRelease = s.readOSRelease(mountPoint)

	// Determine disk type based on findings
	if result.HasInit || (result.HasBinaries && result.HasEtc && result.HasLib) {
		result.DiskType = DiskTypeSystem
	} else if result.HasBinaries || result.HasEtc {
		// Has some system-like structure but incomplete
		result.DiskType = DiskTypeSystem
	} else {
		result.DiskType = DiskTypeData
	}

	return result
}

// mountImage mounts an image file to a mount point
func (s *Scanner) mountImage(imagePath, mountPoint string) error {
	// Use loop device to mount ext4 image
	cmd := exec.Command("mount", "-o", "loop,ro", imagePath, mountPoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

// unmount unmounts a mount point
func (s *Scanner) unmount(mountPoint string) error {
	cmd := exec.Command("umount", mountPoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try lazy unmount if regular unmount fails
		cmd = exec.Command("umount", "-l", mountPoint)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, string(output))
		}
	}
	return nil
}

// checkInit checks for init binaries
func (s *Scanner) checkInit(mountPoint string) bool {
	initPaths := []string{
		"sbin/init",
		"init",
		"usr/lib/systemd/systemd",
		"lib/systemd/systemd",
		"bin/busybox",
	}

	for _, p := range initPaths {
		fullPath := filepath.Join(mountPoint, p)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// checkBinaries checks for standard binary directories
func (s *Scanner) checkBinaries(mountPoint string) bool {
	binDirs := []string{"bin", "sbin", "usr/bin", "usr/sbin"}

	for _, dir := range binDirs {
		fullPath := filepath.Join(mountPoint, dir)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			// Check if directory has any executables
			entries, err := os.ReadDir(fullPath)
			if err == nil && len(entries) > 0 {
				return true
			}
		}
	}
	return false
}

// checkEtc checks for /etc directory with config files
func (s *Scanner) checkEtc(mountPoint string) bool {
	etcPath := filepath.Join(mountPoint, "etc")
	if info, err := os.Stat(etcPath); err == nil && info.IsDir() {
		// Check for typical system config files
		configFiles := []string{"passwd", "group", "fstab", "hosts", "resolv.conf"}
		for _, f := range configFiles {
			if _, err := os.Stat(filepath.Join(etcPath, f)); err == nil {
				return true
			}
		}
	}
	return false
}

// checkLib checks for /lib directory
func (s *Scanner) checkLib(mountPoint string) bool {
	libDirs := []string{"lib", "lib64", "usr/lib", "usr/lib64"}

	for _, dir := range libDirs {
		fullPath := filepath.Join(mountPoint, dir)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			entries, err := os.ReadDir(fullPath)
			if err == nil && len(entries) > 0 {
				return true
			}
		}
	}
	return false
}

// detectInitSystem detects which init system is used
func (s *Scanner) detectInitSystem(mountPoint string) string {
	// Check for systemd
	if _, err := os.Stat(filepath.Join(mountPoint, "usr/lib/systemd/systemd")); err == nil {
		return "systemd"
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "lib/systemd/systemd")); err == nil {
		return "systemd"
	}

	// Check for OpenRC
	if _, err := os.Stat(filepath.Join(mountPoint, "sbin/openrc")); err == nil {
		return "openrc"
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "etc/init.d")); err == nil {
		if entries, err := os.ReadDir(filepath.Join(mountPoint, "etc/init.d")); err == nil && len(entries) > 3 {
			// Has multiple init scripts, likely OpenRC or SysVinit
			if _, err := os.Stat(filepath.Join(mountPoint, "etc/rc.conf")); err == nil {
				return "openrc"
			}
		}
	}

	// Check for SysVinit
	if _, err := os.Stat(filepath.Join(mountPoint, "etc/inittab")); err == nil {
		return "sysvinit"
	}

	// Check for BusyBox init
	if _, err := os.Stat(filepath.Join(mountPoint, "bin/busybox")); err == nil {
		// Check if init is a symlink to busybox
		initPath := filepath.Join(mountPoint, "sbin/init")
		if target, err := os.Readlink(initPath); err == nil {
			if strings.Contains(target, "busybox") {
				return "busybox"
			}
		}
		// Even without symlink, if we have busybox and minimal structure, it's likely busybox init
		if _, err := os.Stat(filepath.Join(mountPoint, "init")); err == nil {
			return "busybox"
		}
		return "busybox"
	}

	// Check for minimal init (like from container conversions)
	if _, err := os.Stat(filepath.Join(mountPoint, "init")); err == nil {
		return "minimal"
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "sbin/init")); err == nil {
		return "minimal"
	}

	return ""
}

// readOSRelease reads the OS release information
func (s *Scanner) readOSRelease(mountPoint string) string {
	osReleasePaths := []string{
		"etc/os-release",
		"usr/lib/os-release",
	}

	for _, p := range osReleasePaths {
		fullPath := filepath.Join(mountPoint, p)
		data, err := os.ReadFile(fullPath)
		if err == nil {
			// Parse PRETTY_NAME or NAME
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					name := strings.TrimPrefix(line, "PRETTY_NAME=")
					name = strings.Trim(name, "\"")
					return name
				}
			}
			for _, line := range lines {
				if strings.HasPrefix(line, "NAME=") {
					name := strings.TrimPrefix(line, "NAME=")
					name = strings.Trim(name, "\"")
					return name
				}
			}
		}
	}

	return ""
}

// ScanSingle scans a single rootfs by ID (for on-demand scanning)
func (s *Scanner) ScanSingle(id string) (*ScanResult, error) {
	fs, err := s.db.GetRootFS(id)
	if err != nil {
		return nil, err
	}
	if fs == nil {
		return nil, fmt.Errorf("rootfs not found")
	}

	result := s.ScanRootFS(fs)
	if result.Error == "" {
		fs.DiskType = string(result.DiskType)
		fs.InitSystem = result.InitSystem
		fs.OSRelease = result.OSRelease
		fs.ScannedAt = result.ScannedAt
		if err := s.db.UpdateRootFS(fs); err != nil {
			return result, err
		}
	}

	return result, nil
}

// TriggerScan triggers an immediate scan of all rootfs
func (s *Scanner) TriggerScan() {
	go s.scanAll()
}
