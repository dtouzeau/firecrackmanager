package setup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/proxyconfig"
)

const (
	FirecrackerReleasesAPI = "https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest"
	DefaultConfigPath      = "/etc/firecrackmanager/settings.json"
	DefaultDataDir         = "/var/lib/firecrackmanager"
	DefaultLogDir          = "/var/log/firecrackmanager"
	DefaultPidFile         = "/var/run/firecrackmanager.pid"

	// Firecracker compatible kernel and rootfs from quickstart guide
	DebianKernelURL = "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"
	DebianRootFSURL = "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/rootfs/bionic.rootfs.ext4"

	DefaultNetworkSubnet  = "192.168.100.0/24"
	DefaultNetworkGateway = "192.168.100.1"
)

// Config represents the settings.json configuration
type Config struct {
	ListenPort                  int    `json:"listen_port"`
	ListenAddress               string `json:"listen_address"`
	DataDir                     string `json:"data_dir"`
	DatabasePath                string `json:"database_path"`
	LogFile                     string `json:"log_file"`
	PidFile                     string `json:"pid_file"`
	EnableHostNetworkManagement bool   `json:"enable_host_network_management"`
	BuilderDir                  string `json:"builder_dir"`
}

// SetupResult holds the result of each setup step
type SetupResult struct {
	Step    string
	Success bool
	Message string
	Error   error
}

// Logger function type
type Logger func(format string, args ...interface{})

// Setup performs the complete setup process
type Setup struct {
	logger  Logger
	config  *Config
	results []SetupResult
}

// NewSetup creates a new Setup instance
func NewSetup(logger Logger) *Setup {
	return &Setup{
		logger:  logger,
		results: make([]SetupResult, 0),
	}
}

// Run executes all setup steps
func (s *Setup) Run() error {
	s.logger("Starting FireCrackManager setup...")
	s.logger("")

	// Step 1: Check prerequisites
	if err := s.checkPrerequisites(); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// Step 2: Download and install Firecracker
	if err := s.installFirecracker(); err != nil {
		return fmt.Errorf("firecracker installation failed: %w", err)
	}

	// Step 3: Create data directories
	if err := s.createDirectories(); err != nil {
		return fmt.Errorf("directory creation failed: %w", err)
	}

	// Step 4: Configure KVM access
	if err := s.configureKVM(); err != nil {
		return fmt.Errorf("KVM configuration failed: %w", err)
	}

	// Step 5: Enable IP forwarding
	if err := s.enableIPForwarding(); err != nil {
		return fmt.Errorf("IP forwarding configuration failed: %w", err)
	}

	// Step 6: Configure NAT with iptables
	if err := s.configureNAT(); err != nil {
		return fmt.Errorf("NAT configuration failed: %w", err)
	}

	// Step 7: Create default configuration
	if err := s.createDefaultConfig(); err != nil {
		return fmt.Errorf("configuration creation failed: %w", err)
	}

	// Step 8: Create systemd service
	if err := s.createSystemdService(); err != nil {
		return fmt.Errorf("systemd service creation failed: %w", err)
	}

	// Step 9: Download kernel and rootfs
	if err := s.downloadImages(); err != nil {
		return fmt.Errorf("image download failed: %w", err)
	}

	// Step 10: Create default network
	if err := s.createDefaultNetwork(); err != nil {
		return fmt.Errorf("default network creation failed: %w", err)
	}

	s.logger("")
	s.logger("Setup completed successfully!")
	s.printSummary()

	return nil
}

// checkPrerequisites verifies system requirements
func (s *Setup) checkPrerequisites() error {
	s.logger("[1/10] Checking prerequisites...")

	// Check if running as root
	if os.Geteuid() != 0 {
		s.addResult("Root privileges", false, "Setup must be run as root", nil)
		return fmt.Errorf("setup must be run as root")
	}
	s.addResult("Root privileges", true, "Running as root", nil)

	// Check architecture
	if runtime.GOARCH != "amd64" {
		s.addResult("Architecture", false, fmt.Sprintf("Unsupported architecture: %s (requires amd64)", runtime.GOARCH), nil)
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}
	s.addResult("Architecture", true, "x86_64/amd64", nil)

	// Check /dev/kvm (warning if not available - VMs won't run but setup can continue)
	if _, err := os.Stat("/dev/kvm"); err != nil {
		s.addResult("/dev/kvm", false, "KVM device not found (VMs will not run)", err)
		s.logger("  WARNING: /dev/kvm not found. Setup will continue but VMs cannot be started.")
		s.logger("           Enable nested virtualization or run on bare metal for KVM support.")
	} else {
		s.addResult("/dev/kvm", true, "KVM device available", nil)
	}

	// Check /dev/net/tun
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		s.addResult("/dev/net/tun", false, "TUN device not found", err)
		return fmt.Errorf("/dev/net/tun not found: %w", err)
	}
	s.addResult("/dev/net/tun", true, "TUN device available", nil)

	// Check CPU virtualization (warning if not available)
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		cpuStr := string(cpuInfo)
		if !strings.Contains(cpuStr, "vmx") && !strings.Contains(cpuStr, "svm") {
			s.addResult("CPU virtualization", false, "No VT-x/AMD-V support (VMs will not run)", nil)
			s.logger("  WARNING: No VT-x/AMD-V support detected. VMs cannot be started.")
		} else {
			s.addResult("CPU virtualization", true, "VT-x/AMD-V supported", nil)
		}
	}

	// Check iptables
	if _, err := exec.LookPath("iptables"); err != nil {
		s.addResult("iptables", false, "iptables not found", err)
		return fmt.Errorf("iptables not found: %w", err)
	}
	s.addResult("iptables", true, "iptables available", nil)

	// Check curl or wget for downloads
	hasCurl := exec.Command("which", "curl").Run() == nil
	hasWget := exec.Command("which", "wget").Run() == nil
	if !hasCurl && !hasWget {
		s.logger("  Warning: Neither curl nor wget found, using Go HTTP client")
	}

	s.logger("  All prerequisites satisfied")
	return nil
}

// installFirecracker downloads and installs Firecracker binaries
func (s *Setup) installFirecracker() error {
	s.logger("[2/10] Installing Firecracker...")

	// Check if already installed
	if _, err := os.Stat("/usr/sbin/firecracker"); err == nil {
		// Get version
		out, _ := exec.Command("/usr/sbin/firecracker", "--version").Output()
		version := strings.TrimSpace(string(out))
		s.logger("  Firecracker already installed: %s", version)
		s.addResult("Firecracker installation", true, "Already installed: "+version, nil)
		return nil
	}

	// Get latest release info
	s.logger("  Fetching latest release information...")
	releaseInfo, err := s.getLatestRelease()
	if err != nil {
		s.addResult("Firecracker installation", false, "Failed to get release info", err)
		return err
	}

	// Find the correct asset for this architecture
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	var downloadURL string
	for _, asset := range releaseInfo.Assets {
		if strings.Contains(asset.Name, arch) && strings.HasSuffix(asset.Name, ".tgz") {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		s.addResult("Firecracker installation", false, "No suitable release found", nil)
		return fmt.Errorf("no suitable release found for architecture %s", arch)
	}

	s.logger("  Downloading %s...", releaseInfo.TagName)

	// Download to temp file
	tmpFile, err := os.CreateTemp("", "firecracker-*.tgz")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	// Create HTTP client with proxy support
	client, err := proxyconfig.NewHTTPClient(30 * time.Minute)
	if err != nil {
		s.addResult("Firecracker installation", false, "Failed to create HTTP client", err)
		return err
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		s.addResult("Firecracker installation", false, "Download failed", err)
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		s.addResult("Firecracker installation", false, "Download failed", err)
		return err
	}
	tmpFile.Close()

	// Extract tarball
	s.logger("  Extracting binaries...")
	if err := s.extractFirecracker(tmpFile.Name(), arch); err != nil {
		s.addResult("Firecracker installation", false, "Extraction failed", err)
		return err
	}

	// Verify installation
	if _, err := os.Stat("/usr/sbin/firecracker"); err != nil {
		s.addResult("Firecracker installation", false, "Installation verification failed", err)
		return fmt.Errorf("installation verification failed")
	}

	s.logger("  Firecracker installed successfully")
	s.addResult("Firecracker installation", true, "Version "+releaseInfo.TagName, nil)
	return nil
}

// extractFirecracker extracts binaries from the tarball and installs them
func (s *Setup) extractFirecracker(tarPath, arch string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// Pattern to match versioned binary names like firecracker-v1.10.0-x86_64 or firecracker-v1.13.1-x86_64
	versionPattern := regexp.MustCompile(`-v[\d.]+-` + arch + `$`)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		baseName := filepath.Base(header.Name)

		// Check if this is firecracker or jailer binary (not debug files, not yaml/json files)
		// Binary names are like: firecracker-v1.13.1-x86_64, jailer-v1.13.1-x86_64
		var destName string
		if versionPattern.MatchString(baseName) {
			if strings.HasPrefix(baseName, "firecracker-v") {
				destName = "firecracker"
			} else if strings.HasPrefix(baseName, "jailer-v") {
				destName = "jailer"
			} else {
				continue
			}
		} else {
			continue
		}

		destPath := filepath.Join("/usr/sbin", destName)
		s.logger("  Installing %s -> %s", baseName, destPath)

		outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return err
		}
		outFile.Close()
	}

	return nil
}

// GitHubRelease represents GitHub release API response
type GitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []GitHubAsset `json:"assets"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func (s *Setup) getLatestRelease() (*GitHubRelease, error) {
	client, err := proxyconfig.NewHTTPClient(30 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	req, err := http.NewRequest("GET", FirecrackerReleasesAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// GetLatestFirecrackerRelease returns the latest Firecracker release info from GitHub
func (s *Setup) GetLatestFirecrackerRelease() (*GitHubRelease, error) {
	return s.getLatestRelease()
}

// UpgradeFirecracker downloads and installs the latest Firecracker version
func (s *Setup) UpgradeFirecracker() error {
	s.logger("Checking for Firecracker updates...")

	// Get latest release info
	releaseInfo, err := s.getLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to get release info: %w", err)
	}

	// Get current version
	currentVersion := ""
	if _, err := os.Stat("/usr/sbin/firecracker"); err == nil {
		out, _ := exec.Command("/usr/sbin/firecracker", "--version").Output()
		currentVersion = strings.TrimSpace(string(out))
		if parts := strings.Fields(currentVersion); len(parts) >= 2 {
			currentVersion = parts[1]
		}
	}

	s.logger("Current version: %s", currentVersion)
	s.logger("Latest version: %s", releaseInfo.TagName)

	if currentVersion == releaseInfo.TagName {
		s.logger("Already running the latest version")
		return nil
	}

	// Find the correct asset for this architecture
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	var downloadURL string
	for _, asset := range releaseInfo.Assets {
		if strings.Contains(asset.Name, arch) && strings.HasSuffix(asset.Name, ".tgz") {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no suitable release found for architecture %s", arch)
	}

	s.logger("Downloading %s...", releaseInfo.TagName)

	// Download to temp file
	tmpFile, err := os.CreateTemp("", "firecracker-*.tgz")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	// Create HTTP client with proxy support
	client, err := proxyconfig.NewHTTPClient(30 * time.Minute)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	tmpFile.Close()

	// Extract tarball
	s.logger("Extracting binaries...")
	if err := s.extractFirecracker(tmpFile.Name(), arch); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Verify installation
	if _, err := os.Stat("/usr/sbin/firecracker"); err != nil {
		return fmt.Errorf("installation verification failed")
	}

	// Get new version
	out, _ := exec.Command("/usr/sbin/firecracker", "--version").Output()
	newVersion := strings.TrimSpace(string(out))

	s.logger("Firecracker upgraded successfully to %s", newVersion)
	return nil
}

// createDirectories creates all required directories
func (s *Setup) createDirectories() error {
	s.logger("[3/10] Creating data directories...")

	dirs := []string{
		DefaultDataDir,
		filepath.Join(DefaultDataDir, "kernels"),
		filepath.Join(DefaultDataDir, "rootfs"),
		filepath.Join(DefaultDataDir, "sockets"),
		DefaultLogDir,
		filepath.Dir(DefaultConfigPath),
		filepath.Dir(DefaultPidFile),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			s.addResult("Directory creation", false, fmt.Sprintf("Failed to create %s", dir), err)
			return err
		}
		s.logger("  Created %s", dir)
	}

	s.addResult("Directory creation", true, "All directories created", nil)
	return nil
}

// configureKVM sets up KVM device permissions
func (s *Setup) configureKVM() error {
	s.logger("[4/10] Configuring KVM access...")

	// Check if /dev/kvm exists
	info, err := os.Stat("/dev/kvm")
	if err != nil {
		s.logger("  Skipping KVM configuration: /dev/kvm not available")
		s.addResult("KVM configuration", false, "Skipped - KVM not available", nil)
		return nil
	}

	mode := info.Mode()
	s.logger("  Current /dev/kvm permissions: %s", mode.String())

	// Check if kvm group exists
	_, err = exec.Command("getent", "group", "kvm").Output()
	kvmGroupExists := err == nil

	if kvmGroupExists {
		// Ensure kvm group has access
		if err := os.Chmod("/dev/kvm", 0660); err != nil {
			s.logger("  Warning: Could not set /dev/kvm permissions: %v", err)
		}

		// Create udev rule for persistent permissions
		udevRule := `KERNEL=="kvm", GROUP="kvm", MODE="0660"`
		udevPath := "/etc/udev/rules.d/99-kvm.rules"

		if _, err := os.Stat(udevPath); os.IsNotExist(err) {
			if err := os.WriteFile(udevPath, []byte(udevRule+"\n"), 0644); err != nil {
				s.logger("  Warning: Could not create udev rule: %v", err)
			} else {
				s.logger("  Created udev rule: %s", udevPath)
			}
		}

		s.addResult("KVM configuration", true, "kvm group access configured", nil)
	} else {
		// No kvm group, set world-readable (less secure but functional)
		if err := os.Chmod("/dev/kvm", 0666); err != nil {
			s.addResult("KVM configuration", false, "Failed to set permissions", err)
			return err
		}
		s.logger("  Warning: kvm group not found, set world-readable permissions")
		s.addResult("KVM configuration", true, "World-readable permissions set", nil)
	}

	return nil
}

// enableIPForwarding enables IPv4 forwarding
func (s *Setup) enableIPForwarding() error {
	s.logger("[5/10] Enabling IP forwarding...")

	// Check current state
	current, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		s.addResult("IP forwarding", false, "Could not read current state", err)
		return err
	}

	if strings.TrimSpace(string(current)) == "1" {
		s.logger("  IP forwarding already enabled")
		s.addResult("IP forwarding", true, "Already enabled", nil)
	} else {
		// Enable temporarily
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
			s.addResult("IP forwarding", false, "Failed to enable", err)
			return err
		}
		s.logger("  Enabled IP forwarding")
	}

	// Make permanent via sysctl
	sysctlConf := "/etc/sysctl.d/99-firecrackmanager.conf"
	sysctlContent := "# FireCrackManager IP forwarding\nnet.ipv4.ip_forward = 1\n"

	if _, err := os.Stat(sysctlConf); os.IsNotExist(err) {
		if err := os.WriteFile(sysctlConf, []byte(sysctlContent), 0644); err != nil {
			s.logger("  Warning: Could not create sysctl config: %v", err)
		} else {
			s.logger("  Created %s for persistent configuration", sysctlConf)
		}
	}

	s.addResult("IP forwarding", true, "Enabled and persistent", nil)
	return nil
}

// configureNAT sets up iptables NAT rules
func (s *Setup) configureNAT() error {
	s.logger("[6/10] Configuring NAT with iptables...")

	// Get default route interface
	defaultIface, err := s.getDefaultInterface()
	if err != nil {
		s.logger("  Warning: Could not determine default interface: %v", err)
		defaultIface = "eth0"
	}
	s.logger("  Default interface: %s", defaultIface)

	// Check if MASQUERADE rule already exists
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", defaultIface, "-j", "MASQUERADE")
	if checkCmd.Run() == nil {
		s.logger("  NAT MASQUERADE rule already exists")
		s.addResult("NAT configuration", true, "Rules already exist", nil)
		return nil
	}

	// Add MASQUERADE rule
	s.logger("  Adding MASQUERADE rule for %s...", defaultIface)
	addCmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", defaultIface, "-j", "MASQUERADE")
	if out, err := addCmd.CombinedOutput(); err != nil {
		s.addResult("NAT configuration", false, "Failed to add MASQUERADE rule", fmt.Errorf("%s: %s", err, out))
		return fmt.Errorf("failed to add MASQUERADE rule: %s", out)
	}

	// Add FORWARD rules for bridge interfaces
	forwardRules := [][]string{
		{"-A", "FORWARD", "-i", "fcbr+", "-j", "ACCEPT"},
		{"-A", "FORWARD", "-o", "fcbr+", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, rule := range forwardRules {
		// Check if rule exists
		checkArgs := append([]string{"-C"}, rule[1:]...)
		if exec.Command("iptables", checkArgs...).Run() == nil {
			continue
		}

		// Add rule
		if out, err := exec.Command("iptables", rule...).CombinedOutput(); err != nil {
			s.logger("  Warning: Failed to add FORWARD rule: %s", out)
		}
	}

	// Save iptables rules
	s.saveIptablesRules()

	s.logger("  NAT configured successfully")
	s.addResult("NAT configuration", true, fmt.Sprintf("MASQUERADE on %s", defaultIface), nil)
	return nil
}

// getDefaultInterface returns the default route interface
func (s *Setup) getDefaultInterface() (string, error) {
	routes, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(routes), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}

	// Fallback: try to find an interface with an IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no default interface found")
}

// saveIptablesRules saves iptables rules persistently
func (s *Setup) saveIptablesRules() {
	// Try iptables-save
	saveCmd := exec.Command("iptables-save")
	output, err := saveCmd.Output()
	if err != nil {
		s.logger("  Warning: Could not save iptables rules: %v", err)
		return
	}

	// Save to file
	savePath := "/etc/iptables/rules.v4"
	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err == nil {
		if err := os.WriteFile(savePath, output, 0644); err != nil {
			s.logger("  Warning: Could not write iptables rules to %s: %v", savePath, err)
		} else {
			s.logger("  Saved iptables rules to %s", savePath)
		}
	}
}

// createDefaultConfig creates the default configuration file
func (s *Setup) createDefaultConfig() error {
	s.logger("[7/10] Creating default configuration...")

	s.config = &Config{
		ListenPort:    8080,
		ListenAddress: "0.0.0.0",
		DataDir:       DefaultDataDir,
		DatabasePath:  filepath.Join(DefaultDataDir, "firecrackmanager.db"),
		LogFile:       filepath.Join(DefaultLogDir, "firecrackmanager.log"),
		PidFile:       DefaultPidFile,
	}

	// Check if config already exists
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		s.logger("  Configuration file already exists: %s", DefaultConfigPath)
		s.addResult("Configuration", true, "Already exists", nil)
		return nil
	}

	// Create config directory
	if err := os.MkdirAll(filepath.Dir(DefaultConfigPath), 0755); err != nil {
		s.addResult("Configuration", false, "Failed to create directory", err)
		return err
	}

	// Write config
	data, err := json.MarshalIndent(s.config, "", "    ")
	if err != nil {
		s.addResult("Configuration", false, "Failed to marshal config", err)
		return err
	}

	if err := os.WriteFile(DefaultConfigPath, data, 0644); err != nil {
		s.addResult("Configuration", false, "Failed to write config", err)
		return err
	}

	s.logger("  Created %s", DefaultConfigPath)
	s.addResult("Configuration", true, DefaultConfigPath, nil)
	return nil
}

// createSystemdService creates the systemd service file
func (s *Setup) createSystemdService() error {
	s.logger("[8/10] Creating systemd service...")

	servicePath := "/etc/systemd/system/firecrackmanager.service"

	// Find the binary location
	binaryPath, err := exec.LookPath("firecrackmanager")
	if err != nil {
		// Try common locations
		for _, path := range []string{"/usr/local/bin/firecrackmanager", "/usr/bin/firecrackmanager", "./firecrackmanager"} {
			if _, err := os.Stat(path); err == nil {
				binaryPath = path
				break
			}
		}
	}

	if binaryPath == "" {
		binaryPath = "/usr/local/bin/firecrackmanager"
		s.logger("  Warning: Binary not found, using default path: %s", binaryPath)
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=FireCrackManager - MicroVM Management Daemon
After=network.target
Documentation=https://github.com/firecracker-microvm/firecracker

[Service]
Type=simple
ExecStart=%s -config %s
PIDFile=%s
Restart=on-failure
RestartSec=5
StandardOutput=append:%s
StandardError=append:%s

# Security settings - relaxed for image building features (chroot, mount, apt)
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false
PrivateTmp=false

# Required capabilities for VM management, networking, and image building
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_KILL CAP_NET_RAW CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_MKNOD CAP_FOWNER
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_KILL CAP_NET_RAW CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT CAP_MKNOD CAP_FOWNER

[Install]
WantedBy=multi-user.target
`, binaryPath, DefaultConfigPath, DefaultPidFile,
		filepath.Join(DefaultLogDir, "firecrackmanager.log"),
		filepath.Join(DefaultLogDir, "firecrackmanager.log"))

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		s.addResult("Systemd service", false, "Failed to write service file", err)
		return err
	}

	s.logger("  Created %s", servicePath)

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		s.logger("  Warning: Could not reload systemd: %v", err)
	} else {
		s.logger("  Reloaded systemd daemon")
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "firecrackmanager").Run(); err != nil {
		s.logger("  Warning: Could not enable service: %v", err)
	} else {
		s.logger("  Enabled firecrackmanager service")
	}

	s.addResult("Systemd service", true, "Service created and enabled", nil)
	return nil
}

// downloadImages downloads the kernel and rootfs images
func (s *Setup) downloadImages() error {
	s.logger("[9/10] Downloading kernel and rootfs images...")

	kernelPath := filepath.Join(DefaultDataDir, "kernels", "vmlinux.bin")
	rootfsPath := filepath.Join(DefaultDataDir, "rootfs", "bionic.rootfs.ext4")

	// Download kernel
	if _, err := os.Stat(kernelPath); os.IsNotExist(err) {
		s.logger("  Downloading kernel...")
		if err := s.downloadFile(DebianKernelURL, kernelPath); err != nil {
			s.addResult("Kernel download", false, "Download failed", err)
			return err
		}
		os.Chmod(kernelPath, 0755)
		s.logger("  Kernel downloaded: %s", kernelPath)
	} else {
		s.logger("  Kernel already exists: %s", kernelPath)
	}

	// Download rootfs
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		s.logger("  Downloading rootfs (this may take a while)...")
		if err := s.downloadFile(DebianRootFSURL, rootfsPath); err != nil {
			s.addResult("RootFS download", false, "Download failed", err)
			return err
		}
		s.logger("  RootFS downloaded: %s", rootfsPath)
	} else {
		s.logger("  RootFS already exists: %s", rootfsPath)
	}

	// Register images in database
	if err := s.registerImages(kernelPath, rootfsPath); err != nil {
		s.logger("  Warning: Could not register images in database: %v", err)
	}

	s.addResult("Image downloads", true, "Kernel and rootfs ready", nil)
	return nil
}

// downloadFile downloads a file from URL with progress
func (s *Setup) downloadFile(url, destPath string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	// Create HTTP client with proxy support
	client, err := proxyconfig.NewHTTPClient(30 * time.Minute)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %s", resp.Status)
	}

	tmpPath := destPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer out.Close()

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)
	lastPercent := -1

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				os.Remove(tmpPath)
				return writeErr
			}
			downloaded += int64(n)

			if total > 0 {
				percent := int(float64(downloaded) / float64(total) * 100)
				if percent != lastPercent && percent%10 == 0 {
					s.logger("    Progress: %d%%", percent)
					lastPercent = percent
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(tmpPath)
			return err
		}
	}

	out.Close()
	return os.Rename(tmpPath, destPath)
}

// registerImages registers downloaded images in the database
func (s *Setup) registerImages(kernelPath, rootfsPath string) error {
	dbPath := filepath.Join(DefaultDataDir, "firecrackmanager.db")
	db, err := database.New(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Check if kernel already registered
	kernels, _ := db.ListKernelImages()
	kernelExists := false
	for _, k := range kernels {
		if k.Path == kernelPath {
			kernelExists = true
			break
		}
	}

	if !kernelExists {
		kernelID := generateID()
		kernelInfo, _ := os.Stat(kernelPath)
		kernel := &database.KernelImage{
			ID:           kernelID,
			Name:         "vmlinux.bin",
			Version:      "4.14",
			Architecture: "x86_64",
			Path:         kernelPath,
			Size:         kernelInfo.Size(),
			IsDefault:    true,
		}
		if err := db.CreateKernelImage(kernel); err != nil {
			return err
		}
	}

	// Check if rootfs already registered
	rootfsList, _ := db.ListRootFS()
	rootfsExists := false
	for _, r := range rootfsList {
		if r.Path == rootfsPath {
			rootfsExists = true
			break
		}
	}

	if !rootfsExists {
		rootfsID := generateID()
		rootfsInfo, _ := os.Stat(rootfsPath)
		rootfs := &database.RootFS{
			ID:     rootfsID,
			Name:   "bionic.rootfs.ext4",
			Path:   rootfsPath,
			Size:   rootfsInfo.Size(),
			Format: "ext4",
		}
		if err := db.CreateRootFS(rootfs); err != nil {
			return err
		}
	}

	return nil
}

// createDefaultNetwork creates the default network configuration
func (s *Setup) createDefaultNetwork() error {
	s.logger("[10/10] Creating default network...")

	dbPath := filepath.Join(DefaultDataDir, "firecrackmanager.db")
	db, err := database.New(dbPath)
	if err != nil {
		s.addResult("Default network", false, "Database error", err)
		return err
	}
	defer db.Close()

	// Check if default network already exists
	existing, _ := db.GetNetworkByName("default")
	if existing != nil {
		s.logger("  Default network already exists")
		s.addResult("Default network", true, "Already exists", nil)
		return nil
	}

	// Create network
	networkID := generateID()
	bridgeName := "fcbr" + networkID[:6]

	network := &database.Network{
		ID:         networkID,
		Name:       "default",
		BridgeName: bridgeName,
		Subnet:     DefaultNetworkSubnet,
		Gateway:    DefaultNetworkGateway,
		EnableNAT:  true,
		Status:     "inactive",
	}

	if err := db.CreateNetwork(network); err != nil {
		s.addResult("Default network", false, "Failed to create network", err)
		return err
	}

	s.logger("  Created default network: %s (%s)", network.Name, network.Subnet)
	s.addResult("Default network", true, fmt.Sprintf("%s (%s)", network.Name, network.Subnet), nil)
	return nil
}

// Helper functions

func (s *Setup) addResult(step string, success bool, message string, err error) {
	s.results = append(s.results, SetupResult{
		Step:    step,
		Success: success,
		Message: message,
		Error:   err,
	})
}

func (s *Setup) printSummary() {
	s.logger("")
	s.logger("Setup Summary:")
	s.logger("==============")

	for _, r := range s.results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
		}
		s.logger("  [%s] %s: %s", status, r.Step, r.Message)
	}

	s.logger("")
	s.logger("Next steps:")
	s.logger("  1. Start the service:  systemctl start firecrackmanager")
	s.logger("  2. Access web UI:      http://localhost:8080")
	s.logger("  3. Default login:      admin / admin")
	s.logger("")
	s.logger("  Activate the default network before creating VMs:")
	s.logger("    curl -X POST http://localhost:8080/api/networks/{id}/activate")
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// LoadConfig loads configuration from settings.json
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenPort:    8080,
		ListenAddress: "0.0.0.0",
		DataDir:       DefaultDataDir,
		DatabasePath:  filepath.Join(DefaultDataDir, "firecrackmanager.db"),
		LogFile:       filepath.Join(DefaultLogDir, "firecrackmanager.log"),
		PidFile:       DefaultPidFile,
	}
}
