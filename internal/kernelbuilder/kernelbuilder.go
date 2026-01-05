package kernelbuilder

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/kernel"
)

const (
	// Kernel versions supported
	KernelVersion6x = "6.1"

	// Amazon Linux kernel repository
	ALKernelRepo = "https://github.com/amazonlinux/linux.git"

	// Firecracker kernel config base URL
	FCConfigBaseURL = "https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs"

	// Build states
	StatePending     = "pending"
	StateInstalling  = "installing_deps"
	StateCloning     = "cloning_repo"
	StateConfiguring = "configuring"
	StateCompiling   = "compiling"
	StateCompleted   = "completed"
	StateFailed      = "failed"
)

// BuildProgress tracks the progress of a kernel build
type BuildProgress struct {
	ID            string    `json:"id"`
	KernelVersion string    `json:"kernel_version"`
	State         string    `json:"state"`
	Progress      int       `json:"progress"` // 0-100
	CurrentStep   string    `json:"current_step"`
	Output        []string  `json:"output"` // Last N lines of output
	Error         string    `json:"error,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	KernelPath    string    `json:"kernel_path,omitempty"`
}

// Builder handles kernel compilation
type Builder struct {
	db          *database.DB
	dataDir     string
	buildDir    string
	logger      func(string, ...interface{})
	mu          sync.Mutex
	builds      map[string]*BuildProgress
	activeBuild string
}

// NewBuilder creates a new kernel builder
func NewBuilder(db *database.DB, dataDir string, logger func(string, ...interface{})) *Builder {
	buildDir := filepath.Join(dataDir, "kernel-build")
	return &Builder{
		db:       db,
		dataDir:  dataDir,
		buildDir: buildDir,
		logger:   logger,
		builds:   make(map[string]*BuildProgress),
	}
}

// GetBuildProgress returns the progress of a build
func (b *Builder) GetBuildProgress(buildID string) *BuildProgress {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.builds[buildID]
}

// GetActiveBuild returns the currently active build
func (b *Builder) GetActiveBuild() *BuildProgress {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.activeBuild != "" {
		return b.builds[b.activeBuild]
	}
	return nil
}

// IsBuilding returns true if a build is in progress
func (b *Builder) IsBuilding() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.activeBuild != ""
}

// StartBuild starts a kernel build in the background
func (b *Builder) StartBuild(version string) (*BuildProgress, error) {
	b.mu.Lock()
	if b.activeBuild != "" {
		b.mu.Unlock()
		return nil, fmt.Errorf("build already in progress: %s", b.activeBuild)
	}

	buildID := fmt.Sprintf("build-%d", time.Now().UnixNano())
	progress := &BuildProgress{
		ID:            buildID,
		KernelVersion: version,
		State:         StatePending,
		Progress:      0,
		CurrentStep:   "Initializing...",
		Output:        make([]string, 0),
		StartedAt:     time.Now(),
	}
	b.builds[buildID] = progress
	b.activeBuild = buildID
	b.mu.Unlock()

	// Start build in background
	go b.runBuild(buildID, version)

	return progress, nil
}

// runBuild executes the build process
func (b *Builder) runBuild(buildID, version string) {
	defer func() {
		b.mu.Lock()
		b.activeBuild = ""
		b.mu.Unlock()
	}()

	ctx := context.Background()

	// Step 1: Install dependencies (0-15%)
	if err := b.installDependencies(buildID); err != nil {
		b.failBuild(buildID, "Failed to install dependencies: "+err.Error())
		return
	}

	// Step 2: Clone/update kernel repository (15-30%)
	srcDir, err := b.cloneKernelRepo(buildID, version)
	if err != nil {
		b.failBuild(buildID, "Failed to clone repository: "+err.Error())
		return
	}

	// Step 3: Download and apply Firecracker config (30-40%)
	if err := b.configureKernel(buildID, srcDir, version); err != nil {
		b.failBuild(buildID, "Failed to configure kernel: "+err.Error())
		return
	}

	// Step 4: Compile kernel (40-95%)
	kernelPath, err := b.compileKernel(ctx, buildID, srcDir)
	if err != nil {
		b.failBuild(buildID, "Failed to compile kernel: "+err.Error())
		return
	}

	// Step 5: Install kernel to kernels directory (95-100%)
	finalPath, err := b.installKernel(buildID, kernelPath, version)
	if err != nil {
		b.failBuild(buildID, "Failed to install kernel: "+err.Error())
		return
	}

	// Mark as completed
	b.mu.Lock()
	if progress, ok := b.builds[buildID]; ok {
		progress.State = StateCompleted
		progress.Progress = 100
		progress.CurrentStep = "Build completed successfully"
		progress.CompletedAt = time.Now()
		progress.KernelPath = finalPath
	}
	b.mu.Unlock()

	b.logger("Kernel build completed: %s -> %s", version, finalPath)
}

// installDependencies installs required build dependencies
func (b *Builder) installDependencies(buildID string) error {
	b.updateProgress(buildID, StateInstalling, 0, "Installing build dependencies...")

	// Check if we're on Debian/Ubuntu or RHEL-based
	var cmd *exec.Cmd
	if _, err := os.Stat("/usr/bin/apt-get"); err == nil {
		// Debian/Ubuntu
		deps := []string{
			"build-essential", "libncurses-dev", "bison", "flex",
			"libssl-dev", "libelf-dev", "bc", "git", "wget", "cpio",
			"python3", "xz-utils", "lz4",
		}

		b.addOutput(buildID, "Updating package lists...")
		cmd = exec.Command("apt-get", "update")
		if err := b.runCommandWithOutput(buildID, cmd); err != nil {
			return fmt.Errorf("apt-get update failed: %v", err)
		}
		b.updateProgress(buildID, StateInstalling, 5, "Installing packages...")

		args := append([]string{"install", "-y"}, deps...)
		cmd = exec.Command("apt-get", args...)
		if err := b.runCommandWithOutput(buildID, cmd); err != nil {
			return fmt.Errorf("apt-get install failed: %v", err)
		}
	} else if _, err := os.Stat("/usr/bin/dnf"); err == nil {
		// Fedora/RHEL
		deps := []string{
			"gcc", "make", "ncurses-devel", "bison", "flex",
			"openssl-devel", "elfutils-libelf-devel", "bc", "git", "wget",
			"python3", "xz", "lz4",
		}

		args := append([]string{"install", "-y"}, deps...)
		cmd = exec.Command("dnf", args...)
		if err := b.runCommandWithOutput(buildID, cmd); err != nil {
			return fmt.Errorf("dnf install failed: %v", err)
		}
	} else {
		return fmt.Errorf("unsupported distribution: cannot find apt-get or dnf")
	}

	b.updateProgress(buildID, StateInstalling, 15, "Dependencies installed")
	return nil
}

// cloneKernelRepo clones or updates the Amazon Linux kernel repository
func (b *Builder) cloneKernelRepo(buildID, version string) (string, error) {
	b.updateProgress(buildID, StateCloning, 15, "Preparing kernel source...")

	// Create build directory
	if err := os.MkdirAll(b.buildDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create build directory: %v", err)
	}

	srcDir := filepath.Join(b.buildDir, fmt.Sprintf("linux-%s", version))

	// Check if repo already exists
	if _, err := os.Stat(filepath.Join(srcDir, ".git")); err == nil {
		b.addOutput(buildID, "Kernel source already exists, updating...")
		b.updateProgress(buildID, StateCloning, 18, "Fetching updates...")

		cmd := exec.Command("git", "fetch", "--all", "--tags")
		cmd.Dir = srcDir
		if err := b.runCommandWithOutput(buildID, cmd); err != nil {
			// If fetch fails, remove and re-clone
			os.RemoveAll(srcDir)
		} else {
			b.updateProgress(buildID, StateCloning, 25, "Checking out version...")
			// Checkout the appropriate tag
			tag, err := b.findKernelTag(srcDir, version)
			if err != nil {
				return "", err
			}
			cmd = exec.Command("git", "checkout", tag)
			cmd.Dir = srcDir
			if err := b.runCommandWithOutput(buildID, cmd); err != nil {
				return "", fmt.Errorf("failed to checkout tag %s: %v", tag, err)
			}
			b.updateProgress(buildID, StateCloning, 30, "Source ready")
			return srcDir, nil
		}
	}

	// Clone the repository
	b.addOutput(buildID, fmt.Sprintf("Cloning Amazon Linux kernel repository..."))
	b.updateProgress(buildID, StateCloning, 18, "Cloning repository (this may take several minutes)...")

	// Clone with depth=1 and specific branch for faster download
	cmd := exec.Command("git", "clone", "--depth", "100", "--branch", fmt.Sprintf("microvm-kernel-%s.y", version), ALKernelRepo, srcDir)
	if err := b.runCommandWithOutput(buildID, cmd); err != nil {
		// Try full clone if shallow clone fails
		b.addOutput(buildID, "Shallow clone failed, trying full clone...")
		cmd = exec.Command("git", "clone", ALKernelRepo, srcDir)
		if err := b.runCommandWithOutput(buildID, cmd); err != nil {
			return "", fmt.Errorf("failed to clone repository: %v", err)
		}
	}

	b.updateProgress(buildID, StateCloning, 25, "Finding kernel tag...")

	// Find and checkout the appropriate tag
	tag, err := b.findKernelTag(srcDir, version)
	if err != nil {
		return "", err
	}

	b.addOutput(buildID, fmt.Sprintf("Checking out tag: %s", tag))
	cmd = exec.Command("git", "checkout", tag)
	cmd.Dir = srcDir
	if err := b.runCommandWithOutput(buildID, cmd); err != nil {
		return "", fmt.Errorf("failed to checkout tag %s: %v", tag, err)
	}

	b.updateProgress(buildID, StateCloning, 30, "Source ready")
	return srcDir, nil
}

// findKernelTag finds the appropriate kernel tag for the version
func (b *Builder) findKernelTag(srcDir, version string) (string, error) {
	cmd := exec.Command("git", "tag", "-l", fmt.Sprintf("microvm-kernel-%s.*", version))
	cmd.Dir = srcDir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %v", err)
	}

	tags := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(tags) == 0 || tags[0] == "" {
		// Try to use the branch directly
		return fmt.Sprintf("microvm-kernel-%s.y", version), nil
	}

	// Return the latest tag
	return tags[len(tags)-1], nil
}

// configureKernel downloads and applies Firecracker kernel configuration
func (b *Builder) configureKernel(buildID, srcDir, version string) error {
	b.updateProgress(buildID, StateConfiguring, 30, "Downloading Firecracker kernel config...")

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	// Download the Firecracker kernel config
	configURL := fmt.Sprintf("%s/microvm-kernel-ci-%s-%s.config", FCConfigBaseURL, arch, version)
	b.addOutput(buildID, fmt.Sprintf("Downloading config from: %s", configURL))

	resp, err := http.Get(configURL)
	if err != nil {
		return fmt.Errorf("failed to download config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download config: HTTP %d", resp.StatusCode)
	}

	configData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}

	b.updateProgress(buildID, StateConfiguring, 33, "Applying kernel configuration...")

	// Write config to .config file
	configPath := filepath.Join(srcDir, ".config")
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	// Download additional config fragments
	configFragments := []string{"ci.config"}
	for _, fragment := range configFragments {
		fragURL := fmt.Sprintf("%s/%s", FCConfigBaseURL, fragment)
		resp, err := http.Get(fragURL)
		if err != nil {
			b.addOutput(buildID, fmt.Sprintf("Warning: failed to download %s: %v", fragment, err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fragData, _ := io.ReadAll(resp.Body)
			// Append fragment to config
			f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString("\n# Fragment: " + fragment + "\n")
				f.Write(fragData)
				f.Close()
			}
		}
	}

	b.updateProgress(buildID, StateConfiguring, 36, "Running olddefconfig...")

	// Run make olddefconfig to resolve any config inconsistencies
	cmd := exec.Command("make", "olddefconfig")
	cmd.Dir = srcDir
	if err := b.runCommandWithOutput(buildID, cmd); err != nil {
		return fmt.Errorf("make olddefconfig failed: %v", err)
	}

	b.updateProgress(buildID, StateConfiguring, 40, "Configuration complete")
	return nil
}

// compileKernel compiles the kernel
func (b *Builder) compileKernel(ctx context.Context, buildID, srcDir string) (string, error) {
	b.updateProgress(buildID, StateCompiling, 40, "Starting kernel compilation...")

	numCPU := runtime.NumCPU()
	b.addOutput(buildID, fmt.Sprintf("Compiling with %d parallel jobs...", numCPU))

	// Determine the kernel output file based on architecture
	arch := runtime.GOARCH
	var kernelFile string
	if arch == "amd64" || arch == "x86_64" {
		kernelFile = "vmlinux"
	} else {
		kernelFile = "arch/arm64/boot/Image"
	}

	// Run make with progress monitoring
	cmd := exec.Command("make", "-j", fmt.Sprintf("%d", numCPU), kernelFile)
	cmd.Dir = srcDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start compilation: %v", err)
	}

	// Monitor output and update progress
	go b.monitorCompilation(buildID, stdout, stderr)

	// Wait for compilation to complete
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("compilation failed: %v", err)
	}

	kernelPath := filepath.Join(srcDir, kernelFile)
	if _, err := os.Stat(kernelPath); os.IsNotExist(err) {
		return "", fmt.Errorf("kernel file not found after compilation: %s", kernelPath)
	}

	b.updateProgress(buildID, StateCompiling, 95, "Compilation complete")
	return kernelPath, nil
}

// monitorCompilation monitors the make output and estimates progress
func (b *Builder) monitorCompilation(buildID string, stdout, stderr io.Reader) {
	// Track compilation progress by counting compiled files
	compiledFiles := 0
	estimatedTotal := 2000 // Rough estimate of files to compile

	scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		b.addOutput(buildID, line)

		// Count compiled files to estimate progress
		if strings.HasPrefix(line, "  CC") || strings.HasPrefix(line, "  AS") ||
			strings.HasPrefix(line, "  LD") || strings.HasPrefix(line, "  AR") {
			compiledFiles++

			// Update progress (40-95% range for compilation)
			progress := 40 + (compiledFiles * 55 / estimatedTotal)
			if progress > 94 {
				progress = 94
			}

			// Update every 50 files to avoid too many updates
			if compiledFiles%50 == 0 {
				b.updateProgress(buildID, StateCompiling, progress,
					fmt.Sprintf("Compiling... (%d files)", compiledFiles))
			}
		}
	}
}

// installKernel copies the compiled kernel to the kernels directory
func (b *Builder) installKernel(buildID, kernelPath, version string) (string, error) {
	b.updateProgress(buildID, StateCompiling, 95, "Installing kernel...")

	kernelsDir := filepath.Join(b.dataDir, "kernels")
	if err := os.MkdirAll(kernelsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create kernels directory: %v", err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102")
	destName := fmt.Sprintf("vmlinux-%s-fc-%s.bin", version, timestamp)
	destPath := filepath.Join(kernelsDir, destName)

	// Copy kernel file
	src, err := os.Open(kernelPath)
	if err != nil {
		return "", fmt.Errorf("failed to open kernel: %v", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination: %v", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy kernel: %v", err)
	}

	// Get file info
	info, err := os.Stat(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat kernel: %v", err)
	}

	b.updateProgress(buildID, StateCompiling, 98, "Registering kernel...")

	// Register kernel in database
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	// Check virtio support in the compiled kernel
	hasVirtio := kernel.CheckVirtioSupport(destPath)

	// Generate unique ID for kernel
	hash := md5.Sum([]byte(destPath + time.Now().String()))
	kernelID := hex.EncodeToString(hash[:])

	kernelImg := &database.KernelImage{
		ID:            kernelID,
		Name:          destName,
		Version:       version,
		Architecture:  arch,
		Path:          destPath,
		Size:          info.Size(),
		IsDefault:     false,
		VirtioSupport: hasVirtio,
	}

	if err := b.db.CreateKernelImage(kernelImg); err != nil {
		return "", fmt.Errorf("failed to register kernel: %v", err)
	}

	b.addOutput(buildID, fmt.Sprintf("Kernel installed: %s (%d bytes)", destPath, info.Size()))
	return destPath, nil
}

// Helper functions

func (b *Builder) updateProgress(buildID, state string, progress int, step string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.builds[buildID]; ok {
		p.State = state
		p.Progress = progress
		p.CurrentStep = step
	}
}

func (b *Builder) addOutput(buildID, line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.builds[buildID]; ok {
		// Keep last 100 lines
		p.Output = append(p.Output, line)
		if len(p.Output) > 100 {
			p.Output = p.Output[len(p.Output)-100:]
		}
	}
}

func (b *Builder) failBuild(buildID, errMsg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.builds[buildID]; ok {
		p.State = StateFailed
		p.Error = errMsg
		p.CompletedAt = time.Now()
	}
	b.logger("Kernel build failed: %s", errMsg)
}

func (b *Builder) runCommandWithOutput(buildID string, cmd *exec.Cmd) error {
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	// Read output
	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for scanner.Scan() {
			b.addOutput(buildID, scanner.Text())
		}
	}()

	return cmd.Wait()
}

// GetSupportedVersions returns the list of kernel versions that can be built
func (b *Builder) GetSupportedVersions() []string {
	return []string{KernelVersion6x}
}

// CleanBuildDir removes the build directory to free space
func (b *Builder) CleanBuildDir() error {
	return os.RemoveAll(b.buildDir)
}
