package RegistryToFC

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"firecrackmanager/internal/futils"
	"firecrackmanager/internal/proxyconfig"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

/* ----- Public API ----- */

type ImageToFCOptions struct {
	OutputImage   string // required: path to write the ext4 (e.g., "./rootfs.ext4")
	SizeGiB       int64  // 0 = auto (from tar, + ~35% headroom, min 2GiB)
	Label         string // ext4 label (default "rootfs")
	InjectMinInit bool   // add /sbin/init that execs /bin/sh if none present
	InstallSSH    bool   // install OpenSSH server and haveged for entropy
	TempDir       string // working dir for the tar; if empty uses a temp dir
	ProxyURL      string // optional http(s) proxy for registry pulls (overrides global config)
}

type ImageToFCResult struct {
	ImageRef     string
	OutputImage  string
	EstimatedGiB int64
}

// ProgressCallback is called during conversion to report progress
type ProgressCallback func(percent int, message string)

// ImageToFirecracker pulls `imageRef` (e.g. "docker.io/library/debian:bookworm"),
// exports its merged filesystem, and builds an ext4 root disk for Firecracker.
func ImageToFirecracker(ctx context.Context, imageRef string, opt ImageToFCOptions) (*ImageToFCResult, error) {
	return ImageToFirecrackerWithProgress(ctx, imageRef, opt, nil)
}

// ImageToFirecrackerWithProgress is like ImageToFirecracker but reports progress via callback
func ImageToFirecrackerWithProgress(ctx context.Context, imageRef string, opt ImageToFCOptions, progress ProgressCallback) (*ImageToFCResult, error) {
	if err := requireRoot(); err != nil {
		return nil, err
	}

	reportProgress := func(pct int, msg string) {
		if progress != nil {
			progress(pct, msg)
		}
	}

	reportProgress(5, "Checking required commands")

	syncCmd := futils.FindProgram("sync")
	mkfsCmd := futils.FindProgram("mkfs.ext4")
	losetupCmd := futils.FindProgram("losetup")
	mountCmd := futils.FindProgram("mount")
	umountCmd := futils.FindProgram("umount")

	for _, b := range []string{mkfsCmd, losetupCmd, mountCmd, umountCmd} {
		if err := ensureCmd(b); err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(opt.OutputImage) == "" {
		return nil, errors.New("OutputImage is required")
	}
	if opt.Label == "" {
		opt.Label = "rootfs"
	}

	imgRef := normalizeRef(imageRef)

	// Prepare temp dir + export tar
	td := opt.TempDir
	var err error
	if td == "" {
		td, err = os.MkdirTemp("", "img2fc-*")
		if err != nil {
			return nil, fmt.Errorf("tempdir: %w", err)
		}
		defer func(path string) {
			_ = os.RemoveAll(path)
		}(td)
	}
	tarPath := filepath.Join(td, "rootfs.tar")

	reportProgress(10, "Preparing to pull image: "+imgRef)

	// Build crane options with proxy support
	craneOpts := []crane.Option{
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
		crane.WithContext(ctx),
	}

	// Determine proxy URL - use option override or global config
	proxyURL := strings.TrimSpace(opt.ProxyURL)
	if proxyURL == "" {
		proxyURL = proxyconfig.GetProxyURL()
	}

	if tr, err := proxyTransport(proxyURL); err != nil {
		return nil, err
	} else if tr != nil {
		craneOpts = append(craneOpts, crane.WithTransport(tr))
	}

	reportProgress(20, "Pulling image from registry")

	img, err := crane.Pull(imgRef, craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", imgRef, err)
	}

	// Extract container config for entrypoint/cmd
	var imgConfig *v1.Config
	if cfgFile, err := img.ConfigFile(); err == nil && cfgFile != nil {
		imgConfig = &cfgFile.Config
	}

	reportProgress(50, "Exporting filesystem")

	if err := func() error {
		f, err := os.Create(tarPath)
		if err != nil {
			return err
		}
		defer f.Close()
		return crane.Export(img, f)
	}(); err != nil {
		return nil, fmt.Errorf("export fs: %w", err)
	}

	reportProgress(60, "Calculating image size")

	// Size
	sizeGiB := opt.SizeGiB
	if sizeGiB == 0 {
		sz, err := tarUnpackedSize(tarPath)
		if err != nil {
			return nil, fmt.Errorf("measure tar: %w", err)
		}
		const GiB = int64(1024 * 1024 * 1024)
		sizeGiB = (sz + sz/3) / GiB
		if sizeGiB < 2 {
			sizeGiB = 2
		}
	}

	reportProgress(65, fmt.Sprintf("Creating %dGiB ext4 filesystem", sizeGiB))

	// Create ext4
	if err := createExt4(opt.OutputImage, sizeGiB, opt.Label, mkfsCmd); err != nil {
		return nil, err
	}

	reportProgress(70, "Mounting filesystem")

	// Mount + extract + optional init
	mnt, loop, err := mountLoop(opt.OutputImage, losetupCmd, mountCmd)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = runCmd(syncCmd)
		_ = umountPath(mnt, umountCmd)
		_ = detachLoop(loop, losetupCmd)
	}()

	reportProgress(75, "Extracting filesystem")

	if err := untarInto(tarPath, mnt); err != nil {
		return nil, err
	}

	reportProgress(80, "Finalizing")

	if opt.InjectMinInit {
		if err := installMinInit(mnt); err != nil {
			return nil, err
		}
	}

	// Install SSH and entropy tools if requested
	if opt.InstallSSH {
		reportProgress(85, "Installing SSH and entropy tools")
		if err := installSSHAndEntropy(mnt, reportProgress); err != nil {
			// Log warning but don't fail the conversion
			reportProgress(88, "Warning: SSH installation incomplete: "+err.Error())
		}
	}

	// Install container entrypoint as systemd service
	if imgConfig != nil {
		reportProgress(90, "Creating container entrypoint service")
		if err := installContainerEntrypoint(mnt, imgConfig, reportProgress); err != nil {
			reportProgress(92, "Warning: Entrypoint service creation incomplete: "+err.Error())
		}
	}

	// Configure DNS fallback (add public DNS servers)
	configureDNSFallback(mnt)

	_ = runCmd(syncCmd)

	reportProgress(100, "Complete")

	return &ImageToFCResult{
		ImageRef:     imgRef,
		OutputImage:  opt.OutputImage,
		EstimatedGiB: sizeGiB,
	}, nil
}

/* ----- Helpers (filesystem, tar, sys, proxy) ----- */

func normalizeRef(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		s = "docker.io/library/" + s
	}
	if !strings.Contains(s, "@sha256:") && !strings.Contains(s, ":") {
		s += ":latest"
	}
	return s
}

func proxyTransport(proxyURL string) (http.RoundTripper, error) {
	p := strings.TrimSpace(proxyURL)
	if p == "" {
		return nil, nil
	}
	u, err := url.Parse(p)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyURL(u)
	return t, nil
}

func createExt4(path string, sizeGiB int64, label string, mkfsCmd string) error {
	const GiB = int64(1024 * 1024 * 1024)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(sizeGiB * GiB); err != nil {
		return err
	}
	if mkfsCmd == "" {
		mkfsCmd = "mkfs.ext4"
	}
	return runCmd(mkfsCmd, "-F", "-L", label, path)
}

func mountLoop(img string, losetupCmd, mountCmd string) (mountpoint, loopdev string, err error) {
	if losetupCmd == "" {
		losetupCmd = futils.FindProgram("losetup")
	}
	out, err := exec.Command(losetupCmd, "--find", "--show", img).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("losetup: %v: %s", err, string(out))
	}
	loop := strings.TrimSpace(string(out))
	mnt, err := os.MkdirTemp("", "img2fc-mnt-")
	if err != nil {
		return "", "", err
	}
	if mountCmd == "" {
		mountCmd = futils.FindProgram("mount")
	}
	if err := runCmd(mountCmd, "-o", "rw", loop, mnt); err != nil {
		_ = detachLoop(loop, losetupCmd)
		return "", "", err
	}
	return mnt, loop, nil
}

func umountPath(mnt string, umountCmd string) error {
	if _, err := os.Stat(mnt); err == nil {
		if umountCmd == "" {
			umountCmd = futils.FindProgram("umount")
		}
		if err := runCmd(umountCmd, mnt); err != nil {
			return err
		}
		return os.RemoveAll(mnt)
	}
	return nil
}

func detachLoop(loop string, losetupCmd string) error {
	if loop == "" {
		return nil
	}
	if losetupCmd == "" {
		losetupCmd = futils.FindProgram("losetup")
	}
	return runCmd(losetupCmd, "-d", loop)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, buf.String())
	}
	return nil
}

func tarUnpackedSize(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var total int64
	tr := tar.NewReader(bufio.NewReader(f))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA {
			total += h.Size
		}
	}
	return total, nil
}

func untarInto(tarPath, dst string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	tr := tar.NewReader(bufio.NewReader(f))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, h.Name)

		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(h.Mode)); err != nil {
				return err
			}
			_ = os.Chown(target, h.Uid, h.Gid)
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			w, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(h.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, tr); err != nil {
				w.Close()
				return err
			}
			w.Close()
			_ = os.Chown(target, h.Uid, h.Gid)
			_ = os.Chtimes(target, h.AccessTime, h.ModTime)
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Remove existing symlink if present
			_ = os.Remove(target)
			if err := os.Symlink(h.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
			_ = os.Lchown(target, h.Uid, h.Gid)
		case tar.TypeLink:
			linkTarget := filepath.Join(dst, h.Linkname)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Link(linkTarget, target); err != nil {
				// fallback: copy
				if err := copyFile(linkTarget, target, fs.FileMode(h.Mode)); err != nil {
					return err
				}
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			mode := uint32(h.Mode)
			dev := int(mkdev(h.Devmajor, h.Devminor))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = syscall.Mknod(target, mode, dev)
			_ = os.Chown(target, h.Uid, h.Gid)
		}
	}
	return nil
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func mkdev(major, minor int64) uint64 { return (uint64(major) << 8) | uint64(minor) }

func installMinInit(root string) error {
	initPath := filepath.Join(root, "sbin", "init")
	if _, err := os.Stat(initPath); err == nil {
		return nil
	} // don't overwrite
	if err := os.MkdirAll(filepath.Dir(initPath), 0o755); err != nil {
		return err
	}
	script := `#!/bin/sh
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
echo "[img2fc] minimal init; exec /bin/sh"
exec /bin/sh
`
	return os.WriteFile(initPath, []byte(script), 0o755)
}

// installContainerEntrypoint creates a systemd service to run the container's entrypoint/cmd on boot
func installContainerEntrypoint(root string, config *v1.Config, reportProgress func(int, string)) error {
	if config == nil {
		return nil
	}

	// Combine entrypoint and cmd to form the full command
	var cmdParts []string
	cmdParts = append(cmdParts, config.Entrypoint...)
	cmdParts = append(cmdParts, config.Cmd...)

	if len(cmdParts) == 0 {
		return nil // No entrypoint or cmd defined
	}

	// Check if systemd exists
	systemdDir := filepath.Join(root, "etc/systemd/system")
	if !futils.FileExists(filepath.Join(root, "usr/lib/systemd/systemd")) &&
		!futils.FileExists(filepath.Join(root, "lib/systemd/systemd")) {
		// No systemd, skip
		return nil
	}

	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return err
	}

	// Build environment variables
	var envLines []string
	for _, env := range config.Env {
		// Escape special characters for systemd
		envLines = append(envLines, fmt.Sprintf("Environment=%s", env))
	}
	envSection := strings.Join(envLines, "\n")

	// Determine working directory
	workDir := config.WorkingDir
	if workDir == "" {
		workDir = "/"
	}

	// Determine user
	user := config.User
	if user == "" {
		user = "root"
	}

	// Build the ExecStart command
	// For complex commands, we create a wrapper script
	wrapperScript := filepath.Join(root, "usr/local/bin/container-entrypoint.sh")
	if err := os.MkdirAll(filepath.Dir(wrapperScript), 0755); err != nil {
		return err
	}

	// Create wrapper script that handles the command properly
	scriptContent := "#!/bin/sh\n"
	scriptContent += fmt.Sprintf("cd %s\n", workDir)
	scriptContent += "exec " + shellQuoteCommand(cmdParts) + "\n"

	if err := os.WriteFile(wrapperScript, []byte(scriptContent), 0755); err != nil {
		return err
	}

	// Create systemd service
	serviceName := "container-app.service"
	servicePath := filepath.Join(systemdDir, serviceName)

	serviceContent := fmt.Sprintf(`[Unit]
Description=Container Application
After=network.target

[Service]
Type=simple
User=%s
WorkingDirectory=%s
%s
ExecStart=/usr/local/bin/container-entrypoint.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, user, workDir, envSection)

	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}

	// Enable the service by creating symlink
	wantsDir := filepath.Join(systemdDir, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0755); err != nil {
		return err
	}

	symlinkPath := filepath.Join(wantsDir, serviceName)
	// Remove existing symlink if present
	os.Remove(symlinkPath)
	if err := os.Symlink(servicePath, symlinkPath); err != nil {
		// Try relative symlink
		os.Symlink("../"+serviceName, symlinkPath)
	}

	reportProgress(91, "Container entrypoint service created and enabled")
	return nil
}

// shellQuoteCommand properly quotes a command for shell execution
func shellQuoteCommand(parts []string) string {
	var quoted []string
	for _, p := range parts {
		// If part contains special chars, quote it
		if strings.ContainsAny(p, " \t\n\"'\\$`!") {
			p = "\"" + strings.ReplaceAll(strings.ReplaceAll(p, "\\", "\\\\"), "\"", "\\\"") + "\""
		}
		quoted = append(quoted, p)
	}
	return strings.Join(quoted, " ")
}

// configureDNSFallback adds public DNS servers to resolv.conf as fallback
func configureDNSFallback(root string) {
	resolvConf := filepath.Join(root, "etc/resolv.conf")

	// Read existing content if any
	existingContent := ""
	if data, err := os.ReadFile(resolvConf); err == nil {
		existingContent = string(data)
	}

	// Check if public DNS already configured
	if strings.Contains(existingContent, "8.8.8.8") || strings.Contains(existingContent, "1.1.1.1") {
		return
	}

	// Ensure /etc directory exists
	os.MkdirAll(filepath.Join(root, "etc"), 0755)

	// Add fallback DNS servers
	fallbackDNS := "\n# Fallback DNS servers added by FireCrackManager\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n"

	if existingContent != "" {
		// Append to existing
		os.WriteFile(resolvConf, []byte(existingContent+fallbackDNS), 0644)
	} else {
		// Create new with fallback
		os.WriteFile(resolvConf, []byte("# DNS configuration\n"+fallbackDNS), 0644)
	}
}

func ensureCmd(name string) error {
	if !futils.FileExists(name) {
		return fmt.Errorf("required command %q not found", name)
	}
	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (loop mount, chown, mknod require root)")
	}
	return nil
}

// ConvertFromRepoToFC is a convenience function to convert a container image to a Firecracker rootfs
func ConvertFromRepoToFC(fullname string, imageDirectory string) error {
	imageName := strings.ReplaceAll(fullname, " ", "")
	imageName = strings.ReplaceAll(imageName, "/", "-")
	imageName = strings.ReplaceAll(imageName, ":", "-")

	futils.CreateDir(imageDirectory)
	outputPath := fmt.Sprintf("%s/%s.ext4", imageDirectory, imageName)

	res, err := ImageToFirecracker(context.Background(), fullname, ImageToFCOptions{
		OutputImage:   outputPath,
		InjectMinInit: true,
	})
	if err != nil {
		return err
	}

	// Log success (caller can check the result)
	_ = res
	return nil
}

// ConvertFromRepoToFCWithProgress converts a container image with progress reporting
func ConvertFromRepoToFCWithProgress(fullname string, imageDirectory string, progress ProgressCallback) (*ImageToFCResult, error) {
	imageName := strings.ReplaceAll(fullname, " ", "")
	imageName = strings.ReplaceAll(imageName, "/", "-")
	imageName = strings.ReplaceAll(imageName, ":", "-")

	futils.CreateDir(imageDirectory)
	outputPath := fmt.Sprintf("%s/%s.ext4", imageDirectory, imageName)

	return ImageToFirecrackerWithProgress(context.Background(), fullname, ImageToFCOptions{
		OutputImage:   outputPath,
		InjectMinInit: true,
	}, progress)
}

// ConvertFromRepoToFCWithSSH converts a container image with SSH and entropy tools installed
func ConvertFromRepoToFCWithSSH(fullname string, imageDirectory string, progress ProgressCallback) (*ImageToFCResult, error) {
	imageName := strings.ReplaceAll(fullname, " ", "")
	imageName = strings.ReplaceAll(imageName, "/", "-")
	imageName = strings.ReplaceAll(imageName, ":", "-")

	futils.CreateDir(imageDirectory)
	outputPath := fmt.Sprintf("%s/%s.ext4", imageDirectory, imageName)

	return ImageToFirecrackerWithProgress(context.Background(), fullname, ImageToFCOptions{
		OutputImage:   outputPath,
		InjectMinInit: true,
		InstallSSH:    true,
	}, progress)
}

// installSSHAndEntropy installs OpenSSH server, haveged, and pre-seeds random for a mounted rootfs
func installSSHAndEntropy(mountPoint string, reportProgress func(int, string)) error {
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

	var pkgManager string
	var installSSHCmd, installHavegedCmd *exec.Cmd

	// Determine package manager and install commands
	if strings.Contains(osRelease, "Debian") || strings.Contains(osRelease, "Ubuntu") ||
		futils.FileExists(filepath.Join(mountPoint, "usr/bin/apt-get")) {
		pkgManager = "apt"
		reportProgress(86, "Detected Debian/Ubuntu, updating package lists...")

		// Update package lists first
		updateCmd := exec.Command("chroot", mountPoint, "apt-get", "update", "-qq")
		updateCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		updateCmd.Run()

		installSSHCmd = exec.Command("chroot", mountPoint, "apt-get", "install", "-y", "-qq", "openssh-server")
		installSSHCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

		installHavegedCmd = exec.Command("chroot", mountPoint, "apt-get", "install", "-y", "-qq", "haveged")
		installHavegedCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	} else if strings.Contains(osRelease, "Alpine") ||
		futils.FileExists(filepath.Join(mountPoint, "sbin/apk")) {
		pkgManager = "apk"
		reportProgress(86, "Detected Alpine, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "haveged")

	} else if strings.Contains(osRelease, "CentOS") || strings.Contains(osRelease, "Red Hat") ||
		strings.Contains(osRelease, "Fedora") ||
		futils.FileExists(filepath.Join(mountPoint, "usr/bin/dnf")) {
		pkgManager = "dnf"
		reportProgress(86, "Detected RHEL/CentOS/Fedora, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "haveged")

	} else if futils.FileExists(filepath.Join(mountPoint, "usr/bin/yum")) {
		pkgManager = "yum"
		reportProgress(86, "Detected RHEL/CentOS, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "haveged")

	} else {
		return fmt.Errorf("unsupported distribution: could not detect package manager")
	}

	// Install OpenSSH server
	reportProgress(87, "Installing OpenSSH server...")
	if installSSHCmd != nil {
		if output, err := installSSHCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install openssh-server: %v - %s", err, string(output))
		}
	}

	// Install haveged for entropy
	reportProgress(88, "Installing haveged for entropy...")
	if installHavegedCmd != nil {
		installHavegedCmd.Run() // Don't fail if haveged is not available
	}

	// Pre-seed the random seed file
	randomSeedDir := filepath.Join(mountPoint, "var/lib/systemd")
	os.MkdirAll(randomSeedDir, 0755)
	randomSeedFile := filepath.Join(randomSeedDir, "random-seed")
	randomData := make([]byte, 512)
	if _, err := rand.Read(randomData); err == nil {
		os.WriteFile(randomSeedFile, randomData, 0600)
	}

	// Enable services based on init system
	if futils.FileExists(filepath.Join(mountPoint, "usr/lib/systemd/systemd")) ||
		futils.FileExists(filepath.Join(mountPoint, "lib/systemd/systemd")) {
		reportProgress(89, "Enabling SSH and haveged in systemd...")
		exec.Command("chroot", mountPoint, "systemctl", "enable", "ssh").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "sshd").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "haveged").Run()
	}

	// For Alpine, enable OpenRC services or create BusyBox init.d scripts
	if pkgManager == "apk" {
		// Check if OpenRC is installed
		if futils.FileExists(filepath.Join(mountPoint, "sbin/openrc")) {
			reportProgress(89, "Enabling SSH and haveged in OpenRC...")
			exec.Command("chroot", mountPoint, "rc-update", "add", "sshd", "default").Run()
			exec.Command("chroot", mountPoint, "rc-update", "add", "haveged", "default").Run()
		} else {
			// No OpenRC - create init.d scripts for BusyBox init
			// These will be executed by the BusyBox inittab: ::wait:/bin/sh -c 'for s in /etc/init.d/S* ...'
			reportProgress(89, "Creating init.d scripts for BusyBox init (no OpenRC)...")
			initdDir := filepath.Join(mountPoint, "etc/init.d")
			os.MkdirAll(initdDir, 0755)

			// S10haveged - start haveged early for entropy
			havegedScript := `#!/bin/sh
case "$1" in
    start)
        [ -x /usr/sbin/haveged ] && /usr/sbin/haveged -w 1024
        ;;
    stop)
        killall haveged 2>/dev/null
        ;;
esac
`
			os.WriteFile(filepath.Join(initdDir, "S10haveged"), []byte(havegedScript), 0755)

			// S50sshd - start sshd after haveged
			sshdScript := `#!/bin/sh
case "$1" in
    start)
        [ -x /usr/sbin/sshd ] && /usr/sbin/sshd
        ;;
    stop)
        killall sshd 2>/dev/null
        ;;
esac
`
			os.WriteFile(filepath.Join(initdDir, "S50sshd"), []byte(sshdScript), 0755)
		}
	}

	// Generate host keys if they don't exist
	sshKeyDir := filepath.Join(mountPoint, "etc/ssh")
	if _, err := os.Stat(filepath.Join(sshKeyDir, "ssh_host_rsa_key")); os.IsNotExist(err) {
		reportProgress(90, "Generating SSH host keys...")
		exec.Command("chroot", mountPoint, "ssh-keygen", "-A").Run()
	}

	// Configure sshd_config
	sshdConfig := filepath.Join(sshKeyDir, "sshd_config")
	if data, err := os.ReadFile(sshdConfig); err == nil {
		config := string(data)
		modified := false

		if strings.Contains(config, "#PasswordAuthentication") {
			config = strings.ReplaceAll(config, "#PasswordAuthentication no", "PasswordAuthentication yes")
			config = strings.ReplaceAll(config, "#PasswordAuthentication yes", "PasswordAuthentication yes")
			modified = true
		}

		if strings.Contains(config, "#PermitRootLogin") {
			config = strings.ReplaceAll(config, "#PermitRootLogin prohibit-password", "PermitRootLogin yes")
			config = strings.ReplaceAll(config, "#PermitRootLogin yes", "PermitRootLogin yes")
			modified = true
		}

		if modified {
			os.WriteFile(sshdConfig, []byte(config), 0644)
		}
	}

	reportProgress(91, "SSH and entropy tools installed successfully")
	return nil
}
