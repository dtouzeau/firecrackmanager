package Compose2FC

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
	"sort"
	"strings"
	"syscall"
	"time"

	"firecrackmanager/internal/futils"
	"firecrackmanager/internal/proxyconfig"

	// compose-go v2
	"github.com/compose-spec/compose-go/v2/cli"
	composetypes "github.com/compose-spec/compose-go/v2/types"

	// No-daemon registry path
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

/*
Package Compose2FC builds an ext4 root filesystem for Firecracker from a service
defined in a docker-compose.yml. It can:
  - pull the service image directly from a registry (no Docker daemon required), or
  - optionally use a Docker/Podman daemon (UseDocker=true) to support compose 'build:'.

Then it:
  - exports the filesystem as a tar
  - creates an ext4 image and extracts the tar into it
  - (optionally) injects a tiny /sbin/init that execs /bin/sh

Requires Linux (root), e2fsprogs (mkfs.ext4), losetup, mount, umount.
*/

type Options struct {
	// Path to docker-compose.yml
	ComposePath string
	// Service name to use; if empty, the first service is used.
	ServiceName string
	// Output ext4 image path
	OutputImage string
	// Size of the ext4 image in GiB. If zero, auto-sizes from the exported tar (adds headroom).
	SizeGiB int64
	// Filesystem label for mkfs.ext4
	Label string
	// If true, install a tiny /sbin/init that execs /bin/sh (skipped if /sbin/init already exists)
	InjectMinInit bool
	// If true, install OpenSSH server and haveged for entropy
	InstallSSH bool
	// Temporary directory to store the exported tar; if empty uses os.MkdirTemp
	TempDir string
	// If false (default), pull directly from registry (no Docker daemon).
	// If true, use Docker/Podman daemon (required to support compose 'build:').
	UseDocker bool
	// Proxy URL (e.g. "http://user:pass@proxy.local:3128") for registry downloads
	// when UseDocker == false. Leave empty to use direct connection or environment
	// variables (HTTP_PROXY/HTTPS_PROXY) via default transport.
	RegistryProxy string
	// Environment variables to inject into the init script
	// These will be exported before the application starts
	Environment map[string]string
}

// Result contains build outputs & metadata.
type Result struct {
	ImageRef     string // final image reference used
	ServiceName  string
	OutputImage  string // path to ext4 image
	EstimatedGiB int64  // chosen size
}

// ProgressCallback is called during conversion to report progress
type ProgressCallback func(percent int, message string)

// BuildExt4FromCompose builds a Firecracker rootfs from a docker-compose service.
func BuildExt4FromCompose(ctx context.Context, opts Options) (*Result, error) {
	return BuildExt4FromComposeWithProgress(ctx, opts, nil)
}

// BuildExt4FromComposeWithProgress builds a Firecracker rootfs with progress reporting
func BuildExt4FromComposeWithProgress(ctx context.Context, opts Options, progress ProgressCallback) (*Result, error) {
	if err := requireRoot(); err != nil {
		return nil, err
	}

	reportProgress := func(pct int, msg string) {
		if progress != nil {
			progress(pct, msg)
		}
	}

	reportProgress(5, "Checking required commands")

	for _, bin := range []string{"mkfs.ext4", "losetup", "mount", "umount"} {
		cmd := futils.FindProgram(bin)
		if cmd == "" {
			return nil, fmt.Errorf("required command %q not found in PATH", bin)
		}
	}

	if opts.ComposePath == "" {
		return nil, errors.New("ComposePath is required")
	}
	if opts.OutputImage == "" {
		return nil, errors.New("OutputImage is required")
	}
	if opts.Label == "" {
		opts.Label = "rootfs"
	}

	reportProgress(10, "Parsing docker-compose.yml")

	// Resolve compose service
	imageRef, buildCfg, svcName, err := pickService(ctx, opts.ComposePath, opts.ServiceName)
	if err != nil {
		return nil, err
	}
	img := imageRef

	// Temp dir + tar destination for exported rootfs
	td := opts.TempDir
	if td == "" {
		td, err = os.MkdirTemp("", "compose2fc-*")
		if err != nil {
			return nil, fmt.Errorf("tempdir: %w", err)
		}
		defer os.RemoveAll(td)
	}
	tarPath := filepath.Join(td, "rootfs.tar")

	reportProgress(20, "Preparing to export image")

	// Export filesystem tar (daemon or registry) and get image config
	var imgConfig *ImageConfig

	if opts.UseDocker {
		// Support compose build: requires a Docker-compatible daemon.
		if buildCfg != nil {
			img = defaultBuildTag(svcName)
			reportProgress(25, "Building image via Docker")
			if err := dockerBuildViaCLI(buildCfg, img); err != nil {
				return nil, err
			}
		}
		reportProgress(40, "Exporting image via Docker")
		var err error
		imgConfig, err = exportImageTarViaDocker(ctx, img, tarPath)
		if err != nil {
			return nil, err
		}
	} else {
		// No daemon path: build: is unsupported.
		if buildCfg != nil {
			return nil, fmt.Errorf("service %q uses compose 'build:' which requires a Docker-compatible daemon; set UseDocker=true or provide an 'image:'", svcName)
		}

		// Build crane options (auth + optional proxy transport)
		craneOpts := []crane.Option{crane.WithAuthFromKeychain(authn.DefaultKeychain)}

		// Determine proxy URL
		proxyURL := strings.TrimSpace(opts.RegistryProxy)
		if proxyURL == "" {
			proxyURL = proxyconfig.GetProxyURL()
		}

		if tr, err := proxyTransport(proxyURL); err != nil {
			return nil, err
		} else if tr != nil {
			craneOpts = append(craneOpts, crane.WithTransport(tr))
		}

		reportProgress(30, "Pulling image from registry: "+img)
		var err error
		imgConfig, err = exportImageTarViaRegistry(img, tarPath, craneOpts...)
		if err != nil {
			return nil, err
		}
	}

	reportProgress(50, "Calculating image size")

	// Determine size
	sizeGiB := opts.SizeGiB
	if sizeGiB == 0 {
		unpacked, err := tarUnpackedSize(tarPath)
		if err != nil {
			return nil, fmt.Errorf("measure tar: %w", err)
		}
		// Add ~35% headroom + minimum 2GiB
		const GiB = int64(1024 * 1024 * 1024)
		sizeGiB = (unpacked + (unpacked / 3)) / GiB
		if sizeGiB < 2 {
			sizeGiB = 2
		}
	}

	reportProgress(60, fmt.Sprintf("Creating %dGiB ext4 filesystem", sizeGiB))

	if err := createExt4(opts.OutputImage, sizeGiB, opts.Label); err != nil {
		return nil, err
	}

	reportProgress(70, "Mounting filesystem")

	// Mount loop, extract, inject init (optional)
	mnt, loop, err := mountLoop(opts.OutputImage)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = runCmd(futils.FindProgram("sync"))
		_ = umountPath(mnt)
		_ = detachLoop(loop)
	}()

	reportProgress(80, "Extracting filesystem")

	if err := untarInto(tarPath, mnt); err != nil {
		return nil, err
	}

	if opts.InjectMinInit {
		reportProgress(85, "Installing minimal init")
		if err := installMinInit(mnt, opts.Environment, imgConfig); err != nil {
			return nil, err
		}
	}

	// Install SSH and entropy tools if requested
	if opts.InstallSSH {
		reportProgress(90, "Installing SSH and entropy tools")
		if err := installSSHAndEntropy(mnt, reportProgress); err != nil {
			// Log warning but don't fail the conversion
			reportProgress(92, "Warning: SSH installation incomplete: "+err.Error())
		}
	}

	// Install container entrypoint as systemd service
	if imgConfig != nil {
		reportProgress(94, "Creating container entrypoint service")
		if err := installContainerEntrypoint(mnt, imgConfig, opts.Environment, reportProgress); err != nil {
			reportProgress(96, "Warning: Entrypoint service creation incomplete: "+err.Error())
		}
	}

	// Configure DNS fallback (add public DNS servers)
	configureDNSFallback(mnt)

	_ = runCmd(futils.FindProgram("sync"))

	reportProgress(100, "Complete")

	return &Result{
		ImageRef:     img,
		ServiceName:  svcName,
		OutputImage:  opts.OutputImage,
		EstimatedGiB: sizeGiB,
	}, nil
}

/* -------------------- Compose handling -------------------- */

func pickService(ctx context.Context, composePath, prefer string) (image string, build *composetypes.BuildConfig, svcName string, err error) {
	opts, err := cli.NewProjectOptions(
		[]string{composePath},
		cli.WithWorkingDirectory(filepath.Dir(composePath)),
		cli.WithOsEnv,
	)
	if err != nil {
		return "", nil, "", err
	}

	project, err := opts.LoadProject(ctx) // replaces deprecated ProjectFromOptions
	if err != nil {
		return "", nil, "", err
	}
	if len(project.Services) == 0 {
		return "", nil, "", fmt.Errorf("no services in %s", composePath)
	}

	// prefer a specific service if provided
	if prefer != "" {
		if svc, ok := project.Services[prefer]; ok {
			name := svc.Name
			if name == "" {
				name = prefer
			}
			return svc.Image, svc.Build, name, nil
		}
		// help the user by listing available services
		var names []string
		for n := range project.Services {
			names = append(names, n)
		}
		sort.Strings(names)
		return "", nil, "", fmt.Errorf(`service %q not found. Available: %s`, prefer, strings.Join(names, ", "))
	}

	// default: pick an arbitrary first service (map iteration order is undefined)
	for name, svc := range project.Services {
		svcName := svc.Name
		if svcName == "" {
			svcName = name
		}
		return svc.Image, svc.Build, svcName, nil
	}
	return "", nil, "", fmt.Errorf("no services found")
}

func defaultBuildTag(svc string) string {
	return fmt.Sprintf("compose2fc:%s-%d", sanitize(svc), time.Now().Unix())
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func dockerBuildViaCLI(b *composetypes.BuildConfig, tag string) error {
	args := []string{"build", "-t", tag}
	if b.Dockerfile != "" {
		args = append(args, "-f", b.Dockerfile)
	}
	for k, v := range b.Args {
		if v == nil {
			args = append(args, "--build-arg", k)
		} else {
			args = append(args, "--build-arg", fmt.Sprintf("%s=%s", k, *v))
		}
	}
	ctxPath := "."
	if b.Context != "" {
		ctxPath = b.Context
	}
	args = append(args, ctxPath)
	return runCmdStreaming("docker", args...)
}

/* -------------------- Image creation & mount -------------------- */

func createExt4(path string, sizeGiB int64, label string) error {
	const GiB = int64(1024 * 1024 * 1024)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(sizeGiB * GiB); err != nil {
		return err
	}
	mkfsCmd := futils.FindProgram("mkfs.ext4")
	return runCmd(mkfsCmd, "-F", "-L", label, path)
}

func mountLoop(img string) (mountpoint, loopdev string, err error) {
	losetupCmd := futils.FindProgram("losetup")
	out, err := exec.Command(losetupCmd, "--find", "--show", img).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("losetup: %v: %s", err, string(out))
	}
	loop := strings.TrimSpace(string(out))
	mnt, err := os.MkdirTemp("", "compose2fc-mnt-")
	if err != nil {
		return "", "", err
	}
	mountCmd := futils.FindProgram("mount")
	if err := runCmd(mountCmd, "-o", "rw", loop, mnt); err != nil {
		_ = detachLoop(loop)
		return "", "", err
	}
	return mnt, loop, nil
}

func umountPath(mnt string) error {
	if _, err := os.Stat(mnt); err == nil {
		umountCmd := futils.FindProgram("umount")
		if err := runCmd(umountCmd, mnt); err != nil {
			return err
		}
		return os.RemoveAll(mnt)
	}
	return nil
}

func detachLoop(loop string) error {
	if loop == "" {
		return nil
	}
	losetupCmd := futils.FindProgram("losetup")
	return runCmd(losetupCmd, "-d", loop)
}

/* -------------------- Tar helpers -------------------- */

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
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			total += h.Size
		default:
			// dirs, symlinks, devices are tiny
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
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dst, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(hdr.Mode)); err != nil {
				return err
			}
			_ = os.Chown(target, hdr.Uid, hdr.Gid)
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			fw, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(fw, tr); err != nil {
				fw.Close()
				return err
			}
			fw.Close()
			_ = os.Chown(target, hdr.Uid, hdr.Gid)
			_ = os.Chtimes(target, hdr.AccessTime, hdr.ModTime)
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Remove existing symlink if present
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
			_ = os.Lchown(target, hdr.Uid, hdr.Gid)
		case tar.TypeLink:
			linkTarget := filepath.Join(dst, hdr.Linkname)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Link(linkTarget, target); err != nil {
				// fallback to copy
				if err := copyFile(linkTarget, target, fs.FileMode(hdr.Mode)); err != nil {
					return err
				}
			}
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			// Requires root; ignore errors if permissions are restricted.
			mode := uint32(hdr.Mode)
			dev := int(mkdev(hdr.Devmajor, hdr.Devminor))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = syscall.Mknod(target, mode, dev)
			_ = os.Chown(target, hdr.Uid, hdr.Gid)
		default:
			// ignore
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

func mkdev(major, minor int64) uint64 {
	return (uint64(major) << 8) | uint64(minor)
}

/* -------------------- Minimal init -------------------- */

func installMinInit(root string, environment map[string]string, imgConfig *ImageConfig) error {
	initPath := filepath.Join(root, "sbin", "init")
	if _, err := os.Stat(initPath); err == nil {
		// real init exists; don't replace
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(initPath), 0o755); err != nil {
		return err
	}

	// Build environment exports - start with image's environment
	var envExports strings.Builder
	envMap := make(map[string]string)

	// First, add image's environment variables
	if imgConfig != nil && len(imgConfig.Env) > 0 {
		for _, env := range imgConfig.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}
	}

	// Then, override with compose environment variables
	for k, v := range environment {
		envMap[k] = v
	}

	if len(envMap) > 0 {
		envExports.WriteString("\n# Environment variables\n")
		// Sort keys for consistent output
		keys := make([]string, 0, len(envMap))
		for k := range envMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := envMap[k]
			// Escape single quotes in values
			escapedVal := strings.ReplaceAll(v, "'", "'\\''")
			envExports.WriteString(fmt.Sprintf("export %s='%s'\n", k, escapedVal))
		}
		envExports.WriteString("\n")
	}

	// Determine the command to run
	var cmdLine string
	var workDir string

	if imgConfig != nil {
		workDir = imgConfig.WorkingDir

		// Build command from ENTRYPOINT + CMD (Docker convention)
		// ENTRYPOINT provides the executable, CMD provides default arguments
		var cmdParts []string
		if len(imgConfig.Entrypoint) > 0 {
			cmdParts = append(cmdParts, imgConfig.Entrypoint...)
		}
		if len(imgConfig.Cmd) > 0 {
			cmdParts = append(cmdParts, imgConfig.Cmd...)
		}

		if len(cmdParts) > 0 {
			// Quote each argument properly for shell
			var quotedParts []string
			for _, part := range cmdParts {
				// Escape single quotes and wrap in single quotes
				escaped := strings.ReplaceAll(part, "'", "'\\''")
				quotedParts = append(quotedParts, "'"+escaped+"'")
			}
			cmdLine = strings.Join(quotedParts, " ")
		}
	}

	// Fallback to /bin/sh if no command is specified
	if cmdLine == "" {
		cmdLine = "/bin/sh"
	}

	// Build the working directory change
	var cdLine string
	if workDir != "" {
		cdLine = fmt.Sprintf("cd '%s' 2>/dev/null || true\n", strings.ReplaceAll(workDir, "'", "'\\''"))
	}

	// Build user switch command if needed
	var userSwitch string
	if imgConfig != nil && imgConfig.User != "" && imgConfig.User != "root" && imgConfig.User != "0" {
		// Escape single quotes in the command for embedding in su -c '...'
		escapedCmd := strings.ReplaceAll(cmdLine, "'", "'\"'\"'")
		escapedCd := ""
		if workDir != "" {
			escapedCd = fmt.Sprintf("cd %s && ", strings.ReplaceAll(workDir, "'", "'\"'\"'"))
		}
		// Use su if available, otherwise try setpriv
		userSwitch = fmt.Sprintf(`
# Switch to user: %s
if command -v su >/dev/null 2>&1; then
    exec su -s /bin/sh '%s' -c '%s%s'
elif command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid='%s' --regid='%s' --init-groups -- %s
fi
# Fallback: run as root if user switch fails
`, imgConfig.User, imgConfig.User, escapedCd, escapedCmd, imgConfig.User, imgConfig.User, cmdLine)
	}

	script := fmt.Sprintf(`#!/bin/sh
# Compose2FC minimal init - compatible with containerized applications
set -e

echo "[init] Starting minimal init..."

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true

# Mount devtmpfs or create device nodes manually
if ! mount -t devtmpfs dev /dev 2>/dev/null; then
    # Fallback: create essential device nodes
    mkdir -p /dev
    [ -e /dev/null ] || mknod -m 666 /dev/null c 1 3
    [ -e /dev/zero ] || mknod -m 666 /dev/zero c 1 5
    [ -e /dev/full ] || mknod -m 666 /dev/full c 1 7
    [ -e /dev/random ] || mknod -m 666 /dev/random c 1 8
    [ -e /dev/urandom ] || mknod -m 666 /dev/urandom c 1 9
    [ -e /dev/tty ] || mknod -m 666 /dev/tty c 5 0
    [ -e /dev/console ] || mknod -m 600 /dev/console c 5 1
    [ -e /dev/ptmx ] || mknod -m 666 /dev/ptmx c 5 2
fi

# Create /dev/pts for PTY support
mkdir -p /dev/pts 2>/dev/null || true
mount -t devpts devpts /dev/pts -o gid=5,mode=620 2>/dev/null || true

# Create /dev/shm for shared memory (required by many apps including Node.js)
mkdir -p /dev/shm 2>/dev/null || true
mount -t tmpfs tmpfs /dev/shm -o mode=1777 2>/dev/null || true

# Setup /tmp with proper permissions
mkdir -p /tmp 2>/dev/null || true
chmod 1777 /tmp 2>/dev/null || true
mount -t tmpfs tmpfs /tmp -o mode=1777 2>/dev/null || true

# Setup /run for runtime data
mkdir -p /run 2>/dev/null || true
mount -t tmpfs tmpfs /run -o mode=755 2>/dev/null || true

# Setup /var/log for application logs
mkdir -p /var/log 2>/dev/null || true

# Set hostname
hostname firecracker 2>/dev/null || true

# Setup loopback interface (only if ip command exists)
if command -v ip >/dev/null 2>&1; then
    ip link set lo up 2>/dev/null || true
    # Setup networking if eth0 exists
    if [ -e /sys/class/net/eth0 ]; then
        ip link set eth0 up 2>/dev/null || true
        # Try DHCP if udhcpc is available and no IP is configured
        if ! ip addr show eth0 | grep -q 'inet '; then
            if command -v udhcpc >/dev/null 2>&1; then
                udhcpc -i eth0 -q -f -n 2>/dev/null &
            fi
        fi
    fi
elif command -v ifconfig >/dev/null 2>&1; then
    # Fallback to ifconfig if available
    ifconfig lo up 2>/dev/null || true
    if [ -e /sys/class/net/eth0 ]; then
        ifconfig eth0 up 2>/dev/null || true
    fi
fi

# Setup DNS resolver if /etc/resolv.conf doesn't exist or is empty
if [ ! -s /etc/resolv.conf ]; then
    # Try to get DNS from kernel command line or use defaults
    mkdir -p /etc 2>/dev/null || true
    cat > /etc/resolv.conf << 'DNSEOF'
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
DNSEOF
fi

# Create /etc/hosts if missing
if [ ! -f /etc/hosts ]; then
    cat > /etc/hosts << 'HOSTSEOF'
127.0.0.1   localhost
::1         localhost ip6-localhost ip6-loopback
HOSTSEOF
fi

# Ensure HOME is set
export HOME="${HOME:-/root}"
%s
echo "[init] Environment configured"
%s
echo "[init] Starting application in background: %s"

# Run application in background and log output
# Use subshell to prevent exec in userSwitch from replacing init
( %s%s ) > /var/log/app.log 2>&1 &
APP_PID=$!
echo "[init] Application started with PID: $APP_PID"

# Give the app a moment to start
sleep 1

# Check if app is still running
if kill -0 $APP_PID 2>/dev/null; then
    echo "[init] Application is running"
else
    echo "[init] Warning: Application may have exited, check /var/log/app.log"
fi

echo "[init] Starting shell on console..."
echo "=== Application running in background (PID: $APP_PID) ==="
echo "=== Logs: /var/log/app.log ==="
echo ""

# Ensure console is properly set up
exec 0</dev/console 2>/dev/null || true
exec 1>/dev/console 2>/dev/null || true
exec 2>/dev/console 2>/dev/null || true

# Start interactive shell with proper job control
exec setsid /bin/sh -i </dev/console >/dev/console 2>&1 || exec /bin/sh -i
`, envExports.String(), cdLine, cmdLine, userSwitch, cmdLine)
	return os.WriteFile(initPath, []byte(script), 0o755)
}

/* -------------------- Sys helpers -------------------- */

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

func runCmdStreaming(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println(sc.Text())
		}
	}()
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		fmt.Println(sc.Text())
	}
	return cmd.Wait()
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (loop mount, chown, mknod require root)")
	}
	return nil
}

/* -------------------- Image export backends -------------------- */

// ImageConfig holds the extracted configuration from a container image
type ImageConfig struct {
	Entrypoint []string
	Cmd        []string
	Env        []string
	WorkingDir string
	User       string
}

// exportImageTarViaRegistry pulls an image from a registry and writes a merged
// filesystem tar to destTar. Uses ~/.docker/config.json creds if present.
// Extra crane options can be supplied (e.g., transport with proxy).
// Returns the image configuration (ENTRYPOINT, CMD, ENV, etc.)
func exportImageTarViaRegistry(imageRef, destTar string, copts ...crane.Option) (*ImageConfig, error) {
	// Accept bare names like "redis" -> docker.io/library/redis"
	if !strings.Contains(imageRef, "/") && !strings.Contains(imageRef, ".") {
		imageRef = "docker.io/library/" + imageRef
	}

	// Pull the image
	img, err := crane.Pull(imageRef, copts...)
	if err != nil {
		return nil, fmt.Errorf("pull %q: %w", imageRef, err)
	}

	// Extract image configuration
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("get config: %w", err)
	}

	imgConfig := &ImageConfig{}
	if cfg != nil && cfg.Config.Entrypoint != nil {
		imgConfig.Entrypoint = cfg.Config.Entrypoint
	}
	if cfg != nil && cfg.Config.Cmd != nil {
		imgConfig.Cmd = cfg.Config.Cmd
	}
	if cfg != nil && cfg.Config.Env != nil {
		imgConfig.Env = cfg.Config.Env
	}
	if cfg != nil {
		imgConfig.WorkingDir = cfg.Config.WorkingDir
		imgConfig.User = cfg.Config.User
	}

	// Export merged filesystem as a tar
	f, err := os.Create(destTar)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := crane.Export(img, f); err != nil {
		return nil, err
	}
	return imgConfig, nil
}

// exportImageTarViaDocker exports an image via Docker CLI (fallback when SDK not available)
// Returns the image configuration (ENTRYPOINT, CMD, ENV, etc.)
func exportImageTarViaDocker(ctx context.Context, img, destTar string) (*ImageConfig, error) {
	// Pull image first
	pullCmd := exec.CommandContext(ctx, "docker", "pull", img)
	if out, err := pullCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker pull %q: %v: %s", img, err, string(out))
	}

	// Extract image configuration using docker inspect
	imgConfig := &ImageConfig{}
	inspectCmd := exec.CommandContext(ctx, "docker", "inspect", "--format",
		`{{json .Config.Entrypoint}}||{{json .Config.Cmd}}||{{json .Config.Env}}||{{.Config.WorkingDir}}||{{.Config.User}}`, img)
	inspectOut, err := inspectCmd.Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(inspectOut)), "||")
		if len(parts) >= 5 {
			// Parse Entrypoint (JSON array or null)
			if ep := strings.TrimSpace(parts[0]); ep != "null" && ep != "" {
				var entrypoint []string
				if err := parseJSONArray(ep, &entrypoint); err == nil {
					imgConfig.Entrypoint = entrypoint
				}
			}
			// Parse Cmd (JSON array or null)
			if cmd := strings.TrimSpace(parts[1]); cmd != "null" && cmd != "" {
				var cmdArr []string
				if err := parseJSONArray(cmd, &cmdArr); err == nil {
					imgConfig.Cmd = cmdArr
				}
			}
			// Parse Env (JSON array or null)
			if env := strings.TrimSpace(parts[2]); env != "null" && env != "" {
				var envArr []string
				if err := parseJSONArray(env, &envArr); err == nil {
					imgConfig.Env = envArr
				}
			}
			imgConfig.WorkingDir = strings.TrimSpace(parts[3])
			imgConfig.User = strings.TrimSpace(parts[4])
		}
	}

	// Create temporary container
	createCmd := exec.CommandContext(ctx, "docker", "create", img)
	createOut, err := createCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker create: %v", err)
	}
	containerID := strings.TrimSpace(string(createOut))

	// Ensure cleanup
	defer func() {
		rmCmd := exec.Command("docker", "rm", "-f", containerID)
		_ = rmCmd.Run()
	}()

	// Export container filesystem
	exportCmd := exec.CommandContext(ctx, "docker", "export", containerID)
	tarFile, err := os.Create(destTar)
	if err != nil {
		return nil, err
	}
	defer tarFile.Close()

	exportCmd.Stdout = tarFile
	if err := exportCmd.Run(); err != nil {
		return nil, fmt.Errorf("docker export: %v", err)
	}

	return imgConfig, nil
}

// parseJSONArray parses a JSON array string into a slice
func parseJSONArray(s string, v *[]string) error {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return nil
	}
	// Simple JSON array parsing without importing encoding/json
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	// Split by comma, handling quoted strings
	var result []string
	var current strings.Builder
	inQuote := false
	escaped := false
	for _, r := range s {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == ',' && !inQuote {
			if str := strings.TrimSpace(current.String()); str != "" {
				result = append(result, str)
			}
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if str := strings.TrimSpace(current.String()); str != "" {
		result = append(result, str)
	}
	*v = result
	return nil
}

/* -------------------- Proxy transport -------------------- */

// proxyTransport returns a RoundTripper that uses the provided proxy URL.
// If proxyURL is empty, it returns nil (meaning: use default transport / env).
func proxyTransport(proxyURL string) (http.RoundTripper, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	// Clone default transport to inherit sane defaults (including system env)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = http.ProxyURL(u)
	return base, nil
}

/* -------------------- Convenience helpers -------------------- */

// ServiceDetails contains full details of a compose service
type ServiceDetails struct {
	Name        string            `json:"name"`
	Image       string            `json:"image,omitempty"`
	HasBuild    bool              `json:"has_build"`
	Environment map[string]string `json:"environment,omitempty"`
	Ports       []string          `json:"ports,omitempty"`
	Command     string            `json:"command,omitempty"`
	Entrypoint  string            `json:"entrypoint,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	User        string            `json:"user,omitempty"`
}

// ListServices returns the list of service names in a docker-compose.yml
func ListServices(composePath string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return listComposeServices(ctx, composePath)
}

// GetServicesDetails returns detailed info about all services in a docker-compose.yml
func GetServicesDetails(composePath string) ([]ServiceDetails, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return getServicesDetails(ctx, composePath)
}

func getServicesDetails(ctx context.Context, composePath string) ([]ServiceDetails, error) {
	opts, err := cli.NewProjectOptions(
		[]string{composePath},
		cli.WithWorkingDirectory(filepath.Dir(composePath)),
		cli.WithOsEnv,
	)
	if err != nil {
		return nil, err
	}
	project, err := opts.LoadProject(ctx)
	if err != nil {
		return nil, err
	}

	var services []ServiceDetails
	for name, svc := range project.Services {
		svcName := svc.Name
		if svcName == "" {
			svcName = name
		}

		details := ServiceDetails{
			Name:     svcName,
			Image:    svc.Image,
			HasBuild: svc.Build != nil,
		}

		// Extract environment variables
		if svc.Environment != nil {
			details.Environment = make(map[string]string)
			for k, v := range svc.Environment {
				if v != nil {
					details.Environment[k] = *v
				} else {
					details.Environment[k] = ""
				}
			}
		}

		// Extract ports
		if len(svc.Ports) > 0 {
			for _, p := range svc.Ports {
				portStr := ""
				if p.HostIP != "" {
					portStr = p.HostIP + ":"
				}
				portStr += fmt.Sprintf("%s:%s", p.Published, p.Target)
				if p.Protocol != "" && p.Protocol != "tcp" {
					portStr += "/" + p.Protocol
				}
				details.Ports = append(details.Ports, portStr)
			}
		}

		// Extract command
		if len(svc.Command) > 0 {
			details.Command = strings.Join(svc.Command, " ")
		}

		// Extract entrypoint
		if len(svc.Entrypoint) > 0 {
			details.Entrypoint = strings.Join(svc.Entrypoint, " ")
		}

		// Extract working dir
		details.WorkingDir = svc.WorkingDir

		// Extract user
		details.User = svc.User

		services = append(services, details)
	}

	// Sort by name for consistent ordering
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	return services, nil
}

func listComposeServices(ctx context.Context, composePath string) ([]string, error) {
	opts, err := cli.NewProjectOptions(
		[]string{composePath},
		cli.WithWorkingDirectory(filepath.Dir(composePath)),
		cli.WithOsEnv,
	)
	if err != nil {
		return nil, err
	}
	project, err := opts.LoadProject(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(project.Services))
	for n := range project.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
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
		reportProgress(91, "Detected Debian/Ubuntu, updating package lists...")

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
		reportProgress(91, "Detected Alpine, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "apk", "add", "--no-cache", "haveged")

	} else if strings.Contains(osRelease, "CentOS") || strings.Contains(osRelease, "Red Hat") ||
		strings.Contains(osRelease, "Fedora") ||
		futils.FileExists(filepath.Join(mountPoint, "usr/bin/dnf")) {
		pkgManager = "dnf"
		reportProgress(91, "Detected RHEL/CentOS/Fedora, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "dnf", "install", "-y", "haveged")

	} else if futils.FileExists(filepath.Join(mountPoint, "usr/bin/yum")) {
		pkgManager = "yum"
		reportProgress(91, "Detected RHEL/CentOS, installing packages...")

		installSSHCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "openssh-server")
		installHavegedCmd = exec.Command("chroot", mountPoint, "yum", "install", "-y", "haveged")

	} else {
		return fmt.Errorf("unsupported distribution: could not detect package manager")
	}

	// Install OpenSSH server
	reportProgress(92, "Installing OpenSSH server...")
	if installSSHCmd != nil {
		if output, err := installSSHCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install openssh-server: %v - %s", err, string(output))
		}
	}

	// Install haveged for entropy
	reportProgress(93, "Installing haveged for entropy...")
	if installHavegedCmd != nil {
		installHavegedCmd.Run()
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
		reportProgress(94, "Enabling SSH and haveged in systemd...")
		exec.Command("chroot", mountPoint, "systemctl", "enable", "ssh").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "sshd").Run()
		exec.Command("chroot", mountPoint, "systemctl", "enable", "haveged").Run()
	}

	// For Alpine, enable OpenRC services
	if pkgManager == "apk" {
		reportProgress(94, "Enabling SSH and haveged in OpenRC...")
		exec.Command("chroot", mountPoint, "rc-update", "add", "sshd", "default").Run()
		exec.Command("chroot", mountPoint, "rc-update", "add", "haveged", "default").Run()
	}

	// Generate host keys if they don't exist
	sshKeyDir := filepath.Join(mountPoint, "etc/ssh")
	if _, err := os.Stat(filepath.Join(sshKeyDir, "ssh_host_rsa_key")); os.IsNotExist(err) {
		reportProgress(95, "Generating SSH host keys...")
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

	reportProgress(96, "SSH and entropy tools installed successfully")
	return nil
}

// installContainerEntrypoint creates a systemd service to run the container's entrypoint/cmd on boot
func installContainerEntrypoint(root string, config *ImageConfig, extraEnv map[string]string, reportProgress func(int, string)) error {
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

	// Build environment variables from image config
	var envLines []string
	for _, env := range config.Env {
		envLines = append(envLines, fmt.Sprintf("Environment=%s", env))
	}
	// Add extra environment variables
	for k, v := range extraEnv {
		envLines = append(envLines, fmt.Sprintf("Environment=%s=%s", k, v))
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

	// Build the ExecStart command - create a wrapper script
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
	os.Remove(symlinkPath) // Remove existing symlink if present
	if err := os.Symlink(servicePath, symlinkPath); err != nil {
		// Try relative symlink
		os.Symlink("../"+serviceName, symlinkPath)
	}

	reportProgress(95, "Container entrypoint service created and enabled")
	return nil
}

// shellQuoteCommand properly quotes a command for shell execution
func shellQuoteCommand(parts []string) string {
	var quoted []string
	for _, p := range parts {
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

	existingContent := ""
	if data, err := os.ReadFile(resolvConf); err == nil {
		existingContent = string(data)
	}

	// Check if public DNS already configured
	if strings.Contains(existingContent, "8.8.8.8") || strings.Contains(existingContent, "1.1.1.1") {
		return
	}

	os.MkdirAll(filepath.Join(root, "etc"), 0755)

	fallbackDNS := "\n# Fallback DNS servers added by FireCrackManager\nnameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n"

	if existingContent != "" {
		os.WriteFile(resolvConf, []byte(existingContent+fallbackDNS), 0644)
	} else {
		os.WriteFile(resolvConf, []byte("# DNS configuration\n"+fallbackDNS), 0644)
	}
}
