package Compose2FC

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
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
	// Temporary directory to store the exported tar; if empty uses os.MkdirTemp
	TempDir string
	// If false (default), pull directly from registry (no Docker daemon).
	// If true, use Docker/Podman daemon (required to support compose 'build:').
	UseDocker bool
	// Proxy URL (e.g. "http://user:pass@proxy.local:3128") for registry downloads
	// when UseDocker == false. Leave empty to use direct connection or environment
	// variables (HTTP_PROXY/HTTPS_PROXY) via default transport.
	RegistryProxy string
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

	// Export filesystem tar (daemon or registry)
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
		if err := exportImageTarViaDocker(ctx, img, tarPath); err != nil {
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
		if err := exportImageTarViaRegistry(img, tarPath, craneOpts...); err != nil {
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
		reportProgress(90, "Installing minimal init")
		if err := installMinInit(mnt); err != nil {
			return nil, err
		}
	}

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

func installMinInit(root string) error {
	initPath := filepath.Join(root, "sbin", "init")
	if _, err := os.Stat(initPath); err == nil {
		// real init exists; don't replace
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(initPath), 0o755); err != nil {
		return err
	}
	script := `#!/bin/sh
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
echo "[compose2fc] minimal init started; exec /bin/sh"
exec /bin/sh
`
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

// exportImageTarViaRegistry pulls an image from a registry and writes a merged
// filesystem tar to destTar. Uses ~/.docker/config.json creds if present.
// Extra crane options can be supplied (e.g., transport with proxy).
func exportImageTarViaRegistry(imageRef, destTar string, copts ...crane.Option) error {
	// Accept bare names like "redis" -> docker.io/library/redis"
	if !strings.Contains(imageRef, "/") && !strings.Contains(imageRef, ".") {
		imageRef = "docker.io/library/" + imageRef
	}

	// Pull the image
	img, err := crane.Pull(imageRef, copts...)
	if err != nil {
		return fmt.Errorf("pull %q: %w", imageRef, err)
	}

	// Export merged filesystem as a tar
	f, err := os.Create(destTar)
	if err != nil {
		return err
	}
	defer f.Close()
	return crane.Export(img, f)
}

// exportImageTarViaDocker exports an image via Docker CLI (fallback when SDK not available)
func exportImageTarViaDocker(ctx context.Context, img, destTar string) error {
	// Pull image first
	pullCmd := exec.CommandContext(ctx, "docker", "pull", img)
	if out, err := pullCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker pull %q: %v: %s", img, err, string(out))
	}

	// Create temporary container
	createCmd := exec.CommandContext(ctx, "docker", "create", img)
	createOut, err := createCmd.Output()
	if err != nil {
		return fmt.Errorf("docker create: %v", err)
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
		return err
	}
	defer tarFile.Close()

	exportCmd.Stdout = tarFile
	if err := exportCmd.Run(); err != nil {
		return fmt.Errorf("docker export: %v", err)
	}

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

// ListServices returns the list of service names in a docker-compose.yml
func ListServices(composePath string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return listComposeServices(ctx, composePath)
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
