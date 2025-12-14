package RegistryToFC

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
	"strings"
	"syscall"

	"firecrackmanager/internal/futils"
	"firecrackmanager/internal/proxyconfig"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
)

/* ----- Public API ----- */

type ImageToFCOptions struct {
	OutputImage   string // required: path to write the ext4 (e.g., "./rootfs.ext4")
	SizeGiB       int64  // 0 = auto (from tar, + ~35% headroom, min 2GiB)
	Label         string // ext4 label (default "rootfs")
	InjectMinInit bool   // add /sbin/init that execs /bin/sh if none present
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

	reportProgress(85, "Finalizing")

	if opt.InjectMinInit {
		if err := installMinInit(mnt); err != nil {
			return nil, err
		}
	}

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
