package kernel

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// Default kernel download URLs (Firecracker-compatible)
	DefaultKernelURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/vmlinux-5.10.225"
	DefaultRootFSURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.10/x86_64/ubuntu-22.04.ext4"

	// Alternative sources
	KernelOrgURL = "https://cdn.kernel.org/pub/linux/kernel"
)

type DownloadProgress struct {
	Total      int64   `json:"total"`
	Downloaded int64   `json:"downloaded"`
	Percent    float64 `json:"percent"`
	Speed      float64 `json:"speed"` // bytes per second
	ETA        int64   `json:"eta"`   // seconds remaining
	Status     string  `json:"status"`
	Error      string  `json:"error,omitempty"`
}

type Manager struct {
	dataDir    string
	kernelDir  string
	rootfsDir  string
	mu         sync.RWMutex
	downloads  map[string]*DownloadProgress
}

func NewManager(dataDir string) (*Manager, error) {
	kernelDir := filepath.Join(dataDir, "kernels")
	rootfsDir := filepath.Join(dataDir, "rootfs")

	for _, dir := range []string{kernelDir, rootfsDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &Manager{
		dataDir:   dataDir,
		kernelDir: kernelDir,
		rootfsDir: rootfsDir,
		downloads: make(map[string]*DownloadProgress),
	}, nil
}

// DownloadKernel downloads a kernel from a URL
func (m *Manager) DownloadKernel(url, name string) (string, error) {
	destPath := filepath.Join(m.kernelDir, name)
	return m.downloadFile(url, destPath, "kernel-"+name)
}

// DownloadRootFS downloads a rootfs image from a URL
func (m *Manager) DownloadRootFS(url, name string) (string, error) {
	destPath := filepath.Join(m.rootfsDir, name)
	return m.downloadFile(url, destPath, "rootfs-"+name)
}

// downloadFile downloads a file with progress tracking
func (m *Manager) downloadFile(url, destPath, progressKey string) (string, error) {
	m.mu.Lock()
	m.downloads[progressKey] = &DownloadProgress{
		Status: "starting",
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.downloads, progressKey)
		m.mu.Unlock()
	}()

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Minute,
	}

	resp, err := client.Get(url)
	if err != nil {
		m.updateProgress(progressKey, -1, -1, "error", err.Error())
		return "", fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.updateProgress(progressKey, -1, -1, "error", fmt.Sprintf("HTTP %d", resp.StatusCode))
		return "", fmt.Errorf("HTTP error: %s", resp.Status)
	}

	total := resp.ContentLength
	m.updateProgress(progressKey, total, 0, "downloading", "")

	// Create destination file
	tmpPath := destPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		m.updateProgress(progressKey, total, -1, "error", err.Error())
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Download with progress tracking
	var downloaded int64
	buf := make([]byte, 32*1024)
	startTime := time.Now()

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				os.Remove(tmpPath)
				m.updateProgress(progressKey, total, downloaded, "error", writeErr.Error())
				return "", fmt.Errorf("failed to write: %w", writeErr)
			}
			downloaded += int64(n)

			// Calculate progress
			elapsed := time.Since(startTime).Seconds()
			speed := float64(downloaded) / elapsed
			var eta int64
			if speed > 0 && total > 0 {
				eta = int64(float64(total-downloaded) / speed)
			}

			m.mu.Lock()
			if p, ok := m.downloads[progressKey]; ok {
				p.Downloaded = downloaded
				p.Speed = speed
				p.ETA = eta
				if total > 0 {
					p.Percent = float64(downloaded) / float64(total) * 100
				}
			}
			m.mu.Unlock()
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(tmpPath)
			m.updateProgress(progressKey, total, downloaded, "error", err.Error())
			return "", fmt.Errorf("download error: %w", err)
		}
	}

	// Close before rename
	out.Close()

	// Rename to final destination
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("failed to rename: %w", err)
	}

	// Make executable if it's a kernel
	os.Chmod(destPath, 0755)

	m.updateProgress(progressKey, total, downloaded, "completed", "")
	return destPath, nil
}

func (m *Manager) updateProgress(key string, total, downloaded int64, status, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, ok := m.downloads[key]; ok {
		p.Total = total
		p.Downloaded = downloaded
		p.Status = status
		p.Error = errMsg
		if total > 0 && downloaded >= 0 {
			p.Percent = float64(downloaded) / float64(total) * 100
		}
	}
}

// GetDownloadProgress returns current download progress
func (m *Manager) GetDownloadProgress(key string) *DownloadProgress {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if p, ok := m.downloads[key]; ok {
		return &DownloadProgress{
			Total:      p.Total,
			Downloaded: p.Downloaded,
			Percent:    p.Percent,
			Speed:      p.Speed,
			ETA:        p.ETA,
			Status:     p.Status,
			Error:      p.Error,
		}
	}
	return nil
}

// ListKernels lists all downloaded kernels
func (m *Manager) ListKernels() ([]string, error) {
	entries, err := os.ReadDir(m.kernelDir)
	if err != nil {
		return nil, err
	}

	var kernels []string
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasSuffix(entry.Name(), ".tmp") {
			kernels = append(kernels, entry.Name())
		}
	}
	return kernels, nil
}

// ListRootFS lists all downloaded root filesystems
func (m *Manager) ListRootFS() ([]string, error) {
	entries, err := os.ReadDir(m.rootfsDir)
	if err != nil {
		return nil, err
	}

	var rootfs []string
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasSuffix(entry.Name(), ".tmp") {
			rootfs = append(rootfs, entry.Name())
		}
	}
	return rootfs, nil
}

// GetKernelPath returns the full path to a kernel
func (m *Manager) GetKernelPath(name string) string {
	return filepath.Join(m.kernelDir, name)
}

// GetRootFSPath returns the full path to a rootfs
func (m *Manager) GetRootFSPath(name string) string {
	return filepath.Join(m.rootfsDir, name)
}

// DeleteKernel removes a kernel file
func (m *Manager) DeleteKernel(name string) error {
	path := filepath.Join(m.kernelDir, name)
	return os.Remove(path)
}

// DeleteRootFS removes a rootfs file
func (m *Manager) DeleteRootFS(name string) error {
	path := filepath.Join(m.rootfsDir, name)
	return os.Remove(path)
}

// CalculateChecksum calculates SHA256 checksum of a file
func (m *Manager) CalculateChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetFileSize returns the size of a file in bytes
func (m *Manager) GetFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// CreateRootFS creates an empty ext4 root filesystem image
func (m *Manager) CreateRootFS(name string, sizeMB int64) (string, error) {
	path := filepath.Join(m.rootfsDir, name)

	// Create sparse file
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}

	// Set size (sparse)
	if err := f.Truncate(sizeMB * 1024 * 1024); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("failed to set file size: %w", err)
	}
	f.Close()

	return path, nil
}

// CopyRootFS creates a copy of an existing rootfs for a new VM
func (m *Manager) CopyRootFS(srcName, dstName string) (string, error) {
	srcPath := filepath.Join(m.rootfsDir, srcName)
	dstPath := filepath.Join(m.rootfsDir, dstName)

	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(dstPath)
		return "", fmt.Errorf("failed to copy: %w", err)
	}

	return dstPath, nil
}

// ExtractGzip extracts a gzip compressed file
func (m *Manager) ExtractGzip(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer src.Close()

	gzr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, gzr); err != nil {
		os.Remove(dstPath)
		return fmt.Errorf("failed to extract: %w", err)
	}

	return nil
}

// VerifyKernel checks if a file looks like a valid Linux kernel
func (m *Manager) VerifyKernel(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Read first 8KB for magic number detection
	header := make([]byte, 8192)
	n, err := f.Read(header)
	if err != nil && err != io.EOF {
		return false, err
	}
	header = header[:n]

	// Check for ELF magic number (vmlinux)
	if len(header) >= 4 && header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return true, nil
	}

	// Check for bzImage magic
	if len(header) >= 514 && header[510] == 0x55 && header[511] == 0xaa {
		// Boot signature found
		if header[0x202] == 'H' && header[0x203] == 'd' && header[0x204] == 'r' && header[0x205] == 'S' {
			return true, nil
		}
	}

	// Check for PE header (EFI stub)
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return true, nil
	}

	return false, nil
}

// GetKernelInfo returns information about a kernel file
func (m *Manager) GetKernelInfo(path string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	info["size"] = stat.Size()
	info["modified"] = stat.ModTime()
	info["path"] = path
	info["name"] = filepath.Base(path)

	// Check if valid
	valid, err := m.VerifyKernel(path)
	if err != nil {
		return nil, err
	}
	info["valid"] = valid

	// Calculate checksum
	checksum, err := m.CalculateChecksum(path)
	if err != nil {
		return nil, err
	}
	info["checksum"] = checksum

	return info, nil
}

// GetRootFSInfo returns information about a rootfs file
func (m *Manager) GetRootFSInfo(path string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	info["size"] = stat.Size()
	info["modified"] = stat.ModTime()
	info["path"] = path
	info["name"] = filepath.Base(path)

	// Detect format by reading magic
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return nil, err
	}

	// Check ext4 superblock at offset 0x438
	f.Seek(0x438, 0)
	extMagic := make([]byte, 2)
	if _, err := f.Read(extMagic); err == nil {
		if extMagic[0] == 0x53 && extMagic[1] == 0xef {
			info["format"] = "ext4"
		}
	}

	if info["format"] == nil {
		// Check for squashfs (hsqs magic)
		if magic[0] == 'h' && magic[1] == 's' && magic[2] == 'q' && magic[3] == 's' {
			info["format"] = "squashfs"
		} else {
			info["format"] = "unknown"
		}
	}

	return info, nil
}

// CleanupTempFiles removes any leftover temporary files
func (m *Manager) CleanupTempFiles() error {
	for _, dir := range []string{m.kernelDir, m.rootfsDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".tmp") {
				os.Remove(filepath.Join(dir, entry.Name()))
			}
		}
	}
	return nil
}

// GetDataDir returns the data directory path
func (m *Manager) GetDataDir() string {
	return m.dataDir
}

// GetKernelDir returns the kernel directory path
func (m *Manager) GetKernelDir() string {
	return m.kernelDir
}

// GetRootFSDir returns the rootfs directory path
func (m *Manager) GetRootFSDir() string {
	return m.rootfsDir
}

// KernelExists checks if a kernel file exists
func (m *Manager) KernelExists(name string) bool {
	_, err := os.Stat(filepath.Join(m.kernelDir, name))
	return err == nil
}

// RootFSExists checks if a rootfs file exists
func (m *Manager) RootFSExists(name string) bool {
	_, err := os.Stat(filepath.Join(m.rootfsDir, name))
	return err == nil
}

// ResizeRootFS resizes an ext4 rootfs image (increases size only)
func (m *Manager) ResizeRootFS(name string, newSizeMB int64) error {
	path := filepath.Join(m.rootfsDir, name)

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	currentSizeMB := info.Size() / (1024 * 1024)
	if newSizeMB <= currentSizeMB {
		return fmt.Errorf("new size must be larger than current size (%d MB)", currentSizeMB)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	if err := f.Truncate(newSizeMB * 1024 * 1024); err != nil {
		return fmt.Errorf("failed to resize: %w", err)
	}

	return nil
}
