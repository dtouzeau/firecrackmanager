package kernelupdater

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"firecrackmanager/internal/database"
	"firecrackmanager/internal/proxyconfig"
)

const (
	CacheFileName = "kernel_version.json"
	// S3 base URL for Firecracker kernels
	FirecrackerKernelBaseURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci"
)

// KnownKernelVersions lists known Firecracker-compatible kernel versions with their S3 paths
// These are officially provided by the Firecracker team
var KnownKernelVersions = []struct {
	Version    string
	FCVersion  string // Firecracker CI version
	KernelFile string
}{
	// Latest kernels (5.x series)
	{Version: "5.10.225", FCVersion: "v1.10", KernelFile: "vmlinux-5.10.225"},
	{Version: "5.10.217", FCVersion: "v1.9", KernelFile: "vmlinux-5.10.217"},
	{Version: "5.10.211", FCVersion: "v1.8", KernelFile: "vmlinux-5.10.211"},
	{Version: "5.10.204", FCVersion: "v1.7", KernelFile: "vmlinux-5.10.204"},
	{Version: "5.10.198", FCVersion: "v1.6", KernelFile: "vmlinux-5.10.198"},
	{Version: "5.10.186", FCVersion: "v1.5", KernelFile: "vmlinux-5.10.186"},
	{Version: "5.10.176", FCVersion: "v1.4", KernelFile: "vmlinux-5.10.176"},
	// Older 4.x series (legacy)
	{Version: "4.14.313", FCVersion: "v1.4", KernelFile: "vmlinux-4.14.313"},
}

// KernelInfo represents information about a kernel version
type KernelInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	Size        int64  `json:"size"`
	ReleaseTag  string `json:"release_tag"`
}

// VersionCache stores the cached kernel version information
type VersionCache struct {
	InstalledKernels  []InstalledKernel `json:"installed_kernels"`
	AvailableKernels  []KernelInfo      `json:"available_kernels"`
	UpdateAvailable   bool              `json:"update_available"`
	LatestVersion     string            `json:"latest_version"`
	CurrentMaxVersion string            `json:"current_max_version"`
	CheckedAt         time.Time         `json:"checked_at"`
	Error             string            `json:"error,omitempty"`
}

// InstalledKernel represents an installed kernel
type InstalledKernel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

// DownloadProgress tracks kernel download progress
type DownloadProgress struct {
	Status      string    `json:"status"` // pending, downloading, completed, failed
	Percent     int       `json:"percent"`
	Message     string    `json:"message"`
	Error       string    `json:"error,omitempty"`
	KernelID    string    `json:"kernel_id,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// KernelUpdater handles background kernel version checking
type KernelUpdater struct {
	dataDir    string
	kernelDir  string
	cachePath  string
	cron       *cron.Cron
	logger     func(string, ...interface{})
	db         *database.DB
	mu         sync.RWMutex
	cache      *VersionCache
	downloads  map[string]*DownloadProgress
	downloadMu sync.RWMutex
}

// NewKernelUpdater creates a new KernelUpdater instance
func NewKernelUpdater(dataDir string, db *database.DB, logger func(string, ...interface{})) *KernelUpdater {
	return &KernelUpdater{
		dataDir:   dataDir,
		kernelDir: filepath.Join(dataDir, "kernels"),
		cachePath: filepath.Join(dataDir, CacheFileName),
		logger:    logger,
		db:        db,
		downloads: make(map[string]*DownloadProgress),
	}
}

// Start initializes the cron scheduler and runs an initial check
func (u *KernelUpdater) Start() error {
	// Load existing cache if available
	u.loadCache()

	// Create cron scheduler
	u.cron = cron.New()

	// Schedule daily check at 3:30 AM (30 minutes after Firecracker check)
	_, err := u.cron.AddFunc("30 3 * * *", func() {
		u.logger("Running scheduled kernel version check")
		u.CheckForUpdates()
	})
	if err != nil {
		return fmt.Errorf("failed to schedule kernel update check: %w", err)
	}

	// Start the cron scheduler
	u.cron.Start()
	u.logger("Kernel update checker started (scheduled daily at 3:30 AM)")

	// Run initial check in background if cache is old or missing
	go func() {
		u.mu.RLock()
		needsCheck := u.cache == nil || time.Since(u.cache.CheckedAt) > 24*time.Hour
		u.mu.RUnlock()

		if needsCheck {
			u.logger("Running initial kernel version check")
			u.CheckForUpdates()
		}
	}()

	return nil
}

// Stop stops the cron scheduler
func (u *KernelUpdater) Stop() {
	if u.cron != nil {
		u.cron.Stop()
	}
}

// CheckForUpdates checks GitHub for available kernel versions
func (u *KernelUpdater) CheckForUpdates() {
	cache := &VersionCache{
		CheckedAt: time.Now(),
	}

	// Get installed kernels from database
	kernels, err := u.db.ListKernelImages()
	if err != nil {
		cache.Error = fmt.Sprintf("failed to list installed kernels: %v", err)
		u.saveAndUpdateCache(cache)
		return
	}

	// Build list of installed kernels
	for _, k := range kernels {
		cache.InstalledKernels = append(cache.InstalledKernels, InstalledKernel{
			ID:      k.ID,
			Name:    k.Name,
			Version: k.Version,
			Path:    k.Path,
		})
	}

	// Find the highest installed version
	cache.CurrentMaxVersion = u.findHighestVersion(kernels)

	// Fetch available kernels from GitHub releases
	availableKernels, err := u.fetchAvailableKernels()
	if err != nil {
		cache.Error = fmt.Sprintf("failed to fetch available kernels: %v", err)
		u.saveAndUpdateCache(cache)
		return
	}

	cache.AvailableKernels = availableKernels

	// Find latest available version
	if len(availableKernels) > 0 {
		cache.LatestVersion = availableKernels[0].Version
	}

	// Check if update is available
	if cache.LatestVersion != "" && cache.CurrentMaxVersion != "" {
		if compareVersions(cache.LatestVersion, cache.CurrentMaxVersion) > 0 {
			cache.UpdateAvailable = true
		}
	} else if cache.LatestVersion != "" && cache.CurrentMaxVersion == "" {
		cache.UpdateAvailable = true
	}

	u.saveAndUpdateCache(cache)

	if cache.UpdateAvailable {
		u.logger("Kernel update available: %s -> %s", cache.CurrentMaxVersion, cache.LatestVersion)
	} else if cache.Error == "" {
		u.logger("Kernels are up to date. Latest: %s, Installed: %s", cache.LatestVersion, cache.CurrentMaxVersion)
	}
}

// fetchAvailableKernels returns known Firecracker-compatible kernels from S3
func (u *KernelUpdater) fetchAvailableKernels() ([]KernelInfo, error) {
	client, err := proxyconfig.NewHTTPClient(30 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	var kernels []KernelInfo

	// Check each known kernel version to verify it's available
	for _, kv := range KnownKernelVersions {
		downloadURL := fmt.Sprintf("%s/%s/x86_64/%s", FirecrackerKernelBaseURL, kv.FCVersion, kv.KernelFile)

		// Do a HEAD request to verify the file exists and get size
		req, err := http.NewRequest("HEAD", downloadURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			kernels = append(kernels, KernelInfo{
				Version:     kv.Version,
				DownloadURL: downloadURL,
				Size:        resp.ContentLength,
				ReleaseTag:  "Firecracker CI " + kv.FCVersion,
			})
		}
	}

	// Sort by version descending
	sort.Slice(kernels, func(i, j int) bool {
		return compareVersions(kernels[i].Version, kernels[j].Version) > 0
	})

	return kernels, nil
}

// GetCache returns the current version cache
func (u *KernelUpdater) GetCache() *VersionCache {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if u.cache != nil {
		return u.cache
	}

	// Return empty cache if not loaded
	return &VersionCache{}
}

// InvalidateCache clears the cache and triggers a new check
func (u *KernelUpdater) InvalidateCache() {
	u.mu.Lock()
	u.cache = nil
	u.mu.Unlock()

	// Remove cache file
	os.Remove(u.cachePath)

	// Trigger a new check
	go u.CheckForUpdates()
}

// DownloadKernel downloads a kernel version
func (u *KernelUpdater) DownloadKernel(version string) (string, error) {
	// Find kernel info
	u.mu.RLock()
	cache := u.cache
	u.mu.RUnlock()

	if cache == nil {
		return "", fmt.Errorf("no kernel information available, please check for updates first")
	}

	var kernelInfo *KernelInfo
	for _, k := range cache.AvailableKernels {
		if k.Version == version {
			kernelInfo = &k
			break
		}
	}

	if kernelInfo == nil {
		return "", fmt.Errorf("kernel version %s not found in available kernels", version)
	}

	// Generate download job ID
	jobID := generateID()

	// Initialize progress
	progress := &DownloadProgress{
		Status:  "pending",
		Percent: 0,
		Message: "Starting download...",
	}

	u.downloadMu.Lock()
	u.downloads[jobID] = progress
	u.downloadMu.Unlock()

	// Start download in background
	go u.performDownload(jobID, kernelInfo)

	return jobID, nil
}

// performDownload performs the actual kernel download
func (u *KernelUpdater) performDownload(jobID string, kernelInfo *KernelInfo) {
	updateProgress := func(status string, percent int, message string, err string) {
		u.downloadMu.Lock()
		if p, ok := u.downloads[jobID]; ok {
			p.Status = status
			p.Percent = percent
			p.Message = message
			p.Error = err
			if status == "completed" || status == "failed" {
				p.CompletedAt = time.Now()
			}
		}
		u.downloadMu.Unlock()
	}

	updateProgress("downloading", 5, "Connecting to server...", "")

	// Create HTTP client
	client, err := proxyconfig.NewHTTPClient(30 * time.Minute)
	if err != nil {
		updateProgress("failed", 0, "Failed to create HTTP client", err.Error())
		return
	}

	// Start download
	resp, err := client.Get(kernelInfo.DownloadURL)
	if err != nil {
		updateProgress("failed", 0, "Download failed", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		updateProgress("failed", 0, "Download failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
		return
	}

	// Create output file
	kernelName := fmt.Sprintf("vmlinux-%s.bin", kernelInfo.Version)
	destPath := filepath.Join(u.kernelDir, kernelName)
	tmpPath := destPath + ".tmp"

	if err := os.MkdirAll(u.kernelDir, 0755); err != nil {
		updateProgress("failed", 0, "Failed to create kernel directory", err.Error())
		return
	}

	outFile, err := os.Create(tmpPath)
	if err != nil {
		updateProgress("failed", 0, "Failed to create file", err.Error())
		return
	}
	defer outFile.Close()

	// Download with progress tracking
	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 64*1024)
	lastPercent := 0

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := outFile.Write(buf[:n]); writeErr != nil {
				os.Remove(tmpPath)
				updateProgress("failed", 0, "Write failed", writeErr.Error())
				return
			}
			downloaded += int64(n)

			if total > 0 {
				percent := int(float64(downloaded)/float64(total)*90) + 5 // 5-95%
				if percent != lastPercent {
					updateProgress("downloading", percent,
						fmt.Sprintf("Downloading... %d MB / %d MB",
							downloaded/(1024*1024), total/(1024*1024)), "")
					lastPercent = percent
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			os.Remove(tmpPath)
			updateProgress("failed", 0, "Download interrupted", readErr.Error())
			return
		}
	}

	outFile.Close()

	// Rename temp file to final
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		updateProgress("failed", 0, "Failed to finalize file", err.Error())
		return
	}

	// Make executable
	os.Chmod(destPath, 0755)

	updateProgress("downloading", 98, "Registering kernel...", "")

	// Register in database
	fileInfo, _ := os.Stat(destPath)
	kernelID := generateID()
	kernel := &database.KernelImage{
		ID:           kernelID,
		Name:         kernelName,
		Version:      kernelInfo.Version,
		Architecture: "x86_64",
		Path:         destPath,
		Size:         fileInfo.Size(),
		IsDefault:    false,
	}

	if err := u.db.CreateKernelImage(kernel); err != nil {
		updateProgress("failed", 0, "Failed to register kernel", err.Error())
		return
	}

	// Update progress with kernel ID
	u.downloadMu.Lock()
	if p, ok := u.downloads[jobID]; ok {
		p.KernelID = kernelID
	}
	u.downloadMu.Unlock()

	updateProgress("completed", 100, fmt.Sprintf("Kernel %s installed successfully", kernelInfo.Version), "")

	// Invalidate cache to reflect new installation
	u.InvalidateCache()

	u.logger("Kernel %s downloaded and registered: %s", kernelInfo.Version, destPath)
}

// GetDownloadProgress returns the progress of a download job
func (u *KernelUpdater) GetDownloadProgress(jobID string) *DownloadProgress {
	u.downloadMu.RLock()
	defer u.downloadMu.RUnlock()

	if p, ok := u.downloads[jobID]; ok {
		return p
	}
	return nil
}

// Helper functions

func (u *KernelUpdater) findHighestVersion(kernels []*database.KernelImage) string {
	var highest string
	for _, k := range kernels {
		if k.Version != "" {
			if highest == "" || compareVersions(k.Version, highest) > 0 {
				highest = k.Version
			}
		}
	}
	return highest
}

func (u *KernelUpdater) saveAndUpdateCache(cache *VersionCache) {
	u.mu.Lock()
	u.cache = cache
	u.mu.Unlock()

	u.saveCache(cache)
}

func (u *KernelUpdater) loadCache() {
	data, err := os.ReadFile(u.cachePath)
	if err != nil {
		return // File doesn't exist yet
	}

	var cache VersionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		u.logger("Failed to parse kernel version cache: %v", err)
		return
	}

	u.mu.Lock()
	u.cache = &cache
	u.mu.Unlock()

	u.logger("Loaded kernel version cache from %s (checked at %s)", u.cachePath, cache.CheckedAt.Format(time.RFC3339))
}

func (u *KernelUpdater) saveCache(cache *VersionCache) {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		u.logger("Failed to marshal kernel version cache: %v", err)
		return
	}

	if err := os.WriteFile(u.cachePath, data, 0644); err != nil {
		u.logger("Failed to save kernel version cache: %v", err)
		return
	}
}

// compareVersions compares two version strings (e.g., "5.10" vs "6.1")
// Returns: 1 if a > b, -1 if a < b, 0 if equal
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &aNum)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bNum)
		}

		if aNum > bNum {
			return 1
		}
		if aNum < bNum {
			return -1
		}
	}
	return 0
}

func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", bytes)
}
