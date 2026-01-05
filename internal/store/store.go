package store

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"firecrackmanager/internal/database"
)

const (
	CatalogURL         = "http://firecracker.articatech.download/index.json"
	BaseURL            = "http://firecracker.articatech.download/"
	RefreshInterval    = 30 * time.Minute
	KernelSyncInterval = 4 * time.Hour
)

// Part represents a part of a split appliance file
type Part struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	MD5      string `json:"md5"`
}

// Appliance represents an appliance in the store catalog
type Appliance struct {
	Name        string `json:"name"`
	Directory   string `json:"directory"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	Date        int64  `json:"date"`
	MD5         string `json:"md5"`
	Parts       []Part `json:"parts"`
}

// CatalogKernel represents a kernel in the store catalog
type CatalogKernel struct {
	Filename     string `json:"filename"`
	Name         string `json:"name,omitempty"` // Alternative to filename
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
	URL          string `json:"url,omitempty"`
	Size         int64  `json:"size"`
	MD5          string `json:"md5"`
	Description  string `json:"description,omitempty"`
}

// GetName returns the kernel filename (prefers filename over name)
func (k CatalogKernel) GetName() string {
	if k.Filename != "" {
		return k.Filename
	}
	return k.Name
}

// FullCatalog represents the complete catalog with appliances and kernels
type FullCatalog struct {
	Appliances []Appliance     `json:"appliances"`
	Kernels    []CatalogKernel `json:"kernels"`
}

// DownloadProgress tracks the progress of a download
type DownloadProgress struct {
	Status          string  `json:"status"` // pending, downloading, verifying, merging, completed, error
	Stage           string  `json:"stage"`
	Percent         float64 `json:"percent"`
	CurrentPart     int     `json:"current_part"`
	TotalParts      int     `json:"total_parts"`
	BytesDownloaded int64   `json:"bytes_downloaded"`
	TotalBytes      int64   `json:"total_bytes"`
	Speed           float64 `json:"speed"` // bytes per second
	Error           string  `json:"error,omitempty"`
	ResultFile      string  `json:"result_file,omitempty"`
}

// Store manages the appliance store catalog and downloads
type Store struct {
	mu        sync.RWMutex
	catalog   []Appliance
	kernels   []CatalogKernel
	lastFetch time.Time
	dataDir   string
	logger    func(format string, args ...interface{})
	db        *database.DB

	downloadsMu sync.RWMutex
	downloads   map[string]*DownloadProgress

	stopChan       chan struct{}
	kernelStopChan chan struct{}

	// Callback invoked when a download completes successfully
	onDownloadComplete func()
}

// New creates a new Store instance
func New(dataDir string, logger func(format string, args ...interface{})) *Store {
	s := &Store{
		dataDir:        dataDir,
		logger:         logger,
		downloads:      make(map[string]*DownloadProgress),
		stopChan:       make(chan struct{}),
		kernelStopChan: make(chan struct{}),
	}
	return s
}

// SetDatabase sets the database for kernel registration
func (s *Store) SetDatabase(db *database.DB) {
	s.db = db
}

// SetOnDownloadComplete sets the callback to invoke when a download completes successfully
func (s *Store) SetOnDownloadComplete(cb func()) {
	s.onDownloadComplete = cb
}

// Start begins the background catalog refresh
func (s *Store) Start() {
	// Initial fetch
	go s.fetchCatalog()

	// Periodic refresh
	go func() {
		ticker := time.NewTicker(RefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.fetchCatalog()
			case <-s.stopChan:
				return
			}
		}
	}()

	// Start kernel sync (initial sync after catalog is fetched, then every 4 hours)
	go s.startKernelSync()
}

// Stop stops the background refresh
func (s *Store) Stop() {
	close(s.stopChan)
	close(s.kernelStopChan)
}

// fetchCatalog fetches the catalog from the remote server
func (s *Store) fetchCatalog() {
	s.logger("Fetching store catalog from %s", CatalogURL)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(CatalogURL)
	if err != nil {
		s.logger("Failed to fetch store catalog: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.logger("Failed to fetch store catalog: HTTP %d", resp.StatusCode)
		return
	}

	// Read body to try both formats
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger("Failed to read store catalog: %v", err)
		return
	}

	// Try to parse as new format (object with appliances and kernels)
	var fullCatalog FullCatalog
	if err := json.Unmarshal(body, &fullCatalog); err == nil && (len(fullCatalog.Appliances) > 0 || len(fullCatalog.Kernels) > 0) {
		s.mu.Lock()
		s.catalog = fullCatalog.Appliances
		s.kernels = fullCatalog.Kernels
		s.lastFetch = time.Now()
		s.mu.Unlock()

		s.logger("Store catalog updated: %d appliances, %d kernels available", len(fullCatalog.Appliances), len(fullCatalog.Kernels))
		return
	}

	// Fall back to old format (array of appliances)
	var catalog []Appliance
	if err := json.Unmarshal(body, &catalog); err != nil {
		s.logger("Failed to parse store catalog: %v", err)
		return
	}

	s.mu.Lock()
	s.catalog = catalog
	s.lastFetch = time.Now()
	s.mu.Unlock()

	s.logger("Store catalog updated: %d appliances available", len(catalog))
}

// GetCatalog returns the current catalog
func (s *Store) GetCatalog() []Appliance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	result := make([]Appliance, len(s.catalog))
	copy(result, s.catalog)
	return result
}

// GetAppliance returns a specific appliance by name
func (s *Store) GetAppliance(name string) *Appliance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, app := range s.catalog {
		if app.Name == name {
			appCopy := app
			return &appCopy
		}
	}
	return nil
}

// GetLastFetch returns when the catalog was last fetched
func (s *Store) GetLastFetch() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastFetch
}

// RefreshCatalog forces a catalog refresh
func (s *Store) RefreshCatalog() {
	go s.fetchCatalog()
}

// GetDownloadProgress returns the progress for a download
func (s *Store) GetDownloadProgress(key string) *DownloadProgress {
	s.downloadsMu.RLock()
	defer s.downloadsMu.RUnlock()

	if p, ok := s.downloads[key]; ok {
		// Return a copy
		pCopy := *p
		return &pCopy
	}
	return nil
}

// setDownloadProgress updates the progress for a download
func (s *Store) setDownloadProgress(key string, progress *DownloadProgress) {
	s.downloadsMu.Lock()
	defer s.downloadsMu.Unlock()
	s.downloads[key] = progress
}

// StartDownload begins downloading an appliance
func (s *Store) StartDownload(name string) (string, error) {
	app := s.GetAppliance(name)
	if app == nil {
		return "", fmt.Errorf("appliance not found: %s", name)
	}

	// Generate download key
	key := fmt.Sprintf("store-%s-%d", name, time.Now().UnixNano())

	// Initialize progress
	s.setDownloadProgress(key, &DownloadProgress{
		Status:     "pending",
		Stage:      "Initializing download...",
		Percent:    0,
		TotalParts: len(app.Parts),
		TotalBytes: app.Size,
	})

	// Start download in background
	go s.downloadAppliance(key, app)

	return key, nil
}

// downloadAppliance downloads and assembles an appliance
func (s *Store) downloadAppliance(key string, app *Appliance) {
	// Create temp directory for parts
	tempDir := filepath.Join(s.dataDir, ".store-temp", app.Name)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		s.setDownloadProgress(key, &DownloadProgress{
			Status: "error",
			Stage:  "Failed to create temp directory",
			Error:  err.Error(),
		})
		return
	}

	// Sort parts by filename to ensure correct order
	parts := make([]Part, len(app.Parts))
	copy(parts, app.Parts)
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].Filename < parts[j].Filename
	})

	var totalDownloaded int64
	startTime := time.Now()

	// Download each part
	for i, part := range parts {
		partPath := filepath.Join(tempDir, part.Filename)

		// Check if part already exists and is valid
		if s.verifyPartMD5(partPath, part.MD5) {
			s.logger("Part %s already downloaded and verified", part.Filename)
			totalDownloaded += part.Size
			continue
		}

		// Update progress
		elapsed := time.Since(startTime).Seconds()
		speed := float64(0)
		if elapsed > 0 {
			speed = float64(totalDownloaded) / elapsed
		}

		s.setDownloadProgress(key, &DownloadProgress{
			Status:          "downloading",
			Stage:           fmt.Sprintf("Downloading part %d of %d: %s", i+1, len(parts), part.Filename),
			Percent:         float64(totalDownloaded) / float64(app.Size) * 100,
			CurrentPart:     i + 1,
			TotalParts:      len(parts),
			BytesDownloaded: totalDownloaded,
			TotalBytes:      app.Size,
			Speed:           speed,
		})

		// Download the part with retries
		var err error
		for retry := 0; retry < 3; retry++ {
			err = s.downloadPart(app.Directory, part, partPath, key, totalDownloaded, app.Size, startTime)
			if err == nil {
				break
			}
			s.logger("Retry %d for part %s: %v", retry+1, part.Filename, err)
			time.Sleep(time.Duration(retry+1) * time.Second)
		}

		if err != nil {
			s.setDownloadProgress(key, &DownloadProgress{
				Status: "error",
				Stage:  fmt.Sprintf("Failed to download part %s", part.Filename),
				Error:  err.Error(),
			})
			return
		}

		// Verify MD5
		s.setDownloadProgress(key, &DownloadProgress{
			Status:          "verifying",
			Stage:           fmt.Sprintf("Verifying part %d of %d: %s", i+1, len(parts), part.Filename),
			Percent:         float64(totalDownloaded) / float64(app.Size) * 100,
			CurrentPart:     i + 1,
			TotalParts:      len(parts),
			BytesDownloaded: totalDownloaded,
			TotalBytes:      app.Size,
		})

		if !s.verifyPartMD5(partPath, part.MD5) {
			os.Remove(partPath)
			s.setDownloadProgress(key, &DownloadProgress{
				Status: "error",
				Stage:  fmt.Sprintf("MD5 verification failed for part %s", part.Filename),
				Error:  "checksum mismatch",
			})
			return
		}

		totalDownloaded += part.Size
	}

	// Merge parts
	s.setDownloadProgress(key, &DownloadProgress{
		Status:          "merging",
		Stage:           "Merging parts into final file...",
		Percent:         95,
		CurrentPart:     len(parts),
		TotalParts:      len(parts),
		BytesDownloaded: totalDownloaded,
		TotalBytes:      app.Size,
	})

	outputFile := filepath.Join(s.dataDir, app.Name+".fcrack")
	if err := s.mergeParts(tempDir, parts, outputFile, key, app.Size); err != nil {
		s.setDownloadProgress(key, &DownloadProgress{
			Status: "error",
			Stage:  "Failed to merge parts",
			Error:  err.Error(),
		})
		return
	}

	// Verify final MD5
	s.setDownloadProgress(key, &DownloadProgress{
		Status:          "verifying",
		Stage:           "Verifying final file checksum...",
		Percent:         98,
		CurrentPart:     len(parts),
		TotalParts:      len(parts),
		BytesDownloaded: app.Size,
		TotalBytes:      app.Size,
	})

	if !s.verifyPartMD5(outputFile, app.MD5) {
		os.Remove(outputFile)
		s.setDownloadProgress(key, &DownloadProgress{
			Status: "error",
			Stage:  "Final file MD5 verification failed",
			Error:  "checksum mismatch",
		})
		return
	}

	// Cleanup temp directory
	os.RemoveAll(tempDir)

	// Done
	s.setDownloadProgress(key, &DownloadProgress{
		Status:          "completed",
		Stage:           "Download completed successfully",
		Percent:         100,
		CurrentPart:     len(parts),
		TotalParts:      len(parts),
		BytesDownloaded: app.Size,
		TotalBytes:      app.Size,
		ResultFile:      app.Name + ".fcrack",
	})

	s.logger("Store download completed: %s", outputFile)

	// Trigger callback to refresh appliances index
	if s.onDownloadComplete != nil {
		s.onDownloadComplete()
	}
}

// downloadPart downloads a single part
func (s *Store) downloadPart(directory string, part Part, destPath string, progressKey string, baseDownloaded int64, totalSize int64, startTime time.Time) error {
	url := BaseURL + directory + "/" + part.Filename

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Create output file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Download with progress updates
	buf := make([]byte, 64*1024) // 64KB buffer
	var partDownloaded int64

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return fmt.Errorf("write error: %w", werr)
			}
			partDownloaded += int64(n)

			// Update progress every 256KB
			if partDownloaded%(256*1024) == 0 || err == io.EOF {
				currentTotal := baseDownloaded + partDownloaded
				elapsed := time.Since(startTime).Seconds()
				speed := float64(0)
				if elapsed > 0 {
					speed = float64(currentTotal) / elapsed
				}

				s.setDownloadProgress(progressKey, &DownloadProgress{
					Status:          "downloading",
					Stage:           fmt.Sprintf("Downloading: %s", part.Filename),
					Percent:         float64(currentTotal) / float64(totalSize) * 100,
					BytesDownloaded: currentTotal,
					TotalBytes:      totalSize,
					Speed:           speed,
				})
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}
	}

	return nil
}

// verifyPartMD5 verifies the MD5 checksum of a file
func (s *Store) verifyPartMD5(path string, expectedMD5 string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}

	actualMD5 := hex.EncodeToString(h.Sum(nil))
	return actualMD5 == expectedMD5
}

// mergeParts merges all parts into a single file
func (s *Store) mergeParts(tempDir string, parts []Part, outputPath string, progressKey string, totalSize int64) error {
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	var written int64
	for i, part := range parts {
		partPath := filepath.Join(tempDir, part.Filename)
		in, err := os.Open(partPath)
		if err != nil {
			return fmt.Errorf("failed to open part %s: %w", part.Filename, err)
		}

		n, err := io.Copy(out, in)
		in.Close()
		if err != nil {
			return fmt.Errorf("failed to copy part %s: %w", part.Filename, err)
		}

		written += n

		// Update progress
		s.setDownloadProgress(progressKey, &DownloadProgress{
			Status:          "merging",
			Stage:           fmt.Sprintf("Merging part %d of %d...", i+1, len(parts)),
			Percent:         95 + (float64(i+1)/float64(len(parts)))*3, // 95-98%
			CurrentPart:     i + 1,
			TotalParts:      len(parts),
			BytesDownloaded: written,
			TotalBytes:      totalSize,
		})
	}

	return nil
}

// CancelDownload cancels an ongoing download
func (s *Store) CancelDownload(key string) {
	s.downloadsMu.Lock()
	defer s.downloadsMu.Unlock()

	if p, ok := s.downloads[key]; ok {
		if p.Status == "downloading" || p.Status == "verifying" || p.Status == "merging" {
			p.Status = "error"
			p.Stage = "Download cancelled"
			p.Error = "cancelled by user"
		}
	}
}

// CleanupDownloads removes old download progress entries
func (s *Store) CleanupDownloads() {
	s.downloadsMu.Lock()
	defer s.downloadsMu.Unlock()

	// Keep only recent entries (last hour)
	// This is a simple implementation - a more sophisticated one would track timestamps
	for key, p := range s.downloads {
		if p.Status == "completed" || p.Status == "error" {
			delete(s.downloads, key)
		}
	}
}

// GetKernelsCatalog returns the current kernels catalog
func (s *Store) GetKernelsCatalog() []CatalogKernel {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]CatalogKernel, len(s.kernels))
	copy(result, s.kernels)
	return result
}

// startKernelSync starts the kernel synchronization scheduler
func (s *Store) startKernelSync() {
	// Wait a bit for catalog to be fetched first
	time.Sleep(10 * time.Second)

	// Initial sync on startup (non-blocking)
	s.syncKernels()

	// Periodic sync every 4 hours
	ticker := time.NewTicker(KernelSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.syncKernels()
		case <-s.kernelStopChan:
			return
		}
	}
}

// syncKernels checks remote kernels and downloads missing ones
func (s *Store) syncKernels() {
	if s.db == nil {
		s.logger("Kernel sync: database not set, skipping")
		return
	}

	s.mu.RLock()
	kernels := make([]CatalogKernel, len(s.kernels))
	copy(kernels, s.kernels)
	s.mu.RUnlock()

	if len(kernels) == 0 {
		s.logger("Kernel sync: no kernels in catalog")
		return
	}

	// Get current architecture
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x86_64"
	}

	kernelsDir := filepath.Join(s.dataDir, "kernels")
	if err := os.MkdirAll(kernelsDir, 0755); err != nil {
		s.logger("Kernel sync: failed to create kernels directory: %v", err)
		return
	}

	s.logger("Kernel sync: checking %d kernels from catalog", len(kernels))

	for _, kernel := range kernels {
		kernelName := kernel.GetName()
		if kernelName == "" {
			continue
		}

		// Skip kernels for different architectures
		if kernel.Architecture != "" && kernel.Architecture != arch {
			continue
		}

		localPath := filepath.Join(kernelsDir, kernelName)

		// Check if kernel exists locally
		if _, err := os.Stat(localPath); err == nil {
			// Verify MD5
			localMD5 := s.getLocalKernelMD5(localPath)
			if localMD5 == kernel.MD5 {
				// Kernel exists and matches, ensure it's in database
				s.ensureKernelInDatabase(kernel, localPath)
				continue
			}
			s.logger("Kernel sync: %s exists but MD5 mismatch (local=%s, remote=%s), re-downloading", kernelName, localMD5, kernel.MD5)
		}

		// Download kernel
		s.logger("Kernel sync: downloading %s", kernelName)
		if err := s.downloadKernel(kernel, localPath); err != nil {
			s.logger("Kernel sync: failed to download %s: %v", kernelName, err)
			continue
		}

		// Verify downloaded file
		downloadedMD5 := s.getLocalKernelMD5(localPath)
		if downloadedMD5 != kernel.MD5 {
			s.logger("Kernel sync: MD5 verification failed for %s (expected=%s, got=%s)", kernelName, kernel.MD5, downloadedMD5)
			os.Remove(localPath)
			continue
		}

		// Add to database
		if err := s.addKernelToDatabase(kernel, localPath); err != nil {
			s.logger("Kernel sync: failed to add %s to database: %v", kernelName, err)
			continue
		}

		s.logger("Kernel sync: successfully downloaded and registered %s", kernelName)
	}

	s.logger("Kernel sync: completed")
}

// getLocalKernelMD5 calculates the MD5 hash of a local file
func (s *Store) getLocalKernelMD5(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}

	return hex.EncodeToString(h.Sum(nil))
}

// downloadKernel downloads a kernel from the catalog
func (s *Store) downloadKernel(kernel CatalogKernel, destPath string) error {
	url := kernel.URL
	if url == "" {
		url = BaseURL + "kernels/" + kernel.GetName()
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Create temp file first
	tempPath := destPath + ".tmp"
	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("download failed: %w", err)
	}

	// Move to final location
	if err := os.Rename(tempPath, destPath); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	return nil
}

// ensureKernelInDatabase ensures a kernel is registered in the database
func (s *Store) ensureKernelInDatabase(kernel CatalogKernel, localPath string) {
	kernelName := kernel.GetName()

	// Check if already in database
	existingKernels, err := s.db.ListKernelImages()
	if err != nil {
		return
	}

	for _, k := range existingKernels {
		if k.Name == kernelName || k.Path == localPath {
			return // Already exists
		}
	}

	// Not in database, add it
	s.addKernelToDatabase(kernel, localPath)
}

// addKernelToDatabase adds a kernel to the database
func (s *Store) addKernelToDatabase(kernel CatalogKernel, localPath string) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("failed to stat kernel: %w", err)
	}

	kernelName := kernel.GetName()

	// Generate unique ID
	hash := md5.Sum([]byte(localPath + time.Now().String()))
	kernelID := hex.EncodeToString(hash[:])

	arch := kernel.Architecture
	if arch == "" {
		arch = runtime.GOARCH
		if arch == "amd64" {
			arch = "x86_64"
		}
	}

	kernelImg := &database.KernelImage{
		ID:            kernelID,
		Name:          kernelName,
		Version:       kernel.Version,
		Architecture:  arch,
		Path:          localPath,
		Size:          info.Size(),
		Checksum:      kernel.MD5,
		IsDefault:     false,
		VirtioSupport: true, // Assume catalog kernels have virtio support
		FCCompatible:  true, // Assume catalog kernels are FC compatible
	}

	return s.db.CreateKernelImage(kernelImg)
}

// TriggerKernelSync forces an immediate kernel sync
func (s *Store) TriggerKernelSync() {
	go s.syncKernels()
}
