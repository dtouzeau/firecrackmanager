package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"firecrackmanager/internal/setup"
)

const (
	CacheFileName = "firecracker_version.json"
)

// VersionCache stores the cached version information
type VersionCache struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	CheckedAt       time.Time `json:"checked_at"`
	Error           string    `json:"error,omitempty"`
}

// Updater handles background version checking
type Updater struct {
	dataDir   string
	cachePath string
	cron      *cron.Cron
	logger    func(string, ...interface{})
	mu        sync.RWMutex
	cache     *VersionCache
}

// NewUpdater creates a new Updater instance
func NewUpdater(dataDir string, logger func(string, ...interface{})) *Updater {
	return &Updater{
		dataDir:   dataDir,
		cachePath: filepath.Join(dataDir, CacheFileName),
		logger:    logger,
	}
}

// Start initializes the cron scheduler and runs an initial check
func (u *Updater) Start() error {
	// Load existing cache if available
	u.loadCache()

	// Create cron scheduler
	u.cron = cron.New()

	// Schedule daily check at 3:00 AM
	_, err := u.cron.AddFunc("0 3 * * *", func() {
		u.logger("Running scheduled Firecracker version check")
		u.CheckForUpdates()
	})
	if err != nil {
		return fmt.Errorf("failed to schedule update check: %w", err)
	}

	// Start the cron scheduler
	u.cron.Start()
	u.logger("Update checker started (scheduled daily at 3:00 AM)")

	// Run initial check in background if cache is old or missing
	go func() {
		u.mu.RLock()
		needsCheck := u.cache == nil || time.Since(u.cache.CheckedAt) > 24*time.Hour
		u.mu.RUnlock()

		if needsCheck {
			u.logger("Running initial Firecracker version check")
			u.CheckForUpdates()
		}
	}()

	return nil
}

// Stop stops the cron scheduler
func (u *Updater) Stop() {
	if u.cron != nil {
		u.cron.Stop()
	}
}

// CheckForUpdates checks GitHub for the latest version and updates the cache
func (u *Updater) CheckForUpdates() {
	cache := &VersionCache{
		CheckedAt: time.Now(),
	}

	// Get current installed version
	fcPath := "/usr/sbin/firecracker"
	if _, err := os.Stat(fcPath); err == nil {
		out, err := exec.Command(fcPath, "--version").Output()
		if err == nil {
			version := strings.TrimSpace(string(out))
			if parts := strings.Fields(version); len(parts) >= 2 {
				cache.CurrentVersion = parts[1]
			}
		}
	}

	// Check GitHub for latest version
	s := setup.NewSetup(func(string, ...interface{}) {})
	latestRelease, err := s.GetLatestFirecrackerRelease()
	if err != nil {
		cache.Error = err.Error()
		u.logger("Failed to check Firecracker version: %v", err)
	} else {
		cache.LatestVersion = latestRelease.TagName
		cache.Error = ""

		// Compare versions
		if cache.CurrentVersion != "" && cache.LatestVersion != "" {
			if cache.CurrentVersion != cache.LatestVersion {
				cache.UpdateAvailable = true
			}
		}
	}

	// Update in-memory cache
	u.mu.Lock()
	u.cache = cache
	u.mu.Unlock()

	// Save to file
	u.saveCache(cache)

	if cache.UpdateAvailable {
		u.logger("Firecracker update available: %s -> %s", cache.CurrentVersion, cache.LatestVersion)
	} else if cache.Error == "" {
		u.logger("Firecracker is up to date: %s", cache.CurrentVersion)
	}
}

// GetCache returns the current version cache
func (u *Updater) GetCache() *VersionCache {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if u.cache != nil {
		return u.cache
	}

	// Return empty cache if not loaded
	return &VersionCache{}
}

// InvalidateCache clears the cache (call after upgrade)
func (u *Updater) InvalidateCache() {
	u.mu.Lock()
	u.cache = nil
	u.mu.Unlock()

	// Remove cache file
	os.Remove(u.cachePath)

	// Trigger a new check
	go u.CheckForUpdates()
}

// loadCache loads the cache from the JSON file
func (u *Updater) loadCache() {
	data, err := os.ReadFile(u.cachePath)
	if err != nil {
		return // File doesn't exist yet
	}

	var cache VersionCache
	if err := json.Unmarshal(data, &cache); err != nil {
		u.logger("Failed to parse version cache: %v", err)
		return
	}

	u.mu.Lock()
	u.cache = &cache
	u.mu.Unlock()

	u.logger("Loaded version cache from %s (checked at %s)", u.cachePath, cache.CheckedAt.Format(time.RFC3339))
}

// saveCache saves the cache to the JSON file
func (u *Updater) saveCache(cache *VersionCache) {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		u.logger("Failed to marshal version cache: %v", err)
		return
	}

	if err := os.WriteFile(u.cachePath, data, 0644); err != nil {
		u.logger("Failed to save version cache: %v", err)
		return
	}

	u.logger("Saved version cache to %s", u.cachePath)
}
