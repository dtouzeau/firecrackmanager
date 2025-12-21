package appliances

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ApplianceInfo holds information about an exported VM appliance
type ApplianceInfo struct {
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	ExportedDate string `json:"exported_date"`
	VMName       string `json:"vm_name"`
	Description  string `json:"description"`
	OwnerID      int    `json:"owner_id,omitempty"`
	OwnerName    string `json:"owner_name,omitempty"`
}

// CacheData holds the cached appliances data
type CacheData struct {
	Appliances []ApplianceInfo `json:"appliances"`
	ScannedAt  string          `json:"scanned_at"`
	Count      int             `json:"count"`
}

// Scanner handles background scanning of appliances
type Scanner struct {
	dataDir      string
	cacheFile    string
	scanInterval time.Duration
	stopCh       chan struct{}
	mu           sync.RWMutex
	cache        *CacheData
	logger       func(format string, args ...interface{})
	descGetter   func(filename string) string
	ownerGetter  func(filename string) (int, string)
	running      bool
}

// NewScanner creates a new appliances scanner
func NewScanner(dataDir string, logger func(format string, args ...interface{})) *Scanner {
	return &Scanner{
		dataDir:      dataDir,
		cacheFile:    filepath.Join(dataDir, "appliances_cache.json"),
		scanInterval: 1 * time.Hour,
		stopCh:       make(chan struct{}),
		logger:       logger,
	}
}

// SetDescriptionGetter sets the function to get appliance descriptions
func (s *Scanner) SetDescriptionGetter(fn func(filename string) string) {
	s.descGetter = fn
}

// SetOwnerGetter sets the function to get appliance owner info
func (s *Scanner) SetOwnerGetter(fn func(filename string) (int, string)) {
	s.ownerGetter = fn
}

// Start starts the background scanner
func (s *Scanner) Start() {
	s.running = true

	// Load existing cache if available
	s.loadCache()

	// Do initial scan
	go s.Scan()

	// Start background scanner
	go s.backgroundLoop()

	s.logger("Appliances scanner started (interval: %v)", s.scanInterval)
}

// Stop stops the background scanner
func (s *Scanner) Stop() {
	if s.running {
		close(s.stopCh)
		s.running = false
		s.logger("Appliances scanner stopped")
	}
}

// backgroundLoop runs the scanner periodically
func (s *Scanner) backgroundLoop() {
	ticker := time.NewTicker(s.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.Scan()
		case <-s.stopCh:
			return
		}
	}
}

// Scan performs a scan and updates the cache
func (s *Scanner) Scan() {
	s.logger("Scanning appliances...")
	startTime := time.Now()

	files, err := os.ReadDir(s.dataDir)
	if err != nil {
		s.logger("Error reading data directory: %v", err)
		return
	}

	var appliances []ApplianceInfo

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".fcrack") {
			continue
		}

		filename := file.Name()
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Parse filename to extract VM name and date
		baseName := strings.TrimSuffix(filename, ".fcrack")
		vmName := baseName
		exportedDate := info.ModTime().Format("2006-01-02 15:04:05")

		// Try to extract date from filename (format: <vm-name>-<YYYYMMDD-HHMMSS>.fcrack)
		if len(baseName) > 16 {
			datePart := baseName[len(baseName)-15:]
			if len(datePart) == 15 && datePart[8] == '-' {
				if t, err := time.Parse("20060102-150405", datePart); err == nil {
					exportedDate = t.Format("2006-01-02 15:04:05")
					vmName = baseName[:len(baseName)-16]
				}
			}
		}

		// Replace underscores back to spaces for display
		vmName = strings.ReplaceAll(vmName, "_", " ")

		// Get description if getter is set
		description := ""
		if s.descGetter != nil {
			description = s.descGetter(filename)
		}

		// Get owner info if getter is set
		ownerID := 0
		ownerName := ""
		if s.ownerGetter != nil {
			ownerID, ownerName = s.ownerGetter(filename)
		}

		appliances = append(appliances, ApplianceInfo{
			Filename:     filename,
			Size:         info.Size(),
			ExportedDate: exportedDate,
			VMName:       vmName,
			Description:  description,
			OwnerID:      ownerID,
			OwnerName:    ownerName,
		})
	}

	// Sort by date descending (most recent first)
	sort.Slice(appliances, func(i, j int) bool {
		return appliances[i].ExportedDate > appliances[j].ExportedDate
	})

	// Update cache
	cacheData := &CacheData{
		Appliances: appliances,
		ScannedAt:  time.Now().Format("2006-01-02 15:04:05"),
		Count:      len(appliances),
	}

	s.mu.Lock()
	s.cache = cacheData
	s.mu.Unlock()

	// Save cache to file
	s.saveCache(cacheData)

	duration := time.Since(startTime)
	s.logger("Appliances scan completed: %d appliances found in %v", len(appliances), duration)
}

// GetCached returns the cached appliances data as interface{} for API compatibility
func (s *Scanner) GetCached() interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cache == nil {
		return &CacheData{
			Appliances: []ApplianceInfo{},
			ScannedAt:  "",
			Count:      0,
		}
	}

	return s.cache
}

// GetCacheData returns the cached appliances data with proper type
func (s *Scanner) GetCacheData() *CacheData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cache == nil {
		return &CacheData{
			Appliances: []ApplianceInfo{},
			ScannedAt:  "",
			Count:      0,
		}
	}

	return s.cache
}

// loadCache loads the cache from file
func (s *Scanner) loadCache() {
	data, err := os.ReadFile(s.cacheFile)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger("Error reading appliances cache: %v", err)
		}
		return
	}

	var cacheData CacheData
	if err := json.Unmarshal(data, &cacheData); err != nil {
		s.logger("Error parsing appliances cache: %v", err)
		return
	}

	s.mu.Lock()
	s.cache = &cacheData
	s.mu.Unlock()

	s.logger("Loaded appliances cache: %d appliances (scanned at %s)", cacheData.Count, cacheData.ScannedAt)
}

// saveCache saves the cache to file
func (s *Scanner) saveCache(data *CacheData) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.logger("Error marshaling appliances cache: %v", err)
		return
	}

	if err := os.WriteFile(s.cacheFile, jsonData, 0644); err != nil {
		s.logger("Error writing appliances cache: %v", err)
		return
	}
}

// TriggerScan triggers an immediate scan (non-blocking)
func (s *Scanner) TriggerScan() {
	go s.Scan()
}

// ScanSync performs a synchronous scan (blocking)
func (s *Scanner) ScanSync() {
	s.Scan()
}

// GetCacheFile returns the path to the cache file
func (s *Scanner) GetCacheFile() string {
	return s.cacheFile
}
