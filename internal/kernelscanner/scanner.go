package kernelscanner

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"firecrackmanager/internal/database"
)

const (
	// MinVirtioSymbols is the minimum number of virtio symbols for reliable compatibility
	MinVirtioSymbols = 200

	// RequiredSymbols are kernel symbols that must be present for Firecracker compatibility
	RequiredSymbolVirtioMmioProbe = "virtio_mmio_probe"
	RequiredSymbolVirtioMmioInit  = "virtio_mmio_init"
	RequiredSymbolVirtioNetInit   = "virtio_net_driver_init"
)

// ScanResult holds the result of scanning a kernel
type ScanResult struct {
	ID               string    `json:"id"`
	FCCompatible     bool      `json:"fc_compatible"`
	VirtioSymbols    int       `json:"virtio_symbols"`
	HasMmioProbe     bool      `json:"has_mmio_probe"`
	HasMmioInit      bool      `json:"has_mmio_init"`
	HasNetInit       bool      `json:"has_net_init"`
	DMADirectSymbols int       `json:"dma_direct_symbols"` // Count of dma_direct_* symbols (5.x+ indicator)
	SwiotlbSymbols   int       `json:"swiotlb_symbols"`    // Count of swiotlb_* symbols
	ScannedAt        time.Time `json:"scanned_at"`
	Error            string    `json:"error,omitempty"`
}

// Scanner handles background scanning of kernel images for Firecracker compatibility
type Scanner struct {
	db       *database.DB
	logger   func(string, ...interface{})
	stopCh   chan struct{}
	wg       sync.WaitGroup
	interval time.Duration
	mu       sync.Mutex
	scanning bool
}

// NewScanner creates a new kernel compatibility scanner
func NewScanner(db *database.DB, logger func(string, ...interface{})) *Scanner {
	return &Scanner{
		db:       db,
		logger:   logger,
		stopCh:   make(chan struct{}),
		interval: 5 * time.Minute, // Scan every 5 minutes
	}
}

// Start begins the background scanning task
func (s *Scanner) Start() {
	s.wg.Add(1)
	go s.scanLoop()
	s.logger("Kernel compatibility scanner started (interval: %v)", s.interval)
}

// Stop stops the background scanning task
func (s *Scanner) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger("Kernel compatibility scanner stopped")
}

// scanLoop runs the periodic scanning
func (s *Scanner) scanLoop() {
	defer s.wg.Done()

	// Initial scan on startup
	s.scanAll()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.scanAll()
		}
	}
}

// scanAll scans all kernel images that need scanning
func (s *Scanner) scanAll() {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return
	}
	s.scanning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
	}()

	kernels, err := s.db.ListKernelImages()
	if err != nil {
		s.logger("Failed to list kernels: %v", err)
		return
	}

	for _, kernel := range kernels {
		// Skip if already scanned and file hasn't changed
		if !kernel.ScannedAt.IsZero() {
			info, err := os.Stat(kernel.Path)
			if err == nil && !info.ModTime().After(kernel.ScannedAt) {
				continue
			}
		}

		result := s.ScanKernel(kernel)
		if result.Error == "" {
			if err := s.db.UpdateKernelCompatibility(kernel.ID, result.FCCompatible, result.VirtioSymbols, result.ScannedAt); err != nil {
				s.logger("Failed to update kernel %s: %v", kernel.ID, err)
			} else {
				status := "compatible"
				reason := ""
				if !result.FCCompatible {
					status = "INCOMPATIBLE"
					if result.DMADirectSymbols > 0 {
						reason = " (5.x kernel with dma_direct - DMA issues)"
					}
				}
				s.logger("Scanned kernel %s: %s%s (virtio=%d, dma_direct=%d, swiotlb=%d)",
					kernel.Name, status, reason, result.VirtioSymbols, result.DMADirectSymbols, result.SwiotlbSymbols)
			}
		} else {
			s.logger("Failed to scan kernel %s: %v", kernel.Name, result.Error)
		}
	}
}

// ScanKernel scans a single kernel image for Firecracker compatibility
func (s *Scanner) ScanKernel(kernel *database.KernelImage) *ScanResult {
	result := &ScanResult{
		ID:        kernel.ID,
		ScannedAt: time.Now(),
	}

	// Trust kernels built specifically for Firecracker (have "fc" in name)
	isFirecrackerKernel := strings.Contains(strings.ToLower(kernel.Name), "fc") ||
		strings.Contains(strings.ToLower(kernel.Name), "firecracker")

	// Check if file exists
	if _, err := os.Stat(kernel.Path); os.IsNotExist(err) {
		result.Error = "file not found"
		return result
	}

	// Check for nm command
	nmPath, err := exec.LookPath("nm")
	if err != nil {
		// Fall back to string-based check if nm is not available
		return s.scanKernelWithStrings(kernel, result)
	}

	// Use nm to count virtio symbols and check for required symbols
	cmd := exec.Command(nmPath, kernel.Path)
	output, err := cmd.Output()
	if err != nil {
		// nm might fail on some kernel formats, fall back to strings
		return s.scanKernelWithStrings(kernel, result)
	}

	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		lineLower := strings.ToLower(line)

		// Count virtio symbols
		if strings.Contains(lineLower, "virtio") {
			result.VirtioSymbols++
		}

		// Count dma_direct symbols (5.x+ kernels with stricter DMA requirements)
		if strings.Contains(lineLower, "dma_direct") {
			result.DMADirectSymbols++
		}

		// Count swiotlb symbols (software I/O TLB for DMA bounce buffering)
		if strings.Contains(lineLower, "swiotlb") {
			result.SwiotlbSymbols++
		}

		// Check for required symbols
		if strings.Contains(line, RequiredSymbolVirtioMmioProbe) {
			result.HasMmioProbe = true
		}
		if strings.Contains(line, RequiredSymbolVirtioMmioInit) {
			result.HasMmioInit = true
		}
		if strings.Contains(line, RequiredSymbolVirtioNetInit) {
			result.HasNetInit = true
		}
	}

	// Determine compatibility
	// A kernel is compatible if it has all required virtio-mmio symbols
	// The key requirement is: virtio_mmio_probe, virtio_mmio_init, virtio_net_driver_init
	hasRequiredSymbols := result.HasMmioProbe && result.HasMmioInit && result.HasNetInit

	// Minimum virtio symbols for a functional kernel
	hasMinVirtio := result.VirtioSymbols >= 100

	// 5.x+ kernels (have dma_direct) need proper DMA configuration
	is5xKernel := result.DMADirectSymbols > 0

	// The 4.14 kernel has 94 swiotlb symbols and works well
	// Generic 5.10 kernels have 29-39 swiotlb and fail with DMA issues
	// Require similar swiotlb support as 4.14 for generic 5.x kernels
	hasSufficientSwiotlb := result.SwiotlbSymbols >= 50

	if isFirecrackerKernel {
		// Trust Firecracker-built kernels if they have required symbols
		// These are compiled with proper Firecracker config
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio
	} else if is5xKernel {
		// Generic 5.x/6.x kernels: require substantial swiotlb support
		// Many generic kernels fail with "Failed to enable 64-bit or 32-bit DMA"
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio && hasSufficientSwiotlb
	} else {
		// 4.x kernels: compatible if they have required symbols
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio
	}

	return result
}

// scanKernelWithStrings is a fallback method that uses string searching
func (s *Scanner) scanKernelWithStrings(kernel *database.KernelImage, result *ScanResult) *ScanResult {
	data, err := os.ReadFile(kernel.Path)
	if err != nil {
		result.Error = "failed to read kernel: " + err.Error()
		return result
	}

	// Trust kernels built specifically for Firecracker
	isFirecrackerKernel := strings.Contains(strings.ToLower(kernel.Name), "fc") ||
		strings.Contains(strings.ToLower(kernel.Name), "firecracker")

	contentLower := bytes.ToLower(data)

	// Check for required patterns
	result.HasMmioProbe = bytes.Contains(data, []byte("virtio_mmio_probe")) || bytes.Contains(data, []byte("virtio-mmio"))
	result.HasMmioInit = bytes.Contains(data, []byte("virtio_mmio_init")) || bytes.Contains(data, []byte("virtio_mmio"))
	result.HasNetInit = bytes.Contains(data, []byte("virtio_net_driver_init")) || bytes.Contains(data, []byte("virtio_net"))

	// Estimate virtio symbols by counting occurrences
	result.VirtioSymbols = bytes.Count(contentLower, []byte("virtio"))

	// Check for dma_direct (5.x+ kernel indicator)
	result.DMADirectSymbols = bytes.Count(contentLower, []byte("dma_direct"))

	// Check for swiotlb
	result.SwiotlbSymbols = bytes.Count(contentLower, []byte("swiotlb"))

	// For string-based check, apply same logic as nm-based check
	hasRequiredSymbols := result.HasMmioProbe && result.HasMmioInit && result.HasNetInit
	hasMinVirtio := result.VirtioSymbols >= 50 // Lower threshold for string matching
	is5xKernel := result.DMADirectSymbols > 0
	hasSufficientSwiotlb := result.SwiotlbSymbols >= 20 // Lower threshold for string matching

	if isFirecrackerKernel {
		// Trust Firecracker-built kernels
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio
	} else if is5xKernel {
		// Generic 5.x/6.x kernels: require swiotlb
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio && hasSufficientSwiotlb
	} else {
		// 4.x kernels: need required symbols
		result.FCCompatible = hasRequiredSymbols && hasMinVirtio
	}

	return result
}

// ScanSingle scans a single kernel by ID (for on-demand scanning)
func (s *Scanner) ScanSingle(id string) (*ScanResult, error) {
	kernel, err := s.db.GetKernelImage(id)
	if err != nil {
		return nil, err
	}
	if kernel == nil {
		return nil, nil
	}

	result := s.ScanKernel(kernel)
	if result.Error == "" {
		if err := s.db.UpdateKernelCompatibility(kernel.ID, result.FCCompatible, result.VirtioSymbols, result.ScannedAt); err != nil {
			return result, err
		}
	}

	return result, nil
}

// TriggerScan triggers an immediate scan of all kernels
func (s *Scanner) TriggerScan() {
	go s.scanAll()
}
