package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"firecrackmanager/internal/Compose2FC"
	"firecrackmanager/internal/QemuToFC"
	"firecrackmanager/internal/RegistryToFC"
	"firecrackmanager/internal/database"
	"firecrackmanager/internal/network"
	"firecrackmanager/internal/proxyconfig"
)

// Registry conversion job tracking
type ConversionJob struct {
	ID        string            `json:"id"`
	ImageRef  string            `json:"image_ref"`
	Status    string            `json:"status"` // pending, running, completed, failed
	Progress  int               `json:"progress"`
	Message   string            `json:"message"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at,omitempty"`
	Result    *ConversionResult `json:"result,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type ConversionResult struct {
	RootFSID     string `json:"rootfs_id"`
	ImageRef     string `json:"image_ref"`
	OutputPath   string `json:"output_path"`
	EstimatedGiB int64  `json:"estimated_gib"`
	DataDiskID   string `json:"data_disk_id,omitempty"`
	VMID         string `json:"vm_id,omitempty"`
}

var (
	conversionJobs   = make(map[string]*ConversionJob)
	conversionJobsMu sync.RWMutex
)

// Debian image build job tracking
type DebianBuildJob struct {
	ID            string    `json:"id"`
	ImageName     string    `json:"image_name"`
	DebianVersion string    `json:"debian_version"`
	DiskSizeMB    int       `json:"disk_size_mb"`
	Status        string    `json:"status"` // pending, running, completed, failed
	Progress      int       `json:"progress"`
	Step          string    `json:"step"`
	Message       string    `json:"message"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at,omitempty"`
	RootFSID      string    `json:"rootfs_id,omitempty"`
	OutputPath    string    `json:"output_path,omitempty"`
	Error         string    `json:"error,omitempty"`
}

var (
	debianBuildJobs   = make(map[string]*DebianBuildJob)
	debianBuildJobsMu sync.RWMutex
)

// handleRegistrySearch handles POST /api/registry/search
func (s *Server) handleRegistrySearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Query) == "" {
		s.jsonError(w, "Query is required", http.StatusBadRequest)
		return
	}

	if req.Limit <= 0 {
		req.Limit = 25
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	hits, err := Compose2FC.SearchPublicImages(ctx, req.Query, Compose2FC.SearchOptions{
		Limit:   req.Limit,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		s.logger("Registry search error: %v", err)
		s.jsonError(w, fmt.Sprintf("Search failed: %v", err), http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"query":   req.Query,
		"count":   len(hits),
		"results": hits,
	})
}

// VMConfig holds VM configuration for automatic creation after conversion
type VMConfig struct {
	CreateVM     bool   `json:"create_vm"`
	VCPU         int    `json:"vm_vcpu"`
	MemoryMB     int    `json:"vm_memory_mb"`
	NetworkID    string `json:"vm_network_id"`
	RootPassword string `json:"root_password"`
}

// handleRegistryConvert handles POST /api/registry/convert
func (s *Server) handleRegistryConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ImageRef       string `json:"image_ref"`
		Name           string `json:"name"`
		InjectMinInit  bool   `json:"inject_min_init"`
		InstallSSH     bool   `json:"install_ssh"`
		DataDiskSizeGB int64  `json:"data_disk_size_gib"`
		CreateVM       bool   `json:"create_vm"`
		VMVCPU         int    `json:"vm_vcpu"`
		VMMemoryMB     int    `json:"vm_memory_mb"`
		VMNetworkID    string `json:"vm_network_id"`
		RootPassword   string `json:"root_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.ImageRef) == "" {
		s.jsonError(w, "image_ref is required", http.StatusBadRequest)
		return
	}

	// Set defaults for VM config
	if req.VMVCPU <= 0 {
		req.VMVCPU = 1
	}
	if req.VMMemoryMB <= 0 {
		req.VMMemoryMB = 512
	}

	vmConfig := &VMConfig{
		CreateVM:     req.CreateVM,
		VCPU:         req.VMVCPU,
		MemoryMB:     req.VMMemoryMB,
		NetworkID:    req.VMNetworkID,
		RootPassword: req.RootPassword,
	}

	// Generate job ID
	jobID := generateID()

	// Create job entry
	job := &ConversionJob{
		ID:        jobID,
		ImageRef:  req.ImageRef,
		Status:    "pending",
		Progress:  0,
		Message:   "Queued",
		StartedAt: time.Now(),
	}

	conversionJobsMu.Lock()
	conversionJobs[jobID] = job
	conversionJobsMu.Unlock()

	// Start conversion in background
	go s.runConversion(job, req.Name, req.InjectMinInit, req.InstallSSH, req.DataDiskSizeGB, vmConfig)

	s.jsonResponse(w, map[string]interface{}{
		"job_id":  jobID,
		"status":  "pending",
		"message": "Conversion started",
	})
}

// runConversion executes the image conversion in background
func (s *Server) runConversion(job *ConversionJob, name string, injectMinInit bool, installSSH bool, dataDiskSizeGB int64, vmConfig *VMConfig) {
	updateJob := func(status string, progress int, message string) {
		conversionJobsMu.Lock()
		job.Status = status
		job.Progress = progress
		job.Message = message
		conversionJobsMu.Unlock()
	}

	updateJob("running", 5, "Starting conversion")

	// Determine output name
	outputName := name
	if outputName == "" {
		// Generate name from image ref
		outputName = strings.ReplaceAll(job.ImageRef, "/", "-")
		outputName = strings.ReplaceAll(outputName, ":", "-")
		outputName = strings.ReplaceAll(outputName, " ", "")
	}

	// Get rootfs directory from kernel manager
	rootfsDir := s.kernelMgr.GetRootFSDir()
	outputPath := filepath.Join(rootfsDir, outputName+".ext4")

	// Progress callback
	progressCb := func(pct int, msg string) {
		updateJob("running", pct, msg)
	}

	// Run conversion
	result, err := RegistryToFC.ImageToFirecrackerWithProgress(
		context.Background(),
		job.ImageRef,
		RegistryToFC.ImageToFCOptions{
			OutputImage:   outputPath,
			InjectMinInit: injectMinInit,
			InstallSSH:    installSSH,
		},
		progressCb,
	)

	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Conversion failed"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Image conversion failed for %s: %v", job.ImageRef, err)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to get file info"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to get file info: %v", err)
		return
	}

	// Register the rootfs in database
	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:        rootfsID,
		Name:      outputName,
		Path:      outputPath,
		Size:      fileInfo.Size(),
		Format:    "ext4",
		BaseImage: job.ImageRef,
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to register rootfs"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to register rootfs: %v", err)
		return
	}

	// Set root password if specified
	if vmConfig != nil && vmConfig.RootPassword != "" {
		updateJob("running", 85, "Setting root password")
		if err := setRootPassword(outputPath, vmConfig.RootPassword); err != nil {
			s.logger("Warning: Failed to set root password: %v", err)
		} else {
			s.logger("Root password set for %s", outputName)
		}
	}

	// Create data disk if requested
	var dataDiskID string
	if dataDiskSizeGB > 0 {
		updateJob("running", 90, "Creating data disk")
		dataDiskName := outputName + "-data"
		dataDiskPath := filepath.Join(rootfsDir, dataDiskName+".ext4")

		if err := createEmptyExt4(dataDiskPath, dataDiskSizeGB); err != nil {
			s.logger("Warning: Failed to create data disk: %v", err)
		} else {
			// Get data disk file info
			dataDiskInfo, err := os.Stat(dataDiskPath)
			if err == nil {
				dataDiskID = generateID()
				dataDisk := &database.RootFS{
					ID:     dataDiskID,
					Name:   dataDiskName,
					Path:   dataDiskPath,
					Size:   dataDiskInfo.Size(),
					Format: "ext4",
				}
				if err := s.db.CreateRootFS(dataDisk); err != nil {
					s.logger("Warning: Failed to register data disk: %v", err)
				} else {
					s.logger("Data disk created: %s (%d GiB)", dataDiskPath, dataDiskSizeGB)
				}
			}
		}
	}

	// Create VM if requested
	var vmID string
	if vmConfig != nil && vmConfig.CreateVM {
		updateJob("running", 95, "Creating VM")

		// Get default kernel
		kernels, err := s.db.ListKernelImages()
		if err != nil || len(kernels) == 0 {
			s.logger("Warning: No kernels available, skipping VM creation")
		} else {
			// Find default kernel or use first one
			var kernel *database.KernelImage
			for _, k := range kernels {
				if k.IsDefault {
					kernel = k
					break
				}
			}
			if kernel == nil {
				kernel = kernels[0]
			}

			// Create VM
			vmID = generateID()
			vm := &database.VM{
				ID:         vmID,
				Name:       outputName,
				VCPU:       vmConfig.VCPU,
				MemoryMB:   vmConfig.MemoryMB,
				KernelPath: kernel.Path,
				RootFSPath: outputPath,
				KernelArgs: "console=ttyS0,115200n8 reboot=k panic=1",
				Status:     "stopped",
			}

			// Configure network if specified
			if vmConfig.NetworkID != "" {
				net, err := s.db.GetNetwork(vmConfig.NetworkID)
				if err == nil && net != nil {
					vm.MacAddress = network.GenerateMAC(vmID)

					// Allocate IP
					existingVMs, _ := s.db.GetVMsByNetwork(vmConfig.NetworkID)
					usedIPs := make([]string, 0, len(existingVMs))
					for _, v := range existingVMs {
						if v.IPAddress != "" {
							usedIPs = append(usedIPs, v.IPAddress)
						}
					}
					ip, err := network.AllocateIP(net.Subnet, net.Gateway, usedIPs)
					if err == nil {
						vm.IPAddress = ip
						vm.NetworkID = vmConfig.NetworkID
						vm.TapDevice = network.GenerateTAPName(vmID)
						vm.KernelArgs = buildKernelArgs("", ip, net.Gateway)
					}
				}
			}

			if err := s.db.CreateVM(vm); err != nil {
				s.logger("Warning: Failed to create VM: %v", err)
				vmID = ""
			} else {
				s.logger("VM created: %s (vcpu=%d, memory=%dMB)", outputName, vmConfig.VCPU, vmConfig.MemoryMB)

				// Add data disk as VMDisk if created
				if dataDiskID != "" {
					dataDiskPath := filepath.Join(rootfsDir, outputName+"-data.ext4")
					vmDisk := &database.VMDisk{
						ID:         generateID(),
						VMID:       vmID,
						Name:       outputName + "-data",
						Path:       dataDiskPath,
						SizeMB:     dataDiskSizeGB * 1024,
						Format:     "ext4",
						MountPoint: "/mnt/data",
						DriveID:    "data",
						IsReadOnly: false,
					}
					if err := s.db.CreateVMDisk(vmDisk); err != nil {
						s.logger("Warning: Failed to attach data disk to VM: %v", err)
					} else {
						s.logger("Data disk attached to VM: %s", vmDisk.Path)
					}
				}
			}
		}
	}

	// Update job with success
	conversionJobsMu.Lock()
	job.Status = "completed"
	job.Progress = 100
	job.Message = "Conversion completed"
	if vmID != "" {
		job.Message = "Conversion completed, VM created"
	}
	job.EndedAt = time.Now()
	job.Result = &ConversionResult{
		RootFSID:     rootfsID,
		ImageRef:     result.ImageRef,
		OutputPath:   result.OutputImage,
		EstimatedGiB: result.EstimatedGiB,
	}
	if dataDiskID != "" {
		job.Result.DataDiskID = dataDiskID
	}
	if vmID != "" {
		job.Result.VMID = vmID
	}
	conversionJobsMu.Unlock()

	s.logger("Image conversion completed: %s -> %s (%d GiB)", job.ImageRef, outputPath, result.EstimatedGiB)

	// Trigger rootfs scan to update the UI immediately
	if s.rootfsScanner != nil {
		s.rootfsScanner.TriggerScan()
	}
}

// handleRegistryConversionStatus handles GET /api/registry/convert/{jobId}
func (s *Server) handleRegistryConversionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/registry/convert/")
	jobID := strings.TrimSuffix(path, "/")

	if jobID == "" {
		s.jsonError(w, "Job ID required", http.StatusBadRequest)
		return
	}

	conversionJobsMu.RLock()
	job, exists := conversionJobs[jobID]
	conversionJobsMu.RUnlock()

	if !exists {
		s.jsonError(w, "Job not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, job)
}

// handleRegistryJobs handles GET /api/registry/jobs
func (s *Server) handleRegistryJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conversionJobsMu.RLock()
	jobs := make([]*ConversionJob, 0, len(conversionJobs))
	for _, job := range conversionJobs {
		jobs = append(jobs, job)
	}
	conversionJobsMu.RUnlock()

	s.jsonResponse(w, map[string]interface{}{
		"jobs": jobs,
	})
}

// handleProxyConfig handles GET/PUT /api/system/proxy
func (s *Server) handleProxyConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := proxyconfig.Load()
		s.jsonResponse(w, map[string]interface{}{
			"config": map[string]interface{}{
				"enabled":  config.Enabled,
				"url":      config.URL,
				"username": config.Username,
				"password": "", // Don't expose password in GET
				"no_proxy": config.NoProxy,
			},
		})

	case http.MethodPut:
		// Update proxy config
		var req struct {
			Enabled  bool   `json:"enabled"`
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
			NoProxy  string `json:"no_proxy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Validate URL if enabled
		if req.Enabled && req.URL == "" {
			s.jsonError(w, "Proxy URL is required when enabled", http.StatusBadRequest)
			return
		}

		// Load current config to preserve password if not provided
		currentConfig := proxyconfig.Load()
		newConfig := proxyconfig.ProxyConfig{
			Enabled:  req.Enabled,
			URL:      req.URL,
			Username: req.Username,
			NoProxy:  req.NoProxy,
		}

		// Preserve password if not provided in update
		if req.Password != "" {
			newConfig.Password = req.Password
		} else {
			newConfig.Password = currentConfig.Password
		}

		// Save config
		if err := proxyconfig.Save(newConfig); err != nil {
			s.jsonError(w, "Failed to save proxy configuration: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.logger("Proxy configuration updated: enabled=%v, url=%s, username=%s",
			newConfig.Enabled, newConfig.URL, newConfig.Username)

		s.jsonResponse(w, map[string]interface{}{
			"status":  "success",
			"message": "Proxy configuration updated",
		})

	default:
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleComposeServices handles POST /api/compose/services
func (s *Server) handleComposeServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ComposePath string `json:"compose_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.ComposePath) == "" {
		s.jsonError(w, "compose_path is required", http.StatusBadRequest)
		return
	}

	// Get detailed service info including environment variables
	services, err := Compose2FC.GetServicesDetails(req.ComposePath)
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to list services: %v", err), http.StatusBadRequest)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"compose_path": req.ComposePath,
		"services":     services,
	})
}

// handleComposeConvert handles POST /api/compose/convert
func (s *Server) handleComposeConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ComposePath   string            `json:"compose_path"`
		ServiceName   string            `json:"service_name"`
		OutputName    string            `json:"output_name"`
		UseDocker     bool              `json:"use_docker"`
		InjectMinInit bool              `json:"inject_min_init"`
		InstallSSH    bool              `json:"install_ssh"`
		Environment   map[string]string `json:"environment"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.ComposePath) == "" {
		s.jsonError(w, "compose_path is required", http.StatusBadRequest)
		return
	}

	// Generate job ID
	jobID := generateID()

	// Create job entry
	job := &ConversionJob{
		ID:        jobID,
		ImageRef:  fmt.Sprintf("compose:%s:%s", req.ComposePath, req.ServiceName),
		Status:    "pending",
		Progress:  0,
		Message:   "Queued",
		StartedAt: time.Now(),
	}

	conversionJobsMu.Lock()
	conversionJobs[jobID] = job
	conversionJobsMu.Unlock()

	// Start conversion in background
	go s.runComposeConversion(job, req.ComposePath, req.ServiceName, req.OutputName, req.UseDocker, req.InjectMinInit, req.InstallSSH, req.Environment)

	s.jsonResponse(w, map[string]interface{}{
		"job_id":  jobID,
		"status":  "pending",
		"message": "Compose conversion started",
	})
}

// runComposeConversion executes compose-based conversion in background
func (s *Server) runComposeConversion(job *ConversionJob, composePath, serviceName, outputName string, useDocker, injectMinInit, installSSH bool, environment map[string]string) {
	updateJob := func(status string, progress int, message string) {
		conversionJobsMu.Lock()
		job.Status = status
		job.Progress = progress
		job.Message = message
		conversionJobsMu.Unlock()
	}

	updateJob("running", 5, "Starting compose conversion")

	// Determine output name
	if outputName == "" {
		if serviceName != "" {
			outputName = serviceName
		} else {
			outputName = "compose-rootfs"
		}
	}

	// Get rootfs directory
	rootfsDir := s.kernelMgr.GetRootFSDir()
	outputPath := filepath.Join(rootfsDir, outputName+".ext4")

	// Progress callback
	progressCb := func(pct int, msg string) {
		updateJob("running", pct, msg)
	}

	// Run conversion
	result, err := Compose2FC.BuildExt4FromComposeWithProgress(
		context.Background(),
		Compose2FC.Options{
			ComposePath:   composePath,
			ServiceName:   serviceName,
			OutputImage:   outputPath,
			InjectMinInit: injectMinInit,
			InstallSSH:    installSSH,
			UseDocker:     useDocker,
			Environment:   environment,
		},
		progressCb,
	)

	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Compose conversion failed"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Compose conversion failed: %v", err)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to get file info"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to get file info: %v", err)
		return
	}

	// Register the rootfs in database
	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:        rootfsID,
		Name:      outputName,
		Path:      outputPath,
		Size:      fileInfo.Size(),
		Format:    "ext4",
		BaseImage: result.ImageRef,
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to register rootfs"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to register rootfs: %v", err)
		return
	}

	// Update job with success
	conversionJobsMu.Lock()
	job.Status = "completed"
	job.Progress = 100
	job.Message = "Compose conversion completed"
	job.EndedAt = time.Now()
	job.Result = &ConversionResult{
		RootFSID:     rootfsID,
		ImageRef:     result.ImageRef,
		OutputPath:   result.OutputImage,
		EstimatedGiB: result.EstimatedGiB,
	}
	conversionJobsMu.Unlock()

	s.logger("Compose conversion completed: %s (service: %s) -> %s", composePath, result.ServiceName, outputPath)

	// Trigger rootfs scan to update the UI immediately
	if s.rootfsScanner != nil {
		s.rootfsScanner.TriggerScan()
	}
}

// handleComposeUpload handles POST /api/compose/upload
func (s *Server) handleComposeUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		s.jsonError(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create temp directory for compose files
	composeDir := filepath.Join(os.TempDir(), "firecrackmanager-compose")
	if err := os.MkdirAll(composeDir, 0755); err != nil {
		s.jsonError(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	// Generate unique filename
	uniqueName := fmt.Sprintf("%s-%s", generateID(), header.Filename)
	destPath := filepath.Join(composeDir, uniqueName)

	// Save the file
	destFile, err := os.Create(destPath)
	if err != nil {
		s.jsonError(w, "Failed to save compose file", http.StatusInternalServerError)
		return
	}
	defer destFile.Close()

	if _, err := destFile.ReadFrom(file); err != nil {
		s.jsonError(w, "Failed to write compose file", http.StatusInternalServerError)
		return
	}

	s.logger("Compose file uploaded: %s", destPath)
	s.jsonResponse(w, map[string]interface{}{
		"status": "success",
		"path":   destPath,
	})
}

// handleCreateDataDisk handles POST /api/rootfs/create-data-disk
func (s *Server) handleCreateDataDisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name    string `json:"name"`
		SizeGiB int64  `json:"size_gib"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		s.jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	if req.SizeGiB <= 0 || req.SizeGiB > 100 {
		s.jsonError(w, "size_gib must be between 1 and 100", http.StatusBadRequest)
		return
	}

	// Get rootfs directory
	rootfsDir := s.kernelMgr.GetRootFSDir()
	outputPath := filepath.Join(rootfsDir, req.Name+".ext4")

	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil {
		s.jsonError(w, "A rootfs with this name already exists", http.StatusConflict)
		return
	}

	// Create the empty ext4 disk
	if err := createEmptyExt4(outputPath, req.SizeGiB); err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to create data disk: %v", err), http.StatusInternalServerError)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		s.jsonError(w, "Failed to get file info", http.StatusInternalServerError)
		return
	}

	// Register in database
	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:     rootfsID,
		Name:   req.Name,
		Path:   outputPath,
		Size:   fileInfo.Size(),
		Format: "ext4",
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to register data disk: %v", err), http.StatusInternalServerError)
		return
	}

	s.logger("Data disk created: %s (%d GiB)", outputPath, req.SizeGiB)
	s.jsonResponse(w, map[string]interface{}{
		"status":    "success",
		"rootfs_id": rootfsID,
		"path":      outputPath,
		"size_gib":  req.SizeGiB,
	})
}

// createEmptyExt4 creates an empty ext4 filesystem of the specified size
func createEmptyExt4(path string, sizeGiB int64) error {
	const GiB = int64(1024 * 1024 * 1024)

	// Create sparse file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := f.Truncate(sizeGiB * GiB); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	f.Close()

	// Format as ext4
	cmd := exec.Command("mkfs.ext4", "-F", "-L", "data", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(path)
		return fmt.Errorf("mkfs.ext4 failed: %v: %s", err, string(output))
	}

	return nil
}

// handleRootFSExtend handles POST /api/rootfs/extend/{id} to extend disk size
func (s *Server) handleRootFSExtend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract rootfs ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/rootfs/extend/")
	rootfsID := strings.TrimSuffix(path, "/")
	if rootfsID == "" {
		s.jsonError(w, "RootFS ID is required", http.StatusBadRequest)
		return
	}

	var req struct {
		NewSizeMB int64 `json:"new_size_mb"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate new size
	if req.NewSizeMB < 128 {
		s.jsonError(w, "New size must be at least 128 MB", http.StatusBadRequest)
		return
	}

	if req.NewSizeMB > 102400 { // 100 GB max
		s.jsonError(w, "New size cannot exceed 100 GB", http.StatusBadRequest)
		return
	}

	// Get rootfs info
	rootfs, err := s.db.GetRootFS(rootfsID)
	if err != nil {
		s.jsonError(w, "RootFS not found", http.StatusNotFound)
		return
	}

	// Check if file exists
	fileInfo, err := os.Stat(rootfs.Path)
	if err != nil {
		s.jsonError(w, "RootFS file not found on disk", http.StatusNotFound)
		return
	}

	// Check current size
	currentSizeMB := fileInfo.Size() / (1024 * 1024)
	if req.NewSizeMB <= currentSizeMB {
		s.jsonError(w, fmt.Sprintf("New size (%d MB) must be larger than current size (%d MB)", req.NewSizeMB, currentSizeMB), http.StatusBadRequest)
		return
	}

	// Check if rootfs is in use by a running VM
	vms, err := s.db.ListVMs()
	if err == nil {
		for _, vm := range vms {
			if vm.RootFSPath == rootfs.Path && vm.Status == "running" {
				s.jsonError(w, "Cannot extend disk while VM is running. Please stop the VM first.", http.StatusConflict)
				return
			}
		}
	}

	// Extend the file using truncate
	newSizeBytes := req.NewSizeMB * 1024 * 1024
	cmd := exec.Command("truncate", "-s", fmt.Sprintf("%d", newSizeBytes), rootfs.Path)
	if output, err := cmd.CombinedOutput(); err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to extend file: %v: %s", err, string(output)), http.StatusInternalServerError)
		return
	}

	// Check filesystem and resize it
	// First run e2fsck to ensure filesystem is clean
	cmd = exec.Command("e2fsck", "-f", "-y", rootfs.Path)
	cmd.CombinedOutput() // Ignore errors, resize2fs will fail if there's an issue

	// Resize the filesystem to fill the new space
	cmd = exec.Command("resize2fs", rootfs.Path)
	if output, err := cmd.CombinedOutput(); err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to resize filesystem: %v: %s", err, string(output)), http.StatusInternalServerError)
		return
	}

	// Update database with new size
	newFileInfo, _ := os.Stat(rootfs.Path)
	rootfs.Size = newFileInfo.Size()
	if err := s.db.UpdateRootFS(rootfs); err != nil {
		s.logger("Warning: Failed to update rootfs size in database: %v", err)
	}

	s.logger("Extended rootfs %s from %d MB to %d MB", rootfs.Name, currentSizeMB, req.NewSizeMB)

	s.jsonResponse(w, map[string]interface{}{
		"status":      "success",
		"message":     fmt.Sprintf("Disk extended from %d MB to %d MB", currentSizeMB, req.NewSizeMB),
		"old_size_mb": currentSizeMB,
		"new_size_mb": req.NewSizeMB,
		"new_size":    newFileInfo.Size(),
	})
}

// handleBuildDebianImage handles POST /api/rootfs/build-debian
func (s *Server) handleBuildDebianImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ImageName     string `json:"image_name"`
		DebianVersion string `json:"debian_version"`
		DiskSizeMB    int    `json:"disk_size_mb"`
		BuilderDir    string `json:"builder_dir"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate image name
	if strings.TrimSpace(req.ImageName) == "" {
		s.jsonError(w, "image_name is required", http.StatusBadRequest)
		return
	}

	// Sanitize image name (only allow alphanumeric, dash, underscore)
	for _, c := range req.ImageName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			s.jsonError(w, "image_name can only contain alphanumeric characters, dashes, and underscores", http.StatusBadRequest)
			return
		}
	}

	// Validate Debian version
	if req.DebianVersion != "bookworm" && req.DebianVersion != "trixie" {
		s.jsonError(w, "debian_version must be 'bookworm' or 'trixie'", http.StatusBadRequest)
		return
	}

	// Validate disk size (min 512MB, max 20480MB/20GB)
	if req.DiskSizeMB < 512 || req.DiskSizeMB > 20480 {
		s.jsonError(w, "disk_size_mb must be between 512 and 20480", http.StatusBadRequest)
		return
	}

	// Set builder directory (use server config if not specified in request)
	builderDir := s.GetBuilderDir()
	if req.BuilderDir != "" {
		builderDir = req.BuilderDir
	}

	// Check if image already exists
	rootfsDir := s.kernelMgr.GetRootFSDir()
	outputPath := filepath.Join(rootfsDir, req.ImageName+".ext4")
	if _, err := os.Stat(outputPath); err == nil {
		s.jsonError(w, "An image with this name already exists", http.StatusConflict)
		return
	}

	// Create job
	jobID := generateID()
	job := &DebianBuildJob{
		ID:            jobID,
		ImageName:     req.ImageName,
		DebianVersion: req.DebianVersion,
		DiskSizeMB:    req.DiskSizeMB,
		Status:        "pending",
		Progress:      0,
		Step:          "initializing",
		Message:       "Starting Debian image build...",
		StartedAt:     time.Now(),
	}

	debianBuildJobsMu.Lock()
	debianBuildJobs[jobID] = job
	debianBuildJobsMu.Unlock()

	// Start build in background
	go s.runDebianBuild(job, builderDir, rootfsDir)

	s.jsonResponse(w, map[string]interface{}{
		"job_id":  jobID,
		"status":  "started",
		"message": "Debian image build started",
	})
}

// handleBuildDebianProgress handles GET /api/rootfs/build-debian/progress?job_id=xxx
func (s *Server) handleBuildDebianProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobID := r.URL.Query().Get("job_id")
	if jobID == "" {
		s.jsonError(w, "job_id is required", http.StatusBadRequest)
		return
	}

	debianBuildJobsMu.RLock()
	job, exists := debianBuildJobs[jobID]
	debianBuildJobsMu.RUnlock()

	if !exists {
		s.jsonError(w, "Job not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, job)
}

// runDebianBuild executes the Debian image build process
func (s *Server) runDebianBuild(job *DebianBuildJob, builderDir, rootfsDir string) {
	updateJob := func(progress int, step, message string) {
		debianBuildJobsMu.Lock()
		job.Progress = progress
		job.Step = step
		job.Message = message
		debianBuildJobsMu.Unlock()
	}

	failJob := func(err error) {
		debianBuildJobsMu.Lock()
		job.Status = "failed"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		debianBuildJobsMu.Unlock()
		s.logger("Debian build failed: %v", err)
	}

	// Update status to running
	debianBuildJobsMu.Lock()
	job.Status = "running"
	debianBuildJobsMu.Unlock()

	workDir := filepath.Join(builderDir, job.ImageName)
	rootfsPath := filepath.Join(workDir, "rootfs")
	imagePath := filepath.Join(workDir, job.ImageName+".ext4")
	mountPath := filepath.Join("/mnt", job.ImageName)

	// Cleanup function
	defer func() {
		// Cleanup mount point
		exec.Command("umount", mountPath).Run()
		os.RemoveAll(mountPath)
		// Cleanup work directory
		os.RemoveAll(workDir)
	}()

	// Step 1: Check/Install debootstrap
	updateJob(5, "checking_debootstrap", "Checking for debootstrap...")
	if _, err := os.Stat("/usr/sbin/debootstrap"); os.IsNotExist(err) {
		updateJob(5, "installing_debootstrap", "Installing debootstrap...")
		cmd := exec.Command("apt-get", "update")
		if output, err := cmd.CombinedOutput(); err != nil {
			failJob(fmt.Errorf("apt-get update failed: %v: %s", err, string(output)))
			return
		}
		cmd = exec.Command("apt-get", "install", "-y", "debootstrap")
		if output, err := cmd.CombinedOutput(); err != nil {
			failJob(fmt.Errorf("apt-get install debootstrap failed: %v: %s", err, string(output)))
			return
		}
	}

	// Step 2: Create working directories
	updateJob(10, "creating_directories", "Creating working directories...")
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		failJob(fmt.Errorf("failed to create rootfs directory: %v", err))
		return
	}
	if err := os.MkdirAll(mountPath, 0755); err != nil {
		failJob(fmt.Errorf("failed to create mount directory: %v", err))
		return
	}

	// Step 3: Run debootstrap
	updateJob(15, "debootstrap", "Running debootstrap (this may take several minutes)...")
	s.logger("Running debootstrap for %s %s", job.ImageName, job.DebianVersion)
	cmd := exec.Command("debootstrap", "--arch=amd64", job.DebianVersion, rootfsPath, "http://deb.debian.org/debian/")
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("debootstrap failed: %v: %s", err, string(output)))
		return
	}

	// Step 4: Configure the chroot
	updateJob(50, "configuring_chroot", "Configuring root filesystem...")

	// Set root password to "root"
	chrootScript := `#!/bin/bash
set -e
echo "root:root" | chpasswd
apt-get update
apt-get install -y --no-install-recommends openssh-server iproute2 iputils-ping curl ca-certificates systemd-sysv haveged
# Configure SSH to allow root login
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
# Enable SSH service
systemctl enable ssh || true
# Enable haveged for entropy generation
systemctl enable haveged || true
apt-get clean
rm -rf /var/lib/apt/lists/*
`
	scriptPath := filepath.Join(rootfsPath, "tmp", "setup.sh")
	if err := os.WriteFile(scriptPath, []byte(chrootScript), 0755); err != nil {
		failJob(fmt.Errorf("failed to write setup script: %v", err))
		return
	}

	cmd = exec.Command("chroot", rootfsPath, "/bin/bash", "/tmp/setup.sh")
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("chroot configuration failed: %v: %s", err, string(output)))
		return
	}

	// Remove setup script
	os.Remove(scriptPath)

	// Step 5: Create ext4 image file
	updateJob(70, "creating_image", fmt.Sprintf("Creating %d MB ext4 image...", job.DiskSizeMB))
	cmd = exec.Command("dd", "if=/dev/zero", "of="+imagePath, "bs=1M", fmt.Sprintf("count=%d", job.DiskSizeMB))
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("dd failed: %v: %s", err, string(output)))
		return
	}

	cmd = exec.Command("mkfs.ext4", "-F", imagePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("mkfs.ext4 failed: %v: %s", err, string(output)))
		return
	}

	// Step 6: Mount and copy rootfs
	updateJob(80, "copying_rootfs", "Copying root filesystem to image...")
	cmd = exec.Command("mount", imagePath, mountPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("mount failed: %v: %s", err, string(output)))
		return
	}

	cmd = exec.Command("cp", "-a", rootfsPath+"/.", mountPath+"/")
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("umount", mountPath).Run()
		failJob(fmt.Errorf("cp failed: %v: %s", err, string(output)))
		return
	}

	cmd = exec.Command("umount", mountPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		failJob(fmt.Errorf("umount failed: %v: %s", err, string(output)))
		return
	}

	// Step 7: Move image to rootfs repository
	updateJob(90, "finalizing", "Moving image to repository...")
	finalPath := filepath.Join(rootfsDir, job.ImageName+".ext4")
	if err := os.Rename(imagePath, finalPath); err != nil {
		// Try copy if rename fails (different filesystem)
		cmd = exec.Command("cp", imagePath, finalPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			failJob(fmt.Errorf("failed to move image: %v: %s", err, string(output)))
			return
		}
	}

	// Step 8: Register in database
	updateJob(95, "registering", "Registering image in database...")
	fileInfo, err := os.Stat(finalPath)
	if err != nil {
		failJob(fmt.Errorf("failed to stat final image: %v", err))
		return
	}

	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:     rootfsID,
		Name:   job.ImageName,
		Path:   finalPath,
		Size:   fileInfo.Size(),
		Format: "ext4",
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		failJob(fmt.Errorf("failed to register rootfs: %v", err))
		return
	}

	// Complete
	debianBuildJobsMu.Lock()
	job.Status = "completed"
	job.Progress = 100
	job.Step = "completed"
	job.Message = "Debian image created successfully"
	job.RootFSID = rootfsID
	job.OutputPath = finalPath
	job.EndedAt = time.Now()
	debianBuildJobsMu.Unlock()

	s.logger("Debian image build completed: %s (%s)", job.ImageName, finalPath)
}

// CleanupOldJobs removes completed/failed jobs older than 1 hour
func CleanupOldJobs() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-1 * time.Hour)

		conversionJobsMu.Lock()
		for id, job := range conversionJobs {
			if (job.Status == "completed" || job.Status == "failed") && job.EndedAt.Before(cutoff) {
				delete(conversionJobs, id)
			}
		}
		conversionJobsMu.Unlock()

		debianBuildJobsMu.Lock()
		for id, job := range debianBuildJobs {
			if (job.Status == "completed" || job.Status == "failed") && job.EndedAt.Before(cutoff) {
				delete(debianBuildJobs, id)
			}
		}
		debianBuildJobsMu.Unlock()
	}
}

// handleQemuConvert handles POST /api/rootfs/convert-qemu
// Converts QEMU/VMDK disk images to Firecracker ext4 rootfs
func (s *Server) handleQemuConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form with a max memory of 64MB (rest will be written to temp files)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		s.jsonError(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get output name from form
	outputName := r.FormValue("name")
	if outputName == "" {
		s.jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	// Sanitize output name
	outputName = strings.ReplaceAll(outputName, " ", "-")
	outputName = strings.ReplaceAll(outputName, "/", "-")

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		s.jsonError(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".qcow2" && ext != ".vmdk" && ext != ".raw" && ext != ".img" {
		s.jsonError(w, "Unsupported file format. Supported formats: .qcow2, .vmdk, .raw, .img", http.StatusBadRequest)
		return
	}

	// Check if output already exists
	rootfsDir := s.kernelMgr.GetRootFSDir()
	outputPath := filepath.Join(rootfsDir, outputName+".ext4")
	if _, err := os.Stat(outputPath); err == nil {
		s.jsonError(w, "A rootfs with this name already exists", http.StatusConflict)
		return
	}

	// Save uploaded file to temp location
	tempDir, err := os.MkdirTemp("", "qemu-upload-*")
	if err != nil {
		s.jsonError(w, "Failed to create temp directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tempPath := filepath.Join(tempDir, header.Filename)
	tempFile, err := os.Create(tempPath)
	if err != nil {
		os.RemoveAll(tempDir)
		s.jsonError(w, "Failed to create temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	written, err := io.Copy(tempFile, file)
	tempFile.Close()
	if err != nil {
		os.RemoveAll(tempDir)
		s.jsonError(w, "Failed to save uploaded file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.logger("QEMU image uploaded: %s (%d bytes)", header.Filename, written)

	// Generate job ID
	jobID := generateID()

	// Create job entry
	job := &ConversionJob{
		ID:        jobID,
		ImageRef:  fmt.Sprintf("qemu:%s", header.Filename),
		Status:    "pending",
		Progress:  0,
		Message:   "Queued",
		StartedAt: time.Now(),
	}

	conversionJobsMu.Lock()
	conversionJobs[jobID] = job
	conversionJobsMu.Unlock()

	// Start conversion in background
	go s.runQemuConversion(job, tempPath, tempDir, outputName, rootfsDir)

	s.jsonResponse(w, map[string]interface{}{
		"job_id":  jobID,
		"status":  "pending",
		"message": "QEMU image conversion started",
	})
}

// runQemuConversion executes the QEMU/VMDK to ext4 conversion in background
func (s *Server) runQemuConversion(job *ConversionJob, inputPath, tempDir, outputName, rootfsDir string) {
	// Cleanup temp files when done
	defer os.RemoveAll(tempDir)

	updateJob := func(status string, progress int, message string) {
		conversionJobsMu.Lock()
		job.Status = status
		job.Progress = progress
		job.Message = message
		conversionJobsMu.Unlock()
	}

	updateJob("running", 5, "Starting QEMU image conversion")

	outputPath := filepath.Join(rootfsDir, outputName+".ext4")

	// Progress callback
	progressCb := func(pct int, msg string) {
		updateJob("running", pct, msg)
	}

	// Run conversion
	result, err := QemuToFC.ConvertQemuImage(inputPath, QemuToFC.ConvertOptions{
		OutputImage: outputPath,
		Label:       "rootfs",
		TempDir:     tempDir,
	}, progressCb)

	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Conversion failed"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("QEMU image conversion failed: %v", err)
		return
	}

	// Get file size
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to get file info"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to get file info: %v", err)
		return
	}

	// Register the rootfs in database
	rootfsID := generateID()
	rootfs := &database.RootFS{
		ID:        rootfsID,
		Name:      outputName,
		Path:      outputPath,
		Size:      fileInfo.Size(),
		Format:    "ext4",
		BaseImage: fmt.Sprintf("qemu:%s", result.InputFormat),
	}

	if err := s.db.CreateRootFS(rootfs); err != nil {
		conversionJobsMu.Lock()
		job.Status = "failed"
		job.Progress = 0
		job.Message = "Failed to register rootfs"
		job.Error = err.Error()
		job.EndedAt = time.Now()
		conversionJobsMu.Unlock()
		s.logger("Failed to register rootfs: %v", err)
		return
	}

	// Update job with success
	conversionJobsMu.Lock()
	job.Status = "completed"
	job.Progress = 100
	job.Message = "Conversion completed"
	job.EndedAt = time.Now()
	job.Result = &ConversionResult{
		RootFSID:     rootfsID,
		ImageRef:     result.InputPath,
		OutputPath:   result.OutputImage,
		EstimatedGiB: result.SizeGiB,
	}
	conversionJobsMu.Unlock()

	s.logger("QEMU image conversion completed: %s -> %s (%d GiB)", result.InputPath, outputPath, result.SizeGiB)
}

// handleQemuUtilsStatus handles GET /api/system/qemu-utils
// Returns the status of qemu-utils availability
func (s *Server) handleQemuUtilsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := QemuToFC.CheckQemuUtils()
	s.jsonResponse(w, status)
}

// handleQemuUtilsInstall handles POST /api/system/qemu-utils/install
// Attempts to install qemu-utils package
func (s *Server) handleQemuUtilsInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if already available
	if QemuToFC.IsAvailable() {
		s.jsonResponse(w, map[string]interface{}{
			"status":  "success",
			"message": "qemu-utils is already installed",
		})
		return
	}

	// Check if we can install
	status := QemuToFC.CheckQemuUtils()
	if !status.CanInstall {
		s.jsonError(w, "Cannot install qemu-utils: "+status.Error, http.StatusBadRequest)
		return
	}

	// Attempt installation
	s.logger("Installing qemu-utils...")
	if err := QemuToFC.InstallQemuUtils(); err != nil {
		s.logger("Failed to install qemu-utils: %v", err)
		s.jsonError(w, "Installation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify installation
	newStatus := QemuToFC.CheckQemuUtils()
	if !newStatus.Available {
		s.jsonError(w, "Installation completed but qemu-img still not available", http.StatusInternalServerError)
		return
	}

	s.logger("qemu-utils installed successfully: %s", newStatus.Version)
	s.jsonResponse(w, map[string]interface{}{
		"status":  "success",
		"message": "qemu-utils installed successfully",
		"version": newStatus.Version,
	})
}
