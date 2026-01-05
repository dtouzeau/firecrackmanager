package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"firecrackmanager/internal/api"
	"firecrackmanager/internal/appliances"
	"firecrackmanager/internal/database"
	"firecrackmanager/internal/hostnet"
	"firecrackmanager/internal/kernel"
	"firecrackmanager/internal/kernelbuilder"
	"firecrackmanager/internal/kernelscanner"
	"firecrackmanager/internal/kernelupdater"
	"firecrackmanager/internal/network"
	"firecrackmanager/internal/rootfs"
	"firecrackmanager/internal/setup"
	"firecrackmanager/internal/store"
	"firecrackmanager/internal/updater"
	"firecrackmanager/internal/vm"
	"firecrackmanager/internal/webconsole"
)

const (
	DefaultConfigPath = "/etc/firecrackmanager/settings.json"
	DefaultDataDir    = "/var/lib/firecrackmanager"
	DefaultLogDir     = "/var/log/firecrackmanager"
	DefaultHTTPPort   = 8080
	DefaultDBFile     = "firecrackmanager.db"
	DefaultPidFile    = "/var/run/firecrackmanager.pid"
)

type Config struct {
	ConfigPath                  string
	DataDir                     string
	DatabasePath                string
	HTTPPort                    int
	HTTPBind                    string
	LogFile                     string
	PidFile                     string
	RunSetup                    bool
	EnableHostNetworkManagement bool
	BuilderDir                  string
}

func main() {
	config := parseFlags()

	// Handle setup mode
	if config.RunSetup {
		runSetup()
		return
	}

	// Setup logging
	var logWriter io.Writer = os.Stdout
	if config.LogFile != "" {
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(config.LogFile), 0755); err != nil {
			log.Fatalf("Failed to create log directory: %v", err)
		}

		logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer logFile.Close()
		logWriter = io.MultiWriter(os.Stdout, logFile)
	}
	log.SetOutput(logWriter)

	logger := func(format string, args ...interface{}) {
		log.Printf("[FireCrackManager] "+format, args...)
	}

	logger("Starting FireCrackManager...")
	logger("Data directory: %s", config.DataDir)
	logger("Database: %s", config.DatabasePath)

	// Write PID file
	if config.PidFile != "" {
		if err := writePidFile(config.PidFile); err != nil {
			logger("Warning: Failed to write PID file: %v", err)
		} else {
			logger("PID file: %s", config.PidFile)
			defer os.Remove(config.PidFile)
		}
	}

	// Create data directories
	dirs := []string{
		config.DataDir,
		filepath.Join(config.DataDir, "kernels"),
		filepath.Join(config.DataDir, "rootfs"),
		filepath.Join(config.DataDir, "sockets"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	// Initialize database
	db, err := database.New(config.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()
	logger("Database initialized: %s", config.DatabasePath)

	// Initialize network manager
	netMgr := network.NewManager()
	logger("Network manager initialized")

	// Initialize kernel manager
	kernelMgr, err := kernel.NewManager(config.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize kernel manager: %v", err)
	}
	kernelMgr.CleanupTempFiles()
	logger("Kernel manager initialized")

	// Initialize VM manager
	vmMgr, err := vm.NewManager(db, netMgr, config.DataDir, logger)
	if err != nil {
		log.Fatalf("Failed to initialize VM manager: %v", err)
	}
	logger("VM manager initialized")

	// Sync VM status on startup
	if err := vmMgr.SyncVMStatus(); err != nil {
		logger("Warning: failed to sync VM status: %v", err)
	}

	// Start autorun VMs (individual VMs with autorun flag)
	autorunVMs, err := db.ListAutorunVMs()
	if err != nil {
		logger("Warning: failed to list autorun VMs: %v", err)
	} else if len(autorunVMs) > 0 {
		logger("Starting %d autorun VM(s)...", len(autorunVMs))
		for _, vmObj := range autorunVMs {
			if vmObj.Status != "running" {
				logger("  Starting autorun VM: %s (%s)", vmObj.Name, vmObj.ID)
				if err := vmMgr.StartVM(vmObj.ID); err != nil {
					logger("  Warning: failed to start autorun VM %s: %v", vmObj.Name, err)
					db.AddVMLog(vmObj.ID, "error", "Autorun failed: "+err.Error())
				} else {
					db.AddVMLog(vmObj.ID, "info", "VM started by autorun")
				}
			}
		}
	}

	// Start VMs from autorun groups
	autorunGroups, err := db.ListAutorunVMGroups()
	if err != nil {
		logger("Warning: failed to list autorun VM groups: %v", err)
	} else if len(autorunGroups) > 0 {
		logger("Processing %d autorun VM group(s)...", len(autorunGroups))
		startedVMs := make(map[string]bool) // Track already started VMs to avoid duplicates
		for _, group := range autorunGroups {
			groupVMs, err := db.GetVMsInGroup(group.ID)
			if err != nil {
				logger("  Warning: failed to get VMs in group %s: %v", group.Name, err)
				continue
			}
			if len(groupVMs) == 0 {
				continue
			}
			logger("  Starting %d VM(s) from group '%s'...", len(groupVMs), group.Name)
			for _, vmObj := range groupVMs {
				// Skip if already started (either by individual autorun or another group)
				if startedVMs[vmObj.ID] || vmObj.Status == "running" {
					continue
				}
				logger("    Starting VM: %s (%s)", vmObj.Name, vmObj.ID)
				if err := vmMgr.StartVM(vmObj.ID); err != nil {
					logger("    Warning: failed to start VM %s: %v", vmObj.Name, err)
					db.AddVMLog(vmObj.ID, "error", "Group autorun failed: "+err.Error())
				} else {
					db.AddVMLog(vmObj.ID, "info", "VM started by group autorun ("+group.Name+")")
					startedVMs[vmObj.ID] = true
				}
			}
		}
	}

	// Initialize updater (background version checker)
	upd := updater.NewUpdater(config.DataDir, logger)
	if err := upd.Start(); err != nil {
		logger("Warning: failed to start updater: %v", err)
	}

	// Initialize kernel updater (background kernel version checker)
	kernelUpd := kernelupdater.NewKernelUpdater(config.DataDir, db, logger)
	if err := kernelUpd.Start(); err != nil {
		logger("Warning: failed to start kernel updater: %v", err)
	}
	logger("Kernel updater initialized (checks daily at 3:30 AM)")

	// Initialize rootfs scanner (background disk type detection)
	rootfsScanner := rootfs.NewScanner(db, config.DataDir, logger)
	rootfsScanner.Start()

	// Initialize kernel compatibility scanner (background Firecracker compatibility check)
	kernelScanner := kernelscanner.NewScanner(db, logger)
	kernelScanner.Start()

	// Initialize appliances scanner (background exported VMs cache)
	appliancesScanner := appliances.NewScanner(config.DataDir, logger)
	appliancesScanner.SetDescriptionGetter(vmMgr.GetApplianceDescription)
	appliancesScanner.SetOwnerGetter(func(filename string) (int, string) {
		ownerID, _ := db.GetApplianceOwner(filename)
		ownerName := ""
		if ownerID > 0 {
			if owner, err := db.GetUser(ownerID); err == nil && owner != nil {
				ownerName = owner.Username
			}
		}
		return ownerID, ownerName
	})
	appliancesScanner.Start()
	logger("Appliances scanner initialized (scans every hour)")

	// Initialize host network manager
	hostNetMgr := hostnet.NewManager(logger)
	logger("Host network manager initialized (enabled: %v)", config.EnableHostNetworkManagement)

	// Initialize store (appliance store)
	applianceStore := store.New(config.DataDir, logger)
	applianceStore.SetDatabase(db) // Enable kernel sync from catalog
	applianceStore.SetOnDownloadComplete(func() {
		logger("Store download complete, refreshing appliances cache...")
		appliancesScanner.TriggerScan()
	})
	applianceStore.Start()
	logger("Appliance store initialized (kernel sync enabled)")

	// Initialize API server
	apiServer := api.NewServer(db, vmMgr, netMgr, kernelMgr, upd, logger)
	apiServer.SetHostNetManager(hostNetMgr, config.EnableHostNetworkManagement)
	apiServer.SetBuilderDir(config.BuilderDir)
	apiServer.SetDataDir(config.DataDir)
	apiServer.SetStore(applianceStore)
	apiServer.SetRootFSScanner(rootfsScanner)
	apiServer.SetKernelUpdater(kernelUpd)
	apiServer.SetAppliancesScanner(appliancesScanner)

	// Initialize kernel builder for compiling custom kernels
	kernelBld := kernelbuilder.NewBuilder(db, config.DataDir, logger)
	apiServer.SetKernelBuilder(kernelBld)
	logger("Kernel builder initialized")

	// Initialize default admin user
	if err := apiServer.InitDefaultAdmin(); err != nil {
		logger("Warning: failed to initialize default admin: %v", err)
	}

	// Start session cleanup goroutine
	go apiServer.CleanupSessions()

	// Start metrics compression and cleanup schedulers
	metricsCleanupCtx, metricsCleanupCancel := context.WithCancel(context.Background())

	// Hourly compression: raw metrics (>1 hour old) -> 10-minute averages
	go func() {
		// Run once at startup
		if deleted, err := db.CompressMetricsTo10Min(); err != nil {
			logger("Warning: failed to compress metrics to 10min: %v", err)
		} else if deleted > 0 {
			logger("Compressed %d raw metrics to 10-minute averages", deleted)
		}

		// Then run every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-metricsCleanupCtx.Done():
				return
			case <-ticker.C:
				if deleted, err := db.CompressMetricsTo10Min(); err != nil {
					logger("Warning: failed to compress metrics to 10min: %v", err)
				} else if deleted > 0 {
					logger("Compressed %d raw metrics to 10-minute averages", deleted)
				}
			}
		}
	}()

	// Daily compression and cleanup scheduler
	go func() {
		// Run compression at startup
		if deleted, err := db.CompressMetricsToHourly(); err != nil {
			logger("Warning: failed to compress metrics to hourly: %v", err)
		} else if deleted > 0 {
			logger("Compressed %d 10-minute metrics to hourly averages", deleted)
		}

		if deleted, err := db.CompressMetricsToDaily(); err != nil {
			logger("Warning: failed to compress metrics to daily: %v", err)
		} else if deleted > 0 {
			logger("Compressed %d hourly metrics to 14-hour averages", deleted)
		}

		// Cleanup old metrics (raw: 1 hour, compressed: 6 months)
		if deleted, err := db.CleanupOldMetrics(1 * time.Hour); err != nil {
			logger("Warning: failed to cleanup old metrics: %v", err)
		} else if deleted > 0 {
			logger("Cleaned up %d old metric records", deleted)
		}

		// Then run daily at 3:00 AM
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-metricsCleanupCtx.Done():
				return
			case <-ticker.C:
				// Compress 10-minute to hourly (data > 1 day old)
				if deleted, err := db.CompressMetricsToHourly(); err != nil {
					logger("Warning: failed to compress metrics to hourly: %v", err)
				} else if deleted > 0 {
					logger("Compressed %d 10-minute metrics to hourly averages", deleted)
				}

				// Compress hourly to 14-hour (data > 1 week old)
				if deleted, err := db.CompressMetricsToDaily(); err != nil {
					logger("Warning: failed to compress metrics to daily: %v", err)
				} else if deleted > 0 {
					logger("Compressed %d hourly metrics to 14-hour averages", deleted)
				}

				// Cleanup old metrics (6 months retention for compressed data)
				if deleted, err := db.CleanupOldMetrics(1 * time.Hour); err != nil {
					logger("Warning: failed to cleanup old metrics: %v", err)
				} else if deleted > 0 {
					logger("Cleaned up %d old metric records", deleted)
				}
			}
		}
	}()

	// Initialize web console
	webConsole := webconsole.New(db, apiServer)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.HTTPBind, config.HTTPPort),
		Handler:      webConsole,
		ReadTimeout:  30 * time.Minute, // Extended for large file uploads
		WriteTimeout: 30 * time.Minute, // Extended for large file uploads
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger("HTTP server listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger("Shutting down...")

	// Stop metrics cleanup scheduler
	metricsCleanupCancel()

	// Stop updater
	upd.Stop()

	// Stop kernel updater
	kernelUpd.Stop()

	// Stop store
	applianceStore.Stop()

	// Stop rootfs scanner
	rootfsScanner.Stop()

	// Stop kernel scanner
	kernelScanner.Stop()

	// Stop all running VMs
	vmMgr.StopAllVMs()

	// Cleanup network resources
	netMgr.Cleanup()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger("HTTP server shutdown error: %v", err)
	}

	// Close database
	db.Close()

	logger("Shutdown complete")
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.ConfigPath, "config", DefaultConfigPath, "Path to settings.json configuration file")
	flag.StringVar(&config.DataDir, "data-dir", "", "Data directory path (overrides config)")
	flag.StringVar(&config.DatabasePath, "db", "", "SQLite database path (overrides config)")
	flag.IntVar(&config.HTTPPort, "port", 0, "HTTP server port (overrides config)")
	flag.StringVar(&config.HTTPBind, "bind", "", "HTTP server bind address (overrides config)")
	flag.StringVar(&config.LogFile, "log-file", "", "Log file path (overrides config)")
	flag.StringVar(&config.PidFile, "pid-file", "", "PID file path (overrides config)")
	flag.BoolVar(&config.RunSetup, "setup", false, "Run initial setup wizard")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "FireCrackManager - MicroVM Management Daemon\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s                              # Start with config file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -setup                       # Run initial setup (requires root)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -port 9000                   # Override port from config\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -config /opt/fcm/settings.json  # Use custom config\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nDefault credentials:\n")
		fmt.Fprintf(os.Stderr, "  Username: admin\n")
		fmt.Fprintf(os.Stderr, "  Password: admin\n")
	}

	flag.Parse()

	// Load configuration from file if it exists
	if _, err := os.Stat(config.ConfigPath); err == nil {
		fileConfig, err := setup.LoadConfig(config.ConfigPath)
		if err != nil {
			log.Printf("Warning: Failed to load config file %s: %v", config.ConfigPath, err)
		} else {
			// Apply file config as defaults (CLI flags override)
			if config.DataDir == "" {
				config.DataDir = fileConfig.DataDir
			}
			if config.DatabasePath == "" {
				config.DatabasePath = fileConfig.DatabasePath
			}
			if config.HTTPPort == 0 {
				config.HTTPPort = fileConfig.ListenPort
			}
			if config.HTTPBind == "" {
				config.HTTPBind = fileConfig.ListenAddress
			}
			if config.LogFile == "" {
				config.LogFile = fileConfig.LogFile
			}
			if config.PidFile == "" {
				config.PidFile = fileConfig.PidFile
			}
			// Feature flags from config file
			config.EnableHostNetworkManagement = fileConfig.EnableHostNetworkManagement
			// Builder directory
			config.BuilderDir = fileConfig.BuilderDir
		}
	}

	// Apply defaults for any still-unset values
	if config.DataDir == "" {
		config.DataDir = DefaultDataDir
	}
	if config.DatabasePath == "" {
		config.DatabasePath = filepath.Join(config.DataDir, DefaultDBFile)
	}
	if config.HTTPPort == 0 {
		config.HTTPPort = DefaultHTTPPort
	}
	if config.HTTPBind == "" {
		config.HTTPBind = "0.0.0.0"
	}
	if config.PidFile == "" {
		config.PidFile = DefaultPidFile
	}
	if config.BuilderDir == "" {
		config.BuilderDir = "/home/Builder"
	}

	return config
}

func runSetup() {
	logger := func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}

	s := setup.NewSetup(logger)
	if err := s.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}
}

func writePidFile(path string) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	pid := os.Getpid()
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0644)
}
