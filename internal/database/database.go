package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	db *sql.DB
	mu sync.RWMutex
}

type VM struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	VCPU         int    `json:"vcpu"`
	MemoryMB     int    `json:"memory_mb"`
	KernelPath   string `json:"kernel_path"`
	RootFSPath   string `json:"rootfs_path"`
	KernelArgs   string `json:"kernel_args"`
	NetworkID    string `json:"network_id"`
	MacAddress   string `json:"mac_address"`
	IPAddress    string `json:"ip_address"`
	DNSServers   string `json:"dns_servers"`   // comma-separated DNS servers
	SnapshotType string `json:"snapshot_type"` // Full, Diff, or empty for disabled
	TapDevice    string `json:"tap_device"`
	SocketPath   string `json:"socket_path"`
	Status       string `json:"status"` // stopped, running, error
	PID          int    `json:"pid"`
	Autorun      bool   `json:"autorun"` // Start VM automatically when FireCrackManager starts
	// Memory hotplug configuration (virtio-mem)
	HotplugMemoryEnabled bool      `json:"hotplug_memory_enabled"`  // Enable virtio-mem device
	HotplugMemoryTotalMB int       `json:"hotplug_memory_total_mb"` // Maximum hotpluggable memory in MiB
	HotplugMemoryBlockMB int       `json:"hotplug_memory_block_mb"` // Block size (default: 2, power of 2)
	HotplugMemorySlotMB  int       `json:"hotplug_memory_slot_mb"`  // Slot size (default: 128, power of 2)
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	ErrorMessage         string    `json:"error_message"`
}

type Network struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	BridgeName    string    `json:"bridge_name"`
	Subnet        string    `json:"subnet"`     // e.g., "192.168.100.0/24"
	Gateway       string    `json:"gateway"`    // e.g., "192.168.100.1"
	DHCPStart     string    `json:"dhcp_start"` // e.g., "192.168.100.10"
	DHCPEnd       string    `json:"dhcp_end"`   // e.g., "192.168.100.254"
	EnableNAT     bool      `json:"enable_nat"`
	OutInterface  string    `json:"out_interface"`  // External interface for NAT (e.g., "eth0")
	MTU           int       `json:"mtu"`            // Bridge MTU (default 1500)
	STP           bool      `json:"stp"`            // Spanning Tree Protocol enabled
	BlockExternal bool      `json:"block_external"` // Block all external access by default
	Status        string    `json:"status"`         // active, inactive
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// FirewallRule represents a firewall rule for network access control
type FirewallRule struct {
	ID          string    `json:"id"`
	NetworkID   string    `json:"network_id"`
	RuleType    string    `json:"rule_type"` // source_ip, port_forward, port_allow
	SourceIP    string    `json:"source_ip"` // Source IP/CIDR for source_ip rules
	DestIP      string    `json:"dest_ip"`   // Destination VM IP for port_forward
	HostPort    int       `json:"host_port"` // External port for port_forward
	DestPort    int       `json:"dest_port"` // Destination port
	Protocol    string    `json:"protocol"`  // tcp, udp, all
	Action      string    `json:"action"`    // allow, forward
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"` // Lower = higher priority
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type KernelImage struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	Architecture  string    `json:"architecture"`
	Path          string    `json:"path"`
	Size          int64     `json:"size"`
	Checksum      string    `json:"checksum"`
	IsDefault     bool      `json:"is_default"`
	VirtioSupport bool      `json:"virtio_support"` // true if kernel has virtio drivers built-in
	FCCompatible  bool      `json:"fc_compatible"`  // true if kernel is Firecracker compatible (DMA, virtio-mmio)
	VirtioSymbols int       `json:"virtio_symbols"` // count of virtio-related symbols in kernel
	ScannedAt     time.Time `json:"scanned_at"`     // when compatibility was last checked
	CreatedAt     time.Time `json:"created_at"`
}

type RootFS struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	Format       string    `json:"format"` // ext4, squashfs
	BaseImage    string    `json:"base_image"`
	Checksum     string    `json:"checksum"`
	DiskType     string    `json:"disk_type"`   // system, data, unknown
	InitSystem   string    `json:"init_system"` // systemd, openrc, sysvinit, busybox, minimal
	OSRelease    string    `json:"os_release"`  // OS name from /etc/os-release
	SSHInstalled bool      `json:"ssh_installed"`
	SSHVersion   string    `json:"ssh_version,omitempty"`
	ScannedAt    time.Time `json:"scanned_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	Role         string    `json:"role"` // admin, user
	Active       bool      `json:"active"`
	LDAPUser     bool      `json:"ldap_user"`
	LDAPDN       string    `json:"ldap_dn,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type VMLog struct {
	ID        int       `json:"id"`
	VMID      string    `json:"vm_id"`
	Level     string    `json:"level"` // info, warning, error
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type VMDisk struct {
	ID         string    `json:"id"`
	VMID       string    `json:"vm_id"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	SizeMB     int64     `json:"size_mb"`
	Format     string    `json:"format"`      // ext4, xfs, raw
	MountPoint string    `json:"mount_point"` // e.g., /mnt/data
	DriveID    string    `json:"drive_id"`    // Firecracker drive ID (e.g., drive1, drive2)
	IsReadOnly bool      `json:"is_read_only"`
	CreatedAt  time.Time `json:"created_at"`
}

// VMNetwork represents a network interface attached to a VM
type VMNetwork struct {
	ID         string    `json:"id"`
	VMID       string    `json:"vm_id"`
	NetworkID  string    `json:"network_id"`
	IfaceIndex int       `json:"iface_index"` // 0=eth0, 1=eth1, etc.
	MacAddress string    `json:"mac_address"`
	IPAddress  string    `json:"ip_address"`
	TapDevice  string    `json:"tap_device"`
	CreatedAt  time.Time `json:"created_at"`
}

// Group represents a privilege group that can access specific VMs
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions string    `json:"permissions"` // comma-separated: start,stop,console,edit,snapshot,disk
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupMember links users to groups
type GroupMember struct {
	ID        int       `json:"id"`
	GroupID   string    `json:"group_id"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"` // For display purposes
	CreatedAt time.Time `json:"created_at"`
}

// GroupVM links groups to VMs they can access
type GroupVM struct {
	ID        int       `json:"id"`
	GroupID   string    `json:"group_id"`
	VMID      string    `json:"vm_id"`
	VMName    string    `json:"vm_name"` // For display purposes
	CreatedAt time.Time `json:"created_at"`
}

// VMGroup represents a logical grouping of VMs (e.g., "Production", "Development")
type VMGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Color       string    `json:"color"`   // Hex color for UI display
	Autorun     bool      `json:"autorun"` // Auto-start all VMs in this group on startup
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// VMGroupMember links VMs to VM groups
type VMGroupMember struct {
	ID        int       `json:"id"`
	VMGroupID string    `json:"vm_group_id"`
	VMID      string    `json:"vm_id"`
	CreatedAt time.Time `json:"created_at"`
}

// VMGroupPermission links user Groups to VM Groups (access control)
type VMGroupPermission struct {
	ID          int       `json:"id"`
	VMGroupID   string    `json:"vm_group_id"`
	GroupID     string    `json:"group_id"`    // User privilege group
	Permissions string    `json:"permissions"` // Override permissions: start,stop,console,edit,snapshot,disk (empty = inherit from group)
	CreatedAt   time.Time `json:"created_at"`
}

// VMSearchParams contains parameters for searching VMs
type VMSearchParams struct {
	Query     string `json:"query"`       // General search term
	Name      string `json:"name"`        // Filter by VM name
	IPAddress string `json:"ip_address"`  // Filter by IP
	OS        string `json:"os"`          // Filter by OS (from rootfs os_release)
	Status    string `json:"status"`      // running, stopped, etc.
	NetworkID string `json:"network_id"`  // Filter by network
	RootFSID  string `json:"rootfs_id"`   // Filter by rootfs image
	KernelID  string `json:"kernel_id"`   // Filter by kernel
	VMGroupID string `json:"vm_group_id"` // Filter by VM group
	GroupID   string `json:"group_id"`    // Filter by user group access
}

// VMMetric stores historical metrics for VMs
type VMMetric struct {
	ID         int64     `json:"id"`
	VMID       string    `json:"vm_id"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float64   `json:"mem_percent"`
	MemUsedMB  int64     `json:"mem_used_mb"`
	CreatedAt  time.Time `json:"created_at"`
}

// MigrationKey represents an authentication key for VM migration
type MigrationKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	KeyHash     string     `json:"key_hash"` // SHA-256 hash of the actual key
	Description string     `json:"description"`
	AllowPush   bool       `json:"allow_push"` // Allow receiving VMs
	AllowPull   bool       `json:"allow_pull"` // Allow sending VMs
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// AppliancePrivilege represents access privileges for exported VM appliances
type AppliancePrivilege struct {
	ID        int       `json:"id"`
	Filename  string    `json:"filename"`
	OwnerID   int       `json:"owner_id"`
	UserID    *int      `json:"user_id,omitempty"`  // nil if group-based privilege
	GroupID   *string   `json:"group_id,omitempty"` // nil if user-based privilege
	CanRead   bool      `json:"can_read"`
	CanWrite  bool      `json:"can_write"`
	CreatedAt time.Time `json:"created_at"`
	// Joined fields for display
	Username  string `json:"username,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS vms (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			vcpu INTEGER NOT NULL DEFAULT 1,
			memory_mb INTEGER NOT NULL DEFAULT 512,
			kernel_path TEXT NOT NULL,
			rootfs_path TEXT NOT NULL,
			kernel_args TEXT DEFAULT '',
			network_id TEXT,
			mac_address TEXT,
			ip_address TEXT,
			tap_device TEXT,
			socket_path TEXT,
			status TEXT NOT NULL DEFAULT 'stopped',
			pid INTEGER DEFAULT 0,
			error_message TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS networks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			bridge_name TEXT NOT NULL UNIQUE,
			subnet TEXT NOT NULL,
			gateway TEXT NOT NULL,
			dhcp_start TEXT,
			dhcp_end TEXT,
			enable_nat BOOLEAN DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'inactive',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS kernel_images (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			version TEXT NOT NULL,
			architecture TEXT NOT NULL DEFAULT 'x86_64',
			path TEXT NOT NULL,
			size INTEGER DEFAULT 0,
			checksum TEXT,
			is_default BOOLEAN DEFAULT 0,
			virtio_support BOOLEAN DEFAULT 1,
			fc_compatible BOOLEAN DEFAULT 1,
			virtio_symbols INTEGER DEFAULT 0,
			scanned_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS rootfs (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			path TEXT NOT NULL,
			size INTEGER DEFAULT 0,
			format TEXT NOT NULL DEFAULT 'ext4',
			base_image TEXT,
			checksum TEXT,
			disk_type TEXT DEFAULT '',
			init_system TEXT DEFAULT '',
			os_release TEXT DEFAULT '',
			ssh_installed BOOLEAN DEFAULT 0,
			ssh_version TEXT DEFAULT '',
			scanned_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			role TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS vm_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id TEXT NOT NULL,
			level TEXT NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vms_status ON vms(status)`,
		`CREATE INDEX IF NOT EXISTS idx_vms_network_id ON vms(network_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_logs_vm_id ON vm_logs(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_logs_created_at ON vm_logs(created_at)`,
		// Migration: Add dns_servers column to vms table
		`ALTER TABLE vms ADD COLUMN dns_servers TEXT DEFAULT ''`,
		// Migration: Add snapshot_type column to vms table
		`ALTER TABLE vms ADD COLUMN snapshot_type TEXT DEFAULT ''`,
		// VM Disks table for additional attached disks
		`CREATE TABLE IF NOT EXISTS vm_disks (
			id TEXT PRIMARY KEY,
			vm_id TEXT NOT NULL,
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			size_mb INTEGER NOT NULL,
			format TEXT NOT NULL DEFAULT 'ext4',
			mount_point TEXT NOT NULL,
			drive_id TEXT NOT NULL,
			is_read_only BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_disks_vm_id ON vm_disks(vm_id)`,
		// Migration: Add autorun column to vms table
		`ALTER TABLE vms ADD COLUMN autorun BOOLEAN DEFAULT 0`,
		// Migration: Add description column to vms table
		`ALTER TABLE vms ADD COLUMN description TEXT DEFAULT ''`,
		// Groups table for privilege management
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT DEFAULT '',
			permissions TEXT DEFAULT 'start,stop,console',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Group members table - links users to groups
		`CREATE TABLE IF NOT EXISTS group_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id TEXT NOT NULL,
			user_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			UNIQUE(group_id, user_id)
		)`,
		// Group VMs table - links groups to VMs they can access
		`CREATE TABLE IF NOT EXISTS group_vms (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			group_id TEXT NOT NULL,
			vm_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
			UNIQUE(group_id, vm_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_group_members_group_id ON group_members(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_members_user_id ON group_members(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_vms_group_id ON group_vms(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_group_vms_vm_id ON group_vms(vm_id)`,
		// Migration: Add disk scanning columns to rootfs table
		`ALTER TABLE rootfs ADD COLUMN disk_type TEXT DEFAULT ''`,
		`ALTER TABLE rootfs ADD COLUMN init_system TEXT DEFAULT ''`,
		`ALTER TABLE rootfs ADD COLUMN os_release TEXT DEFAULT ''`,
		`ALTER TABLE rootfs ADD COLUMN scanned_at DATETIME`,
		// VM metrics table for historical statistics
		`CREATE TABLE IF NOT EXISTS vm_metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id TEXT NOT NULL,
			cpu_percent REAL DEFAULT 0,
			mem_percent REAL DEFAULT 0,
			mem_used_mb INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_vm_id ON vm_metrics(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_created_at ON vm_metrics(created_at)`,
		// Migration keys table for VM migration authentication
		`CREATE TABLE IF NOT EXISTS migration_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			key_hash TEXT NOT NULL,
			description TEXT DEFAULT '',
			allow_push BOOLEAN DEFAULT 1,
			allow_pull BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used_at DATETIME
		)`,
		// Migration: Add bridge management columns to networks table
		`ALTER TABLE networks ADD COLUMN out_interface TEXT DEFAULT ''`,
		`ALTER TABLE networks ADD COLUMN mtu INTEGER DEFAULT 1500`,
		`ALTER TABLE networks ADD COLUMN stp BOOLEAN DEFAULT 0`,
		`ALTER TABLE networks ADD COLUMN block_external BOOLEAN DEFAULT 0`,
		// Firewall rules table for network access control
		`CREATE TABLE IF NOT EXISTS firewall_rules (
			id TEXT PRIMARY KEY,
			network_id TEXT NOT NULL,
			rule_type TEXT NOT NULL,
			source_ip TEXT DEFAULT '',
			dest_ip TEXT DEFAULT '',
			host_port INTEGER DEFAULT 0,
			dest_port INTEGER DEFAULT 0,
			protocol TEXT DEFAULT 'tcp',
			action TEXT DEFAULT 'allow',
			description TEXT DEFAULT '',
			enabled BOOLEAN DEFAULT 1,
			priority INTEGER DEFAULT 100,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_firewall_rules_network_id ON firewall_rules(network_id)`,
		`CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled)`,
		// VM Groups table for logical grouping of VMs
		`CREATE TABLE IF NOT EXISTS vm_groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT DEFAULT '',
			color TEXT DEFAULT '#6366f1',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// VM Group members - links VMs to VM groups
		`CREATE TABLE IF NOT EXISTS vm_group_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_group_id TEXT NOT NULL,
			vm_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_group_id) REFERENCES vm_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
			UNIQUE(vm_group_id, vm_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_group_members_vm_group_id ON vm_group_members(vm_group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_group_members_vm_id ON vm_group_members(vm_id)`,
		// VM Group permissions - links user Groups to VM Groups
		`CREATE TABLE IF NOT EXISTS vm_group_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_group_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			permissions TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_group_id) REFERENCES vm_groups(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
			UNIQUE(vm_group_id, group_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_group_permissions_vm_group_id ON vm_group_permissions(vm_group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_group_permissions_group_id ON vm_group_permissions(group_id)`,
		// VM Groups autorun column
		`ALTER TABLE vm_groups ADD COLUMN autorun BOOLEAN DEFAULT 0`,
		// Compressed metrics tables for efficient storage
		// 10-minute averages for day view
		`CREATE TABLE IF NOT EXISTS vm_metrics_10min (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id TEXT NOT NULL,
			cpu_percent REAL DEFAULT 0,
			mem_percent REAL DEFAULT 0,
			mem_used_mb INTEGER DEFAULT 0,
			period_start DATETIME NOT NULL,
			sample_count INTEGER DEFAULT 1,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_10min_vm_id ON vm_metrics_10min(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_10min_period ON vm_metrics_10min(period_start)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_metrics_10min_unique ON vm_metrics_10min(vm_id, period_start)`,
		// Hourly averages for week view
		`CREATE TABLE IF NOT EXISTS vm_metrics_hourly (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id TEXT NOT NULL,
			cpu_percent REAL DEFAULT 0,
			mem_percent REAL DEFAULT 0,
			mem_used_mb INTEGER DEFAULT 0,
			period_start DATETIME NOT NULL,
			sample_count INTEGER DEFAULT 1,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_hourly_vm_id ON vm_metrics_hourly(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_hourly_period ON vm_metrics_hourly(period_start)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_metrics_hourly_unique ON vm_metrics_hourly(vm_id, period_start)`,
		// 14-hour averages for month view
		`CREATE TABLE IF NOT EXISTS vm_metrics_daily (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			vm_id TEXT NOT NULL,
			cpu_percent REAL DEFAULT 0,
			mem_percent REAL DEFAULT 0,
			mem_used_mb INTEGER DEFAULT 0,
			period_start DATETIME NOT NULL,
			sample_count INTEGER DEFAULT 1,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_daily_vm_id ON vm_metrics_daily(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_metrics_daily_period ON vm_metrics_daily(period_start)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_vm_metrics_daily_unique ON vm_metrics_daily(vm_id, period_start)`,
		// VM Networks table for multiple network interfaces per VM
		`CREATE TABLE IF NOT EXISTS vm_networks (
			id TEXT PRIMARY KEY,
			vm_id TEXT NOT NULL,
			network_id TEXT NOT NULL,
			iface_index INTEGER NOT NULL DEFAULT 0,
			mac_address TEXT NOT NULL,
			ip_address TEXT,
			tap_device TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE,
			FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE,
			UNIQUE(vm_id, iface_index)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_networks_vm_id ON vm_networks(vm_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vm_networks_network_id ON vm_networks(network_id)`,
		// Appliance privileges table
		`CREATE TABLE IF NOT EXISTS appliance_privileges (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			filename TEXT NOT NULL,
			owner_id INTEGER NOT NULL,
			user_id INTEGER,
			group_id TEXT,
			can_read BOOLEAN DEFAULT 1,
			can_write BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_appliance_privileges_filename ON appliance_privileges(filename)`,
		`CREATE INDEX IF NOT EXISTS idx_appliance_privileges_owner ON appliance_privileges(owner_id)`,
		`CREATE INDEX IF NOT EXISTS idx_appliance_privileges_user ON appliance_privileges(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_appliance_privileges_group ON appliance_privileges(group_id)`,
		// Migration: Add virtio_support column to kernel_images table
		`ALTER TABLE kernel_images ADD COLUMN virtio_support BOOLEAN DEFAULT 1`,
		// Migration: Add Firecracker compatibility columns to kernel_images table
		`ALTER TABLE kernel_images ADD COLUMN fc_compatible BOOLEAN DEFAULT 1`,
		`ALTER TABLE kernel_images ADD COLUMN virtio_symbols INTEGER DEFAULT 0`,
		`ALTER TABLE kernel_images ADD COLUMN scanned_at DATETIME`,
		// Migration: Add SSH detection columns to rootfs table
		`ALTER TABLE rootfs ADD COLUMN ssh_installed BOOLEAN DEFAULT 0`,
		`ALTER TABLE rootfs ADD COLUMN ssh_version TEXT DEFAULT ''`,
		// Migration: Add memory hotplug columns to vms table
		`ALTER TABLE vms ADD COLUMN hotplug_memory_enabled BOOLEAN DEFAULT 0`,
		`ALTER TABLE vms ADD COLUMN hotplug_memory_total_mb INTEGER DEFAULT 0`,
		`ALTER TABLE vms ADD COLUMN hotplug_memory_block_mb INTEGER DEFAULT 2`,
		`ALTER TABLE vms ADD COLUMN hotplug_memory_slot_mb INTEGER DEFAULT 128`,
		// LDAP/Active Directory configuration
		`CREATE TABLE IF NOT EXISTS ldap_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled BOOLEAN DEFAULT 0,
			server TEXT DEFAULT '',
			port INTEGER DEFAULT 389,
			use_ssl BOOLEAN DEFAULT 0,
			use_starttls BOOLEAN DEFAULT 0,
			skip_verify BOOLEAN DEFAULT 1,
			bind_dn TEXT DEFAULT '',
			bind_password TEXT DEFAULT '',
			base_dn TEXT DEFAULT '',
			user_search_base TEXT DEFAULT '',
			user_filter TEXT DEFAULT '(&(objectClass=user)(sAMAccountName=%s))',
			group_search_base TEXT DEFAULT '',
			group_filter TEXT DEFAULT '(objectClass=group)',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// LDAP group to privilege mappings
		`CREATE TABLE IF NOT EXISTS ldap_group_mappings (
			id TEXT PRIMARY KEY,
			group_dn TEXT NOT NULL UNIQUE,
			group_name TEXT NOT NULL,
			local_role TEXT NOT NULL DEFAULT 'user',
			local_group_id TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		// Migration: Add ldap_user column to users table for AD users
		`ALTER TABLE users ADD COLUMN ldap_user BOOLEAN DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN ldap_dn TEXT DEFAULT ''`,
	}

	for _, migration := range migrations {
		if _, err := d.db.Exec(migration); err != nil {
			// Ignore "duplicate column" errors from ALTER TABLE migrations
			if !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("migration failed: %w", err)
			}
		}
	}

	return nil
}

// VM operations
func (d *DB) CreateVM(vm *VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vms (id, name, description, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			network_id, mac_address, ip_address, dns_servers, snapshot_type, tap_device, socket_path, status, pid, autorun, error_message,
			hotplug_memory_enabled, hotplug_memory_total_mb, hotplug_memory_block_mb, hotplug_memory_slot_mb)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vm.ID, vm.Name, vm.Description, vm.VCPU, vm.MemoryMB, vm.KernelPath, vm.RootFSPath, vm.KernelArgs,
		vm.NetworkID, vm.MacAddress, vm.IPAddress, vm.DNSServers, vm.SnapshotType, vm.TapDevice, vm.SocketPath, vm.Status, vm.PID, vm.Autorun, vm.ErrorMessage,
		vm.HotplugMemoryEnabled, vm.HotplugMemoryTotalMB, vm.HotplugMemoryBlockMB, vm.HotplugMemorySlotMB)
	return err
}

func (d *DB) GetVM(id string) (*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	vm := &VM{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''),
			COALESCE(hotplug_memory_enabled, 0), COALESCE(hotplug_memory_total_mb, 0),
			COALESCE(hotplug_memory_block_mb, 2), COALESCE(hotplug_memory_slot_mb, 128),
			created_at, updated_at
		FROM vms WHERE id = ?`, id).Scan(
		&vm.ID, &vm.Name, &vm.Description, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
		&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
		&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage,
		&vm.HotplugMemoryEnabled, &vm.HotplugMemoryTotalMB, &vm.HotplugMemoryBlockMB, &vm.HotplugMemorySlotMB,
		&vm.CreatedAt, &vm.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return vm, err
}

func (d *DB) GetVMByName(name string) (*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	vm := &VM{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''),
			COALESCE(hotplug_memory_enabled, 0), COALESCE(hotplug_memory_total_mb, 0),
			COALESCE(hotplug_memory_block_mb, 2), COALESCE(hotplug_memory_slot_mb, 128),
			created_at, updated_at
		FROM vms WHERE name = ?`, name).Scan(
		&vm.ID, &vm.Name, &vm.Description, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
		&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
		&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage,
		&vm.HotplugMemoryEnabled, &vm.HotplugMemoryTotalMB, &vm.HotplugMemoryBlockMB, &vm.HotplugMemorySlotMB,
		&vm.CreatedAt, &vm.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return vm, err
}

func (d *DB) ListVMs() ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, COALESCE(description, ''), vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''),
			COALESCE(hotplug_memory_enabled, 0), COALESCE(hotplug_memory_total_mb, 0),
			COALESCE(hotplug_memory_block_mb, 2), COALESCE(hotplug_memory_slot_mb, 128),
			created_at, updated_at
		FROM vms ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(
			&vm.ID, &vm.Name, &vm.Description, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
			&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage,
			&vm.HotplugMemoryEnabled, &vm.HotplugMemoryTotalMB, &vm.HotplugMemoryBlockMB, &vm.HotplugMemorySlotMB,
			&vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

func (d *DB) UpdateVM(vm *VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vms SET name=?, description=?, vcpu=?, memory_mb=?, kernel_path=?, rootfs_path=?, kernel_args=?,
			network_id=?, mac_address=?, ip_address=?, dns_servers=?, snapshot_type=?, tap_device=?, socket_path=?,
			status=?, pid=?, autorun=?, error_message=?,
			hotplug_memory_enabled=?, hotplug_memory_total_mb=?, hotplug_memory_block_mb=?, hotplug_memory_slot_mb=?,
			updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		vm.Name, vm.Description, vm.VCPU, vm.MemoryMB, vm.KernelPath, vm.RootFSPath, vm.KernelArgs,
		vm.NetworkID, vm.MacAddress, vm.IPAddress, vm.DNSServers, vm.SnapshotType, vm.TapDevice, vm.SocketPath,
		vm.Status, vm.PID, vm.Autorun, vm.ErrorMessage,
		vm.HotplugMemoryEnabled, vm.HotplugMemoryTotalMB, vm.HotplugMemoryBlockMB, vm.HotplugMemorySlotMB,
		vm.ID)
	return err
}

func (d *DB) UpdateVMStatus(id, status string, pid int, errMsg string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vms SET status=?, pid=?, error_message=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`, status, pid, errMsg, id)
	return err
}

func (d *DB) DeleteVM(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM vms WHERE id = ?", id)
	return err
}

func (d *DB) GetVMsByNetwork(networkID string) ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''), created_at, updated_at
		FROM vms WHERE network_id = ? ORDER BY created_at DESC`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(
			&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
			&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

// Network operations
func (d *DB) CreateNetwork(net *Network) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if net.MTU == 0 {
		net.MTU = 1500
	}
	_, err := d.db.Exec(`
		INSERT INTO networks (id, name, bridge_name, subnet, gateway, dhcp_start, dhcp_end, enable_nat, out_interface, mtu, stp, block_external, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		net.ID, net.Name, net.BridgeName, net.Subnet, net.Gateway, net.DHCPStart, net.DHCPEnd, net.EnableNAT, net.OutInterface, net.MTU, net.STP, net.BlockExternal, net.Status)
	return err
}

func (d *DB) GetNetwork(id string) (*Network, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	net := &Network{}
	err := d.db.QueryRow(`
		SELECT id, name, bridge_name, subnet, gateway, COALESCE(dhcp_start, ''),
			COALESCE(dhcp_end, ''), enable_nat, COALESCE(out_interface, ''), COALESCE(mtu, 1500),
			COALESCE(stp, 0), COALESCE(block_external, 0), status, created_at, updated_at
		FROM networks WHERE id = ?`, id).Scan(
		&net.ID, &net.Name, &net.BridgeName, &net.Subnet, &net.Gateway,
		&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.OutInterface, &net.MTU,
		&net.STP, &net.BlockExternal, &net.Status, &net.CreatedAt, &net.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return net, err
}

func (d *DB) GetNetworkByName(name string) (*Network, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	net := &Network{}
	err := d.db.QueryRow(`
		SELECT id, name, bridge_name, subnet, gateway, COALESCE(dhcp_start, ''),
			COALESCE(dhcp_end, ''), enable_nat, COALESCE(out_interface, ''), COALESCE(mtu, 1500),
			COALESCE(stp, 0), COALESCE(block_external, 0), status, created_at, updated_at
		FROM networks WHERE name = ?`, name).Scan(
		&net.ID, &net.Name, &net.BridgeName, &net.Subnet, &net.Gateway,
		&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.OutInterface, &net.MTU,
		&net.STP, &net.BlockExternal, &net.Status, &net.CreatedAt, &net.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return net, err
}

func (d *DB) ListNetworks() ([]*Network, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, bridge_name, subnet, gateway, COALESCE(dhcp_start, ''),
			COALESCE(dhcp_end, ''), enable_nat, COALESCE(out_interface, ''), COALESCE(mtu, 1500),
			COALESCE(stp, 0), COALESCE(block_external, 0), status, created_at, updated_at
		FROM networks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nets []*Network
	for rows.Next() {
		net := &Network{}
		if err := rows.Scan(
			&net.ID, &net.Name, &net.BridgeName, &net.Subnet, &net.Gateway,
			&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.OutInterface, &net.MTU,
			&net.STP, &net.BlockExternal, &net.Status, &net.CreatedAt, &net.UpdatedAt); err != nil {
			return nil, err
		}
		nets = append(nets, net)
	}
	return nets, nil
}

func (d *DB) UpdateNetwork(net *Network) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if net.MTU == 0 {
		net.MTU = 1500
	}
	_, err := d.db.Exec(`
		UPDATE networks SET name=?, bridge_name=?, subnet=?, gateway=?,
			dhcp_start=?, dhcp_end=?, enable_nat=?, out_interface=?, mtu=?, stp=?, block_external=?, status=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		net.Name, net.BridgeName, net.Subnet, net.Gateway,
		net.DHCPStart, net.DHCPEnd, net.EnableNAT, net.OutInterface, net.MTU, net.STP, net.BlockExternal, net.Status, net.ID)
	return err
}

func (d *DB) UpdateNetworkStatus(id, status string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE networks SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, status, id)
	return err
}

func (d *DB) DeleteNetwork(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM networks WHERE id = ?", id)
	return err
}

// Kernel Image operations
func (d *DB) CreateKernelImage(img *KernelImage) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if img.IsDefault {
		d.db.Exec("UPDATE kernel_images SET is_default = 0")
	}

	_, err := d.db.Exec(`
		INSERT INTO kernel_images (id, name, version, architecture, path, size, checksum, is_default, virtio_support, fc_compatible, virtio_symbols, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		img.ID, img.Name, img.Version, img.Architecture, img.Path, img.Size, img.Checksum, img.IsDefault, img.VirtioSupport, img.FCCompatible, img.VirtioSymbols, img.ScannedAt)
	return err
}

func (d *DB) UpdateKernelImage(img *KernelImage) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if img.IsDefault {
		d.db.Exec("UPDATE kernel_images SET is_default = 0")
	}

	_, err := d.db.Exec(`
		UPDATE kernel_images SET name = ?, version = ?, architecture = ?, path = ?, size = ?, checksum = ?, is_default = ?, virtio_support = ?, fc_compatible = ?, virtio_symbols = ?, scanned_at = ?
		WHERE id = ?`,
		img.Name, img.Version, img.Architecture, img.Path, img.Size, img.Checksum, img.IsDefault, img.VirtioSupport, img.FCCompatible, img.VirtioSymbols, img.ScannedAt, img.ID)
	return err
}

func (d *DB) GetKernelImage(id string) (*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	img := &KernelImage{}
	var scannedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, COALESCE(virtio_support, 1), COALESCE(fc_compatible, 1), COALESCE(virtio_symbols, 0), scanned_at, created_at
		FROM kernel_images WHERE id = ?`, id).Scan(
		&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.VirtioSupport, &img.FCCompatible, &img.VirtioSymbols, &scannedAt, &img.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if scannedAt.Valid {
		img.ScannedAt = scannedAt.Time
	}
	return img, err
}

func (d *DB) GetKernelByPath(path string) (*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	img := &KernelImage{}
	var scannedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, COALESCE(virtio_support, 1), COALESCE(fc_compatible, 1), COALESCE(virtio_symbols, 0), scanned_at, created_at
		FROM kernel_images WHERE path = ?`, path).Scan(
		&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.VirtioSupport, &img.FCCompatible, &img.VirtioSymbols, &scannedAt, &img.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if scannedAt.Valid {
		img.ScannedAt = scannedAt.Time
	}
	return img, err
}

func (d *DB) GetDefaultKernel() (*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	img := &KernelImage{}
	var scannedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, COALESCE(virtio_support, 1), COALESCE(fc_compatible, 1), COALESCE(virtio_symbols, 0), scanned_at, created_at
		FROM kernel_images WHERE is_default = 1 LIMIT 1`).Scan(
		&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.VirtioSupport, &img.FCCompatible, &img.VirtioSymbols, &scannedAt, &img.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if scannedAt.Valid {
		img.ScannedAt = scannedAt.Time
	}
	return img, err
}

func (d *DB) ListKernelImages() ([]*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, COALESCE(virtio_support, 1), COALESCE(fc_compatible, 1), COALESCE(virtio_symbols, 0), scanned_at, created_at
		FROM kernel_images ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var imgs []*KernelImage
	for rows.Next() {
		img := &KernelImage{}
		var scannedAt sql.NullTime
		if err := rows.Scan(&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.VirtioSupport, &img.FCCompatible, &img.VirtioSymbols, &scannedAt, &img.CreatedAt); err != nil {
			return nil, err
		}
		if scannedAt.Valid {
			img.ScannedAt = scannedAt.Time
		}
		imgs = append(imgs, img)
	}
	return imgs, nil
}

// UpdateKernelVirtioSupport updates the virtio_support flag for a kernel
func (d *DB) UpdateKernelVirtioSupport(id string, hasSupport bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("UPDATE kernel_images SET virtio_support = ? WHERE id = ?", hasSupport, id)
	return err
}

// UpdateKernelCompatibility updates the Firecracker compatibility fields for a kernel
func (d *DB) UpdateKernelCompatibility(id string, fcCompatible bool, virtioSymbols int, scannedAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("UPDATE kernel_images SET fc_compatible = ?, virtio_symbols = ?, scanned_at = ? WHERE id = ?",
		fcCompatible, virtioSymbols, scannedAt, id)
	return err
}

func (d *DB) SetDefaultKernel(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.db.Exec("UPDATE kernel_images SET is_default = 0")
	_, err := d.db.Exec("UPDATE kernel_images SET is_default = 1 WHERE id = ?", id)
	return err
}

func (d *DB) DeleteKernelImage(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM kernel_images WHERE id = ?", id)
	return err
}

// RootFS operations
func (d *DB) CreateRootFS(fs *RootFS) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO rootfs (id, name, path, size, format, base_image, checksum)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fs.ID, fs.Name, fs.Path, fs.Size, fs.Format, fs.BaseImage, fs.Checksum)
	return err
}

func (d *DB) GetRootFS(id string) (*RootFS, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	fs := &RootFS{}
	var scannedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, path, size, format, COALESCE(base_image, ''), COALESCE(checksum, ''),
		       COALESCE(disk_type, ''), COALESCE(init_system, ''), COALESCE(os_release, ''),
		       COALESCE(ssh_installed, 0), COALESCE(ssh_version, ''),
		       scanned_at, created_at
		FROM rootfs WHERE id = ?`, id).Scan(
		&fs.ID, &fs.Name, &fs.Path, &fs.Size, &fs.Format, &fs.BaseImage, &fs.Checksum,
		&fs.DiskType, &fs.InitSystem, &fs.OSRelease, &fs.SSHInstalled, &fs.SSHVersion,
		&scannedAt, &fs.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if scannedAt.Valid {
		fs.ScannedAt = scannedAt.Time
	}
	return fs, err
}

func (d *DB) GetRootFSByPath(path string) (*RootFS, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	fs := &RootFS{}
	var scannedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, path, size, format, COALESCE(base_image, ''), COALESCE(checksum, ''),
		       COALESCE(disk_type, ''), COALESCE(init_system, ''), COALESCE(os_release, ''),
		       COALESCE(ssh_installed, 0), COALESCE(ssh_version, ''),
		       scanned_at, created_at
		FROM rootfs WHERE path = ?`, path).Scan(
		&fs.ID, &fs.Name, &fs.Path, &fs.Size, &fs.Format, &fs.BaseImage, &fs.Checksum,
		&fs.DiskType, &fs.InitSystem, &fs.OSRelease, &fs.SSHInstalled, &fs.SSHVersion,
		&scannedAt, &fs.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if scannedAt.Valid {
		fs.ScannedAt = scannedAt.Time
	}
	return fs, err
}

// GetVMsByRootFSPath returns all VMs using a specific rootfs path
func (d *DB) GetVMsByRootFSPath(rootfsPath string) ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
		       network_id, mac_address, ip_address, COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''),
		       tap_device, socket_path, status, pid, autorun, created_at, updated_at, COALESCE(error_message, '')
		FROM vms WHERE rootfs_path = ? ORDER BY name`, rootfsPath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(
			&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType,
			&vm.TapDevice, &vm.SocketPath, &vm.Status, &vm.PID, &vm.Autorun, &vm.CreatedAt, &vm.UpdatedAt, &vm.ErrorMessage); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, rows.Err()
}

func (d *DB) ListRootFS() ([]*RootFS, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, path, size, format, COALESCE(base_image, ''), COALESCE(checksum, ''),
		       COALESCE(disk_type, ''), COALESCE(init_system, ''), COALESCE(os_release, ''),
		       COALESCE(ssh_installed, 0), COALESCE(ssh_version, ''),
		       scanned_at, created_at
		FROM rootfs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fsList []*RootFS
	for rows.Next() {
		fs := &RootFS{}
		var scannedAt sql.NullTime
		if err := rows.Scan(&fs.ID, &fs.Name, &fs.Path, &fs.Size, &fs.Format, &fs.BaseImage, &fs.Checksum,
			&fs.DiskType, &fs.InitSystem, &fs.OSRelease, &fs.SSHInstalled, &fs.SSHVersion,
			&scannedAt, &fs.CreatedAt); err != nil {
			return nil, err
		}
		if scannedAt.Valid {
			fs.ScannedAt = scannedAt.Time
		}
		fsList = append(fsList, fs)
	}
	return fsList, nil
}

func (d *DB) UpdateRootFS(fs *RootFS) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE rootfs SET name=?, path=?, size=?, format=?, base_image=?, checksum=?,
		       disk_type=?, init_system=?, os_release=?, ssh_installed=?, ssh_version=?, scanned_at=?
		WHERE id=?`,
		fs.Name, fs.Path, fs.Size, fs.Format, fs.BaseImage, fs.Checksum,
		fs.DiskType, fs.InitSystem, fs.OSRelease, fs.SSHInstalled, fs.SSHVersion, fs.ScannedAt, fs.ID)
	return err
}

func (d *DB) DeleteRootFS(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM rootfs WHERE id = ?", id)
	return err
}

// User operations
func (d *DB) CreateUser(user *User) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	result, err := d.db.Exec(`
		INSERT INTO users (username, password_hash, email, role, active)
		VALUES (?, ?, ?, ?, ?)`,
		user.Username, user.PasswordHash, user.Email, user.Role, user.Active)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	user.ID = int(id)
	return nil
}

func (d *DB) GetUser(id int) (*User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	user := &User{}
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, COALESCE(email, ''), role, active,
		       COALESCE(ldap_user, 0), COALESCE(ldap_dn, ''), created_at, updated_at
		FROM users WHERE id = ?`, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active,
		&user.LDAPUser, &user.LDAPDN, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (d *DB) GetUserByUsername(username string) (*User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	user := &User{}
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, COALESCE(email, ''), role, active,
		       COALESCE(ldap_user, 0), COALESCE(ldap_dn, ''), created_at, updated_at
		FROM users WHERE username = ?`, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active,
		&user.LDAPUser, &user.LDAPDN, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (d *DB) ListUsers() ([]*User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, username, password_hash, COALESCE(email, ''), role, active,
		       COALESCE(ldap_user, 0), COALESCE(ldap_dn, ''), created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active,
			&user.LDAPUser, &user.LDAPDN, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (d *DB) UpdateUser(user *User) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE users SET username=?, email=?, role=?, active=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`, user.Username, user.Email, user.Role, user.Active, user.ID)
	return err
}

func (d *DB) UpdateUserPassword(id int, passwordHash string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, passwordHash, id)
	return err
}

func (d *DB) DeleteUser(id int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

func (d *DB) UserCount() (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// Session operations
func (d *DB) CreateSession(sess *Session) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO sessions (id, user_id, username, role, expires_at)
		VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Username, sess.Role, sess.ExpiresAt)
	return err
}

func (d *DB) GetSession(id string) (*Session, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sess := &Session{}
	err := d.db.QueryRow(`
		SELECT id, user_id, username, role, expires_at, created_at
		FROM sessions WHERE id = ? AND expires_at > datetime('now')`, id).Scan(
		&sess.ID, &sess.UserID, &sess.Username, &sess.Role, &sess.ExpiresAt, &sess.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sess, err
}

func (d *DB) ExtendSession(id string, duration time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	expiresAt := time.Now().Add(duration)
	_, err := d.db.Exec(`UPDATE sessions SET expires_at=? WHERE id=?`, expiresAt, id)
	return err
}

func (d *DB) DeleteSession(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM sessions WHERE id = ?", id)
	return err
}

func (d *DB) CleanExpiredSessions() (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	result, err := d.db.Exec("DELETE FROM sessions WHERE expires_at < datetime('now')")
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// VM Log operations
func (d *DB) AddVMLog(vmID, level, message string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_logs (vm_id, level, message) VALUES (?, ?, ?)`,
		vmID, level, message)
	return err
}

func (d *DB) GetVMLogs(vmID string, limit int) ([]*VMLog, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, vm_id, level, message, created_at
		FROM vm_logs WHERE vm_id = ? ORDER BY created_at DESC LIMIT ?`, vmID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*VMLog
	for rows.Next() {
		log := &VMLog{}
		if err := rows.Scan(&log.ID, &log.VMID, &log.Level, &log.Message, &log.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func (d *DB) GetRecentLogs(limit int) ([]*VMLog, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, vm_id, level, message, created_at
		FROM vm_logs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*VMLog
	for rows.Next() {
		log := &VMLog{}
		if err := rows.Scan(&log.ID, &log.VMID, &log.Level, &log.Message, &log.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func (d *DB) CleanOldLogs(days int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	result, err := d.db.Exec(`
		DELETE FROM vm_logs WHERE created_at < datetime('now', '-' || ? || ' days')`, days)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

// Statistics
func (d *DB) GetStats() (map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := make(map[string]interface{})

	var vmCount, runningCount, stoppedCount, errorCount int
	d.db.QueryRow("SELECT COUNT(*) FROM vms").Scan(&vmCount)
	d.db.QueryRow("SELECT COUNT(*) FROM vms WHERE status='running'").Scan(&runningCount)
	d.db.QueryRow("SELECT COUNT(*) FROM vms WHERE status='stopped'").Scan(&stoppedCount)
	d.db.QueryRow("SELECT COUNT(*) FROM vms WHERE status='error'").Scan(&errorCount)

	stats["vms"] = map[string]int{
		"total":   vmCount,
		"running": runningCount,
		"stopped": stoppedCount,
		"error":   errorCount,
	}

	var networkCount, activeNetworks int
	d.db.QueryRow("SELECT COUNT(*) FROM networks").Scan(&networkCount)
	d.db.QueryRow("SELECT COUNT(*) FROM networks WHERE status='active'").Scan(&activeNetworks)
	stats["networks"] = map[string]int{
		"total":  networkCount,
		"active": activeNetworks,
	}

	var kernelCount int
	d.db.QueryRow("SELECT COUNT(*) FROM kernel_images").Scan(&kernelCount)
	stats["kernels"] = kernelCount

	var rootfsCount int
	d.db.QueryRow("SELECT COUNT(*) FROM rootfs").Scan(&rootfsCount)
	stats["rootfs"] = rootfsCount

	return stats, nil
}

// VMDisk operations
func (d *DB) CreateVMDisk(disk *VMDisk) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_disks (id, vm_id, name, path, size_mb, format, mount_point, drive_id, is_read_only)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		disk.ID, disk.VMID, disk.Name, disk.Path, disk.SizeMB, disk.Format, disk.MountPoint, disk.DriveID, disk.IsReadOnly)
	return err
}

func (d *DB) GetVMDisk(id string) (*VMDisk, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	disk := &VMDisk{}
	err := d.db.QueryRow(`
		SELECT id, vm_id, name, path, size_mb, format, mount_point, drive_id, is_read_only, created_at
		FROM vm_disks WHERE id = ?`, id).Scan(
		&disk.ID, &disk.VMID, &disk.Name, &disk.Path, &disk.SizeMB, &disk.Format, &disk.MountPoint, &disk.DriveID, &disk.IsReadOnly, &disk.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return disk, err
}

func (d *DB) ListVMDisks(vmID string) ([]*VMDisk, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, vm_id, name, path, size_mb, format, mount_point, drive_id, is_read_only, created_at
		FROM vm_disks WHERE vm_id = ? ORDER BY created_at ASC`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var disks []*VMDisk
	for rows.Next() {
		disk := &VMDisk{}
		if err := rows.Scan(&disk.ID, &disk.VMID, &disk.Name, &disk.Path, &disk.SizeMB, &disk.Format, &disk.MountPoint, &disk.DriveID, &disk.IsReadOnly, &disk.CreatedAt); err != nil {
			return nil, err
		}
		disks = append(disks, disk)
	}
	return disks, nil
}

func (d *DB) DeleteVMDisk(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM vm_disks WHERE id = ?", id)
	return err
}

func (d *DB) UpdateVMDisk(disk *VMDisk) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vm_disks SET name=?, path=?, size_mb=?, format=?, mount_point=?, drive_id=?, is_read_only=?
		WHERE id=?`,
		disk.Name, disk.Path, disk.SizeMB, disk.Format, disk.MountPoint, disk.DriveID, disk.IsReadOnly, disk.ID)
	return err
}

func (d *DB) GetNextDriveID(vmID string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM vm_disks WHERE vm_id = ?", vmID).Scan(&count)
	if err != nil {
		return "", err
	}
	// drive0 is rootfs, so additional disks start at drive1
	return fmt.Sprintf("drive%d", count+1), nil
}

// VMNetwork operations

func (d *DB) CreateVMNetwork(vmNet *VMNetwork) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_networks (id, vm_id, network_id, iface_index, mac_address, ip_address, tap_device)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		vmNet.ID, vmNet.VMID, vmNet.NetworkID, vmNet.IfaceIndex, vmNet.MacAddress, vmNet.IPAddress, vmNet.TapDevice)
	return err
}

func (d *DB) GetVMNetwork(id string) (*VMNetwork, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	vmNet := &VMNetwork{}
	err := d.db.QueryRow(`
		SELECT id, vm_id, network_id, iface_index, mac_address, COALESCE(ip_address, ''), COALESCE(tap_device, ''), created_at
		FROM vm_networks WHERE id = ?`, id).Scan(
		&vmNet.ID, &vmNet.VMID, &vmNet.NetworkID, &vmNet.IfaceIndex, &vmNet.MacAddress, &vmNet.IPAddress, &vmNet.TapDevice, &vmNet.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return vmNet, err
}

func (d *DB) ListVMNetworks(vmID string) ([]*VMNetwork, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, vm_id, network_id, iface_index, mac_address, COALESCE(ip_address, ''), COALESCE(tap_device, ''), created_at
		FROM vm_networks WHERE vm_id = ? ORDER BY iface_index ASC`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []*VMNetwork
	for rows.Next() {
		vmNet := &VMNetwork{}
		if err := rows.Scan(&vmNet.ID, &vmNet.VMID, &vmNet.NetworkID, &vmNet.IfaceIndex, &vmNet.MacAddress, &vmNet.IPAddress, &vmNet.TapDevice, &vmNet.CreatedAt); err != nil {
			return nil, err
		}
		networks = append(networks, vmNet)
	}
	return networks, nil
}

func (d *DB) DeleteVMNetwork(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM vm_networks WHERE id = ?", id)
	return err
}

func (d *DB) DeleteVMNetworksByVMID(vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM vm_networks WHERE vm_id = ?", vmID)
	return err
}

func (d *DB) UpdateVMNetwork(vmNet *VMNetwork) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vm_networks SET network_id=?, iface_index=?, mac_address=?, ip_address=?, tap_device=?
		WHERE id=?`,
		vmNet.NetworkID, vmNet.IfaceIndex, vmNet.MacAddress, vmNet.IPAddress, vmNet.TapDevice, vmNet.ID)
	return err
}

func (d *DB) GetNextIfaceIndex(vmID string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var maxIndex sql.NullInt64
	err := d.db.QueryRow("SELECT MAX(iface_index) FROM vm_networks WHERE vm_id = ?", vmID).Scan(&maxIndex)
	if err != nil {
		return 0, err
	}
	if !maxIndex.Valid {
		return 0, nil
	}
	return int(maxIndex.Int64) + 1, nil
}

// ListAutorunVMs returns all VMs with autorun enabled
func (d *DB) ListAutorunVMs() ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''), created_at, updated_at
		FROM vms WHERE autorun = 1 ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(
			&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
			&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

// Group operations
func (d *DB) CreateGroup(group *Group) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO groups (id, name, description, permissions)
		VALUES (?, ?, ?, ?)`,
		group.ID, group.Name, group.Description, group.Permissions)
	return err
}

func (d *DB) GetGroup(id string) (*Group, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	group := &Group{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), COALESCE(permissions, 'start,stop,console'), created_at, updated_at
		FROM groups WHERE id = ?`, id).Scan(
		&group.ID, &group.Name, &group.Description, &group.Permissions, &group.CreatedAt, &group.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return group, err
}

func (d *DB) GetGroupByName(name string) (*Group, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	group := &Group{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), COALESCE(permissions, 'start,stop,console'), created_at, updated_at
		FROM groups WHERE name = ?`, name).Scan(
		&group.ID, &group.Name, &group.Description, &group.Permissions, &group.CreatedAt, &group.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return group, err
}

func (d *DB) ListGroups() ([]*Group, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, COALESCE(description, ''), COALESCE(permissions, 'start,stop,console'), created_at, updated_at
		FROM groups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		group := &Group{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Permissions, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (d *DB) UpdateGroup(group *Group) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE groups SET name=?, description=?, permissions=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`, group.Name, group.Description, group.Permissions, group.ID)
	return err
}

func (d *DB) DeleteGroup(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM groups WHERE id = ?", id)
	return err
}

// GroupMember operations
func (d *DB) AddGroupMember(groupID string, userID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO group_members (group_id, user_id)
		VALUES (?, ?)`, groupID, userID)
	return err
}

func (d *DB) RemoveGroupMember(groupID string, userID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM group_members WHERE group_id = ? AND user_id = ?", groupID, userID)
	return err
}

func (d *DB) ListGroupMembers(groupID string) ([]*GroupMember, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT gm.id, gm.group_id, gm.user_id, COALESCE(u.username, ''), gm.created_at
		FROM group_members gm
		LEFT JOIN users u ON gm.user_id = u.id
		WHERE gm.group_id = ?
		ORDER BY gm.created_at ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*GroupMember
	for rows.Next() {
		member := &GroupMember{}
		if err := rows.Scan(&member.ID, &member.GroupID, &member.UserID, &member.Username, &member.CreatedAt); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, nil
}

func (d *DB) GetUserGroups(userID int) ([]*Group, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT g.id, g.name, COALESCE(g.description, ''), COALESCE(g.permissions, 'start,stop,console'), g.created_at, g.updated_at
		FROM groups g
		INNER JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY g.name ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		group := &Group{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Permissions, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// GetUserPermissions returns a map of all permissions a user has from all their groups
// Available permissions: start, stop, console, edit, snapshot, disk, networks, images, admin
func (d *DB) GetUserPermissions(userID int, userRole string) map[string]bool {
	perms := make(map[string]bool)

	// Admins have all permissions
	if userRole == "admin" {
		perms["start"] = true
		perms["stop"] = true
		perms["console"] = true
		perms["edit"] = true
		perms["snapshot"] = true
		perms["disk"] = true
		perms["networks"] = true
		perms["images"] = true
		perms["admin"] = true
		return perms
	}

	// Get all groups for the user
	groups, err := d.GetUserGroups(userID)
	if err != nil {
		return perms
	}

	// Combine permissions from all groups
	for _, group := range groups {
		for _, perm := range strings.Split(group.Permissions, ",") {
			perm = strings.TrimSpace(perm)
			if perm != "" {
				perms[perm] = true
			}
		}
	}

	return perms
}

// GroupVM operations
func (d *DB) AddGroupVM(groupID, vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO group_vms (group_id, vm_id)
		VALUES (?, ?)`, groupID, vmID)
	return err
}

func (d *DB) RemoveGroupVM(groupID, vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM group_vms WHERE group_id = ? AND vm_id = ?", groupID, vmID)
	return err
}

func (d *DB) ListGroupVMs(groupID string) ([]*GroupVM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT gv.id, gv.group_id, gv.vm_id, COALESCE(v.name, ''), gv.created_at
		FROM group_vms gv
		LEFT JOIN vms v ON gv.vm_id = v.id
		WHERE gv.group_id = ?
		ORDER BY gv.created_at ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*GroupVM
	for rows.Next() {
		gv := &GroupVM{}
		if err := rows.Scan(&gv.ID, &gv.GroupID, &gv.VMID, &gv.VMName, &gv.CreatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, gv)
	}
	return vms, nil
}

// CanUserAccessVM checks if a user has access to a VM through group membership
// Returns true if user is admin, or if user belongs to a group that has access to the VM
func (d *DB) CanUserAccessVM(userID int, userRole, vmID, requiredPermission string) (bool, error) {
	// Admins can access everything
	if userRole == "admin" {
		return true, nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// Check if user belongs to any group that has access to this VM with the required permission
	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*)
		FROM group_members gm
		INNER JOIN group_vms gv ON gm.group_id = gv.group_id
		INNER JOIN groups g ON gm.group_id = g.id
		WHERE gm.user_id = ? AND gv.vm_id = ? AND g.permissions LIKE '%' || ? || '%'`,
		userID, vmID, requiredPermission).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetUserAccessibleVMs returns all VMs that a user can access
func (d *DB) GetUserAccessibleVMs(userID int, userRole string) ([]*VM, error) {
	// Admins can access all VMs
	if userRole == "admin" {
		return d.ListVMs()
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT DISTINCT v.id, v.name, v.vcpu, v.memory_mb, v.kernel_path, v.rootfs_path, v.kernel_args,
			COALESCE(v.network_id, ''), COALESCE(v.mac_address, ''), COALESCE(v.ip_address, ''),
			COALESCE(v.dns_servers, ''), COALESCE(v.snapshot_type, ''), COALESCE(v.tap_device, ''), COALESCE(v.socket_path, ''), v.status, v.pid,
			COALESCE(v.autorun, 0), COALESCE(v.error_message, ''), v.created_at, v.updated_at
		FROM vms v
		INNER JOIN group_vms gv ON v.id = gv.vm_id
		INNER JOIN group_members gm ON gv.group_id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY v.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(
			&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
			&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

// JSON helper
func (d *DB) ExportVMsJSON() ([]byte, error) {
	vms, err := d.ListVMs()
	if err != nil {
		return nil, err
	}
	return json.Marshal(vms)
}

// VM Metrics operations

// SaveVMMetric saves a metric data point for a VM
func (d *DB) SaveVMMetric(vmID string, cpuPercent, memPercent float64, memUsedMB int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_metrics (vm_id, cpu_percent, mem_percent, mem_used_mb)
		VALUES (?, ?, ?, ?)`,
		vmID, cpuPercent, memPercent, memUsedMB)
	return err
}

// GetVMMetrics retrieves metrics for a VM within a time range
func (d *DB) GetVMMetrics(vmID string, since time.Time, limit int) ([]*VMMetric, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Convert to UTC for consistent comparison with stored timestamps
	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	query := `
		SELECT id, vm_id, cpu_percent, mem_percent, mem_used_mb, created_at
		FROM vm_metrics
		WHERE vm_id = ? AND created_at >= ?
		ORDER BY created_at ASC`

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.Query(query, vmID, sinceUTC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*VMMetric
	for rows.Next() {
		m := &VMMetric{}
		if err := rows.Scan(&m.ID, &m.VMID, &m.CPUPercent, &m.MemPercent, &m.MemUsedMB, &m.CreatedAt); err != nil {
			return nil, err
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// GetVMMetricsAggregated retrieves aggregated metrics for longer time ranges
func (d *DB) GetVMMetricsAggregated(vmID string, since time.Time, intervalMinutes int) ([]*VMMetric, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Convert to UTC for consistent comparison with stored timestamps
	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	// Group by time intervals and calculate averages
	query := `
		SELECT
			0 as id,
			vm_id,
			AVG(cpu_percent) as cpu_percent,
			AVG(mem_percent) as mem_percent,
			AVG(mem_used_mb) as mem_used_mb,
			datetime((strftime('%s', created_at) / ?) * ?, 'unixepoch') as created_at
		FROM vm_metrics
		WHERE vm_id = ? AND created_at >= ?
		GROUP BY vm_id, datetime((strftime('%s', created_at) / ?) * ?, 'unixepoch')
		ORDER BY created_at ASC`

	intervalSecs := intervalMinutes * 60
	rows, err := d.db.Query(query, intervalSecs, intervalSecs, vmID, sinceUTC, intervalSecs, intervalSecs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*VMMetric
	for rows.Next() {
		m := &VMMetric{}
		var createdAtStr string
		var memUsedMBFloat float64
		if err := rows.Scan(&m.ID, &m.VMID, &m.CPUPercent, &m.MemPercent, &memUsedMBFloat, &createdAtStr); err != nil {
			return nil, err
		}
		m.MemUsedMB = int64(memUsedMBFloat)
		// Parse the datetime string from SQLite
		if t, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
			m.CreatedAt = t
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// DeleteVMMetrics deletes all metrics for a specific VM (including compressed tables)
func (d *DB) DeleteVMMetrics(vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Delete from all metrics tables
	tables := []string{"vm_metrics", "vm_metrics_10min", "vm_metrics_hourly", "vm_metrics_daily"}
	for _, table := range tables {
		if _, err := d.db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE vm_id = ?`, table), vmID); err != nil {
			// Ignore errors for tables that might not exist yet
			continue
		}
	}
	return nil
}

// ClearVMRealtimeMetrics clears only the realtime metrics (vm_metrics table) for a VM
// This is called when a VM starts to ensure charts start fresh
func (d *DB) ClearVMRealtimeMetrics(vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM vm_metrics WHERE vm_id = ?`, vmID)
	return err
}

// CleanupOldMetrics removes metrics older than the specified duration and returns count deleted
func (d *DB) CleanupOldMetrics(olderThan time.Duration) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().UTC().Add(-olderThan).Format("2006-01-02 15:04:05")
	var totalDeleted int64

	// Clean up raw metrics (keep only recent for real-time view)
	result, err := d.db.Exec(`DELETE FROM vm_metrics WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	if n, _ := result.RowsAffected(); n > 0 {
		totalDeleted += n
	}

	// Clean up compressed tables (6 months = 180 days)
	sixMonthsCutoff := time.Now().UTC().Add(-180 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	compressedTables := []string{"vm_metrics_10min", "vm_metrics_hourly", "vm_metrics_daily"}
	for _, table := range compressedTables {
		result, err := d.db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE period_start < ?`, table), sixMonthsCutoff)
		if err != nil {
			continue // Ignore errors for tables that might not exist yet
		}
		if n, _ := result.RowsAffected(); n > 0 {
			totalDeleted += n
		}
	}

	return totalDeleted, nil
}

// CompressMetricsTo10Min compresses raw metrics older than 1 hour into 10-minute averages
func (d *DB) CompressMetricsTo10Min() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get cutoff time (1 hour ago)
	cutoff := time.Now().UTC().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")

	// Insert aggregated data into 10min table
	// Group by 10-minute intervals (600 seconds)
	insertQuery := `
		INSERT OR REPLACE INTO vm_metrics_10min (vm_id, cpu_percent, mem_percent, mem_used_mb, period_start, sample_count)
		SELECT
			vm_id,
			AVG(cpu_percent),
			AVG(mem_percent),
			CAST(AVG(mem_used_mb) AS INTEGER),
			datetime((strftime('%s', created_at) / 600) * 600, 'unixepoch'),
			COUNT(*)
		FROM vm_metrics
		WHERE created_at < ?
		GROUP BY vm_id, datetime((strftime('%s', created_at) / 600) * 600, 'unixepoch')`

	_, err := d.db.Exec(insertQuery, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to compress to 10min: %w", err)
	}

	// Delete the compressed raw data
	result, err := d.db.Exec(`DELETE FROM vm_metrics WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete compressed data: %w", err)
	}

	return result.RowsAffected()
}

// CompressMetricsToHourly compresses 10-minute metrics older than 1 day into hourly averages
func (d *DB) CompressMetricsToHourly() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get cutoff time (1 day ago)
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")

	// Insert aggregated data into hourly table
	// Group by 1-hour intervals (3600 seconds)
	insertQuery := `
		INSERT OR REPLACE INTO vm_metrics_hourly (vm_id, cpu_percent, mem_percent, mem_used_mb, period_start, sample_count)
		SELECT
			vm_id,
			AVG(cpu_percent),
			AVG(mem_percent),
			CAST(AVG(mem_used_mb) AS INTEGER),
			datetime((strftime('%s', period_start) / 3600) * 3600, 'unixepoch'),
			SUM(sample_count)
		FROM vm_metrics_10min
		WHERE period_start < ?
		GROUP BY vm_id, datetime((strftime('%s', period_start) / 3600) * 3600, 'unixepoch')`

	_, err := d.db.Exec(insertQuery, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to compress to hourly: %w", err)
	}

	// Delete the compressed 10min data
	result, err := d.db.Exec(`DELETE FROM vm_metrics_10min WHERE period_start < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete compressed 10min data: %w", err)
	}

	return result.RowsAffected()
}

// CompressMetricsToDaily compresses hourly metrics older than 1 week into 14-hour averages
func (d *DB) CompressMetricsToDaily() (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get cutoff time (1 week ago)
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour).Format("2006-01-02 15:04:05")

	// Insert aggregated data into daily table
	// Group by 14-hour intervals (50400 seconds)
	insertQuery := `
		INSERT OR REPLACE INTO vm_metrics_daily (vm_id, cpu_percent, mem_percent, mem_used_mb, period_start, sample_count)
		SELECT
			vm_id,
			AVG(cpu_percent),
			AVG(mem_percent),
			CAST(AVG(mem_used_mb) AS INTEGER),
			datetime((strftime('%s', period_start) / 50400) * 50400, 'unixepoch'),
			SUM(sample_count)
		FROM vm_metrics_hourly
		WHERE period_start < ?
		GROUP BY vm_id, datetime((strftime('%s', period_start) / 50400) * 50400, 'unixepoch')`

	_, err := d.db.Exec(insertQuery, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to compress to daily: %w", err)
	}

	// Delete the compressed hourly data
	result, err := d.db.Exec(`DELETE FROM vm_metrics_hourly WHERE period_start < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete compressed hourly data: %w", err)
	}

	return result.RowsAffected()
}

// GetVMMetrics10Min retrieves 10-minute aggregated metrics for day view
func (d *DB) GetVMMetrics10Min(vmID string, since time.Time) ([]*VMMetric, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	query := `
		SELECT id, vm_id, cpu_percent, mem_percent, mem_used_mb, period_start
		FROM vm_metrics_10min
		WHERE vm_id = ? AND period_start >= ?
		ORDER BY period_start ASC`

	rows, err := d.db.Query(query, vmID, sinceUTC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*VMMetric
	for rows.Next() {
		m := &VMMetric{}
		var periodStr string
		if err := rows.Scan(&m.ID, &m.VMID, &m.CPUPercent, &m.MemPercent, &m.MemUsedMB, &periodStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse("2006-01-02 15:04:05", periodStr); err == nil {
			m.CreatedAt = t
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// GetVMMetricsHourly retrieves hourly aggregated metrics for week view
func (d *DB) GetVMMetricsHourly(vmID string, since time.Time) ([]*VMMetric, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	query := `
		SELECT id, vm_id, cpu_percent, mem_percent, mem_used_mb, period_start
		FROM vm_metrics_hourly
		WHERE vm_id = ? AND period_start >= ?
		ORDER BY period_start ASC`

	rows, err := d.db.Query(query, vmID, sinceUTC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*VMMetric
	for rows.Next() {
		m := &VMMetric{}
		var periodStr string
		if err := rows.Scan(&m.ID, &m.VMID, &m.CPUPercent, &m.MemPercent, &m.MemUsedMB, &periodStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse("2006-01-02 15:04:05", periodStr); err == nil {
			m.CreatedAt = t
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// GetVMMetricsDaily retrieves 14-hour aggregated metrics for month view
func (d *DB) GetVMMetricsDaily(vmID string, since time.Time) ([]*VMMetric, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	query := `
		SELECT id, vm_id, cpu_percent, mem_percent, mem_used_mb, period_start
		FROM vm_metrics_daily
		WHERE vm_id = ? AND period_start >= ?
		ORDER BY period_start ASC`

	rows, err := d.db.Query(query, vmID, sinceUTC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metrics []*VMMetric
	for rows.Next() {
		m := &VMMetric{}
		var periodStr string
		if err := rows.Scan(&m.ID, &m.VMID, &m.CPUPercent, &m.MemPercent, &m.MemUsedMB, &periodStr); err != nil {
			return nil, err
		}
		if t, err := time.Parse("2006-01-02 15:04:05", periodStr); err == nil {
			m.CreatedAt = t
		}
		metrics = append(metrics, m)
	}
	return metrics, rows.Err()
}

// Migration Key operations

// CreateMigrationKey creates a new migration key
func (d *DB) CreateMigrationKey(key *MigrationKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO migration_keys (id, name, key_hash, description, allow_push, allow_pull)
		VALUES (?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, key.KeyHash, key.Description, key.AllowPush, key.AllowPull)
	return err
}

// GetMigrationKey retrieves a migration key by ID
func (d *DB) GetMigrationKey(id string) (*MigrationKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	key := &MigrationKey{}
	var lastUsedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, key_hash, COALESCE(description, ''), allow_push, allow_pull, created_at, last_used_at
		FROM migration_keys WHERE id = ?`, id).Scan(
		&key.ID, &key.Name, &key.KeyHash, &key.Description, &key.AllowPush, &key.AllowPull, &key.CreatedAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	return key, nil
}

// GetMigrationKeyByName retrieves a migration key by name
func (d *DB) GetMigrationKeyByName(name string) (*MigrationKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	key := &MigrationKey{}
	var lastUsedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, key_hash, COALESCE(description, ''), allow_push, allow_pull, created_at, last_used_at
		FROM migration_keys WHERE name = ?`, name).Scan(
		&key.ID, &key.Name, &key.KeyHash, &key.Description, &key.AllowPush, &key.AllowPull, &key.CreatedAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	return key, nil
}

// GetMigrationKeyByHash retrieves a migration key by its hash
func (d *DB) GetMigrationKeyByHash(keyHash string) (*MigrationKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	key := &MigrationKey{}
	var lastUsedAt sql.NullTime
	err := d.db.QueryRow(`
		SELECT id, name, key_hash, COALESCE(description, ''), allow_push, allow_pull, created_at, last_used_at
		FROM migration_keys WHERE key_hash = ?`, keyHash).Scan(
		&key.ID, &key.Name, &key.KeyHash, &key.Description, &key.AllowPush, &key.AllowPull, &key.CreatedAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	return key, nil
}

// ListMigrationKeys returns all migration keys
func (d *DB) ListMigrationKeys() ([]*MigrationKey, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, key_hash, COALESCE(description, ''), allow_push, allow_pull, created_at, last_used_at
		FROM migration_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*MigrationKey
	for rows.Next() {
		key := &MigrationKey{}
		var lastUsedAt sql.NullTime
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &key.Description, &key.AllowPush, &key.AllowPull, &key.CreatedAt, &lastUsedAt); err != nil {
			return nil, err
		}
		if lastUsedAt.Valid {
			key.LastUsedAt = &lastUsedAt.Time
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// UpdateMigrationKey updates a migration key
func (d *DB) UpdateMigrationKey(key *MigrationKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE migration_keys SET name=?, description=?, allow_push=?, allow_pull=?
		WHERE id=?`,
		key.Name, key.Description, key.AllowPush, key.AllowPull, key.ID)
	return err
}

// UpdateMigrationKeyLastUsed updates the last_used_at timestamp
func (d *DB) UpdateMigrationKeyLastUsed(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`UPDATE migration_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

// DeleteMigrationKey deletes a migration key
func (d *DB) DeleteMigrationKey(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM migration_keys WHERE id = ?", id)
	return err
}

// Firewall Rule operations

// CreateFirewallRule creates a new firewall rule
func (d *DB) CreateFirewallRule(rule *FirewallRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO firewall_rules (id, network_id, rule_type, source_ip, dest_ip, host_port, dest_port, protocol, action, description, enabled, priority)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.NetworkID, rule.RuleType, rule.SourceIP, rule.DestIP, rule.HostPort, rule.DestPort, rule.Protocol, rule.Action, rule.Description, rule.Enabled, rule.Priority)
	return err
}

// GetFirewallRule retrieves a firewall rule by ID
func (d *DB) GetFirewallRule(id string) (*FirewallRule, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rule := &FirewallRule{}
	err := d.db.QueryRow(`
		SELECT id, network_id, rule_type, COALESCE(source_ip, ''), COALESCE(dest_ip, ''),
			COALESCE(host_port, 0), COALESCE(dest_port, 0), COALESCE(protocol, 'tcp'),
			COALESCE(action, 'allow'), COALESCE(description, ''), enabled, COALESCE(priority, 100),
			created_at, updated_at
		FROM firewall_rules WHERE id = ?`, id).Scan(
		&rule.ID, &rule.NetworkID, &rule.RuleType, &rule.SourceIP, &rule.DestIP,
		&rule.HostPort, &rule.DestPort, &rule.Protocol, &rule.Action, &rule.Description,
		&rule.Enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return rule, err
}

// ListFirewallRules returns all firewall rules for a network, ordered by priority
func (d *DB) ListFirewallRules(networkID string) ([]*FirewallRule, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, network_id, rule_type, COALESCE(source_ip, ''), COALESCE(dest_ip, ''),
			COALESCE(host_port, 0), COALESCE(dest_port, 0), COALESCE(protocol, 'tcp'),
			COALESCE(action, 'allow'), COALESCE(description, ''), enabled, COALESCE(priority, 100),
			created_at, updated_at
		FROM firewall_rules WHERE network_id = ? ORDER BY priority ASC, created_at ASC`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*FirewallRule
	for rows.Next() {
		rule := &FirewallRule{}
		if err := rows.Scan(
			&rule.ID, &rule.NetworkID, &rule.RuleType, &rule.SourceIP, &rule.DestIP,
			&rule.HostPort, &rule.DestPort, &rule.Protocol, &rule.Action, &rule.Description,
			&rule.Enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// ListEnabledFirewallRules returns only enabled firewall rules for a network
func (d *DB) ListEnabledFirewallRules(networkID string) ([]*FirewallRule, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, network_id, rule_type, COALESCE(source_ip, ''), COALESCE(dest_ip, ''),
			COALESCE(host_port, 0), COALESCE(dest_port, 0), COALESCE(protocol, 'tcp'),
			COALESCE(action, 'allow'), COALESCE(description, ''), enabled, COALESCE(priority, 100),
			created_at, updated_at
		FROM firewall_rules WHERE network_id = ? AND enabled = 1 ORDER BY priority ASC, created_at ASC`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*FirewallRule
	for rows.Next() {
		rule := &FirewallRule{}
		if err := rows.Scan(
			&rule.ID, &rule.NetworkID, &rule.RuleType, &rule.SourceIP, &rule.DestIP,
			&rule.HostPort, &rule.DestPort, &rule.Protocol, &rule.Action, &rule.Description,
			&rule.Enabled, &rule.Priority, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// UpdateFirewallRule updates a firewall rule
func (d *DB) UpdateFirewallRule(rule *FirewallRule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE firewall_rules SET rule_type=?, source_ip=?, dest_ip=?, host_port=?, dest_port=?,
			protocol=?, action=?, description=?, enabled=?, priority=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		rule.RuleType, rule.SourceIP, rule.DestIP, rule.HostPort, rule.DestPort,
		rule.Protocol, rule.Action, rule.Description, rule.Enabled, rule.Priority, rule.ID)
	return err
}

// UpdateFirewallRuleEnabled enables or disables a firewall rule
func (d *DB) UpdateFirewallRuleEnabled(id string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`UPDATE firewall_rules SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, enabled, id)
	return err
}

// DeleteFirewallRule deletes a firewall rule
func (d *DB) DeleteFirewallRule(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM firewall_rules WHERE id = ?", id)
	return err
}

// DeleteFirewallRulesByNetwork deletes all firewall rules for a network
func (d *DB) DeleteFirewallRulesByNetwork(networkID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM firewall_rules WHERE network_id = ?", networkID)
	return err
}

// CountFirewallRules returns the number of firewall rules for a network
func (d *DB) CountFirewallRules(networkID string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM firewall_rules WHERE network_id = ?", networkID).Scan(&count)
	return count, err
}

// VM Group operations

// CreateVMGroup creates a new VM group
func (d *DB) CreateVMGroup(group *VMGroup) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_groups (id, name, description, color, autorun)
		VALUES (?, ?, ?, ?, ?)`,
		group.ID, group.Name, group.Description, group.Color, group.Autorun)
	return err
}

// GetVMGroup retrieves a VM group by ID
func (d *DB) GetVMGroup(id string) (*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	group := &VMGroup{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), COALESCE(color, '#6366f1'), COALESCE(autorun, 0), created_at, updated_at
		FROM vm_groups WHERE id = ?`, id).Scan(
		&group.ID, &group.Name, &group.Description, &group.Color, &group.Autorun, &group.CreatedAt, &group.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return group, err
}

// GetVMGroupByName retrieves a VM group by name
func (d *DB) GetVMGroupByName(name string) (*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	group := &VMGroup{}
	err := d.db.QueryRow(`
		SELECT id, name, COALESCE(description, ''), COALESCE(color, '#6366f1'), COALESCE(autorun, 0), created_at, updated_at
		FROM vm_groups WHERE name = ?`, name).Scan(
		&group.ID, &group.Name, &group.Description, &group.Color, &group.Autorun, &group.CreatedAt, &group.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return group, err
}

// ListVMGroups returns all VM groups
func (d *DB) ListVMGroups() ([]*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, COALESCE(description, ''), COALESCE(color, '#6366f1'), COALESCE(autorun, 0), created_at, updated_at
		FROM vm_groups ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*VMGroup
	for rows.Next() {
		group := &VMGroup{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Color, &group.Autorun, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// UpdateVMGroup updates a VM group
func (d *DB) UpdateVMGroup(group *VMGroup) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vm_groups SET name=?, description=?, color=?, autorun=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		group.Name, group.Description, group.Color, group.Autorun, group.ID)
	return err
}

// DeleteVMGroup deletes a VM group
func (d *DB) DeleteVMGroup(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM vm_groups WHERE id = ?", id)
	return err
}

// VM Group Member operations

// AddVMToGroup adds a VM to a VM group
func (d *DB) AddVMToGroup(vmGroupID, vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`INSERT OR IGNORE INTO vm_group_members (vm_group_id, vm_id) VALUES (?, ?)`, vmGroupID, vmID)
	return err
}

// RemoveVMFromGroup removes a VM from a VM group
func (d *DB) RemoveVMFromGroup(vmGroupID, vmID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM vm_group_members WHERE vm_group_id = ? AND vm_id = ?`, vmGroupID, vmID)
	return err
}

// GetVMGroups returns all VM groups a VM belongs to
func (d *DB) GetVMGroups(vmID string) ([]*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT g.id, g.name, COALESCE(g.description, ''), COALESCE(g.color, '#6366f1'), COALESCE(g.autorun, 0), g.created_at, g.updated_at
		FROM vm_groups g
		INNER JOIN vm_group_members m ON g.id = m.vm_group_id
		WHERE m.vm_id = ?
		ORDER BY g.name ASC`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*VMGroup
	for rows.Next() {
		group := &VMGroup{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Color, &group.Autorun, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// ListAutorunVMGroups returns all VM groups with autorun enabled
func (d *DB) ListAutorunVMGroups() ([]*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, COALESCE(description, ''), COALESCE(color, '#6366f1'), COALESCE(autorun, 0), created_at, updated_at
		FROM vm_groups WHERE autorun = 1 ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*VMGroup
	for rows.Next() {
		group := &VMGroup{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Color, &group.Autorun, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// GetVMsInGroup returns all VMs in a VM group
func (d *DB) GetVMsInGroup(vmGroupID string) ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT v.id, v.name, v.vcpu, v.memory_mb, v.kernel_path, v.rootfs_path, v.kernel_args,
			COALESCE(v.network_id, ''), COALESCE(v.mac_address, ''), COALESCE(v.ip_address, ''),
			COALESCE(v.dns_servers, ''), COALESCE(v.snapshot_type, ''), COALESCE(v.tap_device, ''),
			COALESCE(v.socket_path, ''), v.status, v.pid, COALESCE(v.autorun, 0),
			COALESCE(v.error_message, ''), v.created_at, v.updated_at
		FROM vms v
		INNER JOIN vm_group_members m ON v.id = m.vm_id
		WHERE m.vm_group_id = ?
		ORDER BY v.name ASC`, vmGroupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice,
			&vm.SocketPath, &vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, rows.Err()
}

// CountVMsInGroup returns the number of VMs in a group
func (d *DB) CountVMsInGroup(vmGroupID string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM vm_group_members WHERE vm_group_id = ?", vmGroupID).Scan(&count)
	return count, err
}

// VM Group Permission operations

// AddVMGroupPermission adds a user group permission to a VM group
func (d *DB) AddVMGroupPermission(vmGroupID, groupID, permissions string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO vm_group_permissions (vm_group_id, group_id, permissions) VALUES (?, ?, ?)
		ON CONFLICT(vm_group_id, group_id) DO UPDATE SET permissions = ?`,
		vmGroupID, groupID, permissions, permissions)
	return err
}

// RemoveVMGroupPermission removes a user group permission from a VM group
func (d *DB) RemoveVMGroupPermission(vmGroupID, groupID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM vm_group_permissions WHERE vm_group_id = ? AND group_id = ?`, vmGroupID, groupID)
	return err
}

// GetVMGroupPermissions returns all permission entries for a VM group
func (d *DB) GetVMGroupPermissions(vmGroupID string) ([]*VMGroupPermission, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, vm_group_id, group_id, COALESCE(permissions, ''), created_at
		FROM vm_group_permissions WHERE vm_group_id = ?`, vmGroupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*VMGroupPermission
	for rows.Next() {
		p := &VMGroupPermission{}
		if err := rows.Scan(&p.ID, &p.VMGroupID, &p.GroupID, &p.Permissions, &p.CreatedAt); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// GetUserAccessibleVMGroups returns VM groups accessible by a user through their group memberships
func (d *DB) GetUserAccessibleVMGroups(userID int) ([]*VMGroup, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT DISTINCT vg.id, vg.name, COALESCE(vg.description, ''), COALESCE(vg.color, '#6366f1'), vg.created_at, vg.updated_at
		FROM vm_groups vg
		INNER JOIN vm_group_permissions vgp ON vg.id = vgp.vm_group_id
		INNER JOIN group_members gm ON vgp.group_id = gm.group_id
		WHERE gm.user_id = ?
		ORDER BY vg.name ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*VMGroup
	for rows.Next() {
		group := &VMGroup{}
		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &group.Color, &group.CreatedAt, &group.UpdatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// VM Search operations

// SearchVMs searches VMs based on various criteria
func (d *DB) SearchVMs(params *VMSearchParams) ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `
		SELECT DISTINCT v.id, v.name, COALESCE(v.description, ''), v.vcpu, v.memory_mb, v.kernel_path, v.rootfs_path, v.kernel_args,
			COALESCE(v.network_id, ''), COALESCE(v.mac_address, ''), COALESCE(v.ip_address, ''),
			COALESCE(v.dns_servers, ''), COALESCE(v.snapshot_type, ''), COALESCE(v.tap_device, ''),
			COALESCE(v.socket_path, ''), v.status, v.pid, COALESCE(v.autorun, 0),
			COALESCE(v.error_message, ''), v.created_at, v.updated_at
		FROM vms v
		LEFT JOIN rootfs r ON v.rootfs_path = r.path
		LEFT JOIN vm_group_members vgm ON v.id = vgm.vm_id
		LEFT JOIN vm_group_permissions vgp ON vgm.vm_group_id = vgp.vm_group_id
		LEFT JOIN group_vms gv ON v.id = gv.vm_id
		WHERE 1=1`

	var args []interface{}

	// General search query (searches name, IP, MAC, description)
	if params.Query != "" {
		query += ` AND (v.name LIKE ? OR v.ip_address LIKE ? OR v.mac_address LIKE ? OR v.description LIKE ?)`
		searchTerm := "%" + params.Query + "%"
		args = append(args, searchTerm, searchTerm, searchTerm, searchTerm)
	}

	// Specific filters
	if params.Name != "" {
		query += ` AND v.name LIKE ?`
		args = append(args, "%"+params.Name+"%")
	}

	if params.IPAddress != "" {
		query += ` AND v.ip_address LIKE ?`
		args = append(args, "%"+params.IPAddress+"%")
	}

	if params.OS != "" {
		query += ` AND r.os_release LIKE ?`
		args = append(args, "%"+params.OS+"%")
	}

	if params.Status != "" {
		query += ` AND v.status = ?`
		args = append(args, params.Status)
	}

	if params.NetworkID != "" {
		query += ` AND v.network_id = ?`
		args = append(args, params.NetworkID)
	}

	if params.RootFSID != "" {
		query += ` AND r.id = ?`
		args = append(args, params.RootFSID)
	}

	if params.KernelID != "" {
		query += ` AND v.kernel_path IN (SELECT path FROM kernels WHERE id = ?)`
		args = append(args, params.KernelID)
	}

	if params.VMGroupID != "" {
		query += ` AND vgm.vm_group_id = ?`
		args = append(args, params.VMGroupID)
	}

	if params.GroupID != "" {
		query += ` AND (gv.group_id = ? OR vgp.group_id = ?)`
		args = append(args, params.GroupID, params.GroupID)
	}

	query += ` ORDER BY v.name ASC`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vms []*VM
	for rows.Next() {
		vm := &VM{}
		if err := rows.Scan(&vm.ID, &vm.Name, &vm.Description, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
			&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice,
			&vm.SocketPath, &vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt); err != nil {
			return nil, err
		}
		vms = append(vms, vm)
	}
	return vms, rows.Err()
}

// VMSearchResult includes VM with additional info for search results
type VMSearchResult struct {
	VM       *VM          `json:"vm"`
	RootFS   *RootFS      `json:"rootfs,omitempty"`
	Kernel   *KernelImage `json:"kernel,omitempty"`
	Network  *Network     `json:"network,omitempty"`
	VMGroups []*VMGroup   `json:"vm_groups,omitempty"`
}

// ============================================================================
// Appliance Privilege operations
// ============================================================================

// SetApplianceOwner creates an ownership record for an appliance (called after export)
func (d *DB) SetApplianceOwner(filename string, ownerID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Insert owner record (owner has implicit full access)
	_, err := d.db.Exec(`
		INSERT INTO appliance_privileges (filename, owner_id, user_id, group_id, can_read, can_write)
		VALUES (?, ?, NULL, NULL, 1, 1)`,
		filename, ownerID)
	return err
}

// GetApplianceOwner returns the owner ID for an appliance
func (d *DB) GetApplianceOwner(filename string) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var ownerID int
	err := d.db.QueryRow(`
		SELECT owner_id FROM appliance_privileges
		WHERE filename = ? AND user_id IS NULL AND group_id IS NULL
		LIMIT 1`, filename).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return ownerID, err
}

// AddApplianceUserPrivilege grants a user access to an appliance
func (d *DB) AddApplianceUserPrivilege(filename string, ownerID int, userID int, canRead, canWrite bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if privilege already exists
	var exists int
	d.db.QueryRow(`SELECT 1 FROM appliance_privileges WHERE filename = ? AND user_id = ?`,
		filename, userID).Scan(&exists)
	if exists == 1 {
		// Update existing
		_, err := d.db.Exec(`
			UPDATE appliance_privileges SET can_read = ?, can_write = ?
			WHERE filename = ? AND user_id = ?`,
			canRead, canWrite, filename, userID)
		return err
	}

	_, err := d.db.Exec(`
		INSERT INTO appliance_privileges (filename, owner_id, user_id, group_id, can_read, can_write)
		VALUES (?, ?, ?, NULL, ?, ?)`,
		filename, ownerID, userID, canRead, canWrite)
	return err
}

// AddApplianceGroupPrivilege grants a group access to an appliance
func (d *DB) AddApplianceGroupPrivilege(filename string, ownerID int, groupID string, canRead, canWrite bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if privilege already exists
	var exists int
	d.db.QueryRow(`SELECT 1 FROM appliance_privileges WHERE filename = ? AND group_id = ?`,
		filename, groupID).Scan(&exists)
	if exists == 1 {
		// Update existing
		_, err := d.db.Exec(`
			UPDATE appliance_privileges SET can_read = ?, can_write = ?
			WHERE filename = ? AND group_id = ?`,
			canRead, canWrite, filename, groupID)
		return err
	}

	_, err := d.db.Exec(`
		INSERT INTO appliance_privileges (filename, owner_id, user_id, group_id, can_read, can_write)
		VALUES (?, ?, NULL, ?, ?, ?)`,
		filename, ownerID, groupID, canRead, canWrite)
	return err
}

// RemoveApplianceUserPrivilege removes a user's access to an appliance
func (d *DB) RemoveApplianceUserPrivilege(filename string, userID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM appliance_privileges WHERE filename = ? AND user_id = ?`,
		filename, userID)
	return err
}

// RemoveApplianceGroupPrivilege removes a group's access to an appliance
func (d *DB) RemoveApplianceGroupPrivilege(filename string, groupID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM appliance_privileges WHERE filename = ? AND group_id = ?`,
		filename, groupID)
	return err
}

// GetAppliancePrivileges returns all privileges for an appliance
func (d *DB) GetAppliancePrivileges(filename string) ([]*AppliancePrivilege, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT ap.id, ap.filename, ap.owner_id, ap.user_id, ap.group_id, ap.can_read, ap.can_write, ap.created_at,
			COALESCE(u.username, ''), COALESCE(g.name, '')
		FROM appliance_privileges ap
		LEFT JOIN users u ON ap.user_id = u.id
		LEFT JOIN groups g ON ap.group_id = g.id
		WHERE ap.filename = ? AND (ap.user_id IS NOT NULL OR ap.group_id IS NOT NULL)
		ORDER BY ap.created_at`, filename)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var privileges []*AppliancePrivilege
	for rows.Next() {
		p := &AppliancePrivilege{}
		var userID sql.NullInt64
		var groupID sql.NullString
		if err := rows.Scan(&p.ID, &p.Filename, &p.OwnerID, &userID, &groupID,
			&p.CanRead, &p.CanWrite, &p.CreatedAt, &p.Username, &p.GroupName); err != nil {
			return nil, err
		}
		if userID.Valid {
			uid := int(userID.Int64)
			p.UserID = &uid
		}
		if groupID.Valid {
			p.GroupID = &groupID.String
		}
		privileges = append(privileges, p)
	}
	return privileges, rows.Err()
}

// CanUserAccessAppliance checks if a user can access an appliance (read or write)
// Returns: canAccess, canWrite, isOwner
// If no privileges are defined for an appliance, it is available to everyone (read-only)
func (d *DB) CanUserAccessAppliance(filename string, userID int, userRole string) (bool, bool, bool) {
	// Admins have full access to everything
	if userRole == "admin" {
		return true, true, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// Check if any privileges exist for this appliance
	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM appliance_privileges
		WHERE filename = ?`, filename).Scan(&count)
	if err != nil || count == 0 {
		// No privileges defined - appliance is available to everyone (read-only)
		return true, false, false
	}

	// Check if user is the owner
	var ownerID int
	err = d.db.QueryRow(`
		SELECT owner_id FROM appliance_privileges
		WHERE filename = ? AND user_id IS NULL AND group_id IS NULL
		LIMIT 1`, filename).Scan(&ownerID)
	if err == nil && ownerID == userID {
		return true, true, true
	}

	// Check direct user privilege
	var canRead, canWrite bool
	err = d.db.QueryRow(`
		SELECT can_read, can_write FROM appliance_privileges
		WHERE filename = ? AND user_id = ?`, filename, userID).Scan(&canRead, &canWrite)
	if err == nil {
		return canRead || canWrite, canWrite, false
	}

	// Check group privileges
	rows, err := d.db.Query(`
		SELECT ap.can_read, ap.can_write
		FROM appliance_privileges ap
		INNER JOIN group_members gm ON ap.group_id = gm.group_id
		WHERE ap.filename = ? AND gm.user_id = ?`, filename, userID)
	if err != nil {
		return false, false, false
	}
	defer rows.Close()

	for rows.Next() {
		var r, w bool
		if err := rows.Scan(&r, &w); err != nil {
			continue
		}
		if r {
			canRead = true
		}
		if w {
			canWrite = true
		}
	}

	return canRead || canWrite, canWrite, false
}

// GetUserAccessibleAppliances returns filenames that a user can access
func (d *DB) GetUserAccessibleAppliances(userID int, userRole string) (map[string]bool, error) {
	// Admins can access all
	if userRole == "admin" {
		return nil, nil // nil means all access
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	accessible := make(map[string]bool)

	// Get appliances owned by user
	rows, err := d.db.Query(`
		SELECT filename FROM appliance_privileges
		WHERE owner_id = ? AND user_id IS NULL AND group_id IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err == nil {
			accessible[filename] = true
		}
	}
	rows.Close()

	// Get appliances with direct user privilege
	rows, err = d.db.Query(`
		SELECT filename FROM appliance_privileges
		WHERE user_id = ? AND can_read = 1`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err == nil {
			accessible[filename] = true
		}
	}
	rows.Close()

	// Get appliances with group privilege
	rows, err = d.db.Query(`
		SELECT DISTINCT ap.filename
		FROM appliance_privileges ap
		INNER JOIN group_members gm ON ap.group_id = gm.group_id
		WHERE gm.user_id = ? AND ap.can_read = 1`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var filename string
		if err := rows.Scan(&filename); err == nil {
			accessible[filename] = true
		}
	}
	rows.Close()

	return accessible, nil
}

// DeleteAppliancePrivileges removes all privileges for an appliance (called when appliance is deleted)
func (d *DB) DeleteAppliancePrivileges(filename string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM appliance_privileges WHERE filename = ?`, filename)
	return err
}

// CleanupOrphanAppliancePrivileges removes privileges for appliances that no longer exist
// Pass in a list of existing appliance filenames
func (d *DB) CleanupOrphanAppliancePrivileges(existingFiles []string) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(existingFiles) == 0 {
		// Delete all privileges if no files exist
		result, err := d.db.Exec(`DELETE FROM appliance_privileges`)
		if err != nil {
			return 0, err
		}
		return result.RowsAffected()
	}

	// Build placeholder string
	placeholders := make([]string, len(existingFiles))
	args := make([]interface{}, len(existingFiles))
	for i, f := range existingFiles {
		placeholders[i] = "?"
		args[i] = f
	}

	query := fmt.Sprintf(`DELETE FROM appliance_privileges WHERE filename NOT IN (%s)`,
		strings.Join(placeholders, ","))
	result, err := d.db.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// LDAP Configuration types
type LDAPConfig struct {
	Enabled         bool   `json:"enabled"`
	Server          string `json:"server"`
	Port            int    `json:"port"`
	UseSSL          bool   `json:"use_ssl"`
	UseStartTLS     bool   `json:"use_starttls"`
	SkipVerify      bool   `json:"skip_verify"`
	BindDN          string `json:"bind_dn"`
	BindPassword    string `json:"bind_password"`
	BaseDN          string `json:"base_dn"`
	UserSearchBase  string `json:"user_search_base"`
	UserFilter      string `json:"user_filter"`
	GroupSearchBase string `json:"group_search_base"`
	GroupFilter     string `json:"group_filter"`
}

type LDAPGroupMapping struct {
	ID           string `json:"id"`
	GroupDN      string `json:"group_dn"`
	GroupName    string `json:"group_name"`
	LocalRole    string `json:"local_role"`
	LocalGroupID string `json:"local_group_id"`
	CreatedAt    int64  `json:"created_at"`
}

// GetLDAPConfig retrieves the LDAP configuration
func (d *DB) GetLDAPConfig() (*LDAPConfig, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	config := &LDAPConfig{}
	err := d.db.QueryRow(`
		SELECT enabled, server, port, use_ssl, use_starttls, skip_verify,
			bind_dn, bind_password, base_dn, user_search_base, user_filter,
			group_search_base, group_filter
		FROM ldap_config WHERE id = 1
	`).Scan(&config.Enabled, &config.Server, &config.Port, &config.UseSSL,
		&config.UseStartTLS, &config.SkipVerify, &config.BindDN, &config.BindPassword,
		&config.BaseDN, &config.UserSearchBase, &config.UserFilter,
		&config.GroupSearchBase, &config.GroupFilter)

	if err != nil {
		// Return default config if not found
		return &LDAPConfig{
			Enabled:     false,
			Port:        389,
			UseSSL:      false,
			UseStartTLS: false,
			SkipVerify:  true,
			UserFilter:  "(&(objectClass=user)(sAMAccountName=%s))",
			GroupFilter: "(objectClass=group)",
		}, nil
	}

	return config, nil
}

// SaveLDAPConfig saves the LDAP configuration
func (d *DB) SaveLDAPConfig(config *LDAPConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO ldap_config (id, enabled, server, port, use_ssl, use_starttls,
			skip_verify, bind_dn, bind_password, base_dn, user_search_base, user_filter,
			group_search_base, group_filter, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		config.Enabled, config.Server, config.Port, config.UseSSL, config.UseStartTLS,
		config.SkipVerify, config.BindDN, config.BindPassword, config.BaseDN,
		config.UserSearchBase, config.UserFilter, config.GroupSearchBase, config.GroupFilter)
	return err
}

// CreateLDAPGroupMapping creates a new LDAP group mapping
func (d *DB) CreateLDAPGroupMapping(mapping *LDAPGroupMapping) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO ldap_group_mappings (id, group_dn, group_name, local_role, local_group_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		mapping.ID, mapping.GroupDN, mapping.GroupName, mapping.LocalRole, mapping.LocalGroupID, mapping.CreatedAt)
	return err
}

// GetLDAPGroupMapping retrieves a single LDAP group mapping by ID
func (d *DB) GetLDAPGroupMapping(id string) (*LDAPGroupMapping, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mapping := &LDAPGroupMapping{}
	err := d.db.QueryRow(`
		SELECT id, group_dn, group_name, local_role, COALESCE(local_group_id, ''), created_at
		FROM ldap_group_mappings WHERE id = ?
	`, id).Scan(&mapping.ID, &mapping.GroupDN, &mapping.GroupName, &mapping.LocalRole, &mapping.LocalGroupID, &mapping.CreatedAt)
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

// GetLDAPGroupMappingByDN retrieves a LDAP group mapping by group DN
func (d *DB) GetLDAPGroupMappingByDN(groupDN string) (*LDAPGroupMapping, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	mapping := &LDAPGroupMapping{}
	err := d.db.QueryRow(`
		SELECT id, group_dn, group_name, local_role, COALESCE(local_group_id, ''), created_at
		FROM ldap_group_mappings WHERE group_dn = ?
	`, groupDN).Scan(&mapping.ID, &mapping.GroupDN, &mapping.GroupName, &mapping.LocalRole, &mapping.LocalGroupID, &mapping.CreatedAt)
	if err != nil {
		return nil, err
	}
	return mapping, nil
}

// ListLDAPGroupMappings lists all LDAP group mappings
func (d *DB) ListLDAPGroupMappings() ([]*LDAPGroupMapping, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, group_dn, group_name, local_role, COALESCE(local_group_id, ''), created_at
		FROM ldap_group_mappings ORDER BY group_name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mappings []*LDAPGroupMapping
	for rows.Next() {
		m := &LDAPGroupMapping{}
		if err := rows.Scan(&m.ID, &m.GroupDN, &m.GroupName, &m.LocalRole, &m.LocalGroupID, &m.CreatedAt); err != nil {
			return nil, err
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// UpdateLDAPGroupMapping updates an LDAP group mapping
func (d *DB) UpdateLDAPGroupMapping(mapping *LDAPGroupMapping) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE ldap_group_mappings SET group_dn = ?, group_name = ?, local_role = ?, local_group_id = ?
		WHERE id = ?`,
		mapping.GroupDN, mapping.GroupName, mapping.LocalRole, mapping.LocalGroupID, mapping.ID)
	return err
}

// DeleteLDAPGroupMapping deletes an LDAP group mapping
func (d *DB) DeleteLDAPGroupMapping(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`DELETE FROM ldap_group_mappings WHERE id = ?`, id)
	return err
}

// GetUserByLDAPDN gets a user by their LDAP DN
func (d *DB) GetUserByLDAPDN(ldapDN string) (*User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	user := &User{}
	var ldapUser bool
	var ldapDNVal string
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, role, COALESCE(ldap_user, 0), COALESCE(ldap_dn, '')
		FROM users WHERE ldap_dn = ?
	`, ldapDN).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &ldapUser, &ldapDNVal)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateOrUpdateLDAPUser creates or updates a user authenticated via LDAP
func (d *DB) CreateOrUpdateLDAPUser(username, role, ldapDN string) (*User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if user exists
	var existingID int
	err := d.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&existingID)

	if err != nil {
		// User doesn't exist, create new
		result, err := d.db.Exec(`
			INSERT INTO users (username, password_hash, role, active, ldap_user, ldap_dn)
			VALUES (?, '', ?, 1, 1, ?)`,
			username, role, ldapDN)
		if err != nil {
			return nil, err
		}
		id, _ := result.LastInsertId()
		return &User{ID: int(id), Username: username, Role: role, Active: true, LDAPUser: true, LDAPDN: ldapDN}, nil
	}

	// Update existing user
	_, err = d.db.Exec(`
		UPDATE users SET role = ?, ldap_user = 1, ldap_dn = ? WHERE id = ?`,
		role, ldapDN, existingID)
	if err != nil {
		return nil, err
	}

	return &User{ID: existingID, Username: username, Role: role, Active: true, LDAPUser: true, LDAPDN: ldapDN}, nil
}

// IsLDAPUser checks if a user is an LDAP user
func (d *DB) IsLDAPUser(username string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var ldapUser bool
	err := d.db.QueryRow(`SELECT COALESCE(ldap_user, 0) FROM users WHERE username = ?`, username).Scan(&ldapUser)
	if err != nil {
		return false, err
	}
	return ldapUser, nil
}
