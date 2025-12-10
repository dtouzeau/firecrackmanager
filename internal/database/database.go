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
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	VCPU         int       `json:"vcpu"`
	MemoryMB     int       `json:"memory_mb"`
	KernelPath   string    `json:"kernel_path"`
	RootFSPath   string    `json:"rootfs_path"`
	KernelArgs   string    `json:"kernel_args"`
	NetworkID    string    `json:"network_id"`
	MacAddress   string    `json:"mac_address"`
	IPAddress    string    `json:"ip_address"`
	DNSServers   string    `json:"dns_servers"`   // comma-separated DNS servers
	SnapshotType string    `json:"snapshot_type"` // Full, Diff, or empty for disabled
	TapDevice    string    `json:"tap_device"`
	SocketPath   string    `json:"socket_path"`
	Status       string    `json:"status"` // stopped, running, error
	PID          int       `json:"pid"`
	Autorun      bool      `json:"autorun"` // Start VM automatically when FireCrackManager starts
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	ErrorMessage string    `json:"error_message"`
}

type Network struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	BridgeName  string    `json:"bridge_name"`
	Subnet      string    `json:"subnet"`      // e.g., "192.168.100.0/24"
	Gateway     string    `json:"gateway"`     // e.g., "192.168.100.1"
	DHCPStart   string    `json:"dhcp_start"`  // e.g., "192.168.100.10"
	DHCPEnd     string    `json:"dhcp_end"`    // e.g., "192.168.100.254"
	EnableNAT   bool      `json:"enable_nat"`
	Status      string    `json:"status"` // active, inactive
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type KernelImage struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Architecture string    `json:"architecture"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	Checksum     string    `json:"checksum"`
	IsDefault    bool      `json:"is_default"`
	CreatedAt    time.Time `json:"created_at"`
}

type RootFS struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	Format       string    `json:"format"` // ext4, squashfs
	BaseImage    string    `json:"base_image"`
	Checksum     string    `json:"checksum"`
	CreatedAt    time.Time `json:"created_at"`
}

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Email        string    `json:"email"`
	Role         string    `json:"role"` // admin, user
	Active       bool      `json:"active"`
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
		INSERT INTO vms (id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			network_id, mac_address, ip_address, dns_servers, snapshot_type, tap_device, socket_path, status, pid, autorun, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vm.ID, vm.Name, vm.VCPU, vm.MemoryMB, vm.KernelPath, vm.RootFSPath, vm.KernelArgs,
		vm.NetworkID, vm.MacAddress, vm.IPAddress, vm.DNSServers, vm.SnapshotType, vm.TapDevice, vm.SocketPath, vm.Status, vm.PID, vm.Autorun, vm.ErrorMessage)
	return err
}

func (d *DB) GetVM(id string) (*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	vm := &VM{}
	err := d.db.QueryRow(`
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''), created_at, updated_at
		FROM vms WHERE id = ?`, id).Scan(
		&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
		&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
		&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt)
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
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''), created_at, updated_at
		FROM vms WHERE name = ?`, name).Scan(
		&vm.ID, &vm.Name, &vm.VCPU, &vm.MemoryMB, &vm.KernelPath, &vm.RootFSPath, &vm.KernelArgs,
		&vm.NetworkID, &vm.MacAddress, &vm.IPAddress, &vm.DNSServers, &vm.SnapshotType, &vm.TapDevice, &vm.SocketPath,
		&vm.Status, &vm.PID, &vm.Autorun, &vm.ErrorMessage, &vm.CreatedAt, &vm.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return vm, err
}

func (d *DB) ListVMs() ([]*VM, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, vcpu, memory_mb, kernel_path, rootfs_path, kernel_args,
			COALESCE(network_id, ''), COALESCE(mac_address, ''), COALESCE(ip_address, ''),
			COALESCE(dns_servers, ''), COALESCE(snapshot_type, ''), COALESCE(tap_device, ''), COALESCE(socket_path, ''), status, pid,
			COALESCE(autorun, 0), COALESCE(error_message, ''), created_at, updated_at
		FROM vms ORDER BY created_at DESC`)
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

func (d *DB) UpdateVM(vm *VM) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE vms SET name=?, vcpu=?, memory_mb=?, kernel_path=?, rootfs_path=?, kernel_args=?,
			network_id=?, mac_address=?, ip_address=?, dns_servers=?, snapshot_type=?, tap_device=?, socket_path=?,
			status=?, pid=?, autorun=?, error_message=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		vm.Name, vm.VCPU, vm.MemoryMB, vm.KernelPath, vm.RootFSPath, vm.KernelArgs,
		vm.NetworkID, vm.MacAddress, vm.IPAddress, vm.DNSServers, vm.SnapshotType, vm.TapDevice, vm.SocketPath,
		vm.Status, vm.PID, vm.Autorun, vm.ErrorMessage, vm.ID)
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

	_, err := d.db.Exec(`
		INSERT INTO networks (id, name, bridge_name, subnet, gateway, dhcp_start, dhcp_end, enable_nat, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		net.ID, net.Name, net.BridgeName, net.Subnet, net.Gateway, net.DHCPStart, net.DHCPEnd, net.EnableNAT, net.Status)
	return err
}

func (d *DB) GetNetwork(id string) (*Network, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	net := &Network{}
	err := d.db.QueryRow(`
		SELECT id, name, bridge_name, subnet, gateway, COALESCE(dhcp_start, ''),
			COALESCE(dhcp_end, ''), enable_nat, status, created_at, updated_at
		FROM networks WHERE id = ?`, id).Scan(
		&net.ID, &net.Name, &net.BridgeName, &net.Subnet, &net.Gateway,
		&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.Status, &net.CreatedAt, &net.UpdatedAt)
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
			COALESCE(dhcp_end, ''), enable_nat, status, created_at, updated_at
		FROM networks WHERE name = ?`, name).Scan(
		&net.ID, &net.Name, &net.BridgeName, &net.Subnet, &net.Gateway,
		&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.Status, &net.CreatedAt, &net.UpdatedAt)
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
			COALESCE(dhcp_end, ''), enable_nat, status, created_at, updated_at
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
			&net.DHCPStart, &net.DHCPEnd, &net.EnableNAT, &net.Status, &net.CreatedAt, &net.UpdatedAt); err != nil {
			return nil, err
		}
		nets = append(nets, net)
	}
	return nets, nil
}

func (d *DB) UpdateNetwork(net *Network) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE networks SET name=?, bridge_name=?, subnet=?, gateway=?,
			dhcp_start=?, dhcp_end=?, enable_nat=?, status=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		net.Name, net.BridgeName, net.Subnet, net.Gateway,
		net.DHCPStart, net.DHCPEnd, net.EnableNAT, net.Status, net.ID)
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
		INSERT INTO kernel_images (id, name, version, architecture, path, size, checksum, is_default)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		img.ID, img.Name, img.Version, img.Architecture, img.Path, img.Size, img.Checksum, img.IsDefault)
	return err
}

func (d *DB) GetKernelImage(id string) (*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	img := &KernelImage{}
	err := d.db.QueryRow(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, created_at
		FROM kernel_images WHERE id = ?`, id).Scan(
		&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return img, err
}

func (d *DB) GetDefaultKernel() (*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	img := &KernelImage{}
	err := d.db.QueryRow(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, created_at
		FROM kernel_images WHERE is_default = 1 LIMIT 1`).Scan(
		&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return img, err
}

func (d *DB) ListKernelImages() ([]*KernelImage, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, version, architecture, path, size, COALESCE(checksum, ''), is_default, created_at
		FROM kernel_images ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var imgs []*KernelImage
	for rows.Next() {
		img := &KernelImage{}
		if err := rows.Scan(&img.ID, &img.Name, &img.Version, &img.Architecture, &img.Path, &img.Size, &img.Checksum, &img.IsDefault, &img.CreatedAt); err != nil {
			return nil, err
		}
		imgs = append(imgs, img)
	}
	return imgs, nil
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
	err := d.db.QueryRow(`
		SELECT id, name, path, size, format, COALESCE(base_image, ''), COALESCE(checksum, ''), created_at
		FROM rootfs WHERE id = ?`, id).Scan(
		&fs.ID, &fs.Name, &fs.Path, &fs.Size, &fs.Format, &fs.BaseImage, &fs.Checksum, &fs.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return fs, err
}

func (d *DB) ListRootFS() ([]*RootFS, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, name, path, size, format, COALESCE(base_image, ''), COALESCE(checksum, ''), created_at
		FROM rootfs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fsList []*RootFS
	for rows.Next() {
		fs := &RootFS{}
		if err := rows.Scan(&fs.ID, &fs.Name, &fs.Path, &fs.Size, &fs.Format, &fs.BaseImage, &fs.Checksum, &fs.CreatedAt); err != nil {
			return nil, err
		}
		fsList = append(fsList, fs)
	}
	return fsList, nil
}

func (d *DB) UpdateRootFS(fs *RootFS) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		UPDATE rootfs SET name=?, path=?, size=?, format=?, base_image=?, checksum=?
		WHERE id=?`,
		fs.Name, fs.Path, fs.Size, fs.Format, fs.BaseImage, fs.Checksum, fs.ID)
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
		SELECT id, username, password_hash, COALESCE(email, ''), role, active, created_at, updated_at
		FROM users WHERE id = ?`, id).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt)
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
		SELECT id, username, password_hash, COALESCE(email, ''), role, active, created_at, updated_at
		FROM users WHERE username = ?`, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

func (d *DB) ListUsers() ([]*User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, username, password_hash, COALESCE(email, ''), role, active, created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.Role, &user.Active, &user.CreatedAt, &user.UpdatedAt); err != nil {
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
