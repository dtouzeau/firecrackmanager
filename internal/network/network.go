package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	TUNSETIFF      = 0x400454ca
	TUNSETPERSIST  = 0x400454cb
	IFF_TAP        = 0x0002
	IFF_NO_PI      = 0x1000
	IFF_VNET_HDR   = 0x4000
	IFNAMSIZ       = 16
	SIOCGIFFLAGS   = 0x8913
	SIOCSIFFLAGS   = 0x8914
	SIOCGIFADDR    = 0x8915
	SIOCSIFADDR    = 0x8916
	SIOCGIFNETMASK = 0x891b
	SIOCSIFNETMASK = 0x891c
	SIOCGIFBRDADDR = 0x8919
	SIOCSIFBRDADDR = 0x891a
	SIOCGIFINDEX   = 0x8933
	SIOCBRADDIF    = 0x89a2
	SIOCBRDELIF    = 0x89a3
	IFF_UP         = 0x1
	IFF_RUNNING    = 0x40
)

type ifreq struct {
	Name  [IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

type ifreqAddr struct {
	Name [IFNAMSIZ]byte
	Addr syscall.RawSockaddrInet4
	_    [8]byte
}

type ifreqIndex struct {
	Name  [IFNAMSIZ]byte
	Index int32
	_     [20]byte
}

type Manager struct {
	mu         sync.Mutex
	tapDevices map[string]int // tap name -> fd
	bridges    map[string]bool
}

func NewManager() *Manager {
	return &Manager{
		tapDevices: make(map[string]int),
		bridges:    make(map[string]bool),
	}
}

// CreateTAP creates a persistent TAP device that Firecracker can open
func (m *Manager) CreateTAP(name string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if TAP device already exists and clean it up first
	if m.interfaceExistsUnlocked(name) {
		m.cleanupTAPUnlocked(name)
	}

	// Open /dev/net/tun
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// Set up the TAP device
	var ifr ifreq
	copy(ifr.Name[:], name)
	ifr.Flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("failed to create TAP device: %v", errno)
	}

	// Make the TAP device persistent so it survives after we close the FD
	// This allows Firecracker to open it
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETPERSIST), uintptr(1))
	if errno != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("failed to set TAP device persistent: %v", errno)
	}

	// Close the FD - the device persists and Firecracker will open it
	syscall.Close(fd)

	// Track as persistent (fd=-1 indicates persistent device)
	m.tapDevices[name] = -1
	return -1, nil
}

// interfaceExistsUnlocked checks if interface exists (must be called with lock held)
func (m *Manager) interfaceExistsUnlocked(name string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", name))
	return err == nil
}

// cleanupTAPUnlocked removes an existing TAP device (must be called with lock held)
func (m *Manager) cleanupTAPUnlocked(name string) {
	// Remove from tracking
	delete(m.tapDevices, name)

	// Bring down the interface first
	m.setInterfaceDown(name)

	// Try to delete using ip link (most reliable method)
	// This handles cases where the device is stuck
	m.deleteTAPViaIP(name)

	// Also try the ioctl method as fallback
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return // Device may already be gone
	}

	var ifr ifreq
	copy(ifr.Name[:], name)
	ifr.Flags = IFF_TAP | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno == 0 {
		// Clear persistent flag to delete the device when we close
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETPERSIST), uintptr(0))
	}
	syscall.Close(fd)
}

// deleteTAPViaIP uses ip command to delete TAP device (most reliable)
func (m *Manager) deleteTAPViaIP(name string) {
	// Use ip link delete - this is the most reliable way to remove a stuck TAP device
	cmd := exec.Command("ip", "link", "delete", name)
	cmd.Run() // Ignore errors - device may not exist

	// Give kernel time to clean up
	time.Sleep(100 * time.Millisecond)
}

// DeleteTAP removes a TAP device
func (m *Manager) DeleteTAP(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from tracking
	delete(m.tapDevices, name)

	// Bring down the interface first
	m.setInterfaceDown(name)

	// Re-open the device to clear persistent flag and delete it
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil // Device may already be gone
	}

	var ifr ifreq
	copy(ifr.Name[:], name)
	ifr.Flags = IFF_TAP | IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno == 0 {
		// Clear persistent flag to delete the device when we close
		syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(TUNSETPERSIST), uintptr(0))
	}
	syscall.Close(fd)

	return nil
}

// GetTAPFD returns the file descriptor for a TAP device
func (m *Manager) GetTAPFD(name string) (int, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fd, ok := m.tapDevices[name]
	return fd, ok
}

// CreateBridge creates a network bridge using netlink-like syscalls
func (m *Manager) CreateBridge(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create bridge using /sys/class/net
	bridgePath := fmt.Sprintf("/sys/class/net/%s", name)
	if _, err := os.Stat(bridgePath); err == nil {
		m.bridges[name] = true
		return nil // Bridge already exists
	}

	// Use socket and ioctl to create bridge
	fd, err := syscall.Socket(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	// Create bridge via sysfs (alternative method)
	if err := os.WriteFile("/sys/class/net/bonding_masters", []byte("+"+name), 0644); err != nil {
		// Try creating via brctl-like method using SIOCBRADDBR
		var ifr [IFNAMSIZ]byte
		copy(ifr[:], name)

		const SIOCBRADDBR = 0x89a0
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCBRADDBR), uintptr(unsafe.Pointer(&ifr[0])))
		if errno != 0 && errno != syscall.EEXIST {
			return fmt.Errorf("failed to create bridge: %v", errno)
		}
	}

	m.bridges[name] = true
	return nil
}

// DeleteBridge removes a network bridge
func (m *Manager) DeleteBridge(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// First bring down the bridge
	if err := m.setInterfaceDown(name); err != nil {
		// Ignore if interface doesn't exist
	}

	fd, err := syscall.Socket(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr [IFNAMSIZ]byte
	copy(ifr[:], name)

	const SIOCBRDELBR = 0x89a1
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCBRDELBR), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 && errno != syscall.ENXIO {
		return fmt.Errorf("failed to delete bridge: %v", errno)
	}

	delete(m.bridges, name)
	return nil
}

// AddInterfaceToBridge adds an interface to a bridge
func (m *Manager) AddInterfaceToBridge(bridgeName, ifaceName string) error {
	fd, err := syscall.Socket(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	// Get interface index
	ifIndex, err := m.getInterfaceIndex(ifaceName)
	if err != nil {
		return err
	}

	var ifr ifreqIndex
	copy(ifr.Name[:], bridgeName)
	ifr.Index = int32(ifIndex)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCBRADDIF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to add interface to bridge: %v", errno)
	}

	return nil
}

// RemoveInterfaceFromBridge removes an interface from a bridge
func (m *Manager) RemoveInterfaceFromBridge(bridgeName, ifaceName string) error {
	fd, err := syscall.Socket(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	ifIndex, err := m.getInterfaceIndex(ifaceName)
	if err != nil {
		return err
	}

	var ifr ifreqIndex
	copy(ifr.Name[:], bridgeName)
	ifr.Index = int32(ifIndex)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCBRDELIF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to remove interface from bridge: %v", errno)
	}

	return nil
}

// SetInterfaceIP sets an IP address on an interface
func (m *Manager) SetInterfaceIP(name, ipAddr, netmask string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	// Parse IP
	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	// Set IP address
	var ifrAddr ifreqAddr
	copy(ifrAddr.Name[:], name)
	ifrAddr.Addr.Family = syscall.AF_INET
	copy(ifrAddr.Addr.Addr[:], ip)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIFADDR), uintptr(unsafe.Pointer(&ifrAddr)))
	if errno != 0 {
		return fmt.Errorf("failed to set IP address: %v", errno)
	}

	// Set netmask
	mask := net.ParseIP(netmask).To4()
	if mask == nil {
		return fmt.Errorf("invalid netmask: %s", netmask)
	}

	copy(ifrAddr.Addr.Addr[:], mask)
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIFNETMASK), uintptr(unsafe.Pointer(&ifrAddr)))
	if errno != 0 {
		return fmt.Errorf("failed to set netmask: %v", errno)
	}

	return nil
}

// SetInterfaceUp brings an interface up
func (m *Manager) SetInterfaceUp(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr ifreq
	copy(ifr.Name[:], name)

	// Get current flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to get interface flags: %v", errno)
	}

	// Set UP flag
	ifr.Flags |= IFF_UP | IFF_RUNNING

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to bring interface up: %v", errno)
	}

	return nil
}

// setInterfaceDown brings an interface down (internal use)
func (m *Manager) setInterfaceDown(name string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr ifreq
	copy(ifr.Name[:], name)

	// Get current flags
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil // Interface might not exist
	}

	// Clear UP flag
	ifr.Flags &^= IFF_UP

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to bring interface down: %v", errno)
	}

	return nil
}

// getInterfaceIndex gets the index of a network interface
func (m *Manager) getInterfaceIndex(name string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr ifreqIndex
	copy(ifr.Name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFINDEX), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, fmt.Errorf("failed to get interface index: %v", errno)
	}

	return int(ifr.Index), nil
}

// InterfaceExists checks if a network interface exists
func (m *Manager) InterfaceExists(name string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", name))
	return err == nil
}

// SetupNAT configures NAT for a subnet via procfs
func (m *Manager) SetupNAT(bridgeIP, subnet, outInterface string) error {
	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// NAT rules would typically be set via iptables, but since we want to avoid
	// external programs, we'll document that NAT requires iptables/nftables
	// For now, just enable IP forwarding which allows routing
	return nil
}

// DisableNAT disables IP forwarding (note: affects entire system)
func (m *Manager) DisableNAT() error {
	// This is a system-wide setting, so we typically don't want to disable it
	// Just documenting the capability
	return nil
}

// GenerateMAC generates a locally administered MAC address
func GenerateMAC(vmID string) string {
	// Use first 4 bytes of vmID hash for uniqueness
	hash := uint32(0)
	for _, c := range vmID {
		hash = hash*31 + uint32(c)
	}

	// Locally administered, unicast MAC
	// Format: 52:54:00:XX:XX:XX (QEMU/KVM style)
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x",
		byte(hash>>16),
		byte(hash>>8),
		byte(hash))
}

// AllocateIP allocates an IP from a subnet for a VM
func AllocateIP(subnet, gateway string, usedIPs []string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet: %w", err)
	}

	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return "", fmt.Errorf("invalid gateway: %s", gateway)
	}

	usedSet := make(map[string]bool)
	for _, ip := range usedIPs {
		usedSet[ip] = true
	}
	usedSet[gateway] = true

	// Start from .2 (skip network and gateway)
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("not an IPv4 subnet")
	}

	// Convert to uint32 for easy increment
	ipUint := binary.BigEndian.Uint32(ip)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	broadcast := ipUint | ^mask

	// Start at network + 2
	for candidate := ipUint + 2; candidate < broadcast; candidate++ {
		candidateIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidateIP, candidate)
		candidateStr := candidateIP.String()

		if !usedSet[candidateStr] {
			return candidateStr, nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet")
}

// SubnetToNetmask converts CIDR subnet to netmask
func SubnetToNetmask(subnet string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet: %w", err)
	}

	mask := ipNet.Mask
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]), nil
}

// GenerateTAPName generates a unique TAP device name for a VM
func GenerateTAPName(vmID string) string {
	// Use last 8 chars of vmID for uniqueness, prefix with "fc"
	suffix := vmID
	if len(suffix) > 8 {
		suffix = suffix[len(suffix)-8:]
	}
	return fmt.Sprintf("fc%s", suffix)
}

// GetDefaultInterface returns the default network interface name
func GetDefaultInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("failed to read routing table: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0], nil
		}
	}

	return "", fmt.Errorf("no default interface found")
}

// GetInterfaceIP returns the IP address of an interface
func GetInterfaceIP(name string) (string, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return "", fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr ifreqAddr
	copy(ifr.Name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFADDR), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return "", fmt.Errorf("failed to get interface IP: %v", errno)
	}

	ip := net.IP(ifr.Addr.Addr[:])
	return ip.String(), nil
}

// ParseCIDR parses a CIDR notation and returns network, gateway, and broadcast
func ParseCIDR(cidr string) (network, gateway, broadcast string, prefix int, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", "", 0, err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", "", 0, fmt.Errorf("not an IPv4 address")
	}

	mask := ipNet.Mask
	ones, _ := mask.Size()
	prefix = ones

	// Network address
	networkIP := ip4.Mask(mask)
	network = networkIP.String()

	// Gateway (network + 1)
	gwIP := make(net.IP, 4)
	copy(gwIP, networkIP)
	gwIP[3]++
	gateway = gwIP.String()

	// Broadcast
	broadcastIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcastIP[i] = networkIP[i] | ^mask[i]
	}
	broadcast = broadcastIP.String()

	return network, gateway, broadcast, prefix, nil
}

// ValidateSubnet validates that a subnet string is valid CIDR notation
func ValidateSubnet(subnet string) error {
	_, _, err := net.ParseCIDR(subnet)
	return err
}

// ValidateIP validates that an IP address is valid IPv4
func ValidateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return nil
}

// IPInSubnet checks if an IP is within a subnet
func IPInSubnet(ip, subnet string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP: %s", ip)
	}

	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false, fmt.Errorf("invalid subnet: %s", subnet)
	}

	return ipNet.Contains(parsedIP), nil
}

// GenerateBridgeName generates a bridge name from network ID
func GenerateBridgeName(networkID string) string {
	suffix := networkID
	if len(suffix) > 6 {
		suffix = suffix[:6]
	}
	return fmt.Sprintf("fcbr%s", suffix)
}

// GetUsedIPsInNetwork returns list of IPs used by VMs in a network
func GetUsedIPsInNetwork(vms []string) []string {
	return vms
}

// MACToBytes converts MAC address string to bytes
func MACToBytes(mac string) ([]byte, error) {
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid MAC address format")
	}

	result := make([]byte, 6)
	for i, part := range parts {
		val, err := strconv.ParseUint(part, 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address byte: %s", part)
		}
		result[i] = byte(val)
	}
	return result, nil
}

// BridgeInfo contains information about a bridge interface
type BridgeInfo struct {
	Name       string   `json:"name"`
	IsUp       bool     `json:"is_up"`
	MTU        int      `json:"mtu"`
	STP        bool     `json:"stp"`
	IPAddress  string   `json:"ip_address"`
	Interfaces []string `json:"interfaces"` // Attached interfaces (TAPs)
}

// GetBridgeInfo returns detailed information about a bridge
func (m *Manager) GetBridgeInfo(bridgeName string) (*BridgeInfo, error) {
	info := &BridgeInfo{Name: bridgeName}

	// Check if bridge exists
	bridgePath := fmt.Sprintf("/sys/class/net/%s", bridgeName)
	if _, err := os.Stat(bridgePath); err != nil {
		return nil, fmt.Errorf("bridge %s does not exist", bridgeName)
	}

	// Check if interface is up
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err == nil {
		defer syscall.Close(fd)
		var ifr ifreq
		copy(ifr.Name[:], bridgeName)
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
		if errno == 0 {
			info.IsUp = (ifr.Flags & IFF_UP) != 0
		}
	}

	// Get MTU from sysfs
	mtuData, err := os.ReadFile(fmt.Sprintf("%s/mtu", bridgePath))
	if err == nil {
		if mtu, err := strconv.Atoi(strings.TrimSpace(string(mtuData))); err == nil {
			info.MTU = mtu
		}
	}

	// Get STP state from sysfs
	stpData, err := os.ReadFile(fmt.Sprintf("%s/bridge/stp_state", bridgePath))
	if err == nil {
		info.STP = strings.TrimSpace(string(stpData)) != "0"
	}

	// Get IP address
	if ip, err := GetInterfaceIP(bridgeName); err == nil {
		info.IPAddress = ip
	}

	// Get attached interfaces from sysfs
	brifsPath := fmt.Sprintf("%s/brif", bridgePath)
	entries, err := os.ReadDir(brifsPath)
	if err == nil {
		for _, entry := range entries {
			info.Interfaces = append(info.Interfaces, entry.Name())
		}
	}

	return info, nil
}

// SetBridgeMTU sets the MTU for a bridge interface
func (m *Manager) SetBridgeMTU(bridgeName string, mtu int) error {
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid MTU value: %d (must be 576-65535)", mtu)
	}

	mtuPath := fmt.Sprintf("/sys/class/net/%s/mtu", bridgeName)
	return os.WriteFile(mtuPath, []byte(strconv.Itoa(mtu)), 0644)
}

// SetBridgeSTP enables or disables Spanning Tree Protocol on a bridge
func (m *Manager) SetBridgeSTP(bridgeName string, enabled bool) error {
	stpPath := fmt.Sprintf("/sys/class/net/%s/bridge/stp_state", bridgeName)
	value := "0"
	if enabled {
		value = "1"
	}
	return os.WriteFile(stpPath, []byte(value), 0644)
}

// ListBridges returns a list of all bridge interfaces on the system
func (m *Manager) ListBridges() ([]string, error) {
	var bridges []string

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("failed to read network interfaces: %w", err)
	}

	for _, entry := range entries {
		// Check if this is a bridge by looking for the bridge directory
		bridgePath := fmt.Sprintf("/sys/class/net/%s/bridge", entry.Name())
		if _, err := os.Stat(bridgePath); err == nil {
			bridges = append(bridges, entry.Name())
		}
	}

	return bridges, nil
}

// ListPhysicalInterfaces returns a list of physical network interfaces (for NAT selection)
func ListPhysicalInterfaces() ([]string, error) {
	var interfaces []string

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("failed to read network interfaces: %w", err)
	}

	for _, entry := range entries {
		name := entry.Name()

		// Skip virtual interfaces
		if name == "lo" {
			continue
		}
		if strings.HasPrefix(name, "fc") { // Our TAP/bridge interfaces
			continue
		}
		if strings.HasPrefix(name, "veth") {
			continue
		}
		if strings.HasPrefix(name, "docker") {
			continue
		}
		if strings.HasPrefix(name, "br-") {
			continue
		}
		if strings.HasPrefix(name, "virbr") {
			continue
		}

		// Check if it's a bridge (skip)
		bridgePath := fmt.Sprintf("/sys/class/net/%s/bridge", name)
		if _, err := os.Stat(bridgePath); err == nil {
			continue
		}

		// Check if it's a physical interface (has a device link)
		devicePath := fmt.Sprintf("/sys/class/net/%s/device", name)
		if _, err := os.Stat(devicePath); err == nil {
			interfaces = append(interfaces, name)
			continue
		}

		// Also include interfaces that look like physical (eth*, ens*, enp*, etc.)
		if strings.HasPrefix(name, "eth") ||
			strings.HasPrefix(name, "ens") ||
			strings.HasPrefix(name, "enp") ||
			strings.HasPrefix(name, "em") ||
			strings.HasPrefix(name, "wlan") ||
			strings.HasPrefix(name, "wlp") {
			interfaces = append(interfaces, name)
		}
	}

	return interfaces, nil
}

// GetInterfaceStatus returns status information for an interface
func GetInterfaceStatus(name string) (bool, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false, fmt.Errorf("failed to create socket: %w", err)
	}
	defer syscall.Close(fd)

	var ifr ifreq
	copy(ifr.Name[:], name)

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return false, fmt.Errorf("failed to get interface flags: %v", errno)
	}

	return (ifr.Flags & IFF_UP) != 0, nil
}

// Cleanup releases all TAP devices and bridges
func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, fd := range m.tapDevices {
		syscall.Close(fd)
		m.setInterfaceDown(name)
	}
	m.tapDevices = make(map[string]int)

	return nil
}
