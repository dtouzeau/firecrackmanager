// Package hostnet provides host network interface management using standard Linux tools (ip, ip route)
package hostnet

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Interface represents a network interface configuration
type Interface struct {
	Name       string   `json:"name"`
	State      string   `json:"state"` // up, down
	MAC        string   `json:"mac"`
	MTU        string   `json:"mtu"`
	Addresses  []string `json:"addresses"` // IPv4 addresses with CIDR
	Gateway    string   `json:"gateway"`   // Default gateway if this interface has one
	DNSServers []string `json:"dns_servers"`
	IsLoopback bool     `json:"is_loopback"`
	IsVirtual  bool     `json:"is_virtual"` // TAP, bridge, veth, etc.
	Type       string   `json:"type"`       // physical, bridge, tap, veth, loopback
}

// InterfaceConfig is used for setting interface configuration
type InterfaceConfig struct {
	Name       string   `json:"name"`
	Addresses  []string `json:"addresses"` // IPv4 addresses with CIDR (e.g., "192.168.1.10/24")
	Gateway    string   `json:"gateway"`   // Default gateway
	DNSServers []string `json:"dns_servers"`
	MTU        string   `json:"mtu"`
}

// Route represents a routing table entry
type Route struct {
	Destination string `json:"destination"` // Network/CIDR or "default"
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      string `json:"metric"`
	Protocol    string `json:"protocol"` // kernel, static, dhcp
	Scope       string `json:"scope"`    // link, host, global
}

// Manager handles host network operations
type Manager struct {
	logger func(string, ...interface{})
}

// NewManager creates a new host network manager
func NewManager(logger func(string, ...interface{})) *Manager {
	return &Manager{
		logger: logger,
	}
}

// ListInterfaces returns all network interfaces
func (m *Manager) ListInterfaces() ([]Interface, error) {
	// Get interface list using ip link
	output, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	interfaces := make(map[string]*Interface)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		iface := parseInterfaceLine(line)
		if iface != nil {
			interfaces[iface.Name] = iface
		}
	}

	// Get IP addresses using ip addr
	addrOutput, err := exec.Command("ip", "-o", "addr", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses: %w", err)
	}

	addrLines := strings.Split(string(addrOutput), "\n")
	for _, line := range addrLines {
		if line == "" {
			continue
		}
		parseAddressLine(line, interfaces)
	}

	// Get default gateway
	defaultGW, gwIface := m.getDefaultGateway()
	if gwIface != "" {
		if iface, ok := interfaces[gwIface]; ok {
			iface.Gateway = defaultGW
		}
	}

	// Get DNS servers
	dnsServers := m.getDNSServers()

	// Convert map to slice
	result := make([]Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		// Assign DNS servers to interfaces with addresses (simplification)
		if len(iface.Addresses) > 0 && !iface.IsLoopback {
			iface.DNSServers = dnsServers
		}
		result = append(result, *iface)
	}

	return result, nil
}

// GetInterface returns a specific interface by name
func (m *Manager) GetInterface(name string) (*Interface, error) {
	interfaces, err := m.ListInterfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}

// SetInterfaceConfig applies configuration to an interface
func (m *Manager) SetInterfaceConfig(config InterfaceConfig) error {
	if config.Name == "" {
		return fmt.Errorf("interface name is required")
	}

	// Verify interface exists
	_, err := m.GetInterface(config.Name)
	if err != nil {
		return err
	}

	m.logger("Configuring interface %s", config.Name)

	// Set MTU if specified
	if config.MTU != "" {
		if err := m.setMTU(config.Name, config.MTU); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Flush existing addresses
	if err := m.flushAddresses(config.Name); err != nil {
		m.logger("Warning: failed to flush addresses on %s: %v", config.Name, err)
	}

	// Add new addresses
	for _, addr := range config.Addresses {
		if err := m.addAddress(config.Name, addr); err != nil {
			return fmt.Errorf("failed to add address %s: %w", addr, err)
		}
	}

	// Set gateway if specified
	if config.Gateway != "" {
		if err := m.setDefaultGateway(config.Gateway, config.Name); err != nil {
			return fmt.Errorf("failed to set gateway: %w", err)
		}
	}

	// Set DNS if specified
	if len(config.DNSServers) > 0 {
		if err := m.setDNSServers(config.DNSServers); err != nil {
			return fmt.Errorf("failed to set DNS servers: %w", err)
		}
	}

	return nil
}

// AddAddress adds an IP address to an interface
func (m *Manager) AddAddress(ifaceName, address string) error {
	return m.addAddress(ifaceName, address)
}

// RemoveAddress removes an IP address from an interface
func (m *Manager) RemoveAddress(ifaceName, address string) error {
	cmd := exec.Command("ip", "addr", "del", address, "dev", ifaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove address: %s", string(output))
	}
	m.logger("Removed address %s from %s", address, ifaceName)
	return nil
}

// SetInterfaceUp brings an interface up
func (m *Manager) SetInterfaceUp(name string) error {
	cmd := exec.Command("ip", "link", "set", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up interface: %s", string(output))
	}
	m.logger("Interface %s brought up", name)
	return nil
}

// SetInterfaceDown brings an interface down
func (m *Manager) SetInterfaceDown(name string) error {
	cmd := exec.Command("ip", "link", "set", name, "down")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring down interface: %s", string(output))
	}
	m.logger("Interface %s brought down", name)
	return nil
}

// ListRoutes returns all routes
func (m *Manager) ListRoutes() ([]Route, error) {
	output, err := exec.Command("ip", "-o", "route", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	var routes []Route
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		route := parseRouteLine(line)
		if route != nil {
			routes = append(routes, *route)
		}
	}

	return routes, nil
}

// AddRoute adds a static route
func (m *Manager) AddRoute(destination, gateway, iface string) error {
	args := []string{"route", "add", destination}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if iface != "" {
		args = append(args, "dev", iface)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add route: %s", string(output))
	}
	m.logger("Added route: %s via %s dev %s", destination, gateway, iface)
	return nil
}

// DeleteRoute removes a route
func (m *Manager) DeleteRoute(destination, gateway, iface string) error {
	args := []string{"route", "del", destination}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	if iface != "" {
		args = append(args, "dev", iface)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to delete route: %s", string(output))
	}
	m.logger("Deleted route: %s", destination)
	return nil
}

// GetDNSServers returns current DNS servers from /etc/resolv.conf
func (m *Manager) GetDNSServers() []string {
	return m.getDNSServers()
}

// SetDNSServers updates DNS servers in /etc/resolv.conf
func (m *Manager) SetDNSServers(servers []string) error {
	return m.setDNSServers(servers)
}

// Helper functions

func (m *Manager) addAddress(ifaceName, address string) error {
	// Validate address format
	_, _, err := net.ParseCIDR(address)
	if err != nil {
		return fmt.Errorf("invalid address format (expected CIDR notation): %w", err)
	}

	cmd := exec.Command("ip", "addr", "add", address, "dev", ifaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore "RTNETLINK answers: File exists" - address already exists
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("failed to add address: %s", string(output))
		}
	}
	m.logger("Added address %s to %s", address, ifaceName)
	return nil
}

func (m *Manager) flushAddresses(ifaceName string) error {
	cmd := exec.Command("ip", "addr", "flush", "dev", ifaceName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush addresses: %s", string(output))
	}
	return nil
}

func (m *Manager) setMTU(ifaceName, mtu string) error {
	cmd := exec.Command("ip", "link", "set", ifaceName, "mtu", mtu)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %s", string(output))
	}
	m.logger("Set MTU %s on %s", mtu, ifaceName)
	return nil
}

func (m *Manager) getDefaultGateway() (string, string) {
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}

	// Parse: default via 192.168.1.1 dev eth0 ...
	line := strings.TrimSpace(string(output))
	if line == "" {
		return "", ""
	}

	parts := strings.Fields(line)
	var gateway, iface string
	for i, part := range parts {
		if part == "via" && i+1 < len(parts) {
			gateway = parts[i+1]
		}
		if part == "dev" && i+1 < len(parts) {
			iface = parts[i+1]
		}
	}

	return gateway, iface
}

func (m *Manager) setDefaultGateway(gateway, iface string) error {
	// Delete existing default route first
	exec.Command("ip", "route", "del", "default").Run()

	args := []string{"route", "add", "default", "via", gateway}
	if iface != "" {
		args = append(args, "dev", iface)
	}

	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set default gateway: %s", string(output))
	}
	m.logger("Set default gateway to %s via %s", gateway, iface)
	return nil
}

func (m *Manager) getDNSServers() []string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				servers = append(servers, parts[1])
			}
		}
	}

	return servers
}

func (m *Manager) setDNSServers(servers []string) error {
	// Read existing resolv.conf to preserve other entries
	file, err := os.Open("/etc/resolv.conf")
	var existingLines []string
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			// Keep non-nameserver lines (like search, domain, options)
			if !strings.HasPrefix(strings.TrimSpace(line), "nameserver") {
				existingLines = append(existingLines, line)
			}
		}
		file.Close()
	}

	// Build new content
	var content strings.Builder
	for _, line := range existingLines {
		content.WriteString(line + "\n")
	}
	for _, server := range servers {
		content.WriteString(fmt.Sprintf("nameserver %s\n", server))
	}

	// Write to resolv.conf
	if err := os.WriteFile("/etc/resolv.conf", []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write /etc/resolv.conf: %w", err)
	}

	m.logger("Updated DNS servers: %v", servers)
	return nil
}

// parseInterfaceLine parses a line from "ip -o link show"
// Example: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
func parseInterfaceLine(line string) *Interface {
	// Extract interface name
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return nil
	}

	name := strings.TrimSpace(parts[1])
	rest := parts[2]

	iface := &Interface{
		Name:      name,
		Addresses: []string{},
	}

	// Check if loopback
	if strings.Contains(rest, "LOOPBACK") {
		iface.IsLoopback = true
		iface.Type = "loopback"
	}

	// Check state (UP or DOWN)
	if strings.Contains(rest, ",UP") || strings.Contains(rest, "<UP") {
		iface.State = "up"
	} else {
		iface.State = "down"
	}

	// Extract MTU
	mtuRe := regexp.MustCompile(`mtu\s+(\d+)`)
	if match := mtuRe.FindStringSubmatch(rest); len(match) > 1 {
		iface.MTU = match[1]
	}

	// Extract MAC address
	macRe := regexp.MustCompile(`link/ether\s+([0-9a-f:]+)`)
	if match := macRe.FindStringSubmatch(rest); len(match) > 1 {
		iface.MAC = match[1]
	}

	// Detect interface type
	if !iface.IsLoopback {
		iface.Type = detectInterfaceType(name, rest)
		iface.IsVirtual = isVirtualInterface(name, rest)
	}

	return iface
}

// parseAddressLine parses a line from "ip -o addr show"
// Example: 2: eth0    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0
func parseAddressLine(line string, interfaces map[string]*Interface) {
	// Skip IPv6 for now
	if strings.Contains(line, "inet6") {
		return
	}

	if !strings.Contains(line, "inet ") {
		return
	}

	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return
	}

	rest := parts[1]
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return
	}

	ifaceName := fields[0]
	iface, ok := interfaces[ifaceName]
	if !ok {
		return
	}

	// Find inet address
	for i, field := range fields {
		if field == "inet" && i+1 < len(fields) {
			addr := fields[i+1]
			iface.Addresses = append(iface.Addresses, addr)
			break
		}
	}
}

// parseRouteLine parses a line from "ip -o route show"
// Example: default via 192.168.1.1 dev eth0 proto dhcp metric 100
// Example: 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10 metric 100
func parseRouteLine(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return nil
	}

	route := &Route{
		Destination: fields[0],
	}

	for i, field := range fields {
		switch field {
		case "via":
			if i+1 < len(fields) {
				route.Gateway = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				route.Interface = fields[i+1]
			}
		case "proto":
			if i+1 < len(fields) {
				route.Protocol = fields[i+1]
			}
		case "metric":
			if i+1 < len(fields) {
				route.Metric = fields[i+1]
			}
		case "scope":
			if i+1 < len(fields) {
				route.Scope = fields[i+1]
			}
		}
	}

	return route
}

func detectInterfaceType(name, info string) string {
	// Check for bridge
	if strings.HasPrefix(name, "br") || strings.HasPrefix(name, "virbr") || strings.HasPrefix(name, "fcbr") {
		return "bridge"
	}
	if strings.Contains(info, "master br") {
		return "bridge-port"
	}

	// Check for TAP/TUN
	if strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "fc") {
		return "tap"
	}

	// Check for veth
	if strings.HasPrefix(name, "veth") {
		return "veth"
	}

	// Check for VLAN
	if strings.Contains(name, ".") {
		return "vlan"
	}

	// Check for bond
	if strings.HasPrefix(name, "bond") {
		return "bond"
	}

	// Check for wireless
	if strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") {
		return "wireless"
	}

	return "physical"
}

func isVirtualInterface(name, info string) bool {
	virtualPrefixes := []string{"br", "virbr", "fcbr", "tap", "tun", "fc", "veth", "docker", "vxlan"}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
