// Package firewall provides iptables-based firewall management for network bridges
package firewall

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"firecrackmanager/internal/database"
)

const (
	// Chain names for FireCrackManager firewall rules
	ChainInput   = "FCM_INPUT"
	ChainForward = "FCM_FORWARD"
	ChainNAT     = "FCM_NAT"

	// Rule types
	RuleTypeSourceIP    = "source_ip"
	RuleTypePortForward = "port_forward"
	RuleTypePortAllow   = "port_allow"
)

// Manager handles firewall rule management via iptables
type Manager struct {
	mu     sync.Mutex
	logger func(string, ...interface{})
}

// NewManager creates a new firewall manager
func NewManager(logger func(string, ...interface{})) *Manager {
	return &Manager{
		logger: logger,
	}
}

// Initialize sets up the firewall chains
func (m *Manager) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create custom chains if they don't exist
	chains := []struct {
		table string
		chain string
	}{
		{"filter", ChainInput},
		{"filter", ChainForward},
		{"nat", ChainNAT},
	}

	for _, c := range chains {
		// Try to create the chain (ignore error if it already exists)
		exec.Command("iptables", "-t", c.table, "-N", c.chain).Run()

		// Ensure chain is referenced from main chain
		switch c.chain {
		case ChainInput:
			m.ensureJumpRule("filter", "INPUT", c.chain)
		case ChainForward:
			m.ensureJumpRule("filter", "FORWARD", c.chain)
		case ChainNAT:
			m.ensureJumpRule("nat", "PREROUTING", c.chain)
		}
	}

	m.logger("Firewall chains initialized")
	return nil
}

// ensureJumpRule ensures a jump rule exists from parent chain to our chain
func (m *Manager) ensureJumpRule(table, parentChain, targetChain string) {
	// Check if jump rule already exists
	checkCmd := exec.Command("iptables", "-t", table, "-C", parentChain, "-j", targetChain)
	if checkCmd.Run() != nil {
		// Rule doesn't exist, add it
		exec.Command("iptables", "-t", table, "-I", parentChain, "1", "-j", targetChain).Run()
	}
}

// ApplyNetworkRules applies all firewall rules for a network
func (m *Manager) ApplyNetworkRules(net *database.Network, rules []*database.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// First, clear existing rules for this network
	m.clearNetworkRules(net)

	// If block_external is enabled, add a default drop rule for the subnet
	if net.BlockExternal && net.OutInterface != "" {
		m.addBlockExternalRule(net)
	}

	// Apply each enabled rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if err := m.applyRule(net, rule); err != nil {
			m.logger("Failed to apply firewall rule %s: %v", rule.ID, err)
		}
	}

	// Setup NAT if enabled
	if net.EnableNAT && net.OutInterface != "" {
		m.setupNAT(net)
	}

	return nil
}

// clearNetworkRules removes all rules associated with a network
func (m *Manager) clearNetworkRules(net *database.Network) {
	// Remove rules with network-specific comments
	comment := fmt.Sprintf("fcm-%s", net.ID[:8])

	// Clear from each chain
	tables := []struct {
		table string
		chain string
	}{
		{"filter", ChainInput},
		{"filter", ChainForward},
		{"nat", ChainNAT},
		{"nat", "POSTROUTING"},
	}

	for _, t := range tables {
		m.removeRulesWithComment(t.table, t.chain, comment)
	}
}

// removeRulesWithComment removes all rules with a specific comment from a chain
func (m *Manager) removeRulesWithComment(table, chain, comment string) {
	for {
		// List rules with line numbers
		cmd := exec.Command("iptables", "-t", table, "-L", chain, "--line-numbers", "-n")
		output, err := cmd.Output()
		if err != nil {
			break
		}

		// Find rules with our comment
		lines := strings.Split(string(output), "\n")
		found := false
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], comment) {
				// Extract line number
				parts := strings.Fields(lines[i])
				if len(parts) > 0 {
					lineNum := parts[0]
					exec.Command("iptables", "-t", table, "-D", chain, lineNum).Run()
					found = true
					break // Restart from the end after deletion
				}
			}
		}
		if !found {
			break
		}
	}
}

// addBlockExternalRule adds a rule to block external access to the network subnet
func (m *Manager) addBlockExternalRule(net *database.Network) {
	comment := fmt.Sprintf("fcm-%s-block", net.ID[:8])

	// Allow established connections
	exec.Command("iptables", "-A", ChainInput,
		"-d", net.Subnet,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT").Run()

	// Allow from bridge itself (host to VM)
	exec.Command("iptables", "-A", ChainInput,
		"-d", net.Subnet,
		"-i", net.BridgeName,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT").Run()

	// Drop incoming from external interface to subnet
	exec.Command("iptables", "-A", ChainInput,
		"-d", net.Subnet,
		"-i", net.OutInterface,
		"-m", "comment", "--comment", comment,
		"-j", "DROP").Run()

	// Similar for FORWARD chain
	exec.Command("iptables", "-A", ChainForward,
		"-d", net.Subnet,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT").Run()

	exec.Command("iptables", "-A", ChainForward,
		"-d", net.Subnet,
		"-i", net.OutInterface,
		"-m", "comment", "--comment", comment,
		"-j", "DROP").Run()
}

// applyRule applies a single firewall rule
func (m *Manager) applyRule(net *database.Network, rule *database.FirewallRule) error {
	comment := fmt.Sprintf("fcm-%s-%s", net.ID[:8], rule.ID[:8])

	switch rule.RuleType {
	case RuleTypeSourceIP:
		return m.applySourceIPRule(net, rule, comment)
	case RuleTypePortForward:
		return m.applyPortForwardRule(net, rule, comment)
	case RuleTypePortAllow:
		return m.applyPortAllowRule(net, rule, comment)
	default:
		return fmt.Errorf("unknown rule type: %s", rule.RuleType)
	}
}

// applySourceIPRule allows traffic from a specific source IP/CIDR
func (m *Manager) applySourceIPRule(net *database.Network, rule *database.FirewallRule, comment string) error {
	// Insert before block rules (use -I to insert at beginning)
	args := []string{"-I", ChainInput, "1",
		"-s", rule.SourceIP,
		"-d", net.Subnet,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"}
	if err := exec.Command("iptables", args...).Run(); err != nil {
		return err
	}

	// Also allow forwarding
	args = []string{"-I", ChainForward, "1",
		"-s", rule.SourceIP,
		"-d", net.Subnet,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"}
	return exec.Command("iptables", args...).Run()
}

// applyPortForwardRule sets up DNAT for port forwarding
func (m *Manager) applyPortForwardRule(net *database.Network, rule *database.FirewallRule, comment string) error {
	// DNAT rule in nat table
	protoFlag := strings.ToLower(rule.Protocol)
	if protoFlag == "all" {
		protoFlag = "tcp" // Default to TCP for port forwarding
	}

	// PREROUTING DNAT rule
	dnatArgs := []string{"-t", "nat", "-A", ChainNAT,
		"-p", protoFlag,
		"--dport", fmt.Sprintf("%d", rule.HostPort),
		"-m", "comment", "--comment", comment,
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.DestIP, rule.DestPort)}

	if net.OutInterface != "" {
		dnatArgs = append(dnatArgs[:4], append([]string{"-i", net.OutInterface}, dnatArgs[4:]...)...)
	}

	if err := exec.Command("iptables", dnatArgs...).Run(); err != nil {
		return fmt.Errorf("failed to add DNAT rule: %w", err)
	}

	// FORWARD rule to allow the forwarded traffic
	fwdArgs := []string{"-I", ChainForward, "1",
		"-p", protoFlag,
		"-d", rule.DestIP,
		"--dport", fmt.Sprintf("%d", rule.DestPort),
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"}

	if err := exec.Command("iptables", fwdArgs...).Run(); err != nil {
		return fmt.Errorf("failed to add FORWARD rule: %w", err)
	}

	return nil
}

// applyPortAllowRule allows traffic to a specific port on VMs
func (m *Manager) applyPortAllowRule(net *database.Network, rule *database.FirewallRule, comment string) error {
	protoFlag := strings.ToLower(rule.Protocol)
	if protoFlag == "all" {
		// Apply for both TCP and UDP
		for _, proto := range []string{"tcp", "udp"} {
			args := []string{"-I", ChainForward, "1",
				"-p", proto,
				"-d", net.Subnet,
				"--dport", fmt.Sprintf("%d", rule.DestPort),
				"-m", "comment", "--comment", comment,
				"-j", "ACCEPT"}
			exec.Command("iptables", args...).Run()
		}
		return nil
	}

	args := []string{"-I", ChainForward, "1",
		"-p", protoFlag,
		"-d", net.Subnet,
		"--dport", fmt.Sprintf("%d", rule.DestPort),
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT"}

	return exec.Command("iptables", args...).Run()
}

// setupNAT configures NAT for outbound traffic from the network
func (m *Manager) setupNAT(net *database.Network) {
	comment := fmt.Sprintf("fcm-%s-nat", net.ID[:8])

	// Enable IP forwarding
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// MASQUERADE rule for outbound traffic
	args := []string{"-t", "nat", "-A", "POSTROUTING",
		"-s", net.Subnet,
		"-o", net.OutInterface,
		"-m", "comment", "--comment", comment,
		"-j", "MASQUERADE"}

	exec.Command("iptables", args...).Run()

	// Allow forwarding from bridge to external
	exec.Command("iptables", "-A", ChainForward,
		"-i", net.BridgeName,
		"-o", net.OutInterface,
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT").Run()

	// Allow return traffic
	exec.Command("iptables", "-A", ChainForward,
		"-i", net.OutInterface,
		"-o", net.BridgeName,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT").Run()
}

// RemoveNetworkRules removes all firewall rules for a network
func (m *Manager) RemoveNetworkRules(net *database.Network) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clearNetworkRules(net)
	m.logger("Removed firewall rules for network %s", net.Name)
	return nil
}

// ListRules returns current iptables rules (for debugging)
func (m *Manager) ListRules() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var output strings.Builder

	// Filter table
	cmd := exec.Command("iptables", "-L", "-n", "-v", "--line-numbers")
	out, err := cmd.Output()
	if err == nil {
		output.WriteString("=== FILTER TABLE ===\n")
		output.Write(out)
		output.WriteString("\n")
	}

	// NAT table
	cmd = exec.Command("iptables", "-t", "nat", "-L", "-n", "-v", "--line-numbers")
	out, err = cmd.Output()
	if err == nil {
		output.WriteString("=== NAT TABLE ===\n")
		output.Write(out)
	}

	return output.String(), nil
}

// Cleanup removes all FireCrackManager firewall rules and chains
func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Flush our chains
	exec.Command("iptables", "-F", ChainInput).Run()
	exec.Command("iptables", "-F", ChainForward).Run()
	exec.Command("iptables", "-t", "nat", "-F", ChainNAT).Run()

	// Remove jump rules from main chains
	exec.Command("iptables", "-D", "INPUT", "-j", ChainInput).Run()
	exec.Command("iptables", "-D", "FORWARD", "-j", ChainForward).Run()
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", ChainNAT).Run()

	// Delete our chains
	exec.Command("iptables", "-X", ChainInput).Run()
	exec.Command("iptables", "-X", ChainForward).Run()
	exec.Command("iptables", "-t", "nat", "-X", ChainNAT).Run()

	m.logger("Firewall cleanup complete")
}

// CheckIptables verifies iptables is available
func CheckIptables() bool {
	cmd := exec.Command("iptables", "--version")
	return cmd.Run() == nil
}
