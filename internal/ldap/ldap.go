package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config holds the LDAP/Active Directory configuration
type Config struct {
	Enabled         bool   `json:"enabled"`
	Server          string `json:"server"`            // AD server hostname or IP
	Port            int    `json:"port"`              // LDAP port (389 or 636 for LDAPS)
	UseSSL          bool   `json:"use_ssl"`           // Use LDAPS (port 636)
	UseStartTLS     bool   `json:"use_starttls"`      // Use StartTLS on port 389
	SkipVerify      bool   `json:"skip_verify"`       // Skip TLS certificate verification
	BindDN          string `json:"bind_dn"`           // Service account in user@domain.tld format
	BindPassword    string `json:"bind_password"`     // Password for the service account
	BaseDN          string `json:"base_dn"`           // Base DN for searches (auto-derived from domain)
	UserSearchBase  string `json:"user_search_base"`  // Base DN for user searches (defaults to BaseDN)
	UserFilter      string `json:"user_filter"`       // LDAP filter for users (fixed: (&(objectClass=user)(sAMAccountName=%s)))
	GroupSearchBase string `json:"group_search_base"` // Base DN for group searches (defaults to BaseDN)
	GroupFilter     string `json:"group_filter"`      // LDAP filter for groups (fixed: (objectClass=group))
}

// getDomainFromUPN extracts domain.tld from user@domain.tld
func getDomainFromUPN(upn string) string {
	if idx := strings.Index(upn, "@"); idx != -1 {
		return upn[idx+1:]
	}
	return ""
}

// getUPN returns user@domain.tld format for authentication
func (c *Client) getUPN(username string) string {
	// If username already contains @, return as is
	if strings.Contains(username, "@") {
		return username
	}
	// Get domain from bind_dn (service account)
	domain := getDomainFromUPN(c.config.BindDN)
	if domain != "" {
		return username + "@" + domain
	}
	return username
}

// GroupMapping maps an AD group DN to local privileges
type GroupMapping struct {
	ID           string `json:"id"`
	GroupDN      string `json:"group_dn"`       // Full DN of the AD group
	GroupName    string `json:"group_name"`     // Display name of the group
	LocalRole    string `json:"local_role"`     // Local role: admin, user, or group-based
	LocalGroupID string `json:"local_group_id"` // If role is group-based, the local group ID
	CreatedAt    int64  `json:"created_at"`
}

// ADGroup represents an Active Directory group
type ADGroup struct {
	DN          string `json:"dn"`
	CN          string `json:"cn"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ADUser represents an Active Directory user
type ADUser struct {
	DN                string   `json:"dn"`
	SAMAccountName    string   `json:"sam_account_name"`
	UserPrincipalName string   `json:"user_principal_name"`
	DisplayName       string   `json:"display_name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"` // List of group DNs the user belongs to
}

// Client handles LDAP/AD operations
type Client struct {
	config *Config
	logger func(format string, args ...interface{})
}

// NewClient creates a new LDAP client
func NewClient(config *Config, logger func(format string, args ...interface{})) *Client {
	return &Client{
		config: config,
		logger: logger,
	}
}

// connect establishes a connection to the LDAP server
func (c *Client) connect() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", c.config.Server, c.config.Port)

	if c.config.UseSSL {
		// LDAPS connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.SkipVerify,
			ServerName:         c.config.Server,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Plain LDAP connection
		conn, err = ldap.Dial("tcp", address)
		if err == nil && c.config.UseStartTLS {
			// Upgrade to TLS using StartTLS
			tlsConfig := &tls.Config{
				InsecureSkipVerify: c.config.SkipVerify,
				ServerName:         c.config.Server,
			}
			err = conn.StartTLS(tlsConfig)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Set timeout
	conn.SetTimeout(30 * time.Second)

	return conn, nil
}

// TestConnection tests the LDAP connection and bind credentials
func (c *Client) TestConnection() error {
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return fmt.Errorf("failed to bind: %w", err)
	}

	c.logger("LDAP connection test successful")
	return nil
}

// AuthenticateUser authenticates a user against AD using user@domain.tld format
func (c *Client) AuthenticateUser(username, password string) (*ADUser, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Get username in user@domain.tld format for AD authentication
	userUPN := c.getUPN(username)

	// Try to bind directly as the user with UPN format (user@domain.tld)
	if err := conn.Bind(userUPN, password); err != nil {
		return nil, fmt.Errorf("authentication failed")
	}

	// Now search for the user details using the authenticated connection
	userFilter := "(&(objectClass=user)(sAMAccountName=%s))"
	// Extract just the username part if it contains @
	searchUsername := username
	if idx := strings.Index(username, "@"); idx != -1 {
		searchUsername = username[:idx]
	}
	userFilter = fmt.Sprintf(userFilter, ldap.EscapeFilter(searchUsername))

	searchBase := c.config.BaseDN

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		[]string{"dn", "sAMAccountName", "userPrincipalName", "displayName", "mail", "memberOf"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		// User authenticated but not found in search - create minimal user info
		return &ADUser{
			SAMAccountName:    searchUsername,
			UserPrincipalName: userUPN,
			Groups:            []string{},
		}, nil
	}

	userEntry := result.Entries[0]

	// Get user's groups from memberOf attribute
	groups := userEntry.GetAttributeValues("memberOf")

	user := &ADUser{
		DN:                userEntry.DN,
		SAMAccountName:    userEntry.GetAttributeValue("sAMAccountName"),
		UserPrincipalName: userEntry.GetAttributeValue("userPrincipalName"),
		DisplayName:       userEntry.GetAttributeValue("displayName"),
		Email:             userEntry.GetAttributeValue("mail"),
		Groups:            groups,
	}

	c.logger("LDAP authentication successful for user: %s", username)
	return user, nil
}

// SearchGroups searches for AD groups matching a query
func (c *Client) SearchGroups(query string, limit int) ([]ADGroup, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account (user@domain.tld format)
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Use BaseDN for searching groups
	searchBase := c.config.BaseDN

	// Build filter - always use (objectClass=group)
	var filter string
	if query == "" || query == "*" {
		filter = "(objectClass=group)"
	} else {
		// Search by CN or name containing the query
		escapedQuery := ldap.EscapeFilter(query)
		filter = fmt.Sprintf("(&(objectClass=group)(|(cn=*%s*)(name=*%s*)))", escapedQuery, escapedQuery)
	}

	if limit <= 0 {
		limit = 100
	}

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, false,
		filter,
		[]string{"dn", "cn", "name", "description", "member"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group search failed: %w", err)
	}

	groups := make([]ADGroup, 0, len(result.Entries))
	for _, entry := range result.Entries {
		groups = append(groups, ADGroup{
			DN:          entry.DN,
			CN:          entry.GetAttributeValue("cn"),
			Name:        entry.GetAttributeValue("name"),
			Description: entry.GetAttributeValue("description"),
		})
	}

	return groups, nil
}

// GetGroup retrieves a specific AD group by DN
func (c *Client) GetGroup(groupDN string) (*ADGroup, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=group)",
		[]string{"dn", "cn", "name", "description"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group lookup failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("group not found")
	}

	entry := result.Entries[0]
	return &ADGroup{
		DN:          entry.DN,
		CN:          entry.GetAttributeValue("cn"),
		Name:        entry.GetAttributeValue("name"),
		Description: entry.GetAttributeValue("description"),
	}, nil
}

// GetGroupMemberCount returns the number of members in an AD group
func (c *Client) GetGroupMemberCount(groupDN string) (int, error) {
	conn, err := c.connect()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return 0, fmt.Errorf("failed to bind: %w", err)
	}

	// Search for the group and get member attribute
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=group)",
		[]string{"member"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return 0, fmt.Errorf("group lookup failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return 0, nil
	}

	// Count members
	members := result.Entries[0].GetAttributeValues("member")
	return len(members), nil
}

// ADGroupMember represents a member of an AD group
type ADGroupMember struct {
	DN          string `json:"dn"`
	CN          string `json:"cn"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Type        string `json:"type"` // "user" or "group"
}

// GetGroupMembers returns the members of an AD group with their details
func (c *Client) GetGroupMembers(groupDN string) ([]ADGroupMember, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Search for the group and get member attribute
	searchRequest := ldap.NewSearchRequest(
		groupDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=group)",
		[]string{"member"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group lookup failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("group not found")
	}

	memberDNs := result.Entries[0].GetAttributeValues("member")
	members := make([]ADGroupMember, 0, len(memberDNs))

	// Look up each member to get their details
	for _, memberDN := range memberDNs {
		member := ADGroupMember{DN: memberDN}

		// Extract CN from DN
		if idx := strings.Index(memberDN, "CN="); idx != -1 {
			end := strings.Index(memberDN[idx+3:], ",")
			if end != -1 {
				member.CN = memberDN[idx+3 : idx+3+end]
			} else {
				member.CN = memberDN[idx+3:]
			}
		}

		// Try to look up the member for more details
		memberSearch := ldap.NewSearchRequest(
			memberDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)",
			[]string{"objectClass", "displayName", "mail", "cn"},
			nil,
		)

		memberResult, err := conn.Search(memberSearch)
		if err == nil && len(memberResult.Entries) > 0 {
			entry := memberResult.Entries[0]
			if member.CN == "" {
				member.CN = entry.GetAttributeValue("cn")
			}
			member.DisplayName = entry.GetAttributeValue("displayName")
			member.Email = entry.GetAttributeValue("mail")

			// Determine if this is a user or group
			objectClasses := entry.GetAttributeValues("objectClass")
			for _, oc := range objectClasses {
				if strings.ToLower(oc) == "group" {
					member.Type = "group"
					break
				} else if strings.ToLower(oc) == "user" || strings.ToLower(oc) == "person" {
					member.Type = "user"
				}
			}
			if member.Type == "" {
				member.Type = "user"
			}
		} else {
			member.Type = "user"
		}

		members = append(members, member)
	}

	return members, nil
}

// GetUserGroups retrieves all groups a user belongs to (including nested groups)
func (c *Client) GetUserGroups(userDN string) ([]string, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind with service account
	if err := conn.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Use LDAP_MATCHING_RULE_IN_CHAIN to get nested group membership
	// This is an AD-specific feature (OID 1.2.840.113556.1.4.1941)
	filter := fmt.Sprintf("(member:1.2.840.113556.1.4.1941:=%s)", ldap.EscapeFilter(userDN))

	searchBase := c.config.BaseDN

	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("group membership search failed: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		groups = append(groups, entry.DN)
	}

	return groups, nil
}

// IsUserInGroup checks if a user is a member of a specific group (including nested)
func (c *Client) IsUserInGroup(userDN, groupDN string) (bool, error) {
	groups, err := c.GetUserGroups(userDN)
	if err != nil {
		return false, err
	}

	// Normalize DNs for comparison (case-insensitive)
	groupDNLower := strings.ToLower(groupDN)
	for _, g := range groups {
		if strings.ToLower(g) == groupDNLower {
			return true, nil
		}
	}

	return false, nil
}

// DefaultConfig returns a default LDAP configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     false,
		Port:        389,
		UseSSL:      false,
		UseStartTLS: false,
		SkipVerify:  true,
		UserFilter:  "(&(objectClass=user)(sAMAccountName=%s))",
		GroupFilter: "(objectClass=group)",
	}
}
