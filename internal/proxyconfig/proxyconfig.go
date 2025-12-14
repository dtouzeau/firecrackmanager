package proxyconfig

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ProxyConfig holds HTTP proxy settings for outbound connections
type ProxyConfig struct {
	Enabled  bool   `json:"enabled"`
	URL      string `json:"url"`      // e.g., "http://proxy.example.com:3128"
	Username string `json:"username"` // optional auth
	Password string `json:"password"` // optional auth
	NoProxy  string `json:"no_proxy"` // comma-separated list of hosts to bypass
}

var (
	config     ProxyConfig
	configOnce sync.Once
	configMu   sync.RWMutex
	configPath = "/etc/firecrackmanager/proxy.json"
)

// SetConfigPath allows overriding the default config path
func SetConfigPath(path string) {
	configMu.Lock()
	defer configMu.Unlock()
	configPath = path
}

// Load reads proxy configuration from file or environment
func Load() ProxyConfig {
	configMu.RLock()
	path := configPath
	configMu.RUnlock()

	var cfg ProxyConfig

	// Try loading from config file first
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.Enabled && cfg.URL != "" {
			return cfg
		}
	}

	// Fall back to environment variables
	if proxyURL := os.Getenv("HTTPS_PROXY"); proxyURL != "" {
		cfg.Enabled = true
		cfg.URL = proxyURL
	} else if proxyURL := os.Getenv("https_proxy"); proxyURL != "" {
		cfg.Enabled = true
		cfg.URL = proxyURL
	} else if proxyURL := os.Getenv("HTTP_PROXY"); proxyURL != "" {
		cfg.Enabled = true
		cfg.URL = proxyURL
	} else if proxyURL := os.Getenv("http_proxy"); proxyURL != "" {
		cfg.Enabled = true
		cfg.URL = proxyURL
	}

	if noProxy := os.Getenv("NO_PROXY"); noProxy != "" {
		cfg.NoProxy = noProxy
	} else if noProxy := os.Getenv("no_proxy"); noProxy != "" {
		cfg.NoProxy = noProxy
	}

	return cfg
}

// Save writes the proxy configuration to file
func Save(cfg ProxyConfig) error {
	configMu.RLock()
	path := configPath
	configMu.RUnlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// GetProxyURL returns the configured proxy URL or empty string if disabled
func GetProxyURL() string {
	cfg := Load()
	if !cfg.Enabled || cfg.URL == "" {
		return ""
	}

	// If credentials are provided separately, inject them into the URL
	if cfg.Username != "" && cfg.Password != "" {
		if u, err := url.Parse(cfg.URL); err == nil {
			if u.User == nil || u.User.String() == "" {
				u.User = url.UserPassword(cfg.Username, cfg.Password)
				return u.String()
			}
		}
	}

	return cfg.URL
}

// GetNoProxyList returns the list of hosts that should bypass the proxy
func GetNoProxyList() []string {
	cfg := Load()
	if cfg.NoProxy == "" {
		return nil
	}
	hosts := strings.Split(cfg.NoProxy, ",")
	for i := range hosts {
		hosts[i] = strings.TrimSpace(hosts[i])
	}
	return hosts
}

// ShouldBypassProxy checks if a host should bypass the proxy
func ShouldBypassProxy(host string) bool {
	noProxyList := GetNoProxyList()
	host = strings.ToLower(strings.TrimSpace(host))

	for _, pattern := range noProxyList {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		// Direct match
		if host == pattern {
			return true
		}
		// Wildcard suffix match (e.g., .example.com matches foo.example.com)
		if strings.HasPrefix(pattern, ".") && strings.HasSuffix(host, pattern) {
			return true
		}
		// Suffix match without dot (e.g., example.com matches foo.example.com)
		if strings.HasSuffix(host, "."+pattern) {
			return true
		}
	}
	return false
}

// NewHTTPTransport creates an http.Transport configured with proxy settings
func NewHTTPTransport() (*http.Transport, error) {
	proxyURL := GetProxyURL()

	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}

		// Custom proxy function that respects NO_PROXY
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			if ShouldBypassProxy(req.URL.Host) {
				return nil, nil // No proxy for this host
			}
			return u, nil
		}
	}

	return transport, nil
}

// NewHTTPClient creates an http.Client configured with proxy settings and timeout
func NewHTTPClient(timeout time.Duration) (*http.Client, error) {
	transport, err := NewHTTPTransport()
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}
