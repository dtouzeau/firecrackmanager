package version

const (
	// Version is the current version of FireCrackManager
	Version = "1.0.1"

	// BuildDate can be set at build time using -ldflags
	// go build -ldflags="-X firecrackmanager/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	BuildDate = ""

	// GitCommit can be set at build time using -ldflags
	// go build -ldflags="-X firecrackmanager/internal/version.GitCommit=$(git rev-parse --short HEAD)"
	GitCommit = ""
)

// Info returns version information as a map
func Info() map[string]string {
	info := map[string]string{
		"version": Version,
	}
	if BuildDate != "" {
		info["build_date"] = BuildDate
	}
	if GitCommit != "" {
		info["git_commit"] = GitCommit
	}
	return info
}

// String returns the version string
func String() string {
	if GitCommit != "" {
		return Version + "-" + GitCommit
	}
	return Version
}
