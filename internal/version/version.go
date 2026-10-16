// Package version carries the build identity, injected at link time.
//
// Build with:
//
//	go build -ldflags "\
//	  -X chromecdm/internal/version.Version=v1.2.3 \
//	  -X chromecdm/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X chromecdm/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

import (
	"fmt"
	"runtime"
)

// Set at link time via -ldflags -X.
var (
	// Version is the release tag, e.g. "v1.2.3".
	Version = "dev"
	// Commit is the short git revision.
	Commit = "none"
	// Date is the build timestamp in RFC 3339 UTC.
	Date = "unknown"
)

// String returns a one-line description of this build.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s %s/%s)",
		Version, Commit, Date, runtime.Version(),
		runtime.GOOS, runtime.GOARCH)
}

// Short returns just the version and commit, for compact output.
func Short() string {
	if Commit == "none" || Commit == "" {
		return Version
	}
	return Version + "+" + Commit
}
