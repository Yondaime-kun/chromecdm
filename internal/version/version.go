// Package version carries the build identity, injected at link time.
//
// The version string is a Semantic Versioning 2.0.0 version (see
// https://semver.org): X.Y.Z with optional -prerelease and +build
// metadata, and NO leading "v" — the "v" belongs to the git tag, not to
// the version.
//
// Build with:
//
//	go build -ldflags "\
//	  -X chromecdm/internal/version.Version=1.2.3 \
//	  -X chromecdm/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X chromecdm/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// Set at link time via -ldflags -X.
var (
	// Version is the semantic version, e.g. "1.2.3" or "1.3.0-rc.1".
	// No leading "v": the tag is v1.2.3, the version is 1.2.3.
	Version = "0.0.0-dev"
	// Commit is the short git revision.
	Commit = "none"
	// Date is the build timestamp in RFC 3339 UTC.
	Date = "unknown"
)

// semverRe is the grammar published at
// https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
var semverRe = regexp.MustCompile(
	`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)` +
		`(-(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)` +
		`(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*)?` +
		`(\+[0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?$`)

// IsSemver reports whether v is a valid Semantic Versioning 2.0.0 version.
// A leading "v" is rejected, because it is not part of a version.
func IsSemver(v string) bool {
	return semverRe.MatchString(v)
}

// IsPrerelease reports whether v carries a pre-release identifier, which
// makes it lower precedence than the release it leads to.
func IsPrerelease(v string) bool {
	// Strip build metadata, then look for "-" before it.
	base := v
	if i := strings.IndexByte(base, '+'); i >= 0 {
		base = base[:i]
	}
	return strings.Contains(base, "-")
}

// String returns a one-line description of this build.
func String() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s %s/%s)",
		Version, Commit, Date, runtime.Version(),
		runtime.GOOS, runtime.GOARCH)
}

// Short returns the version, qualified by the commit when the build is not
// exactly a release. In semver, "+" introduces build metadata, so the
// commit goes there rather than being concatenated with a bare separator.
func Short() string {
	switch Commit {
	case "", "none":
		return Version
	}
	if IsSemver(Version) {
		return Version + "+" + Commit
	}
	return Version + "+" + Commit
}
