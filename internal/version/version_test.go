package version

import (
	"strings"
	"testing"
)

// The grammar is the one published at semver.org. These cases are the ones
// that matter for tags, which is where a malformed version would enter.
func TestIsSemverValid(t *testing.T) {
	valid := []string{
		"0.0.0", "1.0.0", "0.1.0", "1.2.3", "10.20.30",
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7",
		"1.0.0-x.7.z.92", "1.0.0-x-y-z.--",
		"1.0.0-alpha+001", "1.0.0+20130313144700",
		"1.0.0-beta+exp.sha.5114f85", "1.0.0+21AF26D3---117B344092BD",
		"0.0.0-dev.abc1234",
	}
	for _, v := range valid {
		if !IsSemver(v) {
			t.Errorf("IsSemver(%q) = false, want true", v)
		}
	}
}

func TestIsSemverInvalid(t *testing.T) {
	invalid := []string{
		"", "1", "1.2", "1.2.3.4",
		"01.0.0",   // leading zero in major
		"1.01.0",   // leading zero in minor
		"1.0.01",   // leading zero in patch
		"v1.0.0",   // the "v" belongs to the tag, not the version
		"1.0.0-",   // empty prerelease
		"1.0.0+",   // empty build metadata
		"1.0.0-01", // leading zero in a numeric prerelease identifier
		"a.b.c",
		"1.0.0 ", // trailing space
		" 1.0.0",
	}
	for _, v := range invalid {
		if IsSemver(v) {
			t.Errorf("IsSemver(%q) = true, want false", v)
		}
	}
}

func TestIsPrerelease(t *testing.T) {
	cases := map[string]bool{
		"1.0.0":                      false,
		"1.0.0+build.5":              false,
		"1.0.0-rc.1":                 true,
		"1.0.0-alpha":                true,
		"1.0.0-alpha+build.5":        true, // prerelease, metadata stripped first
		"1.0.0-beta+exp.sha.5114f85": true,
	}
	for v, want := range cases {
		if got := IsPrerelease(v); got != want {
			t.Errorf("IsPrerelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestShortUsesBuildMetadataForCommit(t *testing.T) {
	origV, origC := Version, Commit
	defer func() { Version, Commit = origV, origC }()

	Version, Commit = "1.2.3", "a1b2c3d"
	got := Short()
	if got != "1.2.3+a1b2c3d" {
		t.Fatalf("Short() = %q, want 1.2.3+a1b2c3d", got)
	}
	// The qualifier must be valid semver build metadata, so the result
	// stays parseable.
	if !IsSemver("1.2.3") {
		t.Fatal("precondition: base version must be valid semver")
	}
}

func TestShortWithoutCommit(t *testing.T) {
	origV, origC := Version, Commit
	defer func() { Version, Commit = origV, origC }()

	Version, Commit = "1.2.3", "none"
	if got := Short(); got != "1.2.3" {
		t.Fatalf("Short() = %q, want 1.2.3", got)
	}
}

func TestStringBracesAllFields(t *testing.T) {
	origV, origC, origD := Version, Commit, Date
	defer func() { Version, Commit, Date = origV, origC, origD }()

	Version, Commit, Date = "1.2.3", "a1b2c3d", "2026-10-17T00:00:00Z"
	s := String()
	for _, want := range []string{"1.2.3", "a1b2c3d", "2026-10-17T00:00:00Z"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
