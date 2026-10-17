package cdp

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A build that fails to report a version must sort last, not abort the
// search: BrowserVersion returns "" for it and "" compares lowest.
func TestBrowserVersionUnparseable(t *testing.T) {
	if v := BrowserVersion("/nonexistent/chrome"); v != "" {
		t.Fatalf("want empty version for a missing binary, got %q", v)
	}
	if v := BrowserVersion("/bin/true"); v != "" {
		t.Fatalf("want empty version for a binary that prints nothing, got %q", v)
	}
}

// Zero-padding is what makes lexical comparison agree with numeric: without
// it "145" > "155" because '4' > '5' at the second character.
func TestBrowserVersionZeroPads(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fakechrome")
	// Echo a version the way real chrome does, then exit.
	if err := writeScript(script, `#!/bin/sh
echo "Google Chrome for Testing 155.0.8059.84"
`); err != nil {
		t.Skipf("cannot write script: %v", err)
	}

	got := BrowserVersion(script)
	want := "000155.000000.008059.000084"
	if got != want {
		t.Fatalf("BrowserVersion = %q, want %q", got, want)
	}
	if !(got > "000145.000000.007632.000006") {
		t.Fatal("155 must sort above 145; zero-padding is broken")
	}
}

// FindBrowser is the guard against picking a build whose CDM the license
// server rejects. It must not return an error on a machine that has any
// chrome at all, and the result must run.
func TestFindBrowserReturnsRunnableBinary(t *testing.T) {
	p, err := FindBrowser()
	if err != nil {
		t.Skipf("no chrome on this machine: %v", err)
	}
	if BrowserVersion(p) == "" {
		t.Fatalf("FindBrowser returned %q, which does not report a version", p)
	}
	if _, err := exec.Command(p, "--version").Output(); err != nil {
		t.Fatalf("FindBrowser returned a binary that will not run: %v", err)
	}
	t.Logf("picked %s", p)
}

func writeScript(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o755)
}
