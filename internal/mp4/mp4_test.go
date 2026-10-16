package mp4

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tencBox builds a minimal version-0 tenc box carrying one default_KID.
//
// The bytes after the 4-byte "tenc" type are, per the real file this was
// checked against:
//
//	version(1) flags(3) | reserved(1) | is_protected(1) | IV_size(1) | default_KID(16)
//	74656e63  00000000  |     00      |       01        |     08     | <16 bytes>
//
// which puts the default_KID 12 bytes past the 't', and extends the box to
// 28 bytes.
func tencBox(kid []byte) []byte {
	return append([]byte{
		't', 'e', 'n', 'c', // box type
		0x00, 0x00, 0x00, 0x00, // version, flags
		0x00, // reserved
		0x01, // is_protected
		0x08, // IV_size
		0x00, // reserved (pads the prefix to 12, matching real files)
	}, kid...)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

const (
	fileKID  = "800aacaa522958ae888062b5695db6bf"
	otherKID = "bf82a2f58ecfb327c0ab0a0b6f4a1234"
	thirdKID = "100b6c20940f779a4589152b57d2dacb"
)

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sample.mp4")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestDefaultKIDs(t *testing.T) {
	// Real Google Shaka asset KID, embedded in a synthetic tenc box.
	data := append([]byte("junk-padding"), tencBox(mustHex(t, fileKID))...)
	got := defaultKIDs(data)
	if len(got) != 1 || got[0] != fileKID {
		t.Fatalf("want [%s], got %v", fileKID, got)
	}
}

func TestDefaultKIDsDedupesAndKeepsOrder(t *testing.T) {
	data := bytes.Join([][]byte{
		tencBox(mustHex(t, fileKID)),
		tencBox(mustHex(t, otherKID)),
		tencBox(mustHex(t, fileKID)), // duplicate
	}, nil)
	got := defaultKIDs(data)
	if len(got) != 2 {
		t.Fatalf("want 2 unique KIDs, got %d: %v", len(got), got)
	}
	if got[0] != fileKID || got[1] != otherKID {
		t.Fatalf("order not preserved: %v", got)
	}
}

func TestDefaultKIDsNonePresent(t *testing.T) {
	if got := defaultKIDs([]byte("no encryption boxes here at all")); got != nil {
		t.Fatalf("want nil, got %v", got)
	}
}

// The regression that motivated this package: with a multi-key license the
// correct key is the one matching the file's KID, not the first in the
// license. Picking the first silently corrupts output.
func TestSelectContentKeyPicksByKIDNotFirst(t *testing.T) {
	path := writeTemp(t, append([]byte("ftypmp42"), tencBox(mustHex(t, fileKID))...))

	first := []byte("AAAA-first-in-license")
	correct := []byte("BBBB-matches-the-kid")
	third := []byte("CCCC-unrelated")

	kidIndex := map[string][]byte{
		otherKID: first, // listed FIRST, and wrong
		fileKID:  correct,
		thirdKID: third,
	}

	key, matched, err := SelectContentKey(path, [][]byte{first, correct, third}, kidIndex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(key, correct) {
		t.Fatalf("picked the wrong key: got %q, want the KID-matched one", key)
	}
	if matched != fileKID {
		t.Fatalf("reported KID %q, want %q", matched, fileKID)
	}
}

func TestSelectContentKeySingleKeyShortCircuits(t *testing.T) {
	path := writeTemp(t, tencBox(mustHex(t, fileKID)))
	only := []byte("only-key")

	key, matched, err := SelectContentKey(path, [][]byte{only}, map[string][]byte{fileKID: only})
	if err != nil || !bytes.Equal(key, only) {
		t.Fatalf("single key should be returned as-is: %v %v", key, err)
	}
	if matched != "" {
		t.Fatalf("no KID matching needed for one key, got %q", matched)
	}
}

func TestSelectContentKeyNoMatchIsAnError(t *testing.T) {
	// File encrypted with fileKID; license offers only unrelated keys.
	path := writeTemp(t, tencBox(mustHex(t, fileKID)))
	kidIndex := map[string][]byte{
		otherKID: []byte("x"),
		thirdKID: []byte("y"),
	}

	_, _, err := SelectContentKey(path, [][]byte{[]byte("x"), []byte("y")}, kidIndex)
	if err == nil {
		t.Fatal("want an error when no license key matches the file KID")
	}
	if !strings.Contains(err.Error(), fileKID) {
		t.Fatalf("error should name the file KID, got: %v", err)
	}
}

func TestSelectContentKeyNoTencFallsBackToFirst(t *testing.T) {
	path := writeTemp(t, []byte("unencrypted-looking file"))
	first := []byte("first")
	kidIndex := map[string][]byte{otherKID: first}

	key, matched, err := SelectContentKey(path, [][]byte{first, []byte("second")}, kidIndex)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(key, first) {
		t.Fatalf("want documented fallback to first key, got %q", key)
	}
	if matched != "" {
		t.Fatalf("a fallback is not a match; got %q", matched)
	}
}

func TestSelectContentKeyEmptyLicense(t *testing.T) {
	path := writeTemp(t, tencBox(mustHex(t, fileKID)))
	if _, _, err := SelectContentKey(path, nil, nil); err == nil {
		t.Fatal("want an error for a license with no content key")
	}
}

func TestDefaultKIDsMissingFile(t *testing.T) {
	if got := DefaultKIDs(filepath.Join(t.TempDir(), "nope.mp4")); got != nil {
		t.Fatalf("missing file should yield nil, got %v", got)
	}
}
