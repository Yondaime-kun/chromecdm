package main

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
)

// The PSSH a real DASH manifest carries: 62 bytes, Widevine system ID.
// Layout is size(4) type(4) version(1) flags(3) systemID(16) ...
const realPSSHB64 = "AAAAPnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAB4iFnNoYWthX2NlYzJmNjRhYTc4OTBhMTFI49yVmwY="

// buildPSSH assembles a pssh box around the real payload, prefixed with
// unrelated bytes so offsets are exercised.
func buildPSSH(t *testing.T) []byte {
	t.Helper()
	box, err := base64.StdEncoding.DecodeString(realPSSHB64)
	if err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	out := []byte("ftypmp42paddingbefore")
	return append(out, box...)
}

func TestFindPSSHOffset(t *testing.T) {
	data := buildPSSH(t)
	boxes := findPSSH(data)
	if len(boxes) != 1 {
		t.Fatalf("want 1 Widevine pssh box, got %d", len(boxes))
	}

	// The system ID lives at offset 12: size(4) type(4) version+flags(4).
	got := hex.EncodeToString(boxes[0][12:28])
	want := "edef8ba979d64acea3c827dcd51d21ed"
	if got != want {
		t.Fatalf("system ID at offset 12 = %s, want %s", got, want)
	}

	// Reading at offset 8 is the bug this test exists to prevent: it
	// picks up the last 4 bytes of version+flags.
	if wrong := hex.EncodeToString(boxes[0][8:24]); wrong != got {
		t.Logf("offset 8 yields %s (would have been misread as the system ID)", wrong)
	}

	if b64 := base64.StdEncoding.EncodeToString(boxes[0]); b64 != realPSSHB64 {
		t.Fatalf("round trip changed the box: %s", b64)
	}
}

func TestFindPSSHBoxAtEndOfFile(t *testing.T) {
	// A box ending exactly at the last byte must still be found.
	data := buildPSSH(t)
	boxes := findPSSH(data)
	if len(boxes) != 1 {
		t.Fatalf("box at end of file not found (got %d)", len(boxes))
	}
}

func TestFindPSSHIgnoresOtherSystems(t *testing.T) {
	// A pssh box carrying a non-Widevine system ID must be skipped.
	box, _ := base64.StdEncoding.DecodeString(realPSSHB64)
	other := make([]byte, len(box))
	copy(other, box)
	copy(other[12:28], []byte("00000000000000000000000000000000\x00"))

	if boxes := findPSSH(other); len(boxes) != 0 {
		t.Fatalf("non-Widevine system was accepted (%d boxes)", len(boxes))
	}
}

func TestFindPSSHRejectsTruncatedBox(t *testing.T) {
	box, _ := base64.StdEncoding.DecodeString(realPSSHB64)
	if boxes := findPSSH(box[:30]); len(boxes) != 0 {
		t.Fatalf("truncated box accepted (%d)", len(boxes))
	}
}

func TestFindPSSHRealFile(t *testing.T) {
	const ref = "/home/agentuser/cdm-keep/SERVER_ENC.mp4"
	data, err := os.ReadFile(ref)
	if err != nil {
		t.Skip("reference asset not present")
	}
	boxes := findPSSH(data)
	if len(boxes) == 0 {
		t.Fatal("no pssh found in the real server-encrypted file")
	}
	if b64 := base64.StdEncoding.EncodeToString(boxes[0]); b64 != realPSSHB64 {
		t.Fatalf("real file pssh = %s, want %s", b64, realPSSHB64)
	}
}
