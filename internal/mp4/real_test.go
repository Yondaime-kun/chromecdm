package mp4

import (
	"os"
	"testing"
)

// realEncryptedFile is a real server-encrypted asset, used to check the
// tenc parsing against media these tests did not produce.
const realEncryptedFile = "/home/agentuser/cdm-keep/SERVER_ENC.mp4"

// The KID that file is actually encrypted with.
const realFileKID = "800aacaa522958ae888062b5695db6bf"

// Runs only where the reference asset is present, so CI (which does not
// ship copyrighted media) stays green while a machine that has the file
// still gets the stronger check.
func TestDefaultKIDsRealServerFile(t *testing.T) {
	if _, err := os.Stat(realEncryptedFile); err != nil {
		t.Skip("reference asset not present; skipping the real-file check")
	}

	got := DefaultKIDs(realEncryptedFile)
	if len(got) == 0 {
		t.Fatal("no KID found in the real server-encrypted file")
	}
	if got[0] != realFileKID {
		t.Fatalf("want %s, got %s", realFileKID, got[0])
	}
	t.Logf("real file KID: %s", got[0])
}
