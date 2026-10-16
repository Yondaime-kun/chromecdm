// Package mp4 provides the minimal MP4 box reading the CLI needs: finding a
// track encryption box's default_KID so a multi-key license can be matched
// to the key the file was actually encrypted with.
package mp4

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// DefaultKIDs returns every default_KID found in the file's `tenc` boxes,
// lowercased hex and de-duplicated, in file order.
//
// A DASH/CENC file may carry one tenc box per track; we return them all
// rather than guessing which track matters. An empty result means the file
// carries no tenc box (unencrypted, or encryption described elsewhere).
func DefaultKIDs(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return defaultKIDs(data)
}

// defaultKIDs is the pure form, so it can be tested without a file.
func defaultKIDs(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; i+28 <= len(data); i++ {
		if data[i] != 't' || data[i+1] != 'e' || data[i+2] != 'n' || data[i+3] != 'c' {
			continue
		}
		// `tenc` box layout, after the 4-byte box type:
		//   version(1) flags(3)  reserved(1)  is_protected(1)  IV_size(1)  default_KID(16)
		// So the default_KID starts 12 bytes after the 't' of "tenc".
		kid := data[i+12 : i+28]
		h := strings.ToLower(hex.EncodeToString(kid))
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// SelectContentKey returns the content key whose KID matches a default_KID
// in the file at path.
//
// This exists because picking the first content key in a license is wrong
// for multi-key licenses: the file is encrypted with exactly one of them,
// and using the wrong one yields garbage output with no error. The file's
// tenc default_KID is the authority.
//
// keys maps lowercased-hex KID -> key bytes. When the file carries no tenc
// box, or only one content key is offered, the fallback is returned and
// the caller is told which case applied.
func SelectContentKey(path string, contentKeys [][]byte, kidIndex map[string][]byte) (key []byte, matchedKID string, err error) {
	if len(contentKeys) == 0 {
		return nil, "", fmt.Errorf("no content key in license")
	}
	if len(contentKeys) == 1 {
		return contentKeys[0], "", nil
	}

	for _, kid := range DefaultKIDs(path) {
		if k, ok := kidIndex[kid]; ok {
			return k, kid, nil
		}
	}

	if kids := DefaultKIDs(path); len(kids) > 0 {
		return nil, "", fmt.Errorf(
			"license has %d content keys but none match the file's KID (%s)",
			len(contentKeys), strings.Join(kids, ", "))
	}
	// No tenc KID in the file: fall back to the first key, and the caller
	// reports that it did.
	return contentKeys[0], "", nil
}
