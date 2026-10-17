package api

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"chromecdm/internal/cdm"
)

// The real KID/key pair from a server-issued license, so the encoding
// assertions are anchored to something real.
const (
	realKID = "800aacaa522958ae888062b5695db6bf"
	realKey = "775dbf7289c4cc5847becd571f536ff2"
)

func sampleKeys() []cdm.Key {
	return []cdm.Key{
		{ // signing key: no KID, must not be rendered
			Type: "SIGNING",
			Key:  "18db447c4a1e618c1ee02eaa609d7cf7cb3b308f582d2fca44e1c3fc254f53710146d8a908b65f6b1224c1641dcb561fc6854ad65ea457422af8717b13993174",
			IV:   "2b8df14abdb3eb338fb446c6750f46d5",
		},
		{
			Type: "CONTENT",
			ID:   realKID,
			Key:  realKey,
			IV:   "1cbe2e9a56c552647dfd98a7b4e9abe0",
		},
		{
			Type: "CONTENT",
			ID:   "d21373c0b8ab5ba9954742bcdfb5f48b",
			Key:  "150a6c7d7dee6a91b74dccfce5b31928",
		},
	}
}

func TestKeysToJSONDropsSigningKeys(t *testing.T) {
	out := keysToJSON(sampleKeys())
	if len(out) != 2 {
		t.Fatalf("want 2 content keys, got %d", len(out))
	}
	for _, m := range out {
		if m["type"] == "SIGNING" {
			t.Fatal("signing key leaked into JSON")
		}
		if m["kid"] == "" {
			t.Fatalf("content key rendered with empty kid: %+v", m)
		}
		if m["key"] == "" {
			t.Fatalf("content key rendered with empty key: %+v", m)
		}
	}
}

// The headline guarantee: the response carries the key, not just the KID.
func TestKeysToJSONCarriesKeyMaterial(t *testing.T) {
	out := keysToJSON(sampleKeys())

	var found map[string]string
	for _, m := range out {
		if m["kid"] == realKID {
			found = m
			break
		}
	}
	if found == nil {
		t.Fatal("the real KID is missing from the response")
	}
	if found["key"] != realKey {
		t.Fatalf("key = %q, want %q", found["key"], realKey)
	}

	// Hex and base64 must decode to the same bytes.
	rawHex, err := hex.DecodeString(found["key"])
	if err != nil {
		t.Fatalf("key is not valid hex: %v", err)
	}
	rawB64, err := base64.StdEncoding.DecodeString(found["key_b64"])
	if err != nil {
		t.Fatalf("key_b64 is not valid base64: %v", err)
	}
	if string(rawHex) != string(rawB64) {
		t.Fatal("hex and base64 forms disagree")
	}
	if len(rawHex) != 16 {
		t.Fatalf("AES-128 key should be 16 bytes, got %d", len(rawHex))
	}
}

func TestContentKeyCountMatchesRendered(t *testing.T) {
	keys := sampleKeys()
	if got, want := contentKeyCount(keys), len(keysToJSON(keys)); got != want {
		t.Fatalf("key_count = %d but %d keys rendered", got, want)
	}
	if got := contentKeyCount(keys); got != 2 {
		t.Fatalf("contentKeyCount = %d, want 2", got)
	}
}

func TestKeysTextIsPipeable(t *testing.T) {
	txt := keysText(sampleKeys())
	lines := strings.Split(strings.TrimSpace(txt), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), txt)
	}
	for _, l := range lines {
		parts := strings.Split(l, ":")
		if len(parts) != 2 {
			t.Fatalf("line %q is not KID:KEY", l)
		}
		if len(parts[0]) != 32 || len(parts[1]) != 32 {
			t.Fatalf("line %q does not have 32-hex KID and key", l)
		}
	}
	if strings.Contains(txt, "SIGNING") {
		t.Fatal("signing key leaked into text output")
	}
	if !strings.Contains(txt, realKID+":"+realKey) {
		t.Fatal("expected KID:KEY pair missing from text output")
	}
}
