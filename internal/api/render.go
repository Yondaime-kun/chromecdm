package api

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"chromecdm/internal/cdm"
)

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// keysToJSON renders keys with hex and base64 forms.
func keysToJSON(keys []cdm.Key) []map[string]string {
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		m := map[string]string{
			"type": k.Type,
			"kid":  k.ID,
			"key":  k.Key,
		}
		if k.IV != "" {
			m["iv"] = k.IV
		}
		// base64 mirrors for piping into other tools
		if raw, err := hex.DecodeString(k.ID); err == nil {
			m["kid_b64"] = base64.StdEncoding.EncodeToString(raw)
		}
		if raw, err := hex.DecodeString(k.Key); err == nil {
			m["key_b64"] = base64.StdEncoding.EncodeToString(raw)
		}
		out = append(out, m)
	}
	return out
}

// keysText renders content keys as "KID:KEY" lines, one per line.
// Signing keys are excluded: they are not content keys.
func keysText(keys []cdm.Key) string {
	var b strings.Builder
	for _, k := range keys {
		if strings.EqualFold(k.Type, "SIGNING") {
			continue
		}
		b.WriteString(k.ID)
		b.WriteByte(':')
		b.WriteString(k.Key)
		b.WriteByte('\n')
	}
	return b.String()
}
