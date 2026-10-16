// Package cdm wraps a real Widevine CDM device.
//
// A device is a provisioned .wvd file (client id + RSA private key).
// The CDM protocol is implemented in pure Go, so no libwidevinecdm.so,
// no Chrome host-verification .sig files, and no cgo are involved.
package cdm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"github.com/iyear/gowidevine"
	"github.com/iyear/gowidevine/widevinepb"
)

// Key is one content key returned by a license.
type Key struct {
	Type string
	ID   string // hex KID
	Key  string // hex AES key
	IV   string // hex, may be empty
}

// Device holds a loaded Widevine device plus its derived metadata.
type Device struct {
	path string

	raw []byte

	mu        sync.Mutex
	instances int
}

// Load reads and validates a .wvd device file.
func Load(path string) (*Device, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read device: %w", err)
	}
	// Validate by decoding once up front; a revoked/corrupt device fails here.
	if _, err := widevine.NewDevice(widevine.FromWVD(bytes.NewReader(raw))); err != nil {
		return nil, fmt.Errorf("invalid device %s: %w", path, err)
	}
	return &Device{path: path, raw: raw}, nil
}

// Path is the device file this instance was loaded from.
func (d *Device) Path() string { return d.path }

// newCDM builds a fresh CDM bound to this device.
func (d *Device) newCDM() (*widevine.CDM, error) {
	dev, err := widevine.NewDevice(widevine.FromWVD(bytes.NewReader(d.raw)))
	if err != nil {
		return nil, fmt.Errorf("device: %w", err)
	}
	d.mu.Lock()
	d.instances++
	d.mu.Unlock()
	return widevine.NewCDM(dev), nil
}

// Session is one CDM session: challenge out, license in, keys out.
type Session struct {
	Device *Device

	Challenge []byte

	cdn   *widevine.CDM
	parse func([]byte) ([]*widevine.Key, error)
	PSSH  string
}

// OpenSession generates a license challenge for the given PSSH (raw bytes).
func (d *Device) OpenSession(psshRaw []byte) (*Session, error) {
	cdn, err := d.newCDM()
	if err != nil {
		return nil, err
	}
	pssh, err := widevine.NewPSSH(psshRaw)
	if err != nil {
		return nil, fmt.Errorf("pssh: %w", err)
	}
	challenge, parse, err := cdn.GetLicenseChallenge(
		pssh, widevinepb.LicenseType_STREAMING, false)
	if err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	return &Session{
		Device:    d,
		cdn:       cdn,
		parse:     parse,
		Challenge: challenge,
	}, nil
}

// ParseLicense turns a license response into keys.
func (s *Session) ParseLicense(license []byte) ([]Key, error) {
	raw, err := s.parse(license)
	if err != nil {
		return nil, fmt.Errorf("parse license: %w", err)
	}
	keys := make([]Key, 0, len(raw))
	for _, k := range raw {
		keys = append(keys, Key{
			Type: k.Type.String(),
			ID:   hex.EncodeToString(k.ID),
			Key:  hex.EncodeToString(k.Key),
			IV:   hex.EncodeToString(k.IV),
		})
	}
	return keys, nil
}
