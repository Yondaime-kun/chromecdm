package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"chromecdm/internal/cdm"
	"chromecdm/internal/cdp"
)

// pairedKey is one KID with whatever each backend could say about it.
type pairedKey struct {
	KID    string
	Key    string // hex, empty when only the browser could speak
	Status string // browser-reported status, empty when not consulted
}

// runPairedKeys resolves the full KID:KEY set by combining both backends:
//
//   - the browser CDM proves which KIDs are live, because key status only
//     appears once the CDM actually decrypts;
//   - the .wvd device yields the raw key bytes, which a browser CDM never
//     exposes to page script.
//
// Neither path alone gives both. Joined on KID, they do.
func runPairedKeys(o cdpOptions, inPath, devicePath string) {
	if inPath == "" {
		fatal(fmt.Errorf("-i <encrypted.mp4> is required"))
	}
	if devicePath == "" {
		fatal(fmt.Errorf("-d <device.wvd> is required"))
	}
	if o.licenseURL() == "" {
		fatal(fmt.Errorf("-l <license-url> is required"))
	}

	// --- browser side: KID + status, proven by decryption ---
	fmt.Fprintln(os.Stderr, "[1/2] browser CDM (KID + status)")
	status := browserKeyStatus(o, inPath)
	if len(status) == 0 {
		fmt.Fprintln(os.Stderr, "      no key status: the CDM did not decrypt, nothing confirmed")
	} else {
		fmt.Fprintf(os.Stderr, "      %d KID(s) confirmed: the CDM decrypted with them\n", len(status))
	}

	// --- device side: raw key bytes ---
	fmt.Fprintln(os.Stderr, "[2/2] .wvd device (key bytes)")
	devKeys := deviceContentKeys(devicePath, o.licenseURL(), o.pssh(), o.hdrs)
	fmt.Fprintf(os.Stderr, "      %d content key(s) from the license\n", len(devKeys))

	// --- join on KID ---
	merged := map[string]*pairedKey{}
	for kid, st := range status {
		merged[kid] = &pairedKey{KID: kid, Status: st}
	}
	for kid, key := range devKeys {
		p, ok := merged[kid]
		if !ok {
			p = &pairedKey{KID: kid}
			merged[kid] = p
		}
		p.Key = key
	}

	kids := make([]string, 0, len(merged))
	for k := range merged {
		kids = append(kids, k)
	}
	sort.Strings(kids)

	both, deviceOnly, browserOnly := 0, 0, 0
	for _, kid := range kids {
		p := merged[kid]
		switch {
		case p.Key != "" && p.Status != "":
			both++
		case p.Key != "":
			deviceOnly++
		default:
			browserOnly++
		}
	}

	// stdout stays machine-readable: KID:KEY, one per line, the format
	// mp4decrypt and similar tools read. KIDs with no key are reported on
	// stderr so the stream stays parseable.
	for _, kid := range kids {
		p := merged[kid]
		if p.Key == "" {
			fmt.Fprintf(os.Stderr, "[!] KID %s: browser reports %q, no device key matched\n",
				p.KID, p.Status)
			continue
		}
		fmt.Printf("%s:%s\n", p.KID, p.Key)
	}

	fmt.Fprintf(os.Stderr,
		"\n[+] %d KID(s): %d with a key and confirmed by the CDM, %d device-only, %d browser-only\n",
		len(kids), both, deviceOnly, browserOnly)
	if browserOnly > 0 {
		fmt.Fprintf(os.Stderr,
			"[!] %d KID(s) have no key here: a browser CDM holds keys but never exposes\n"+
				"    the bytes, and the device's license did not cover them\n", browserOnly)
	}
	if both == 0 && deviceOnly == 0 {
		os.Exit(1)
	}
}

// browserKeyStatus feeds the media to a browser CDM and returns KID->status
// for whatever the CDM reports as present.
func browserKeyStatus(o cdpOptions, inPath string) map[string]string {
	media, err := os.ReadFile(inPath)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	sess, page, err := cdp.NewSession(ctx, o.opts())
	if err != nil {
		fatal(err)
	}
	defer sess.Close()

	out, err := page.Decrypt(o.pssh(), media)
	if err != nil {
		fatal(err)
	}
	if len(out.Keys) > 0 {
		return out.Keys
	}
	if k, err := page.WaitForKeys(20 * time.Second); err == nil {
		return k
	}
	return nil
}

// deviceContentKeys opens a session on the .wvd device and returns
// KID->key for the content keys in the license.
func deviceContentKeys(devicePath, licURL, psshB64 string, hdrs headerList) map[string]string {
	dev, err := cdm.Load(devicePath)
	if err != nil {
		fatal(err)
	}
	psshRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(psshB64))
	if err != nil {
		fatal(fmt.Errorf("pssh: %w", err))
	}
	sess, err := dev.OpenSession(psshRaw)
	if err != nil {
		fatal(err)
	}
	license, err := postLicense(licURL, sess.Challenge, hdrs)
	if err != nil {
		fatal(err)
	}
	keys, err := sess.ParseLicense(license)
	if err != nil {
		fatal(err)
	}
	out := map[string]string{}
	for _, k := range keys {
		if strings.EqualFold(k.Type, "SIGNING") || k.ID == "" {
			continue
		}
		out[strings.ToLower(k.ID)] = k.Key
	}
	return out
}
