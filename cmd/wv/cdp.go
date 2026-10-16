package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"chromecdm/internal/cdp"
)

// cdpOptions collects the flags shared by the browser-backed commands.
type cdpOptions struct {
	browser string
	port    int
	psshm   string
	licURL  string
	hdrs    headerList
}

func (o cdpOptions) licenseURL() string {
	if o.licURL != "" {
		return o.licURL
	}
	return defaultLicenseURL
}

func (o cdpOptions) pssh() string {
	if o.psshm != "" {
		return o.psshm
	}
	return defaultTestPSSH
}

func (o cdpOptions) headerMap() map[string]string {
	m := map[string]string{}
	for _, h := range o.hdrs {
		name, val, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		m[strings.TrimSpace(name)] = strings.TrimSpace(val)
	}
	return m
}

func (o cdpOptions) opts() cdp.Options {
	return cdp.Options{BrowserPath: o.browser, Port: o.port}
}

// postLicense relays a challenge to a license server and returns the raw
// license bytes.
func postLicense(url string, challenge []byte, hdrs headerList) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(challenge))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	for _, h := range hdrs {
		name, val, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(val))
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("license request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license server rejected (%d): %s",
			resp.StatusCode, truncate(body, 200))
	}
	return body, nil
}

// runCDPChallenge drives the browser's own CDM and prints the challenge.
func runCDPChallenge(o cdpOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, page, err := cdp.NewSession(ctx, o.opts())
	if err != nil {
		fatal(err)
	}
	defer sess.Close()

	if v, err := sess.Backend().Version(); err == nil {
		fmt.Fprintf(os.Stderr, "[+] browser: %s\n", v)
	}

	challenge, err := page.Challenge(o.pssh())
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[+] challenge from browser CDM: %d bytes\n", len(challenge))
	fmt.Println(base64.StdEncoding.EncodeToString(challenge))

	if log, err := page.Log(); err == nil {
		for _, l := range log {
			fmt.Fprintf(os.Stderr, "    %s\n", l)
		}
	}
}

// runCDPKeys runs the EME handshake and the license exchange without
// feeding media, so the CDM has nothing to decrypt and reports no keys.
func runCDPKeys(o cdpOptions) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sess, page, err := cdp.NewSession(ctx, o.opts())
	if err != nil {
		fatal(err)
	}
	defer sess.Close()
	sess.SetLicense(o.licURL, o.headerMap())

	if v, err := sess.Backend().Version(); err == nil {
		fmt.Fprintf(os.Stderr, "[+] browser: %s\n", v)
	}

	challenge, err := page.Challenge(o.pssh())
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[+] challenge: %d bytes (browser CDM)\n", len(challenge))

	license, err := postLicense(o.licenseURL(), challenge, o.hdrs)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[+] license: %d bytes\n", len(license))

	if err := page.Update(license); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[+] CDM accepted the license\n")
	fmt.Fprintln(os.Stderr,
		"[!] no key status without media: use 'wv cdp-feed' to feed an "+
			"encrypted stream and watch the CDM decrypt it")
}

// runCDPFeed is the complete flow: the browser CDM builds the challenge,
// the license server answers, and an encrypted stream is fed through MSE
// so the CDM actually decrypts. Key status arrives only on decryption.
func runCDPFeed(o cdpOptions, inPath string) {
	if inPath == "" {
		fatal(fmt.Errorf("-i <encrypted.mp4> is required"))
	}
	media, err := os.ReadFile(inPath)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	sess, page, err := cdp.NewSession(ctx, o.opts())
	if err != nil {
		fatal(err)
	}
	defer sess.Close()
	sess.SetLicense(o.licURL, o.headerMap())

	if v, err := sess.Backend().Version(); err == nil {
		fmt.Fprintf(os.Stderr, "[+] browser: %s\n", v)
	}
	fmt.Fprintf(os.Stderr, "[+] media: %d bytes\n", len(media))

	out, err := page.Decrypt(o.pssh(), media)
	if err != nil {
		fatal(err)
	}
	for _, l := range out.Log {
		fmt.Fprintf(os.Stderr, "    %s\n", l)
	}
	if out.Error != "" {
		fatal(fmt.Errorf("browser CDM: %s", out.Error))
	}

	keys := out.Keys
	if len(keys) == 0 {
		if k, err := page.WaitForKeys(15 * time.Second); err == nil && len(k) > 0 {
			keys = k
		}
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr,
			"[!] the CDM reported no key status: the license was rejected "+
				"or the media does not match the PSSH")
		os.Exit(1)
	}

	usable := 0
	for kid, status := range keys {
		fmt.Printf("%s:%s\n", kid, status)
		if status == "usable" {
			usable++
		}
	}
	fmt.Fprintf(os.Stderr, "[+] %d key(s), %d usable\n", len(keys), usable)
	fmt.Fprintf(os.Stderr, "[+] playback: %.2fs, readyState %d\n", out.Time, out.Ready)
	if usable == 0 {
		os.Exit(1)
	}
}
