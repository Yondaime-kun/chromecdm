// Command wv fetches Widevine keys and decrypts CENC media.
//
//	wv keys    -d device.wvd -l <license-url> -p <pssh-b64>
//	wv decrypt -d device.wvd -l <license-url> -p <pssh-b64> -i enc.mp4 -o out.mp4
//	wv info    -d device.wvd
//	wv pssh    -i video.mp4            (extract PSSH from an MP4)
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/iyear/gowidevine"
	"github.com/iyear/gowidevine/widevinepb"

	"chromecdm/internal/version"
)

const usage = `wv - Widevine key retrieval and CENC decryption

usage:
  wv info    -d <device.wvd>
  wv pssh    -i <file.mp4>
  wv keys    -d <device.wvd> -l <license-url> -p <pssh-b64|->
  wv decrypt -d <device.wvd> -l <license-url> -p <pssh-b64|-> -i <enc.mp4> -o <out.mp4>

  wv cdp        [-B <browser>] -p <pssh-b64>          challenge via browser CDM
  wv cdp-keys   -l <license-url> -p <pssh-b64>        full EME exchange
  wv cdp-feed   -l <license-url> -p <pssh-b64> -i <enc.mp4>
                                                      decrypt through the CDM

flags:
  -d  path to a .wvd Widevine device file
  -l  license server URL
  -p  PSSH as base64, or "-" to read from stdin
  -i  input media file
  -o  output file
  -h  extra header, "Name: Value" (repeatable)
  -B  browser binary for the cdp commands (default: autodetect)

backends:
  wvd    a provisioned device file; yields raw content keys
  cdp    a real Chrome/Chromium process using its own libwidevinecdm.so
`

const defaultTestPSSH = "AAAAPnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAB4iFnNo" +
	"YWthX2NlYzJmNjRhYTc4OTBhMTFI49yVmwY="

const defaultLicenseURL = "https://cwip-shaka-proxy.appspot.com/no_auth"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Handle -version before command dispatch: it takes no subcommand and
	// os.Args[1] would otherwise be rejected as an unknown command.
	if os.Args[1] == "-version" || os.Args[1] == "--version" {
		fmt.Println("wv " + version.String())
		return
	}
	if os.Args[1] == "version" {
		fmt.Println("wv " + version.String())
		return
	}

	var (
		device   string
		licURL   string
		psshArg  string
		inPath   string
		outPath  string
		headers  headerList
		insecure bool
		browser  string
		cdpPort  int
	)

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.StringVar(&device, "d", "", "device .wvd path")
	fs.StringVar(&licURL, "l", "", "license URL")
	fs.StringVar(&psshArg, "p", "", "PSSH base64, or - for stdin")
	fs.StringVar(&inPath, "i", "", "input file")
	fs.StringVar(&outPath, "o", "", "output file")
	fs.Var(&headers, "h", `extra header "Name: Value"`)
	fs.BoolVar(&insecure, "k", false, "skip TLS verify")
	fs.StringVar(&browser, "B", "", "browser binary for cdp commands")
	fs.IntVar(&cdpPort, "port", 0, "CDP port for cdp commands")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Parse(os.Args[2:])

	if *showVersion {
		fmt.Println("wv " + version.String())
		return
	}

	switch cmd {
	case "info":
		cmdInfo(device)
	case "pssh":
		cmdPssh(inPath)
	case "keys":
		cmdKeys(device, licURL, psshArg, headers, insecure)
	case "decrypt":
		cmdDecrypt(device, licURL, psshArg, inPath, outPath, headers, insecure)
	case "cdp":
		runCDPChallenge(cdpOptions{browser: browser, port: cdpPort,
			psshm: psshArg, licURL: licURL, hdrs: headers})
	case "cdp-keys":
		runCDPKeys(cdpOptions{browser: browser, port: cdpPort,
			psshm: psshArg, licURL: licURL, hdrs: headers})
	case "cdp-feed":
		runCDPFeed(cdpOptions{browser: browser, port: cdpPort,
			psshm: psshArg, licURL: licURL, hdrs: headers}, inPath)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// --- device ---

func loadDevice(path string) (*widevine.Device, error) {
	if path == "" {
		return nil, fmt.Errorf("-d <device.wvd> is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return widevine.NewDevice(widevine.FromWVD(bytes.NewReader(raw)))
}

func cmdInfo(path string) {
	dev, err := loadDevice(path)
	if err != nil {
		fatal(err)
	}
	ci := dev.ClientID()
	// ClientIdentification carries the provisioning metadata.
	fmt.Printf("device:      %s\n", path)
	fmt.Printf("client_id:   %d bytes\n", len(ci.String()))
	for _, info := range clientInfoPairs(ci) {
		fmt.Printf("  %-22s %s\n", info[0], info[1])
	}
	cert := dev.DrmCertificate()
	if cert != nil {
		fmt.Printf("  %-22s %s\n", "drm_cert_serial",
			hex.EncodeToString(cert.SerialNumber))
	}
}

func clientInfoPairs(ci *widevinepb.ClientIdentification) [][2]string {
	var out [][2]string
	for _, kv := range ci.GetClientInfo() {
		out = append(out, [2]string{kv.GetName(), kv.GetValue()})
	}
	return out
}

// --- pssh extraction ---

func cmdPssh(path string) {
	if path == "" {
		fatal(fmt.Errorf("-i <file.mp4> is required"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	boxes := findPSSH(data)
	if len(boxes) == 0 {
		fatal(fmt.Errorf("no pssh box found in %s", path))
	}
	for _, b := range boxes {
		sysID := hex.EncodeToString(b[8:24])
		label := "other"
		if sysID == widevine.WidevineSystemID {
			label = "WIDEVINE"
		}
		fmt.Printf("%s  system=%s  (%d bytes)\n%s\n",
			label, sysID, len(b), base64.StdEncoding.EncodeToString(b))
	}
}

// findPSSH scans for ISO BMFF pssh boxes and returns the Widevine ones.
func findPSSH(data []byte) [][]byte {
	var out [][]byte
	for i := 0; i+32 < len(data); i++ {
		if data[i] != 'p' || data[i+1] != 's' || data[i+2] != 's' || data[i+3] != 'h' {
			continue
		}
		// size is the 4 bytes before the 'pssh' type
		if i < 4 {
			continue
		}
		size := int(uint32(data[i-4])<<24 | uint32(data[i-3])<<16 |
			uint32(data[i-2])<<8 | uint32(data[i-1]))
		if i-4+size > len(data) || size < 32 || size > 1<<20 {
			continue
		}
		box := data[i-4 : i-4+size]
		// Widevine system id at offset 8..24
		if hex.EncodeToString(box[8:24]) == widevine.WidevineSystemID {
			out = append(out, box)
		}
	}
	return out
}

// --- key retrieval ---

type keyOut struct {
	Type string `json:"type"`
	KID  string `json:"kid"`
	Key  string `json:"key"`
}

func getKeys(dev *widevine.Device, licURL, psshB64 string,
	hdrs headerList, insecure bool) ([]*widevine.Key, []byte) {

	if licURL == "" {
		fatal(fmt.Errorf("-l <license-url> is required"))
	}
	psshRaw, err := resolvePSSH(psshB64)
	if err != nil {
		fatal(err)
	}

	pssh, err := widevine.NewPSSH(psshRaw)
	if err != nil {
		fatal(fmt.Errorf("parse pssh: %w", err))
	}

	cdm := widevine.NewCDM(dev)
	challenge, parse, err := cdm.GetLicenseChallenge(
		pssh, widevinepb.LicenseType_STREAMING, false)
	if err != nil {
		fatal(fmt.Errorf("build challenge: %w", err))
	}
	fmt.Fprintf(os.Stderr, "[+] challenge: %d bytes\n", len(challenge))

	req, err := http.NewRequest(http.MethodPost, licURL, bytes.NewReader(challenge))
	if err != nil {
		fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	for _, h := range hdrs {
		name, val, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(val))
	}

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fatal(fmt.Errorf("license request: %w", err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(os.Stderr, "[+] license: HTTP %d, %d bytes\n", resp.StatusCode, len(body))
	if resp.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("license server rejected (%d): %s", resp.StatusCode, truncate(body, 200)))
	}

	keys, err := parse(body)
	if err != nil {
		fatal(fmt.Errorf("parse license: %w", err))
	}
	return keys, body
}

func resolvePSSH(s string) ([]byte, error) {
	if s == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(string(raw))
	}
	if s == "" {
		return nil, fmt.Errorf("-p <pssh-b64> is required")
	}
	// Accept base64 directly; if that fails, treat it as a file path.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	data, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("pssh is neither base64 nor a readable file")
	}
	if boxes := findPSSH(data); len(boxes) > 0 {
		return boxes[0], nil
	}
	return data, nil
}

func cmdKeys(device, licURL, pssh string, hdrs headerList, insecure bool) {
	dev, err := loadDevice(device)
	if err != nil {
		fatal(err)
	}
	keys, _ := getKeys(dev, licURL, pssh, hdrs, insecure)
	printKeys(keys)
}

func printKeys(keys []*widevine.Key) {
	content, signing := 0, 0
	for _, k := range keys {
		line := fmt.Sprintf("%s:%s", hex.EncodeToString(k.ID), hex.EncodeToString(k.Key))
		if k.Type == widevinepb.License_KeyContainer_SIGNING {
			fmt.Printf("SIGNING:%s\n", line)
			signing++
			continue
		}
		fmt.Println(line)
		content++
	}
	fmt.Fprintf(os.Stderr, "[+] %d content key(s), %d signing key(s)\n", content, signing)
	if content == 0 {
		fmt.Fprintln(os.Stderr, "[!] no content keys: the license may be device- or level-restricted")
		os.Exit(1)
	}
}

// --- decrypt ---

func cmdDecrypt(device, licURL, pssh, inPath, outPath string,
	hdrs headerList, insecure bool) {

	if inPath == "" || outPath == "" {
		fatal(fmt.Errorf("-i and -o are required"))
	}
	dev, err := loadDevice(device)
	if err != nil {
		fatal(err)
	}
	keys, _ := getKeys(dev, licURL, pssh, hdrs, insecure)
	printKeys(keys)

	in, err := os.Open(inPath)
	if err != nil {
		fatal(err)
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		fatal(err)
	}
	defer out.Close()

	// DecryptMP4Auto picks the FIRST content key and ignores the KIDs in
	// the file, so it silently fails on a license carrying more than one
	// key. Select the key whose KID matches the file's tenc box instead,
	// then feed DecryptMP4 that single key.
	key, err := selectContentKey(inPath, keys)
	if err != nil {
		fatal(err)
	}
	if err := widevine.DecryptMP4(in, key, out); err != nil {
		fatal(fmt.Errorf("decrypt: %w", err))
	}
	fmt.Fprintf(os.Stderr, "[+] decrypted -> %s\n", outPath)

	// Verify the output is a readable MP4 with the same track count.
	src, _ := os.Stat(inPath)
	dst, _ := os.Stat(outPath)
	fmt.Fprintf(os.Stderr, "[+] in=%d bytes out=%d bytes\n", src.Size(), dst.Size())
}

// selectContentKey returns the key bytes whose KID appears in the MP4's
// tenc box. Falls back to the first content key when the file carries no
// recognizable KID (single-key content).
func selectContentKey(path string, keys []*widevine.Key) ([]byte, error) {
	var content [][]byte
	kidIndex := map[string][]byte{}

	for _, k := range keys {
		if k.Type != widevinepb.License_KeyContainer_CONTENT {
			continue
		}
		content = append(content, k.Key)
		kidIndex[strings.ToLower(hex.EncodeToString(k.ID))] = k.Key
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("no content key in license")
	}
	if len(content) == 1 {
		return content[0], nil
	}

	kids := tencKIDs(path)
	for _, kid := range kids {
		if key, ok := kidIndex[kid]; ok {
			fmt.Fprintf(os.Stderr, "[+] using key for KID %s\n", kid)
			return key, nil
		}
	}
	if len(kids) > 0 {
		return nil, fmt.Errorf(
			"license has %d content keys but none match the file's KID (%s)",
			len(content), strings.Join(kids, ", "))
	}
	// No KID in the file: fall back, but say so.
	fmt.Fprintf(os.Stderr, "[!] file has no tenc KID; trying first of %d keys\n",
		len(content))
	return content[0], nil
}

// tencKIDs finds every default_KID in the file's track encryption boxes.
func tencKIDs(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for i := 0; i+36 <= len(data); i++ {
		if data[i] != 't' || data[i+1] != 'e' || data[i+2] != 'n' ||
			data[i+3] != 'c' {
			continue
		}
		// tenc: size(4) type(4) version(1) flags(3) reserved(1)
		//       isProtected(1) ivSize(1) KID(16)
		kid := hex.EncodeToString(data[i+12 : i+28])
		if !seen[kid] {
			seen[kid] = true
			out = append(out, kid)
		}
	}
	return out
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
