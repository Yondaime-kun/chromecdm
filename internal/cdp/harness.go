package cdp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

const defaultLicenseURL = "https://cwip-shaka-proxy.appspot.com/no_auth"

// harness is a local HTTPS origin. EME requires a secure context, so the
// page the CDM runs on cannot be about:blank or a data: URL. It also
// relays license challenges, because page script cannot POST cross-origin
// to a license server without CORS.
type harness struct {
	srv  *http.Server
	url  string
	stop func()

	mu      sync.RWMutex
	licURL  string
	headers map[string]string
}

const harnessBody = `<!doctype html><html><body></body></html>`

func newHarness() (*harness, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cert, err := selfSigned()
	if err != nil {
		ln.Close()
		return nil, err
	}

	h := &harness{licURL: defaultLicenseURL, headers: map[string]string{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(harnessBody))
	})
	mux.HandleFunc("/license", h.handleLicense)

	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go srv.ServeTLS(ln, "", "")

	h.srv = srv
	h.url = "https://" + ln.Addr().String() + "/"
	h.stop = func() { srv.Close() }
	return h, nil
}

// setLicense configures where challenges are relayed, plus extra headers.
func (h *harness) setLicense(url string, headers map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if url != "" {
		h.licURL = url
	}
	h.headers = headers
}

func (h *harness) handleLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Challenge string `json:"challenge"`
		URL       string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	challenge, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad challenge"})
		return
	}

	h.mu.RLock()
	url := h.licURL
	if req.URL != "" {
		url = req.URL
	}
	hdrs := make(map[string]string, len(h.headers))
	for k, v := range h.headers {
		hdrs[k] = v
	}
	h.mu.RUnlock()

	licReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(challenge))
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	licReq.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range hdrs {
		licReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(licReq)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		writeJSON(w, 502, map[string]string{
			"error":  "license server rejected",
			"status": resp.Status,
			"body":   string(body[:min(len(body), 200)]),
		})
		return
	}
	writeJSON(w, 200, map[string]string{
		"license": base64.StdEncoding.EncodeToString(body),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func jsonUnmarshal(s string, v any) error {
	if s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), v)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
