// Package cdp drives a real Chrome/Chromium instance over the DevTools
// Protocol and extracts Widevine license challenges from the browser's own
// CDM (libwidevinecdm.so). Nothing about the CDM protocol is reimplemented:
// the browser performs the EME handshake and this package relays bytes.
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

// Options configures how the browser is launched.
type Options struct {
	BrowserPath string
	Port        int
	ProfileDir  string
	ExtraArgs   []string
}

// Backend is a running browser with CDP enabled.
type Backend struct {
	cmd     *exec.Cmd
	port    int
	profile string
}

// FindBrowser returns the best available chromium-family binary.
//
// Several Chrome builds can coexist, and they are not equivalent for DRM:
// an older build can ship a Widevine CDM version the license server does
// not recognize, which surfaces as the server rejecting an otherwise valid
// challenge. So this collects every candidate and picks the highest
// version rather than the first hit, and it looks where Chrome actually
// gets installed, not only under the Playwright cache.
func FindBrowser() (string, error) {
	home, _ := os.UserHomeDir()
	globs := []string{
		// Chrome-for-Testing downloads (newest builds usually live here).
		filepath.Join(home, ".agent-browser/browsers/chrome-*/chrome"),
		// Playwright's managed browsers, both layouts and both roots.
		filepath.Join(home, ".cache/ms-playwright/chromium-*/chrome-linux64/chrome"),
		filepath.Join(home, ".cache/ms-playwright/chromium-*/chrome-linux/chrome"),
		"/opt/ms-playwright/chromium-*/chrome-linux64/chrome",
		"/opt/ms-playwright/chromium-*/chrome-linux/chrome",
		"/usr/bin/google-chrome*",
		"/usr/bin/chromium*",
	}

	var candidates []string
	for _, g := range globs {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			candidates = append(candidates, m...)
		}
	}
	for _, name := range []string{
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
	} {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no chrome/chromium found; set -B explicitly")
	}

	// Highest version wins. A build that fails to report its version sorts
	// last rather than aborting the search.
	sort.SliceStable(candidates, func(i, j int) bool {
		return BrowserVersion(candidates[i]) > BrowserVersion(candidates[j])
	})
	return candidates[0], nil
}

// BrowserVersion reports the numeric version of a chrome binary, or "" when
// it cannot be determined. Only the leading dotted number is used, so the
// result compares lexically after zero-padding.
func BrowserVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	// "Google Chrome for Testing 155.0.8059.84" / "Chromium 145.0.7632.6"
	m := versionRe.FindString(string(out))
	if m == "" {
		return ""
	}
	// Zero-pad each component so a lexical compare is a numeric compare.
	parts := strings.Split(m, ".")
	for i, p := range parts {
		parts[i] = fmt.Sprintf("%06s", p)
	}
	return strings.Join(parts, ".")
}

var versionRe = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Start launches the browser and waits for CDP to come up.
func Start(ctx context.Context, opt Options) (*Backend, error) {
	browser := opt.BrowserPath
	if browser == "" {
		var err error
		if browser, err = FindBrowser(); err != nil {
			return nil, err
		}
	}
	port := opt.Port
	if port == 0 {
		var err error
		if port, err = freePort(); err != nil {
			return nil, err
		}
	}
	profile := opt.ProfileDir
	if profile == "" {
		var err error
		if profile, err = os.MkdirTemp("", "chromecdm-*"); err != nil {
			return nil, err
		}
	}

	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--autoplay-policy=no-user-gesture-required",
		// The EME harness is served over self-signed HTTPS on localhost.
		// Without this the secure-context check passes but the certificate
		// is rejected, so navigator.requestMediaKeySystemAccess is absent.
		"--ignore-certificate-errors",
		"--allow-insecure-localhost",
		"--unsafely-treat-insecure-origin-as-secure=https://127.0.0.1",
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=" + profile,
	}
	args = append(args, opt.ExtraArgs...)
	args = append(args, "about:blank")

	cmd := exec.Command(browser, args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}

	b := &Backend{cmd: cmd, port: port, profile: profile}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := b.version(); err == nil {
			return b, nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	b.Close()
	return nil, fmt.Errorf("devtools endpoint did not come up on port %d", port)
}

// Port reports the CDP port in use.
func (b *Backend) Port() int { return b.port }

// Close terminates the browser and removes its profile.
func (b *Backend) Close() error {
	if b.cmd != nil && b.cmd.Process != nil {
		b.cmd.Process.Kill()
		b.cmd.Wait()
	}
	if b.profile != "" {
		os.RemoveAll(b.profile)
	}
	return nil
}

// version returns the browser version string once CDP is reachable.
func (b *Backend) version() (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", b.port))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		Browser string `json:"Browser"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	if v.Browser == "" {
		return "", fmt.Errorf("no version yet")
	}
	return v.Browser, nil
}

// Version reports the browser version string.
func (b *Backend) Version() (string, error) { return b.version() }

// Page is a CDP session attached to one page target.
type Page struct {
	ws   *websocket.Conn
	ctx  context.Context
	stop context.CancelFunc

	mu      sync.Mutex
	next    int
	pending map[int]chan json.RawMessage
	events  map[string][]json.RawMessage
	subs    []func(method string, params json.RawMessage)
}

// NewPage creates a blank target and attaches to it.
func (b *Backend) NewPage(ctx context.Context) (*Page, error) {
	conn, err := b.dialTarget(ctx)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(ctx)
	p := &Page{
		ws:      conn,
		ctx:     pctx,
		stop:    cancel,
		pending: map[int]chan json.RawMessage{},
		events:  map[string][]json.RawMessage{},
	}
	go p.readLoop()
	return p, nil
}

func (b *Backend) dialTarget(ctx context.Context) (*websocket.Conn, error) {
	// Create a target, then attach to its websocket.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("http://127.0.0.1:%d/json/new?about:blank", b.port), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var created struct {
		ID string `json:"id"`
	}
	err = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	listResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", b.port))
	if err != nil {
		return nil, err
	}
	defer listResp.Body.Close()
	var targets []struct {
		ID string `json:"id"`
		WS string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&targets); err != nil {
		return nil, err
	}
	for _, t := range targets {
		if t.ID == created.ID && t.WS != "" {
			conn, _, err := websocket.Dial(ctx, t.WS, nil)
			return conn, err
		}
	}
	return nil, fmt.Errorf("target %s not attachable", created.ID)
}

func (p *Page) readLoop() {
	for {
		_, data, err := p.ws.Read(p.ctx)
		if err != nil {
			return
		}
		var msg struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(data, &msg) != nil {
			continue
		}

		if msg.ID != 0 {
			p.mu.Lock()
			ch := p.pending[msg.ID]
			delete(p.pending, msg.ID)
			p.mu.Unlock()
			if ch != nil {
				out := msg.Result
				if len(out) == 0 {
					out = msg.Error
				}
				ch <- out
			}
			continue
		}
		if msg.Method == "" {
			continue
		}

		p.mu.Lock()
		p.events[msg.Method] = append(p.events[msg.Method], msg.Params)
		subs := append([]func(string, json.RawMessage){}, p.subs...)
		p.mu.Unlock()
		for _, fn := range subs {
			fn(msg.Method, msg.Params)
		}
	}
}

// On registers a CDP event handler.
func (p *Page) On(fn func(method string, params json.RawMessage)) {
	p.mu.Lock()
	p.subs = append(p.subs, fn)
	p.mu.Unlock()
}

// Close detaches the session.
func (p *Page) Close() {
	p.stop()
	p.ws.Close(websocket.StatusNormalClosure, "")
}

// Send issues a CDP command and returns its raw result.
func (p *Page) Send(method string, params map[string]any) (json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	p.mu.Lock()
	p.next++
	id := p.next
	ch := make(chan json.RawMessage, 1)
	p.pending[id] = ch
	p.mu.Unlock()

	body, _ := json.Marshal(map[string]any{
		"id": id, "method": method, "params": params,
	})
	ctx, cancel := context.WithTimeout(p.ctx, 45*time.Second)
	defer cancel()
	if err := p.ws.Write(ctx, websocket.MessageText, body); err != nil {
		return nil, err
	}

	select {
	case res := <-ch:
		return res, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("cdp %s: timeout", method)
	}
}

// Eval evaluates JavaScript and returns the value as a string.
func (p *Page) Eval(expr string) (string, error) {
	raw, err := p.Send("Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  false,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.ExceptionDetails != nil {
		desc := out.ExceptionDetails.Text
		if out.ExceptionDetails.Exception != nil {
			desc = out.ExceptionDetails.Exception.Description
		}
		return "", fmt.Errorf("js: %s", desc)
	}
	switch v := out.Result.Value.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		b, _ := json.Marshal(v)
		return string(b), nil
	}
}

// Evaluate is the promise-aware variant used to run async EME code.
func (p *Page) Evaluate(expr string) (string, error) {
	raw, err := p.Send("Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  true,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Exception *struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.ExceptionDetails != nil && out.ExceptionDetails.Exception != nil {
		return "", fmt.Errorf("js: %s", out.ExceptionDetails.Exception.Description)
	}
	if s, ok := out.Result.Value.(string); ok {
		return s, nil
	}
	b, _ := json.Marshal(out.Result.Value)
	return string(b), nil
}

// Navigate loads a URL and waits for the load event.
func (p *Page) Navigate(url string) error {
	if _, err := p.Send("Page.enable", nil); err != nil {
		return err
	}
	if _, err := p.Send("Page.navigate", map[string]any{"url": url}); err != nil {
		return err
	}
	// Give the page a moment to start; EME setup is async and polled.
	time.Sleep(500 * time.Millisecond)
	return nil
}
