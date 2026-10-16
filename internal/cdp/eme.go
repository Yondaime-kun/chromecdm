package cdp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// emeScript performs the full EME exchange using the browser's own CDM and
// parks the results on window.__chromecdm for the Go side to read back.
const emeScript = `
(function(){
  if (window.__chromecdm) return "already-running";
  const S = window.__chromecdm = { log: [], challenge: null, license: null,
                                   keys: {}, done: false, error: null };
  (async () => {
    try {
      const cfg = [{
        initDataTypes: ['cenc'],
        videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }],
        distinctiveIdentifier: 'optional',
        persistentState: 'optional',
        sessionTypes: ['temporary'],
      }];
      S.log.push('requestMediaKeySystemAccess');
      const access = await navigator.requestMediaKeySystemAccess('com.widevine.alpha', cfg);
      S.log.push('access:' + access.keySystem);
      const keys = await access.createMediaKeys();
      const session = keys.createSession('temporary');
      S.session = session;
      S.log.push('session-created');

      const b64ToBytes = (b) => Uint8Array.from(atob(b), c => c.charCodeAt(0));
      const bytesToB64 = (b) => btoa(String.fromCharCode.apply(null, new Uint8Array(b)));

      session.addEventListener('message', (e) => {
        if (e.messageType === 'license-request') {
          S.challenge = bytesToB64(new Uint8Array(e.message));
          S.log.push('challenge:' + atob(S.challenge).length);
        } else if (e.messageType === 'license-renewal') {
          S.log.push('renewal');
        }
      });
      session.addEventListener('keystatuschange', (e) => {
        e.keyStatuses.forEach((status, kid) => {
          S.keys[bytesToB64(kid)] = status;
        });
        S.log.push('keystatus:' + JSON.stringify(S.keys));
      });

      S.pssh = window.__cdmPssh || 'AAAAPnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAB4iFnNoYWthX2NlYzJmNjRhYTc4OTBhMTFI49yVmwY=';
      S.log.push('generateRequest');
      await session.generateRequest('cenc', b64ToBytes(S.pssh));
      S.log.push('request-generated');
      S.done = true;
    } catch (err) {
      S.error = (err && err.name ? err.name + ': ' : '') + (err && err.message ? err.message : String(err));
      S.done = true;
    }
  })();
  return "started";
})()
`

// Result is the outcome of one EME exchange.
type Result struct {
	Challenge []byte
	License   []byte
	Keys      map[string]string // KID (hex) -> key status
	Log       []string
	Error     string
}

// Session drives one EME exchange against the browser's CDM.
//
// The caller runs the challenge through a license server and feeds the
// response back with Update; the browser CDM owns all key material.
type Session struct {
	page *Page
	auth *Backend
	h    *harness
}

// NewSession launches a browser, opens a page, and serves it a local
// harness document so the page is a secure context (required for EME).
func NewSession(ctx context.Context, opt Options) (*Session, *Page, error) {
	b, err := Start(ctx, opt)
	if err != nil {
		return nil, nil, err
	}
	page, err := b.NewPage(ctx)
	if err != nil {
		b.Close()
		return nil, nil, err
	}
	srv, err := newHarness()
	if err != nil {
		page.Close()
		b.Close()
		return nil, nil, err
	}
	if err := page.Navigate(srv.url); err != nil {
		srv.stop()
		page.Close()
		b.Close()
		return nil, nil, err
	}
	return &Session{page: page, auth: b, h: srv}, page, nil
}

// SetLicense tells the harness where to relay challenges.
func (s *Session) SetLicense(url string, headers map[string]string) {
	s.h.setLicense(url, headers)
}

// Close shuts down the browser and the harness.
func (s *Session) Close() {
	if s.h != nil {
		s.h.stop()
	}
	if s.auth != nil {
		s.auth.Close()
	}
}

// Backend exposes the underlying browser.
func (s *Session) Backend() *Backend { return s.auth }

// Page exposes the attached page.
func (s *Session) Page() *Page { return s.page }

// Challenge runs the EME handshake and returns the browser CDM's raw
// license challenge. psshB64 may be empty for the default test PSSH.
func (p *Page) Challenge(psshB64 string) ([]byte, error) {
	if psshB64 != "" {
		if _, err := p.Eval(fmt.Sprintf("window.__cdmPssh = %q", psshB64)); err != nil {
			return nil, err
		}
	}
	if _, err := p.Eval(emeScript); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := p.status()
		if err != nil {
			return nil, err
		}
		if st.Error != "" {
			return nil, fmt.Errorf("eme: %s", st.Error)
		}
		if st.Challenge != "" {
			return base64.StdEncoding.DecodeString(st.Challenge)
		}
		if st.Done {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("no challenge from browser CDM " +
		"(is the CDM present and the origin secure?)")
}

type pageState struct {
	Challenge string
	Error     string
	Done      bool
	Log       string
}

func (p *Page) status() (pageState, error) {
	expr := `JSON.stringify({challenge: (window.__chromecdm||{}).challenge,
	                          error: (window.__chromecdm||{}).error,
	                          done: !!(window.__chromecdm||{}).done,
	                          log: ((window.__chromecdm||{}).log||[]).join('|')})`
	raw, err := p.Eval(expr)
	if err != nil {
		return pageState{}, err
	}
	var s struct {
		Challenge string `json:"challenge"`
		Error     string `json:"error"`
		Done      bool   `json:"done"`
		Log       string `json:"log"`
	}
	if err := jsonUnmarshal(raw, &s); err != nil {
		return pageState{}, err
	}
	return pageState{
		Challenge: s.Challenge, Error: s.Error, Done: s.Done, Log: s.Log,
	}, nil
}

// Update delivers a license response to the CDM session.
func (p *Page) Update(license []byte) error {
	b64 := base64.StdEncoding.EncodeToString(license)
	expr := fmt.Sprintf(`(async () => {
	  const S = window.__chromecdm;
	  const bytes = Uint8Array.from(atob(%q), c => c.charCodeAt(0));
	  await S.session.update(bytes);
	  S.license = %q;
	  S.log.push('update-ok');
	  return 'ok';
	})()`, b64, b64)
	if _, err := p.Evaluate(expr); err != nil {
		return err
	}
	return nil
}

// KeyStatuses returns KID -> status for every key the CDM reports.
func (p *Page) KeyStatuses() (map[string]string, error) {
	raw, err := p.Eval("JSON.stringify((window.__chromecdm||{}).keys||{})")
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := jsonUnmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range m {
		kb, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			out[strings.ToLower(k)] = v
			continue
		}
		out[hex.EncodeToString(kb)] = v
	}
	return out, nil
}

// Log returns the browser-side EME log.
func (p *Page) Log() ([]string, error) {
	raw, err := p.Eval("((window.__chromecdm||{}).log||[]).join('\\n')")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	return strings.Split(raw, "\n"), nil
}
