package cdp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// mseScript runs the whole EME exchange against the browser's CDM and then
// feeds an encrypted CENC stream through Media Source Extensions. Only when
// the CDM actually decrypts does it report key status, which is the signal
// that the license really was accepted and the keys are usable.
//
// Inputs on window: __cdmPssh (base64 PSSH), __cdmMedia (base64 encrypted
// MP4), __cdmLicensePath (same-origin relaying endpoint).
const mseScript = `
(async () => {
  const R = { log: [], keys: null, error: null, time: 0, ready: 0, playing: false };
  const L = (m) => R.log.push(m);
  try {
    const cfg = [{
      initDataTypes: ['cenc'],
      videoCapabilities: [{ contentType: 'video/mp4; codecs="avc1.42E01E"' }],
      distinctiveIdentifier: 'optional', persistentState: 'optional',
      sessionTypes: ['temporary'],
    }];
    const acc = await navigator.requestMediaKeySystemAccess('com.widevine.alpha', cfg);
    L('cdm:' + acc.keySystem);
    const mk = await acc.createMediaKeys();

    document.querySelectorAll('video').forEach(e => e.remove());
    const v = document.createElement('video');
    v.muted = true; v.autoplay = true; v.playsInline = true;
    v.setAttribute('playsinline', '');
    document.body.appendChild(v);
    await v.setMediaKeys(mk);
    L('mediakeys-set');

    const s = mk.createSession('temporary');
    window.__session = s;
    const B = (b) => Uint8Array.from(atob(b), c => c.charCodeAt(0));
    const b64 = (b) => btoa(String.fromCharCode.apply(null, new Uint8Array(b)));

    s.addEventListener('message', async (e) => {
      if (e.messageType !== 'license-request') return;
      const chal = b64(e.message);
      L('challenge:' + atob(chal).length);
      try {
        const resp = await fetch(window.__cdmLicensePath, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge: chal }),
        });
        const j = await resp.json();
        if (!j.license) { L('license-error:' + JSON.stringify(j).slice(0, 120)); return; }
        await s.update(B(j.license));
        L('update-ok');
      } catch (ue) {
        L('update-fail:' + ue.name + ':' + ue.message);
      }
    });

    s.addEventListener('keystatuschange', (e) => {
      const o = {};
      e.keyStatuses.forEach((st, kid) => { o[b64(kid)] = st; });
      R.keys = o;
      L('keystatus:' + JSON.stringify(o));
    });

    await s.generateRequest('cenc', B(window.__cdmPssh));
    L('request-generated');

    // Feed the encrypted media so the CDM has something to decrypt.
    const ms = new MediaSource();
    v.src = URL.createObjectURL(ms);
    await new Promise(r => ms.addEventListener('sourceopen', r, { once: true }));
    const sb = ms.addSourceBuffer('video/mp4; codecs="avc1.42E01E"');
    const data = B(window.__cdmMedia);
    await new Promise((res, rej) => {
      sb.addEventListener('updateend', res, { once: true });
      sb.addEventListener('error', () => rej(new Error('sourcebuffer')), { once: true });
      sb.appendBuffer(data);
    });
    L('appended:' + data.length);
    try { ms.endOfStream(); } catch (e) {}

    await v.play().catch(e => L('play-fail:' + e.message));
    for (let i = 0; i < 24; i++) {
      await new Promise(r => setTimeout(r, 250));
      R.time = v.currentTime; R.ready = v.readyState;
      if (v.currentTime > 0.1) { R.playing = true; }
      // Key status arrives after decryption starts; stop once we have it.
      if (R.keys && Object.keys(R.keys).length) break;
    }
    L('played:' + R.time.toFixed(2) + ' rs:' + R.ready);
  } catch (e) {
    R.error = (e.name || '') + ': ' + (e.message || String(e));
  }
  return JSON.stringify(R);
})()
`

// MSEOutcome is the result of a full browser-CDM decryption run.
type MSEOutcome struct {
	Keys    map[string]string // KID (hex) -> status
	Log     []string
	Error   string
	Time    float64
	Ready   int
	Playing bool
}

// Decrypt drives the browser CDM all the way through: challenge, license,
// and an encrypted stream fed via MSE. Key status is only reported by the
// CDM once it genuinely decrypts, so a non-empty Keys map is proof the
// license was accepted and is usable.
func (p *Page) Decrypt(psshB64 string, media []byte) (*MSEOutcome, error) {
	if psshB64 == "" {
		return nil, fmt.Errorf("a PSSH is required for the browser feed")
	}
	setup := fmt.Sprintf(
		"window.__cdmPssh = %q; window.__cdmMedia = %q; window.__cdmLicensePath = '/license';",
		psshB64, base64.StdEncoding.EncodeToString(media))
	if _, err := p.Eval(setup); err != nil {
		return nil, err
	}

	raw, err := p.Evaluate(mseScript)
	if err != nil {
		return nil, err
	}

	var r struct {
		Log     []string          `json:"log"`
		Keys    map[string]string `json:"keys"`
		Error   string            `json:"error"`
		Time    float64           `json:"time"`
		Ready   int               `json:"ready"`
		Playing bool              `json:"playing"`
	}
	if err := jsonUnmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse cdm result: %w (raw: %.200s)", err, raw)
	}

	out := &MSEOutcome{
		Log: r.Log, Error: r.Error, Time: r.Time,
		Ready: r.Ready, Playing: r.Playing,
		Keys: map[string]string{},
	}
	for b64kid, status := range r.Keys {
		kb, err := base64.StdEncoding.DecodeString(b64kid)
		if err != nil {
			out.Keys[strings.ToLower(b64kid)] = status
			continue
		}
		out.Keys[hex.EncodeToString(kb)] = status
	}
	return out, nil
}

// WaitForKeys polls until key status appears or the timeout elapses; the
// CDM dispatches the event asynchronously and it can land after the
// injected script has already returned.
func (p *Page) WaitForKeys(timeout time.Duration) (map[string]string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := p.Eval(`(function(){
		  const s = window.__session;
		  if (!s) return "";
		  const o = {};
		  s.keyStatuses.forEach((v, k) => {
		    o[btoa(String.fromCharCode.apply(null, new Uint8Array(k)))] = v;
		  });
		  return JSON.stringify(o);
		})()`)
		if err != nil {
			return nil, err
		}
		if raw != "" && raw != "{}" {
			var m map[string]string
			if err := jsonUnmarshal(raw, &m); err != nil {
				return nil, err
			}
			out := map[string]string{}
			for b64kid, st := range m {
				kb, err := base64.StdEncoding.DecodeString(b64kid)
				if err != nil {
					out[strings.ToLower(b64kid)] = st
					continue
				}
				out[hex.EncodeToString(kb)] = st
			}
			if len(out) > 0 {
				return out, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, nil
}
