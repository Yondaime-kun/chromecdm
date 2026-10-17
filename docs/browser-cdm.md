# Browser CDM backend

The `cdp` commands drive a real Chrome/Chromium process over the DevTools
Protocol and use the CDM that ships inside it. Nothing about the Widevine
protocol is reimplemented — the browser performs the EME exchange and this
package relays bytes.

## Why a browser at all

A `.wvd` device file is a reimplementation: you hold the client ID and
private key and speak the wire protocol yourself. A browser CDM is the
genuine article — Google's `libwidevinecdm.so`, loaded by Chrome, driven
through the standard EME API. Both are L3 (see
[security-levels.md](security-levels.md)); the difference is fidelity.

## The flow

1. Launch Chrome with `--remote-debugging-port` and a throwaway profile.
2. Open a page on a **local HTTPS origin**. EME requires a secure context:
   `about:blank` and `data:` URLs do not expose
   `navigator.requestMediaKeySystemAccess`.
3. From page script: request `com.widevine.alpha`, create MediaKeys, create
   a session, and `generateRequest` with the PSSH.
4. The CDM emits a `license-request` message. Relay it to the license
   server — page script cannot POST cross-origin, so the harness serves a
   same-origin `/license` endpoint that forwards the challenge.
5. Call `session.update()` with the license bytes.

Steps 1–5 are the full handshake. The CDM accepts or rejects the license
here, but reports nothing about keys yet.

## Why key status needs media

`keystatuschange` only fires once the CDM *uses* a key. A session that has
accepted a license but never decrypted anything reports nothing.

So `cdp-feed` goes further: it appends an encrypted CENC stream through
Media Source Extensions.

```js
const ms = new MediaSource();
video.src = URL.createObjectURL(ms);
const sb = ms.addSourceBuffer('video/mp4; codecs="avc1.42E01E"');
sb.appendBuffer(encryptedSegment);
```

Now the CDM has to decrypt for playback to advance, and it publishes
`keyStatuses` for the keys it holds:

```
800aacaa522958ae888062b5695db6bf:usable
```

`usable` means the key is present and the CDM is willing to decrypt with
it. If the license were wrong, the status would be `output-restricted` or
the map would stay empty, and playback would not advance.

This is why `cdp-feed` is the good test: a non-empty `usable` set, plus
video actually progressing, cannot be faked by a broken handshake.

## Reading the challenge

The challenge is a protobuf `SignedMessage`. Decoded, it carries the
client identity:

```
model_name           ChromeCDM
company_name         Google
platform_name        Linux
architecture_name    x86-64
widevine_cdm_version 4.10.3112.0
```

That is the browser's own CDM reporting itself. If you see a different
`model_name`, you are talking to a different component.

## Notes and gotchas

- **Browser version matters.** Several Chrome builds can coexist on a
  machine, and their bundled Widevine CDM versions differ. An older CDM
  can have its challenge rejected by a license server that accepts a
  newer one — the failure looks like `ACCESS_DENIED` from the server, or a
  rejected `update()`, even though the code and the PSSH are correct. Two
  builds on one machine that behaved differently against the same server:

  ```
  Chrome 145.0.7632.6  CDM 4.10.2934.0  -> ACCESS_DENIED
  Chrome 155.0.8059.84 CDM 4.10.3112.02  -> update-ok, 5 keys usable
  ```

  `cdp` commands therefore select the highest installed version rather
  than the first one found. Pin a specific build with `-B /path/to/chrome`.
- The harness uses a self-signed certificate. Chrome needs
  `--ignore-certificate-errors` and `--allow-insecure-localhost`, otherwise
  the page is not a usable secure context and the EME API is missing.
- Each media key session accepts `update()` exactly once. Calling it twice
  fails with `InvalidStateError` and system code 44, which reads like a
  signing-key mismatch but is really a duplicate call.
- The PSSH must be the one the media was packaged with. A PSSH from a
  different representation yields a license the CDM rejects, because the
  KIDs do not line up.
- The keys a browser CDM holds are never exposed to page script. For raw
  key bytes, use the `.wvd` backend.
- `keyStatuses` can be read directly off the live session, which is useful
  when the event fires after your polling loop has already finished:

  ```js
  session.keyStatuses.forEach((status, kid) => { /* ... */ });
  ```
