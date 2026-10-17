# chromecdm

[![ci](https://github.com/Yondaime-kun/chromecdm/actions/workflows/ci.yml/badge.svg)](https://github.com/Yondaime-kun/chromecdm/actions/workflows/ci.yml)
[![release](https://github.com/Yondaime-kun/chromecdm/actions/workflows/release.yml/badge.svg)](https://github.com/Yondaime-kun/chromecdm/actions/workflows/release.yml)

Widevine CDM toolkit: fetch content keys from a provisioned device, decrypt
CENC media, and drive a real browser CDM over the DevTools Protocol.

Two backends, one CLI:

| Backend | What it is | What it gives you |
|---|---|---|
| **`wvd`** | a provisioned device file (`client_id.bin` + RSA key) | raw content keys, and decryption |
| **`cdp`** | a real Chrome/Chromium using its own `libwidevinecdm.so` | proof of decryption, plus the KIDs the CDM holds |

```console
$ wv keys -d device.wvd -l https://license.example/path -p "$PSSH"
800aacaa522958ae888062b5695db6bf:775dbf7289c4cc5847becd571f536ff2
4d97930a3d7b55fa81d0028653f5e499:429ec76475e7a952d224d8ef867f12b6
[+] 5 content key(s), 1 signing key(s)
```

```console
$ wv cdp-feed -p "$PSSH" -i encrypted.mp4
[+] browser: Chrome/155.0.8059.84
    cdm:com.widevine.alpha
    challenge:1714
    update-ok
    played:5.66 rs:4
KID 800aacaa522958ae888062b5695db6bf  status=usable
[+] 5 key(s), 5 usable  (KID + status only; the browser never exposes key bytes)
```

The two outputs are different on purpose. `wvd` emits `KID:KEY`, ready for
`mp4decrypt`. `cdp` emits `KID … status=…` because a browser CDM never
hands out key bytes. See [Why the browser gives no keys](#why-the-browser-gives-no-keys).

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Decrypting](#decrypting)
- [Browser CDM](#browser-cdm)
- [Both backends at once](#both-backends-at-once)
- [HTTP API](#http-api)
- [Devices](#devices)
- [Troubleshooting](#troubleshooting)
- [Why the browser gives no keys](#why-the-browser-gives-no-keys)
- [Status](#status)

---

## Install

### Prebuilt binary

Grab the archive for your platform from
[Releases](https://github.com/Yondaime-kun/chromecdm/releases):

```
wv_<version>_<os>_<arch>            linux / darwin / freebsd
wv_<version>_<os>_<arch>.exe        windows
chromecdm_<version>_<os>_<arch>     the HTTP server
```

Verify before running:

```console
$ sha256sum -c checksums.txt
$ chmod +x wv_1.0.0_linux_amd64
$ ./wv_1.0.0_linux_amd64 -version
wv 1.0.0 (commit a1b2c3d, built 2026-10-17T00:00:00Z, go1.27.1 linux/amd64)
```

Supported: linux amd64/arm64/armv7/386, darwin amd64/arm64, windows
amd64/arm64, freebsd amd64.

### From source

```console
$ git clone https://github.com/Yondaime-kun/chromecdm
$ cd chromecdm
$ make build          # bin/ for this machine
$ make test           # vet + tests
$ make release        # dist/ for every platform, plus checksums
```

Go 1.22 or newer. No cgo, so the binaries are static.

The `cdp` backend needs a Chrome/Chromium that ships a Widevine CDM. Chrome
for Testing and the Playwright Chromium builds both qualify; a distro
Chromium usually does not.

---

## Quick start

Three steps: get a device, find the PSSH, fetch the keys.

### 1. Get a device

You need a `.wvd` file. If you have the raw parts:

```console
$ pywidevine create-device -k device_private_key \
                           -c device_client_id_blob \
                           -t ANDROID -l 3 -o device.wvd

$ wv info -d device.wvd
```

`wv info` prints the type, security level, and system ID. If it errors, the
file is corrupt or revoked.

### 2. Find the PSSH

The PSSH is the DRM header inside the media file:

```console
$ wv pssh -i movie.mp4
WIDEVINE  system=edef8ba979d64acea3c827dcd51d21ed  (62 bytes)
AAAAPnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAB4iFnNoYWthX2NlYzJmNjRhYTc4OTBhMTFI49yVmwY=
```

Every `wv` command accepts `-p` as base64, as `-`, or as a media path —
`-p movie.mp4` extracts it for you.

### 3. Fetch the keys

```console
$ wv keys -d device.wvd -l https://license.example/path -p movie.mp4
```

Pipe straight into `mp4decrypt`:

```console
$ wv keys -d device.wvd -l https://license.example/path -p movie.mp4 \
    | sed 's/^/--key /' \
    | xargs mp4decrypt encrypted.mp4 --output plain.mp4
```

---

## Commands

```
wv info    -d <device.wvd>                     device metadata
wv pssh    -i <file.mp4>                       find PSSH boxes in a file

wv keys    -d <wvd> -l <url> -p <pssh>         content keys
wv decrypt -d <wvd> -l <url> -p <pssh> -i in.mp4 -o out.mp4

wv cdp       [-B <browser>] -p <pssh>          challenge from a browser CDM
wv cdp-keys  -l <url> -p <pssh>                EME handshake + license
wv cdp-feed  -l <url> -p <pssh> -i <enc.mp4>   decrypt through the CDM
wv cdp-pair  -d <wvd> -l <url> -p <pssh> -i <enc.mp4>
                                               KID:KEY from both backends

wv -version                                    print version
wv help                                        full usage
```

Flags:

```
-l <url>            license server URL
-p <b64>            PSSH: base64, "-" for stdin, or a .mp4 path
-d <file.wvd>       device file
-i / -o             input / output
-h "Name: Value"    extra license request header (repeatable)
-B <path>           browser binary for cdp commands (default: autodetect)
-k                  skip TLS verification on the license request
```

### License servers that want a token

Some servers expect an authorization header alongside the challenge:

```console
$ wv keys -d device.wvd -l https://license.example/path \
          -h "X-AxDRM-Message: <token>" -p "$PSSH"
```

Repeat `-h` for several headers. The same flags work on `cdp-keys`,
`cdp-feed`, and `cdp-pair`.

### Self-signed license servers

```console
$ wv keys -d device.wvd -l https://10.0.0.5/license -k -p "$PSSH"
```

---

## Decrypting

```console
$ wv decrypt -d device.wvd -l https://license.example/path \
             -p movie.mp4 -i movie.mp4 -o movie.dec.mp4

[+] challenge: 2164 bytes
[+] license: HTTP 200, 1315 bytes
[+] using key for KID 800aacaa522958ae888062b5695db6bf
[+] decrypted -> movie.dec.mp4
[+] in=3041412 bytes out=3019569 bytes
```

**Input must be a fragmented MP4** (DASH or HLS segments). For a plain MP4,
use the keys from `wv keys` with `mp4decrypt` — that path is well tested and
`wv decrypt` only wraps it for the single-key case.

The key is chosen by matching the file's `tenc` default_KID against the
license, not by taking the first key. A multi-key license decrypted with
the wrong key produces silent garbage rather than an error, so this matters.

Verify the result actually decodes:

```console
$ ffmpeg -v error -i movie.dec.mp4 -f null -
$ echo $?
0
```

A correct decrypt exits 0 with no output. A wrong key floods the terminal
with `decode_slice_header error`.

---

## Browser CDM

Runs a real Chrome and speaks to its CDM over the DevTools Protocol. The
CDM's own challenge identifies it as `ChromeCDM` from Google with its real
version — this is the genuine `libwidevinecdm.so`, not a reimplementation
of the protocol.

```console
$ wv cdp -p "$PSSH"                    # challenge only
$ wv cdp-keys -l "$URL" -p "$PSSH"     # challenge + license exchange
$ wv cdp-feed -l "$URL" -p "$PSSH" -i enc.mp4
                                       # + feed the stream and let it decrypt
```

`cdp-feed` is the strong one: it appends the encrypted segments through
Media Source Extensions, so the CDM has to decrypt for playback to advance.
Key status only appears when decryption succeeds, so a non-empty `usable`
set is proof the CDM is working.

Output is **KID plus status, not key material**:

```
KID 800aacaa522958ae888062b5695db6bf  status=usable
```

Chrome is picked automatically: the highest installed version wins. Pin one
with `-B`:

```console
$ wv cdp-feed -B /opt/google/chrome/chrome -p "$PSSH" -i enc.mp4
```

Version matters more than it looks — see
[Wrong browser version](#wrong-browser-version).

---

## Both backends at once

Neither backend alone gives a verified, complete answer. `cdp-pair` runs
both and joins them on KID:

- the **browser** proves the KIDs are live, because the CDM only reports
  `usable` after it decrypts;
- the **device** supplies the raw key bytes.

```console
$ wv cdp-pair -d device.wvd -l "$URL" -p "$PSSH" -i enc.mp4

[1/2] browser CDM (KID + status)
      5 KID(s) confirmed: the CDM decrypted with them
[2/2] .wvd device (key bytes)
      5 content key(s) from the license
4d97930a3d7b55fa81d0028653f5e499:429ec76475e7a952d224d8ef867f12b6
800aacaa522958ae888062b5695db6bf:775dbf7289c4cc5847becd571f536ff2

[+] 5 KID(s): 5 with a key and confirmed by the CDM, 0 device-only, 0 browser-only
```

stdout is `KID:KEY` — the format `mp4decrypt` reads — so it pipes directly.
KIDs the device cannot cover stay out of stdout and are reported on stderr,
so the stream remains parseable.

---

## HTTP API

```console
$ ./chromecdm -device device.wvd -license https://license-server/path
```

Flags or env: `-device`/`CDM_DEVICE`, `-license`/`LICENSE_URL`,
`-addr`/`LISTEN_ADDR` (default `:8443`).

```
GET    /healthz
GET    /device
POST   /keys                        {"pssh":"<b64>","license_url":"<optional>"}
POST   /session                     same body; returns the challenge first
GET    /session/:id
GET    /session/:id/challenge
GET    /session/:id/keys            JSON, hex and base64
GET    /session/:id/keys.txt        "KID:KEY" lines
POST   /session/:id/update          {"license":"<b64>"}
DELETE /session/:id
```

```console
$ curl -s localhost:8443/keys -H 'Content-Type: application/json' \
    -d '{"pssh":"'$PSSH'"}'
```

```json
{
  "status": "keys_ready",
  "key_count": 5,
  "keys": [
    {
      "type": "CONTENT",
      "kid": "800aacaa522958ae888062b5695db6bf",
      "key": "775dbf7289c4cc5847becd571f536ff2",
      "iv": "1cbe2e9a56c552647dfd98a7b4e9abe0",
      "kid_b64": "gAqsqlIpWK6IgGK1aV22vw==",
      "key_b64": "d12/conEzFhHvs1XH1Nv8g=="
    }
  ]
}
```

`key_count` counts content keys only; signing keys are filtered out so every
entry in `keys` has a KID.

Fetch `keys.txt` when you want to pipe somewhere:

```console
$ curl -s localhost:8443/session/sess-0001/keys.txt \
    | sed 's/^/--key /' | xargs mp4decrypt enc.mp4 out.mp4
```

---

## Devices

A `.wvd` file holds a client ID blob and an RSA private key. `wv info` shows
what it contains; `wv keys` uses it to sign license challenges.

Shared devices get revoked periodically. When one stops working the license
server answers with an error, and swapping the file is the fix — no code
changes.

Only **L3** devices are obtainable this way. L1/L2 keys live in a TEE and
cannot be exported as a file; see
[docs/security-levels.md](docs/security-levels.md).

---

## Troubleshooting

### `no chrome/chromium found`

Nothing matched the usual install locations. Point at one directly:

```console
$ wv cdp -B /path/to/chrome -p "$PSSH"
```

### Wrong browser version

Several Chrome builds can coexist, and their bundled Widevine CDM versions
differ. An older CDM can be rejected by a license server that accepts a
newer one, which looks like a code problem but is not:

```
Chrome 145.0.7632.6   CDM 4.10.2934.0   -> ACCESS_DENIED
Chrome 155.0.8059.84  CDM 4.10.3112.02  -> update-ok, 5 keys usable
```

`wv` picks the highest version automatically. If a specific build works
better, pin it with `-B`.

### `ACCESS_DENIED` or a rejected `update()`

Usually the PSSH does not match the media. Take the PSSH from the file you
are decrypting:

```console
$ wv pssh -i enc.mp4
```

If it still fails, the license server may not serve that PSSH at all.

### `no key status` from `cdp-feed`

The CDM never decrypted, so it reports nothing. Either the license was
rejected, or the media does not match the PSSH. Check the log lines
`cdp-feed` prints — `update-ok` means the license was accepted.

### `requestMediaKeySystemAccess is not a function`

The page is not a secure context. `wv` serves its harness over HTTPS for
exactly this reason; if you are scripting against your own page, serve it
over localhost HTTPS rather than `file://` or `about:blank`.

### `decode_slice_header error` everywhere after decrypting

The wrong key was used. Do not take the first key from a multi-key license —
match the file's `tenc` default_KID. `wv decrypt` and `cdp-pair` both do
this; if you are calling `mp4decrypt` yourself, pass the matching pair.

### `insecure certificate`

Only relevant when driving Firefox yourself; `wv` does not use Firefox.
Chrome handles this with `--ignore-certificate-errors`, which `wv` already
passes.

---

## Why the browser gives no keys

A browser CDM holds keys but never exposes their bytes to page script. This
is by design, and it was verified rather than assumed:

| route | result |
|---|---|
| `keyStatuses` iteration | KID + status only |
| property introspection of the live session | no key accessor exists |
| scan of the `window` object graph for the 16 key bytes | absent |
| scan of 85 live Chrome processes during active decryption (~41k memory regions per pass, 12 passes, raw + hex encodings) | 0 regions held the key; a control string was found 136 times, so the scan works |
| `JSON.stringify(session.keyStatuses)` | `{}` |

The key never enters readable memory, not even while frames are being
decrypted. If a page could read it, DRM would accomplish nothing.

That is why the two backends exist. Use `wvd` for key bytes, `cdp` for proof
that the media really decrypts, and `cdp-pair` when you want both.

---

## Status

Verified by running, not asserted. Last checked against a live license
server and a real server-encrypted asset.

| Stage | Result |
|---|---|
| Load device, `wv info` | ✅ |
| License challenge | ✅ 2164 bytes |
| Live license server, key parse | ✅ 5 content + 1 signing key |
| Keys match published reference | ✅ `ccbf5fb4…:9cc0c920…` |
| Decrypt vs `mp4decrypt` | ✅ byte-identical, 0 decode errors |
| Decrypt a real server asset | ✅ 1500 frames, 0 decode errors |
| HTTP API, all routes | ✅ |
| Browser CDM challenge | ✅ `ChromeCDM`, 1714 bytes |
| Browser CDM license exchange | ✅ `update-ok` |
| Browser CDM full decrypt | ✅ played 5.7 s, 5 KIDs `usable` |
| `cdp-pair` join | ✅ 5/5 with key and CDM confirmation |
| Raw key extraction from a browser CDM | ❌ not possible — see above |

---

## Documentation

- [docs/versioning.md](docs/versioning.md) — semver rules, tagging, CI/CD.
- [docs/browser-cdm.md](docs/browser-cdm.md) — how the browser backend
  drives EME, and the evidence for the key-exposure limit.
- [docs/cenc-testing.md](docs/cenc-testing.md) — building test vectors,
  validating decryption, known library traps.
- [docs/security-levels.md](docs/security-levels.md) — L1/L2/L3, what is
  reachable and why.

## Layout

```
cmd/wv/               CLI
cmd/chromecdm/        HTTP server
internal/cdm/         .wvd loading, challenge, license parsing
internal/cdp/         browser CDM backend (DevTools Protocol, EME, MSE)
internal/mp4/         tenc default_KID parsing, key selection
internal/version/     build identity, injected at link time
internal/api/         HTTP handlers
.github/workflows/    ci (test + matrix) and release (tag -> binaries)
```
