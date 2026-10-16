# chromecdm

Widevine CDM toolkit. Two backends, one CLI.

- **`wvd`** — a provisioned device file. Produces raw content keys.
- **`cdp`** — a real Chrome/Chromium process using its own
  `libwidevinecdm.so`. Runs the whole EME exchange without reimplementing
  anything.

```console
$ wv keys -d device.wvd -l https://license.example/path -p "$PSSH"
ccbf5fb4c2965be7aa130ffb3ba9fd73:9cc0c92044cb1d69433f5f5839a159df
[+] 2 content key(s)
```

```console
$ wv cdp-feed -p "$PSSH" -i encrypted.mp4
[+] browser: Chrome/156.0.8078.4
    cdm:com.widevine.alpha
    challenge:1714
    update-ok
    played:5.66 rs:4
800aacaa522958ae888062b5695db6bf:usable
[+] 1 key(s), 1 usable
```

## Install

```console
$ git clone https://chromecdm
$ cd chromecdm
$ go build -o wv ./cmd/wv
$ go build -o chromecdm ./cmd/chromecdm
```

Go 1.22+. No cgo. The `cdp` backend needs a Chrome/Chromium build that
ships a Widevine CDM (the Playwright Chromium works).

## CLI

```
wv info    -d <device.wvd>                    device metadata
wv pssh    -i <file.mp4>                      find PSSH boxes in a file
wv keys    -d <device.wvd> -l <url> -p <pssh> content keys
wv decrypt -d <device.wvd> -l <url> -p <pssh> -i in.mp4 -o out.mp4
wv cdp       [-B <browser>] -p <pssh>         challenge from a browser CDM
wv cdp-keys  -l <url> -p <pssh>               EME handshake + license
wv cdp-feed  -l <url> -p <pssh> -i <enc.mp4>  decrypt through the CDM
```

Common flags:

```
-l <url>            license server URL
-p <b64>            PSSH as base64; "-" reads stdin; a .mp4 path extracts it
-d <file.wvd>       device file
-i / -o             input / output
-h "Name: Value"    extra license request header (repeatable)
-B <path>           browser binary for the cdp commands
```

### Fetch keys

```console
$ wv pssh -i movie.mp4
WIDEVINE  system=edef8ba979d64acea3c827dcd51d21ed  (62 bytes)
AAAAPnBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAB4iFnNoYWthX2NlYzJmNjRhYTc4OTBhMTFI49yVmwY=

$ wv keys -d device.wvd -l https://license.example/path -p movie.mp4
```

Feed stdout straight into `mp4decrypt`:

```console
$ wv keys -d device.wvd -l https://license.example/path -p "$PSSH" \
    | sed 's/^/--key /' \
    | xargs mp4decrypt encrypted.mp4 --output plain.mp4
```

### Decrypt

```console
$ wv decrypt -d device.wvd -l https://license.example/path \
             -p movie.mp4 -i movie.mp4 -o movie.dec.mp4
[+] challenge: 2164 bytes
[+] license: HTTP 200, 1315 bytes
[+] using key for KID 800aacaa522958ae888062b5695db6bf
[+] decrypted -> movie.dec.mp4
```

Input must be a **fragmented** MP4 (DASH/HLS segments). For plain MP4, use
`mp4decrypt` with the keys from `wv keys`.

### License servers that want a token

```console
$ wv keys -d device.wvd -l https://license.example/path \
          -h "X-AxDRM-Message: <token>" -p "$PSSH"
```

### Browser CDM backend

Runs a real Chrome and speaks to its CDM over the DevTools Protocol. The
CDM's own challenge identifies it as `ChromeCDM` from Google with its real
version — this is the genuine `libwidevinecdm.so`, not a reimplementation
of the protocol.

```console
$ wv cdp                    # just the challenge
$ wv cdp-keys               # challenge + license exchange
$ wv cdp-feed -i enc.mp4    # + feed the stream and let it decrypt
```

`cdp-feed` is the strong one: it appends the encrypted segments through
Media Source Extensions, so the CDM has to actually decrypt for playback
to advance. The key statuses it prints (`usable`) come from the CDM itself
and only appear when decryption succeeds.

A browser CDM never exposes raw key bytes to page script — that is by
design. Use the `wvd` backend when you need the keys themselves.

## HTTP API

```console
$ ./chromecdm -device device.wvd -license https://license-server/path
```

Env: `CDM_DEVICE`, `LICENSE_URL`, `LISTEN_ADDR`.

```
GET    /healthz
GET    /device
POST   /keys                        {"pssh":"<b64>","license_url":"<optional>"}
POST   /session                     same body; returns the challenge first
GET    /session/:id
GET    /session/:id/challenge
GET    /session/:id/keys
GET    /session/:id/keys.txt        "KID:KEY" lines
POST   /session/:id/update          {"license":"<b64>"}
DELETE /session/:id
```

```console
$ curl -s localhost:8443/keys -H 'Content-Type: application/json' \
    -d '{"pssh":"'$PSSH'"}'
{"status":"keys_ready","key_count":5,"keys":[{"type":"CONTENT",
 "kid":"ccbf5fb4c2965be7aa130ffb3ba9fd73",
 "key":"9cc0c92044cb1d69433f5f5839a159df"}]}
```

## Devices

A device is a `.wvd` file: a client ID blob plus an RSA private key.

```console
$ pywidevine create-device -k device_private_key \
                           -c device_client_id_blob \
                           -t ANDROID -l 3 -o device.wvd
```

`wv info -d device.wvd` prints what the file contains. Shared devices get
revoked periodically; when one stops working, swap the file — no code
changes.

Only **L3** devices are obtainable this way. L1/L2 keys live in a TEE and
cannot be exported as a file. See [docs/security-levels.md](docs/security-levels.md).

## Status

Verified by running, not asserted.

| Stage | Result |
|---|---|
| Load device, `wv info` | ✅ |
| License challenge | ✅ 2164 bytes |
| Live license server, key parse | ✅ 5 content + 1 signing key |
| Keys match published reference | ✅ `ccbf5fb4…:9cc0c920…` |
| Decrypt vs `mp4decrypt` | ✅ byte-identical, 0 decode errors |
| Decrypt a real server asset | ✅ Google's Widevine stream, 1500 frames |
| HTTP API, all routes | ✅ |
| Browser CDM challenge | ✅ `ChromeCDM`, 1714 bytes |
| Browser CDM license exchange | ✅ `session.update` accepted |
| Browser CDM full decrypt | ✅ stream played, keys `usable` |

Reproduce the decrypt check:

```console
$ mp4decrypt --key <KID>:<KEY> enc.mp4 ref.mp4
$ ffmpeg -v error -i enc.mp4 -f rawvideo -pix_fmt rgb24 - | sha256sum
$ ffmpeg -v error -i ref.mp4 -f rawvideo -pix_fmt rgb24 - | sha256sum
```

## Documentation

- [docs/security-levels.md](docs/security-levels.md) — L1/L2/L3, what is
  reachable and why.
- [docs/cenc-testing.md](docs/cenc-testing.md) — building test vectors,
  validating decryption, known library traps.
- [docs/browser-cdm.md](docs/browser-cdm.md) — how the browser backend
  drives EME and why key status is the proof.

## Layout

```
cmd/wv/               CLI
cmd/chromecdm/        HTTP server
internal/cdm/         .wvd loading, challenge, license parsing
internal/cdp/         browser CDM backend over DevTools Protocol
internal/api/         HTTP handlers
```
