# CENC testing and decryption traps

Notes from building and validating the decrypt path. Each item cost real
debugging time.

## Build test vectors with Bento4, not ffmpeg

ffmpeg 6.1.1's `-encryption_key` / `-decryption_key` roundtrip produces
corrupt output on its own files — `mp4decrypt` fails on them too. Use
Bento4.

### Order matters: encrypt first, then fragment

```console
$ mp4encrypt --method MPEG-CENC \
    --key 1:<KID>:<KEY>:9 --property 1:KID:<KID> in.mp4 enc.mp4
$ mp4fragment enc.mp4 frag.mp4 --fragment-duration 500
$ mp4decrypt --key <KID>:<KEY> frag.mp4 dec.mp4
```

Fragmenting **before** encrypting corrupts the sample tables. The failure
mode is deceptive: `mp4decrypt`, ffmpeg, and any library then agree on the
*same wrong bytes*, which looks like a library bug but is a bad vector.

### Validate a vector before trusting it

```console
$ ffmpeg -v error -i in.mp4  -f rawvideo -pix_fmt rgb24 - | sha256sum
$ ffmpeg -v error -i dec.mp4 -f rawvideo -pix_fmt rgb24 - | sha256sum
$ ffmpeg -v error -i dec.mp4 -f null - 2>&1 | wc -l      # must be 0
```

Interpretation:

- Hashes differ **and** both decryptors give the same nonzero error count
  → the vector is bad.
- Error counts differ **between** decryptors on the same input → the tool
  is bad.

Comparing a single frame index across differently fragmented files gives
false mismatches. Compare full-stream hashes only.

## Prefer real server-encrypted media over your own vectors

A locally built vector can be wrong in a way that makes every tool agree.
A real asset is the stronger test:

```console
$ curl -O https://storage.googleapis.com/shaka-demo-assets/angel-one-widevine/v-0240p-0400k-libx264.mp4
```

That file is a real Widevine CENC stream. Its Widevine PSSH is in the
sibling `dash.mpd`; the MP4 itself carries no `pssh` box.

## `gowidevine.DecryptMP4Auto` is wrong for multi-key licenses

It takes the **first** content key and ignores the KID in the file:

```go
// github.com/iyear/gowidevine v0.1.3, decrypt.go
for _, k := range keys {
    if k.Type == widevinepb.License_KeyContainer_CONTENT {
        key = k.Key
        break          // <-- no KID matching
    }
}
return DecryptMP4(r, key, w)
```

With a multi-key license this silently decrypts using the wrong key. No
error is returned; the output is garbage. Measured on a real asset with a
5-key license: 2349 decode errors, versus 0 when the correct key is used.

### The fix

Read `default_KID` from the file's `tenc` box and pick the matching key:

```go
// tenc box layout, after the 4-byte type:
//   version(1) flags(3) reserved(1) isProtected(1) ivSize(1) KID(16)
kid := data[i+12 : i+28]
```

Then call `widevine.DecryptMP4(r, key, w)` with that single key.
`wv decrypt` reports which key it chose:

```
[+] using key for KID 800aacaa522958ae888062b5695db6bf
```

If no key matches, it fails loudly rather than emitting garbage.

## Fragmented input only

`gowidevine`'s decrypter rejects non-fragmented MP4 with
`file is not fragmented`. For plain MP4, decrypt with `mp4decrypt` using
keys from `wv keys`.

## Reference key

Sanity-check a device and license setup against a published value. For the
Bitmovin test PSSH:

```
PSSH  AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA==
KID   ccbf5fb4c2965be7aa130ffb3ba9fd73
KEY   9cc0c92044cb1d69433f5f5839a159df
```

If a setup returns exactly this pair, the device, challenge, license
server, and parsing are all correct.
