# Security levels

Widevine devices come in three security levels. Only one is reachable from
software.

| Level | Key material | Decryption | Extractable? |
|---|---|---|---|
| **L3** | software | software (CPU) | ✅ yes — this is what `wv` drives |
| **L2** | TEE (TrustZone) | hardware | ❌ keys never leave the TEE |
| **L1** | TEE | TEE, secure video path | ❌ neither keys nor frames leave |

## L3

All cryptography runs on the CPU. A provisioned device is an ordinary
encrypted blob that can be copied out of a device and used anywhere. This
is the level every public `.wvd` file is.

## L2 and L1

The content keys are generated inside a hardware TEE and are not readable
from the host CPU. On L1 the decrypted frames stay inside the TEE too, so
there is no point at which plaintext video reaches normal memory.

A library or service advertising "L1 CDMs" for desktop use is either
reselling material extracted from a physical device or mislabeling what it
has. There is no software path to L1.

## `security_level` in a `.wvd` file is a label

The field is one byte in the file header. Changing `03` to `01` makes the
file *claim* L1:

```
WVD 02 02 03 ...   -> reports L3
WVD 02 02 01 ...   -> reports "L1"
```

It has no cryptographic effect. The license server decides what a device
receives, based on the client ID and certificate it recognises — not on a
number in a file you control. A file claiming L1 still receives exactly the
L3 license it would otherwise get.

## Realistic paths to L1

Both require physical hardware access; neither is a software step:

- **eMMC / firmware dump** from a TV built on an MStar or MediaTek SoC
  (LG webOS, Hisense, Sharp, Philips, Panasonic).
- **Attestation key** provisioned into a real device keystore. Scarce,
  revoked quickly, and the install is permanent.

## Practical effect

An L3 device gets 480p–720p, sometimes 1080p, on services that allow L3.
Services that gate high resolutions behind L1 will not return usable keys
regardless of the client code.

## Why this matters for the CDM backend

Running Chrome and driving its CDM over the DevTools Protocol gives you a
genuine `libwidevinecdm.so` — the real component, not a reimplementation.
It is still an L3 CDM: Chrome on Linux is software-only, and an emulator
has no TrustZone at all. What the CDM backend buys is fidelity (the actual
Google binary, the actual EME path), not a higher security level.
