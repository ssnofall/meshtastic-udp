# Key Configuration

This file documents how to configure decryption keys for `main2.py`.

---

## private_keys.json

Used to decrypt **PKI-encrypted** messages (Meshtastic 2.7.15+, private DMs).

The file lives at `private_keys.json` (same directory as `main2.py`).  
Alternatively, set the `MESHTASTIC_PRIVATE_KEYS` environment variable to the same JSON content (useful for Docker/containers).

### Structure

```json
{
  "nodes": {
    "<node_num_decimal>": "<base64_private_key>"
  },
  "pubkeys": {
    "<base64_or_hex_sender_public_key>": "<base64_private_key>"
  },
  "clients": {
    "<meshtastic_client_url>": "<base64_private_key>"
  }
}
```

All three sections are optional — include whichever you have available.

---

### Section: `nodes`

Maps a **decimal node number** to its **X25519 private key** (32 bytes, base64-encoded).  
Use this when you own the receiving node and can export its key.

```json
"nodes": {
  "123456789": "YOUR_BASE64_PRIVATE_KEY_HERE="
}
```

**How to get the private key:**

1. **Meshtastic Python CLI:**
   ```
   meshtastic --export-config
   ```
   Look for `security.private_key` in the output (base64, 32 bytes).

2. **From the Meshtastic Android/iOS app:**
   Go to *Device Config → Security → Private Key* and copy the base64 value.

3. **Meshtastic Web Client:**
   Settings → Security → show private key.

The decimal node number is the numeric form of the `!xxxxxxxx` hex ID:
```python
# Convert !2fc6c8b8 → decimal
int("2fc6c8b8", 16)  # → 801556664
```

---

### Section: `pubkeys`

Maps a **sender's public key** → **recipient's private key**.  
This is useful when you already know who will send you PKI messages and you have their key.  
The sniffer derives the sender's public key automatically from any `nodes` entry, so this section is rarely needed manually.

```json
"pubkeys": {
  "BASE64_SENDER_PUBLIC_KEY=": "BASE64_RECIPIENT_PRIVATE_KEY="
}
```

---

### Section: `clients`

Maps a **Meshtastic client share URL** → **private key**.  
When you share your node via the "Share" button in the app, you get a URL like:

```
https://meshtastic.org/v/#CLiRm_4CEkYKCSEyZmM2YzhiOBIPTWVzaHRhc3RpYyBjOGI4...
```

The URL encodes the node's public key. The sniffer extracts the public key from the URL automatically, so you only need to paste the URL and the matching private key.

```json
"clients": {
  "https://meshtastic.org/v/#YOUR_SHARE_URL": "YOUR_BASE64_PRIVATE_KEY_HERE="
}
```

---

### Full example: `private_keys.json`

```json
{
  "nodes": {
    "123456789":  "BASE64_PRIVATE_KEY_FOR_NODE_aabbccdd",
    "987654321":  "BASE64_PRIVATE_KEY_FOR_NODE_11223344"
  },
  "pubkeys": {
    "BASE64_SENDER_PUBLIC_KEY=": "BASE64_RECIPIENT_PRIVATE_KEY="
  },
  "clients": {
    "https://meshtastic.org/v/#YOUR_SHARE_URL": "BASE64_PRIVATE_KEY"
  }
}
```

> **Security note:** `private_keys.json` contains secret key material. Keep it out of version control (add it to `.gitignore`). The file is read-only at startup; restarting `main2.py` picks up changes.

---

## Channel PSK Keys (`CHANNEL_KEYS` in `main2.py`)

Used to decrypt **PSK-encrypted** messages on named channels. Edit the `CHANNEL_KEYS` dict near the top of `main2.py` (around line 136).

```python
CHANNEL_KEYS = {
    0: 1,   # Channel index 0 → Meshtastic default key (variant 1)
    31: 1,  # Channel index 31 → same
}
```

### Key value formats

| Value | Meaning |
|---|---|
| `1` | Meshtastic default key (`AQ==`, the well-known public PSK) |
| `2` – `10` | Default key with last byte incremented by 1–9 (rarely used) |
| `"d4f1bb3a20290759f0bcffabcf4e6901"` | Raw hex string (32 hex chars = 16 bytes for AES-128, 64 = 32 bytes for AES-256) |
| `"0xd4f1bb3a20290759f0bcffabcf4e6901"` | Hex with `0x` prefix |
| `"1PG7OiAPn0/LobXkjxP3Xw=="` | Base64-encoded key bytes |

### How to find your channel key

**From the Meshtastic app:**  
Long-press the channel → *Edit* → copy the *PSK* field (shown as base64 or a QR code URL).

From the **channel URL** (e.g. from a QR code scan):
```
https://meshtastic.org/v/#CgUYAyIBAQ==
```
The `#` fragment is base64-encoded protobuf. You can decode it online or examine the key material in the app directly.

**From Meshtastic Python CLI:**
```
meshtastic --info
```
Look for `channels[N].settings.psk`.

### Adding a custom channel key

```python
CHANNEL_KEYS = {
    0: 1,                                          # Primary channel — default key
    1: "1PG7OiAPn0/LobXkjxP3Xw==",               # Channel 1 — custom base64 PSK
    2: "d4f1bb3a20290759f0bcffabcf4e690100000000"  # Channel 2 — custom hex PSK
    31: 1,                                         # LongFast fallback
}
```

Channel indices are 0–7 for the eight configurable channels, plus administrative channel 31. If a channel index is not in `CHANNEL_KEYS`, the sniffer still tries the full default key sweep (variants 1–10) as a fallback.

---

## PSK key format reference

Meshtastic derives the actual AES key from the PSK using a padding/expansion step:

| PSK length | AES mode |
|---|---|
| 16 bytes | AES-128-CTR |
| 32 bytes | AES-256-CTR |

The nonce is `packet_id[0:4] + extraNonce[4] + fromNode[4] + 0x00` (13 bytes, padded to 16 bytes for CTR mode with a 4-byte counter).
