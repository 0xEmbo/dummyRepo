# Ultimus CPS Crypto (Burp Montoya extension)

Burp Suite extension that decrypts/encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Load in Burp

1. Extender → Extensions → Add
2. Extension type: Java
3. Select `ultimus-cps-crypto.jar`
4. Browse `/UltimusCPS/` once through Burp to capture session keys

## Fixes in this build

- **Response Ultimus tab is editable** during Proxy intercept / Repeater (respects Burp `EditorMode`). Edited plaintext is re-encrypted into `encrdata` when you forward/send.
- **ID image / large form Send**: payloads up to ~3MB decrypt in the Ultimus tab (pretty/expand skipped above 128KB). Only extreme sizes pass through without decrypt so Burp does not freeze on Forward/Send.
- **No lone x-RToken rewrite on encrypted bodies**: unmodified Forward/Send keeps the exact wire request when `encrprm` is already in the body (avoids server closing the connection mid-upload).
- Fast `encrprm` / `encrdata` presence checks (no capturing multi-MB ciphertext just to enable tabs).
- Handler skips auto-encrypt for plaintext bodies over ~512KB and skips binary/image responses in the HTML session scanner.

Crypto algorithms (`UltimusCrypto`, token/format codecs) are unchanged.
