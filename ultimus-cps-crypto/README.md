# Ultimus CPS Crypto (Burp Montoya extension)

Burp Suite extension that decrypts/encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Load in Burp

1. Extender → Extensions → Add
2. Extension type: Java
3. Select `ultimus-cps-crypto.jar`
4. Browse `/UltimusCPS/` once through Burp to capture session keys

## Fixes in this build

- **Response Ultimus tab is editable** during Proxy intercept / Repeater (respects Burp `EditorMode`). Edited plaintext is re-encrypted into `encrdata` when you forward/send.
- **Send no longer freezes** on large image-upload payloads: unmodified requests only refresh tokens (no full re-encrypt), and large bodies skip expand/pretty-print on the UI thread.
- **Binary/image responses** are skipped by the HTTP handler HTML session scanner so large upload responses do not block Burp.

Crypto algorithms (`UltimusCrypto`, token/format codecs) are unchanged.
