# Ultimus CPS Crypto (Burp Montoya extension)

Burp Suite extension that decrypts/encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Load in Burp

1. Extender → Extensions → Add
2. Extension type: Java
3. Select `ultimus-cps-crypto.jar`
4. Browse `/UltimusCPS/` once through Burp to capture session keys

## Fixes in this build

- **Response Ultimus tab is editable** during Proxy intercept / Repeater (respects Burp `EditorMode`). Edited plaintext is re-encrypted into `encrdata` when you forward/send.
- **ID image / large form Send no longer freezes**: bodies over ~256KB are **not** decrypted or loaded into the Ultimus editor (pass-through + token refresh only). Decrypting multi-MB ID images into the UI was freezing Burp so Forward/Send never completed.
- Fast `encrprm` / `encrdata` presence checks (no capturing multi-MB ciphertext just to enable tabs).
- Handler skips auto-encrypt for plaintext bodies over ~512KB and skips binary/image responses in the HTML session scanner.

Crypto algorithms (`UltimusCrypto`, token/format codecs) are unchanged.
