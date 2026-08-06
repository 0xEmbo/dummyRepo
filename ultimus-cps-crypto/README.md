# Ultimus CPS Crypto (Burp Montoya)

Burp Suite extension that decrypts/re-encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Fix in 1.0.5 (load this)

Repeater image-upload **Send** must always get a response:

- HTTP response handling returns immediately; session ingest runs on a **background thread**
- Auto-encrypt only for tiny JSON bodies (≤64KB) — uploads pass through untouched
- Ultimus request tab does not re-encrypt large/multipart bodies on Send
- Editor tabs refuse oversized ciphertext (use Raw tab for uploads)

Crypto algorithms are unchanged.

### Install

1. Burp → Extensions → remove any old **Ultimus CPS Crypto**
2. Add → Java → select `ultimus-cps-crypto/ultimus-cps-crypto.jar`
3. Extension class: `burp.ultimus.UltimusBurpExtension`
4. Confirm Extender output shows: `Ultimus CPS Crypto loaded...`
5. Browse `/UltimusCPS/` once through **Proxy**
6. Retry image upload in Repeater (stay on **Raw** tab for the upload request)

## Earlier fixes

- **1.0.4:** Proxy-only ingest, skip `data:image` blobs
- **1.0.2:** Editable Ultimus response tab (intercept / re-encrypt `encrdata`)
- **1.0.1:** Initial image data-URI hang mitigation

## Build

```bash
mvn -f ultimus-cps-crypto/pom.xml -q test package
```
