# Ultimus CPS Crypto (Burp Montoya)

Burp Suite extension that decrypts/re-encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Fix in 1.0.2

Intercepted / Repeater responses with `encrdata` are editable in the **Ultimus** response tab. Edits are re-encrypted back into `encrdata` on forward/send. Crypto algorithms are unchanged.

## Fix in 1.0.1

Image upload / large HTML responses with `data:image/...;base64,...` no longer freeze Burp Repeater.

**Cause:** `KeyCache.ingestFromHtml` treated the first `base64,...` blob as session material and AES-decrypted multi-MB image payloads on Burp's HTTP handler thread.

**Change:** skip oversized blobs (session keys are &lt; 4KB) and skip binary/huge responses in the HTTP handler. Encrypt/decrypt algorithms are unchanged.

## Build

```bash
mvn -f ultimus-cps-crypto/pom.xml -q test package
```

Load `ultimus-cps-crypto/target/ultimus-cps-crypto-1.0.2.jar` in Burp → Extensions.
