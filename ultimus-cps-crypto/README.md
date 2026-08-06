# Ultimus CPS Crypto (Burp Montoya)

Burp Suite extension that decrypts/re-encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Fix in 1.0.4

Repeater **Send** on image upload no longer spins forever:

- Session key capture runs **only for Proxy** traffic (not Repeater/Intruder)
- `KeyCache` skips `data:image/...;base64,...` with an index scan (no regex capture of multi-MB blobs)
- Request editor passes through multipart / huge bodies on Send instead of re-encrypting
- Handler failures never block Burp’s HTTP pipeline

Encrypt/decrypt algorithms are unchanged.

## Fix in 1.0.3

Hardened the send/editor path so large image-upload JSON (`encrprm` / `encrdata`) cannot freeze Burp. Crypto unchanged.

## Fix in 1.0.2

Intercepted / Repeater responses with `encrdata` are editable in the **Ultimus** response tab. Edits are re-encrypted back into `encrdata` on forward/send. Crypto unchanged.

## Fix in 1.0.1

Image upload / large HTML responses with `data:image/...;base64,...` no longer freeze Burp Repeater via session-ingest AES on image blobs. Crypto unchanged.

## Build

```bash
mvn -f ultimus-cps-crypto/pom.xml -q test package
```

Load **`ultimus-cps-crypto/ultimus-cps-crypto.jar`** (1.0.4) in Burp → Extensions.

Browse `https://<host>/UltimusCPS/` through **Proxy** once so session keys are captured, then use Repeater.
