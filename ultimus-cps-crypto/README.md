# Ultimus CPS Crypto (Burp Montoya)

Burp Suite extension that decrypts/re-encrypts Ultimus CPS `encrprm` / `encrdata` traffic.

## Fix in 1.0.6 (load this)

Fixes **“No session cached for RSID …”**:

- Session capture accepts larger Ultimus HTML (async, up to 2MB) and percent-encoded blobs
- RSID lookup is case-insensitive
- Opening the **Ultimus** tab on the `/UltimusCPS/` HTML response captures keys immediately
- Image-upload hang protections from 1.0.5 kept (crypto unchanged)

### Capture session keys

1. Reload `ultimus-cps-crypto/ultimus-cps-crypto.jar` (remove old extension first)
2. Browse `/UltimusCPS/` through **Proxy**
3. In Proxy history, open that HTML response → click **Ultimus** tab  
   Status should say `Session cached.` / Extender: `Ultimus session captured`
4. Re-open your Repeater request → Ultimus tab

## Earlier

- **1.0.5:** Non-blocking HTTP path for image uploads
- **1.0.2:** Editable response intercept / re-encrypt `encrdata`

## Build

```bash
mvn -f ultimus-cps-crypto/pom.xml -q test package
```
