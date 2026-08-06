package burp.ultimus.crypto;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusRToken.class */
public class UltimusRToken {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private final UltimusCrypto crypto;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DateTimeFormatter SERVER_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    public UltimusRToken(UltimusCrypto ultimusCrypto) {
        this.crypto = ultimusCrypto;
    }

    public String headerToken(String str, String str2) {
        return this.crypto.encrypt(buildPayload(str2, 0), str);
    }

    public String queryToken(String str, String str2, String str3) {
        return jsUriEncode(this.crypto.encrypt(buildPayload(str2, str3 == null ? 0 : jsHashCode(str3)), str));
    }

    private static String buildPayload(String str, int i) {
        return makeRandom(16) + "|" + str + "|" + SERVER_TIME.format(Instant.now()) + "|" + i;
    }

    static int jsHashCode(String str) {
        int i = 0;
        for (int i2 = 0; i2 < str.length(); i2++) {
            i = (((i << 5) - i) + str.charAt(i2)) | 0;
        }
        return i;
    }

    static String makeRandom(int i) {
        StringBuilder sb = new StringBuilder(i);
        for (int i2 = 0; i2 < i; i2++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    static String jsUriEncode(String str) {
        return URLEncoder.encode(str, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
