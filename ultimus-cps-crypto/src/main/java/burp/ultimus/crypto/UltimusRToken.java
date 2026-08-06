package burp.ultimus.crypto;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class UltimusRToken {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final UltimusCrypto crypto;
    private static final DateTimeFormatter SERVER_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    public UltimusRToken(UltimusCrypto crypto) {
        this.crypto = crypto;
    }

    public String headerToken(String otk, String sessionToken) {
        return crypto.encrypt(buildPayload(sessionToken, 0), otk);
    }

    public String queryToken(String otk, String sessionToken, String search) {
        int hash = search == null ? 0 : jsHashCode(search);
        return jsUriEncode(crypto.encrypt(buildPayload(sessionToken, hash), otk));
    }

    private static String buildPayload(String sessionToken, int hash) {
        return makeRandom(16) + "|" + sessionToken + "|" + SERVER_TIME.format(Instant.now()) + "|" + hash;
    }

    static int jsHashCode(String value) {
        int hash = 0;
        for (int i = 0; i < value.length(); ++i) {
            hash = (hash << 5) - hash + value.charAt(i) | 0;
        }
        return hash;
    }

    static String makeRandom(int length) {
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; ++i) {
            out.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return out.toString();
    }

    static String jsUriEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
