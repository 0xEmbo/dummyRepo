package burp.ultimus.crypto;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/KeyCache.class */
public class KeyCache {
    private static final Pattern BACKGROUND_PATTERN = Pattern.compile("base64,([^\"'\\s)]+)", 2);
    private final ConcurrentHashMap<String, SessionMaterial> sessions = new ConcurrentHashMap<>();

    public void ingestFromHtml(String str, UltimusCrypto ultimusCrypto) {
        if (str == null || str.isBlank() || ultimusCrypto == null) {
            return;
        }
        Matcher matcher = BACKGROUND_PATTERN.matcher(str);
        if (!matcher.find()) {
            return;
        }
        String group = matcher.group(1);
        if (group.length() < 32) {
            return;
        }
        String substring = group.substring(0, 16);
        String substring2 = group.substring(16, 32);
        this.sessions.put(substring, new SessionMaterial(substring, substring2, ultimusCrypto.decrypt(group.substring(32), substring2)));
    }

    public Optional<SessionMaterial> getSession(String str) {
        if (str == null || str.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(this.sessions.get(str));
    }

    public Optional<String> getOtk(String str) {
        return getSession(str).map((v0) -> {
            return v0.otk();
        });
    }

    public int size() {
        return this.sessions.size();
    }
}
