package burp.ultimus.crypto;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class KeyCache {
    /**
     * Session material embedded in Ultimus HTML is short (rsid + otk + encrypted token).
     * Without a length cap, CSS/image data-URIs matching {@code base64,...} get treated as
     * session blobs and AES-decrypting multi-MB payloads freezes Burp's HTTP pipeline
     * (classic symptom: Repeater spins forever after image upload).
     */
    public static final int MAX_SESSION_BLOB_LENGTH = 4096;
    public static final int MIN_SESSION_BLOB_LENGTH = 32;
    private static final Pattern BACKGROUND_PATTERN = Pattern.compile("base64,([^\"'\\s)]+)", Pattern.CASE_INSENSITIVE);
    private final ConcurrentHashMap<String, SessionMaterial> sessions = new ConcurrentHashMap<>();

    public void ingestFromHtml(String html, UltimusCrypto crypto) {
        if (html == null || html.isBlank() || crypto == null) {
            return;
        }
        Matcher matcher = BACKGROUND_PATTERN.matcher(html);
        while (matcher.find()) {
            int blobLength = matcher.end(1) - matcher.start(1);
            // Check length via indices first — avoids allocating multi-MB strings for image data-URIs.
            if (blobLength < MIN_SESSION_BLOB_LENGTH || blobLength > MAX_SESSION_BLOB_LENGTH) {
                continue;
            }
            String blob = matcher.group(1);
            try {
                String rsid = blob.substring(0, 16);
                String otk = blob.substring(16, 32);
                String encryptedSession = blob.substring(32);
                String sessionToken = crypto.decrypt(encryptedSession, otk);
                sessions.put(rsid, new SessionMaterial(rsid, otk, sessionToken));
                return;
            } catch (RuntimeException ignored) {
                // Not session material (e.g. truncated image data-URI) — try next match.
            }
        }
    }

    public Optional<SessionMaterial> getSession(String rsid) {
        if (rsid == null || rsid.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(rsid));
    }

    public Optional<String> getOtk(String rsid) {
        return getSession(rsid).map(SessionMaterial::otk);
    }

    public int size() {
        return sessions.size();
    }
}
