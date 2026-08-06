package burp.ultimus.crypto;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class KeyCache {
    /**
     * Session material embedded in Ultimus HTML is short (rsid + otk + encrypted token).
     * Image data-URIs also contain {@code base64,...} and must never be AES-decrypted —
     * that freezes Burp's HTTP pipeline (Repeater spins forever after image upload).
     */
    public static final int MAX_SESSION_BLOB_LENGTH = 4096;
    public static final int MIN_SESSION_BLOB_LENGTH = 32;

    private final ConcurrentHashMap<String, SessionMaterial> sessions = new ConcurrentHashMap<>();

    public void ingestFromHtml(String html, UltimusCrypto crypto) {
        if (html == null || html.isBlank() || crypto == null) {
            return;
        }
        // Index scan — never let a regex capture a multi-MB image data-URI.
        int from = 0;
        while (from < html.length()) {
            int marker = indexOfIgnoreCase(html, "base64,", from);
            if (marker < 0) {
                return;
            }
            int blobStart = marker + "base64,".length();
            // Skip optional whitespace after "base64,"
            while (blobStart < html.length() && Character.isWhitespace(html.charAt(blobStart))) {
                blobStart++;
            }
            if (isImageDataUri(html, marker)) {
                from = skipPastBlob(html, blobStart);
                continue;
            }
            int blobEnd = scanBase64End(html, blobStart);
            int blobLength = blobEnd - blobStart;
            if (blobLength > MAX_SESSION_BLOB_LENGTH) {
                from = skipPastBlob(html, blobStart);
                continue;
            }
            if (blobLength >= MIN_SESSION_BLOB_LENGTH) {
                String blob = html.substring(blobStart, blobEnd);
                if (tryIngestBlob(blob, crypto)) {
                    return;
                }
            }
            from = blobStart + Math.max(1, blobLength);
        }
    }

    private boolean tryIngestBlob(String blob, UltimusCrypto crypto) {
        try {
            // Strip whitespace/newlines that some pages insert into data-URIs.
            String compact = blob.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "");
            if (compact.length() < MIN_SESSION_BLOB_LENGTH) {
                return false;
            }
            String rsid = compact.substring(0, 16);
            String otk = compact.substring(16, 32);
            // Ciphertext may be percent-encoded or URL-safe base64 in HTML.
            String encryptedSession = compact.substring(32);
            String sessionToken = crypto.decrypt(encryptedSession, otk);
            sessions.put(rsid, new SessionMaterial(rsid, otk, sessionToken));
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    /**
     * True when {@code base64,} at {@code marker} sits inside a {@code data:image/...;base64,} URI.
     */
    static boolean isImageDataUri(String html, int base64Marker) {
        int dataIdx = lastIndexOfIgnoreCase(html, "data:", base64Marker);
        if (dataIdx < 0 || base64Marker - dataIdx > 96) {
            return false;
        }
        String prefix = html.substring(dataIdx, base64Marker).toLowerCase();
        return prefix.contains("image/");
    }

    static int scanBase64End(String html, int start) {
        int end = start;
        int max = Math.min(html.length(), start + MAX_SESSION_BLOB_LENGTH + 1);
        while (end < max) {
            char c = html.charAt(end);
            if (c == '"' || c == '\'' || c == ')' || c == '<' || c == '>' || c == ';' || Character.isWhitespace(c)) {
                break;
            }
            if (!isBlobChar(c)) {
                break;
            }
            end++;
        }
        return end;
    }

    /** Advance past a (possibly multi-MB) base64 blob to the next delimiter. */
    static int skipPastBlob(String html, int start) {
        int end = start;
        while (end < html.length()) {
            char c = html.charAt(end);
            if (c == '"' || c == '\'' || c == ')' || c == '<' || c == '>' || Character.isWhitespace(c)) {
                return end + 1;
            }
            if (!isBlobChar(c)) {
                return end + 1;
            }
            end++;
        }
        return html.length();
    }

    /** Standard / URL-safe base64 plus percent-encoding used in some Ultimus HTML embeds. */
    private static boolean isBlobChar(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '='
                || c == '-' || c == '_'
                || c == '%';
    }

    private static int indexOfIgnoreCase(String haystack, String needle, int fromIndex) {
        final int max = haystack.length() - needle.length();
        for (int i = Math.max(0, fromIndex); i <= max; ++i) {
            if (haystack.regionMatches(true, i, needle, 0, needle.length())) {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOfIgnoreCase(String haystack, String needle, int before) {
        int start = Math.min(before, haystack.length()) - needle.length();
        for (int i = start; i >= 0; --i) {
            if (haystack.regionMatches(true, i, needle, 0, needle.length())) {
                return i;
            }
        }
        return -1;
    }

    public Optional<SessionMaterial> getSession(String rsid) {
        if (rsid == null || rsid.isBlank()) {
            return Optional.empty();
        }
        SessionMaterial exact = sessions.get(rsid);
        if (exact != null) {
            return Optional.of(exact);
        }
        // Header casing can differ from the HTML-embedded RSID.
        for (var entry : sessions.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(rsid)) {
                return Optional.of(entry.getValue());
            }
        }
        return Optional.empty();
    }

    public Optional<String> getOtk(String rsid) {
        return getSession(rsid).map(SessionMaterial::otk);
    }

    public int size() {
        return sessions.size();
    }
}
