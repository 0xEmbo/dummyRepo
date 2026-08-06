package burp.ultimus.crypto;

/**
 * Shared Ultimus HTML session-key capture used by the HTTP handler and editors.
 * Safe for large HTML: skips {@code data:image} blobs and never AES-decrypts multi-MB payloads.
 */
public final class UltimusSessionCapture {
    public static final int MAX_ASYNC_INGEST_BODY_BYTES = 2 * 1024 * 1024;

    private UltimusSessionCapture() {
    }

    public static boolean looksLikeUltimusHtml(String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        String lower = body.toLowerCase();
        return lower.contains("ultimuscps")
                && lower.contains("base64,")
                && (lower.contains("backgroundstyle") || lower.contains("octet-stream"));
    }

    /**
     * @return number of new sessions captured (0 or 1 with current KeyCache).
     */
    public static int capture(String html, KeyCache keyCache, UltimusCrypto crypto) {
        if (html == null || keyCache == null || crypto == null) {
            return 0;
        }
        if (!looksLikeUltimusHtml(html) && !html.toLowerCase().contains("base64,")) {
            return 0;
        }
        int before = keyCache.size();
        keyCache.ingestFromHtml(html, crypto);
        return Math.max(0, keyCache.size() - before);
    }
}
