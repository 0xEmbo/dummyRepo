package burp.ultimus.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class KeyCacheImageUploadHangTest {
    private static final String RSID = "ABCDEF1234567890";
    private static final String OTK = "0123456789abcdef"; // 16 bytes for AES-128

    @Test
    void ingestSkipsHugeImageDataUriWithoutHanging() {
        UltimusCrypto crypto = new UltimusCrypto();
        String sessionToken = "session-token-value";
        String encryptedSession = crypto.encrypt(sessionToken, OTK);
        String sessionBlob = RSID + OTK + encryptedSession;

        // Simulate Ultimus HTML that also embeds a multi-MB image data-URI (upload response / CSS).
        // The buggy extension AES-decrypted this blob and froze Burp Repeater forever.
        String hugeImage = "A".repeat(3 * 1024 * 1024);
        String html = ""
                + "<html><body class=\"UltimusCPS\">"
                + "<div style=\"backgroundstyle:url(data:image/png;base64," + hugeImage + ")\"></div>"
                + "<div style=\"backgroundstyle:url(data:application/octet-stream;base64," + sessionBlob + ")\"></div>"
                + "</body></html>";

        KeyCache cache = new KeyCache();
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> cache.ingestFromHtml(html, crypto));

        assertEquals(1, cache.size());
        SessionMaterial session = cache.getSession(RSID).orElseThrow();
        assertEquals(OTK, session.otk());
        assertEquals(sessionToken, session.sessionToken());
    }

    @Test
    void ingestIgnoresHugeBlobOnlyHtml() {
        UltimusCrypto crypto = new UltimusCrypto();
        String hugeImage = Base64.getEncoder().encodeToString(("PNG" + "B".repeat(2 * 1024 * 1024)).getBytes());
        String html = "<html UltimusCPS><div backgroundstyle=\"data:image/jpeg;base64," + hugeImage + "\"></div></html>";

        KeyCache cache = new KeyCache();
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> cache.ingestFromHtml(html, crypto));
        assertEquals(0, cache.size());
    }

    @Test
    void isUltimusHtmlStillRecognizesSessionPages() {
        String html = "<html><body UltimusCPS backgroundstyle=\"base64,abc\"></body></html>";
        assertTrue(UltimusMessageParser.isUltimusHtml(html));
    }
}
