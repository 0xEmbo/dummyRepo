package burp.ultimus.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class UltimusSessionCaptureTest {
    private static final String RSID = "63ig4KXRUugPDmE1";
    private static final String OTK = "0123456789abcdef";

    @Test
    void capturesAlphanumericRsidLikeProduction() {
        UltimusCrypto crypto = new UltimusCrypto();
        String token = "sess-token-xyz";
        String blob = RSID + OTK + crypto.encrypt(token, OTK);
        String html = "<html class=\"UltimusCPS\"><div backgroundstyle=\"url(data:application/octet-stream;base64,"
                + blob + ")\"></div></html>";

        KeyCache cache = new KeyCache();
        assertEquals(1, UltimusSessionCapture.capture(html, cache, crypto));
        assertEquals(token, cache.getSession(RSID).orElseThrow().sessionToken());
        // Case-insensitive RSID lookup (header casing)
        assertTrue(cache.getSession(RSID.toLowerCase()).isPresent());
    }

    @Test
    void capturesPercentEncodedCiphertextInHtml() {
        UltimusCrypto crypto = new UltimusCrypto();
        String token = "sess-token-pct";
        String encrypted = crypto.encrypt(token, OTK);
        String encoded = URLEncoder.encode(encrypted, StandardCharsets.UTF_8).replace("+", "%20");
        String blob = RSID + OTK + encoded;
        String html = "<html UltimusCPS backgroundstyle=\"data:application/octet-stream;base64," + blob + "\"></html>";

        KeyCache cache = new KeyCache();
        assertTimeoutPreemptively(Duration.ofSeconds(3),
                () -> assertEquals(1, UltimusSessionCapture.capture(html, cache, crypto)));
        assertEquals(token, cache.getSession(RSID).orElseThrow().sessionToken());
    }

    @Test
    void looksLikeUltimusHtmlIsCaseInsensitive() {
        assertTrue(UltimusSessionCapture.looksLikeUltimusHtml(
                "<HTML>ultimuscps BACKGROUNDSTYLE=\"BASE64,abc\"</HTML>"));
    }
}
