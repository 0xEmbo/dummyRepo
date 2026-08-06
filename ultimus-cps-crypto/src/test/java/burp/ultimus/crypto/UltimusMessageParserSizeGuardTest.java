package burp.ultimus.crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class UltimusMessageParserSizeGuardTest {
    @Test
    void hasEditableEncrdataRejectsHugeCiphertextWithoutAllocatingGroupSemantics() {
        String huge = "A".repeat(UltimusMessageParser.MAX_EDITOR_CIPHERTEXT_CHARS + 1);
        String body = "{\"encrdata\":\"" + huge + "\"}";
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            assertTrue(UltimusMessageParser.hasEncrdata(body));
            assertFalse(UltimusMessageParser.hasEditableEncrdata(body));
        });
    }

    @Test
    void hasEditableEncrdataAcceptsNormalCiphertext() {
        String body = "{\"encrdata\":\"c2hvcnQ=\"}";
        assertTrue(UltimusMessageParser.hasEditableEncrdata(body));
    }

    @Test
    void isUltimusHtmlStillWorks() {
        assertTrue(UltimusMessageParser.isUltimusHtml(
                "<html UltimusCPS backgroundstyle=\"base64,abc\"></html>"));
    }
}
