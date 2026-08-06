package burp.ultimus.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UltimusResponseMutatorTest {
    @Test
    void withEncryptedEncrdataBodyPreservesSiblingFields() {
        String original = "{\"status\":\"ok\",\"encrdata\":\"OLD\",\"meta\":1}";
        String updated = UltimusMessageParser.withEncryptedEncrdataBody(original, "NEW+VALUE/abc=");
        assertTrue(updated.contains("\"encrdata\":\"NEW+VALUE/abc=\""));
        assertTrue(updated.contains("\"status\":\"ok\""));
        assertTrue(updated.contains("\"meta\":1"));
        assertEquals("NEW+VALUE/abc=", UltimusMessageParser.extractEncrdata(updated).orElseThrow());
    }

    @Test
    void withEncryptedEncrdataBodyCreatesBodyWhenMissing() {
        String updated = UltimusMessageParser.withEncryptedEncrdataBody("", "cipher");
        assertEquals("{\"encrdata\":\"cipher\"}", updated);
    }

    @Test
    void encryptDecryptRoundTripForEditedResponsePayload() {
        UltimusCrypto crypto = new UltimusCrypto();
        String otk = "0123456789abcdef";
        String plaintext = "{\"result\":\"ok\",\"items\":\"{\\\"id\\\":1}\"}";
        String encrypted = crypto.encrypt(plaintext, otk);
        String body = UltimusMessageParser.withEncryptedEncrdataBody(null, encrypted);

        String extracted = UltimusMessageParser.extractEncrdata(body).orElseThrow();
        assertEquals(plaintext, crypto.decrypt(extracted, otk));

        String edited = "{\"result\":\"patched\",\"value\":42}";
        String collapsed = UltimusPayloadCodec.collapseForEncryption(edited);
        String reEncrypted = crypto.encrypt(collapsed, otk);
        String newBody = UltimusMessageParser.withEncryptedEncrdataBody(body, reEncrypted);
        assertEquals(collapsed, crypto.decrypt(UltimusMessageParser.extractEncrdata(newBody).orElseThrow(), otk));
    }
}
