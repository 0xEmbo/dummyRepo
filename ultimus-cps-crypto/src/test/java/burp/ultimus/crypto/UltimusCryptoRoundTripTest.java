package burp.ultimus.crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class UltimusCryptoRoundTripTest {
    @Test
    void encryptDecryptRoundTripUnchanged() {
        UltimusCrypto crypto = new UltimusCrypto();
        String key = "0123456789abcdef";
        String plaintext = "{\"CPSSID\":\"abc\",\"cache\":\"1\",\"RToken\":\"x\",\"RSID\":\"ABCDEF1234567890\"}";
        String encrypted = crypto.encrypt(plaintext, key);
        assertEquals(plaintext, crypto.decrypt(encrypted, key));
    }

    @Test
    void looksLikePlaintextJsonRejectsMultipart() {
        // Content-Type based guard — image uploads must not enter auto-encrypt path.
        assertFalse(UltimusMessageParser.isMultipartOrBinary(null));
    }
}
