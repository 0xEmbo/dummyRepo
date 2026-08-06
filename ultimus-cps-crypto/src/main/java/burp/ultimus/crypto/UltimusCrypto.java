package burp.ultimus.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class UltimusCrypto {
    private static final byte[] ZERO_IV = new byte[16];

    public String encrypt(String plaintext, String key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, (Key) new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES"), new IvParameterSpec(ZERO_IV));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception exception) {
            throw new IllegalStateException("Encryption failed: " + exception.getMessage(), exception);
        }
    }

    public String decrypt(String ciphertext, String key) {
        try {
            String normalized = normalizeCiphertext(ciphertext);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, (Key) new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES"), new IvParameterSpec(ZERO_IV));
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(normalized));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception exception) {
            throw new IllegalStateException("Decryption failed: " + exception.getMessage(), exception);
        }
    }

    static String normalizeCiphertext(String ciphertext) {
        if (ciphertext == null) {
            return "";
        }
        String normalized = ciphertext.trim();
        normalized = percentDecode(normalized);
        normalized = normalized.replace(' ', '+');
        normalized = normalized.replace("\r", "").replace("\n", "").replace("\t", "");
        return normalized;
    }

    private static String percentDecode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); ++i) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                int hi = Character.digit(value.charAt(i + 1), 16);
                int lo = Character.digit(value.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.append((char) (hi << 4 | lo));
                    i += 2;
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }
}
