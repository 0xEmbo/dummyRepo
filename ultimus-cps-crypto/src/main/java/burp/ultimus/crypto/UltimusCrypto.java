package burp.ultimus.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusCrypto.class */
public class UltimusCrypto {
    private static final byte[] ZERO_IV = new byte[16];

    public String encrypt(String str, String str2) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(1, new SecretKeySpec(str2.getBytes(StandardCharsets.UTF_8), "AES"), new IvParameterSpec(ZERO_IV));
            return Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed: " + e.getMessage(), e);
        }
    }

    public String decrypt(String str, String str2) {
        try {
            String normalizeCiphertext = normalizeCiphertext(str);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, new SecretKeySpec(str2.getBytes(StandardCharsets.UTF_8), "AES"), new IvParameterSpec(ZERO_IV));
            return new String(cipher.doFinal(Base64.getDecoder().decode(normalizeCiphertext)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed: " + e.getMessage(), e);
        }
    }

    static String normalizeCiphertext(String str) {
        if (str == null) {
            return "";
        }
        return percentDecode(str.trim()).replace(' ', '+').replace("\r", "").replace("\n", "").replace("\t", "");
    }

    private static String percentDecode(String str) {
        StringBuilder sb = new StringBuilder(str.length());
        int i = 0;
        while (i < str.length()) {
            char charAt = str.charAt(i);
            if (charAt == '%' && i + 2 < str.length()) {
                int digit = Character.digit(str.charAt(i + 1), 16);
                int digit2 = Character.digit(str.charAt(i + 2), 16);
                if (digit >= 0 && digit2 >= 0) {
                    sb.append((char) ((digit << 4) | digit2));
                    i += 2;
                    i++;
                }
            }
            sb.append(charAt);
            i++;
        }
        return sb.toString();
    }
}
