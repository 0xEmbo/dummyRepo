package burp.ultimus.crypto;

import burp.api.montoya.http.message.responses.HttpResponse;

public final class UltimusResponseMutator {
    private UltimusResponseMutator() {
    }

    /**
     * Encrypts edited plaintext and writes it back into the response {@code encrdata} field.
     * Uses the same encode/encrypt helpers as requests; crypto algorithm is unchanged.
     */
    public static HttpResponse applyPlaintext(HttpResponse response, String plaintextJson, String otk, UltimusCrypto crypto) {
        String collapsed;
        try {
            collapsed = UltimusPayloadCodec.collapseForEncryption(plaintextJson);
        } catch (RuntimeException ignored) {
            collapsed = plaintextJson == null ? "" : plaintextJson.trim();
        }
        String encrypted = crypto.encrypt(collapsed, otk);
        String newBody = UltimusMessageParser.withEncryptedEncrdataBody(response.bodyToString(), encrypted);
        return response.withBody(newBody);
    }
}
