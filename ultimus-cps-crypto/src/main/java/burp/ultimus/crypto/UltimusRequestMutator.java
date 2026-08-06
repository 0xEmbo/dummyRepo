package burp.ultimus.crypto;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.Optional;

public final class UltimusRequestMutator {
    private UltimusRequestMutator() {
    }

    public static HttpRequest applyBodyPlaintext(HttpRequest request, String plaintextJson, SessionMaterial session, UltimusCrypto crypto, UltimusRToken rToken) {
        String collapsed = UltimusPayloadCodec.collapseForEncryption(plaintextJson);
        String encrypted = crypto.encrypt(collapsed, session.otk());
        HttpRequest withBody = UltimusMessageParser.withEncryptedBody(request, encrypted);
        return refreshTokens(withBody, session, crypto, rToken);
    }

    public static HttpRequest applyQueryPlaintext(HttpRequest request, String plaintextJson, SessionMaterial session, UltimusCrypto crypto, UltimusRToken rToken) {
        String collapsed = UltimusPayloadCodec.collapseForEncryption(plaintextJson);
        String encryptedQuery = UltimusQueryRefresher.refreshEncryptedQuery(collapsed, crypto, rToken, session);
        HttpRequest withQuery = UltimusMessageParser.withEncryptedQuery(request, encryptedQuery);
        return withQuery.withUpdatedHeader("x-RToken", rToken.headerToken(session.otk(), session.sessionToken()));
    }

    public static HttpRequest refreshTokens(HttpRequest request, SessionMaterial session, UltimusCrypto crypto, UltimusRToken rToken) {
        HttpRequest updated = request.withUpdatedHeader("x-RToken", rToken.headerToken(session.otk(), session.sessionToken()));
        Optional<String> queryEncrprm = UltimusMessageParser.extractEncrprmFromQuery(updated);
        if (queryEncrprm.isEmpty()) {
            return updated;
        }
        String decrypted = crypto.decrypt(queryEncrprm.get(), session.otk());
        String refreshed = UltimusQueryRefresher.refreshEncryptedQuery(decrypted, crypto, rToken, session);
        return UltimusMessageParser.withEncryptedQuery(updated, refreshed);
    }
}
