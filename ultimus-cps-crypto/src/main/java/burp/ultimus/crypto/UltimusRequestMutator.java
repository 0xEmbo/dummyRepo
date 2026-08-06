package burp.ultimus.crypto;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.Optional;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusRequestMutator.class */
public final class UltimusRequestMutator {
    private UltimusRequestMutator() {
    }

    public static HttpRequest applyBodyPlaintext(HttpRequest httpRequest, String str, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        return refreshTokens(UltimusMessageParser.withEncryptedBody(httpRequest, ultimusCrypto.encrypt(UltimusPayloadCodec.collapseForEncryption(str), sessionMaterial.otk())), sessionMaterial, ultimusCrypto, ultimusRToken);
    }

    public static HttpRequest applyQueryPlaintext(HttpRequest httpRequest, String str, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        return UltimusMessageParser.withEncryptedQuery(httpRequest, UltimusQueryRefresher.refreshEncryptedQuery(UltimusPayloadCodec.collapseForEncryption(str), ultimusCrypto, ultimusRToken, sessionMaterial)).withUpdatedHeader("x-RToken", ultimusRToken.headerToken(sessionMaterial.otk(), sessionMaterial.sessionToken()));
    }

    public static HttpRequest refreshTokens(HttpRequest httpRequest, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        HttpRequest withUpdatedHeader = httpRequest.withUpdatedHeader("x-RToken", ultimusRToken.headerToken(sessionMaterial.otk(), sessionMaterial.sessionToken()));
        Optional<String> extractEncrprmFromQuery = UltimusMessageParser.extractEncrprmFromQuery(withUpdatedHeader);
        if (extractEncrprmFromQuery.isEmpty()) {
            return withUpdatedHeader;
        }
        return UltimusMessageParser.withEncryptedQuery(withUpdatedHeader, UltimusQueryRefresher.refreshEncryptedQuery(ultimusCrypto.decrypt(extractEncrprmFromQuery.get(), sessionMaterial.otk()), ultimusCrypto, ultimusRToken, sessionMaterial));
    }
}
