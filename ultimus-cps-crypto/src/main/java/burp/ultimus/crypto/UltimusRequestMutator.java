package burp.ultimus.crypto;

import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.Optional;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusRequestMutator.class */
public final class UltimusRequestMutator {
    private UltimusRequestMutator() {
    }

    public static HttpRequest applyBodyPlaintext(HttpRequest httpRequest, String str, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        // Encrypt body only. Do not decrypt/re-encrypt query encrprm — that hangs/fails
        // on dual-encrprm RunAction requests (query + ~500KB body ciphertext).
        HttpRequest withBody = UltimusMessageParser.withEncryptedBody(
                httpRequest,
                ultimusCrypto.encrypt(UltimusPayloadCodec.collapseForEncryption(str), sessionMaterial.otk()));
        return withBody.withUpdatedHeader(
                "x-RToken",
                ultimusRToken.headerToken(sessionMaterial.otk(), sessionMaterial.sessionToken()));
    }

    public static HttpRequest applyQueryPlaintext(HttpRequest httpRequest, String str, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        return UltimusMessageParser.withEncryptedQuery(httpRequest, UltimusQueryRefresher.refreshEncryptedQuery(str, ultimusCrypto, ultimusRToken, sessionMaterial)).withUpdatedHeader("x-RToken", ultimusRToken.headerToken(sessionMaterial.otk(), sessionMaterial.sessionToken()));
    }

    public static HttpRequest refreshTokens(HttpRequest httpRequest, SessionMaterial sessionMaterial, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        HttpRequest withUpdatedHeader = httpRequest.withUpdatedHeader("x-RToken", ultimusRToken.headerToken(sessionMaterial.otk(), sessionMaterial.sessionToken()));
        // Body already carries the action payload — leave query encrprm alone.
        if (UltimusMessageParser.hasEncrprmInBody(withUpdatedHeader)) {
            return withUpdatedHeader;
        }
        Optional<String> extractEncrprmFromQuery = UltimusMessageParser.extractEncrprmFromQuery(withUpdatedHeader);
        if (extractEncrprmFromQuery.isEmpty()) {
            return withUpdatedHeader;
        }
        return UltimusMessageParser.withEncryptedQuery(withUpdatedHeader, UltimusQueryRefresher.refreshEncryptedQuery(ultimusCrypto.decrypt(extractEncrprmFromQuery.get(), sessionMaterial.otk()), ultimusCrypto, ultimusRToken, sessionMaterial));
    }
}
