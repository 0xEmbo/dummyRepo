package burp.ultimus.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.SessionMaterial;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusMessageParser;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.crypto.UltimusRequestMutator;

public class UltimusHttpHandler implements HttpHandler {
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;
    private final MontoyaApi api;

    public UltimusHttpHandler(KeyCache keyCache, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken, MontoyaApi montoyaApi) {
        this.keyCache = keyCache;
        this.crypto = ultimusCrypto;
        this.rToken = ultimusRToken;
        this.api = montoyaApi;
    }

    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        // Skip binary/image responses so large upload responses do not block Burp on bodyToString/HTML scan.
        if (!UltimusMessageParser.looksLikeHtmlCandidate(httpResponseReceived.headerValue("Content-Type"))) {
            return ResponseReceivedAction.continueWith(httpResponseReceived);
        }
        String bodyToString = httpResponseReceived.bodyToString();
        if (UltimusMessageParser.isUltimusHtml(bodyToString)) {
            int size = this.keyCache.size();
            this.keyCache.ingestFromHtml(bodyToString, this.crypto);
            if (this.keyCache.size() > size) {
                this.api.logging().logToOutput("Ultimus session captured (cache size: " + this.keyCache.size() + ")");
            }
        }
        return ResponseReceivedAction.continueWith(httpResponseReceived);
    }

    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        if (!UltimusMessageParser.isUltimusRequest(httpRequestToBeSent)) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        if (UltimusMessageParser.hasEncrprmInBody(httpRequestToBeSent)) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        if (!UltimusMessageParser.looksLikePlaintextJson(httpRequestToBeSent)) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        String orElse = UltimusMessageParser.rsidFromRequest(httpRequestToBeSent).orElse(null);
        if (orElse == null) {
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        SessionMaterial orElse2 = this.keyCache.getSession(orElse).orElse(null);
        if (orElse2 == null) {
            this.api.logging().logToError("Ultimus: no session for RSID " + orElse + ". Load /UltimusCPS/ in browser first.");
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
        try {
            return RequestToBeSentAction.continueWith(UltimusRequestMutator.applyBodyPlaintext(httpRequestToBeSent, httpRequestToBeSent.bodyToString().trim(), orElse2, this.crypto, this.rToken));
        } catch (Exception e) {
            this.api.logging().logToError("Ultimus auto-encrypt failed: " + e.getMessage());
            return RequestToBeSentAction.continueWith(httpRequestToBeSent);
        }
    }
}
