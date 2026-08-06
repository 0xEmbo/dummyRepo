package burp.ultimus.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.SessionMaterial;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusMessageParser;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.crypto.UltimusRequestMutator;

public class UltimusHttpHandler implements HttpHandler {
    /** Skip session ingest on oversized bodies (image uploads / large HTML with data-URIs). */
    private static final int MAX_SESSION_INGEST_BODY_CHARS = 2 * 1024 * 1024;

    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;
    private final MontoyaApi api;

    public UltimusHttpHandler(KeyCache keyCache, UltimusCrypto crypto, UltimusRToken rToken, MontoyaApi api) {
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.rToken = rToken;
        this.api = api;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        if (!shouldAttemptSessionCapture(response)) {
            return ResponseReceivedAction.continueWith(response);
        }
        String body = response.bodyToString();
        if (UltimusMessageParser.isUltimusHtml(body)) {
            int before = keyCache.size();
            keyCache.ingestFromHtml(body, crypto);
            if (keyCache.size() > before) {
                api.logging().logToOutput("Ultimus session captured (cache size: " + keyCache.size() + ")");
            }
        }
        return ResponseReceivedAction.continueWith(response);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (UltimusMessageParser.isMultipartOrBinary(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        // Cheap byte-length guard BEFORE bodyToString()/regex — image uploads often ship as
        // multi-MB JSON encrprm and would freeze Burp's send path (Repeater spins forever).
        if (request.body().length() > UltimusMessageParser.MAX_AUTO_ENCRYPT_CHARS) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (UltimusMessageParser.hasEncrprmInBody(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (!UltimusMessageParser.looksLikePlaintextJson(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        String body = request.bodyToString();
        String rsid = UltimusMessageParser.rsidFromRequest(request).orElse(null);
        if (rsid == null) {
            return RequestToBeSentAction.continueWith(request);
        }
        SessionMaterial session = keyCache.getSession(rsid).orElse(null);
        if (session == null) {
            api.logging().logToError("Ultimus: no session for RSID " + rsid + ". Load /UltimusCPS/ in browser first.");
            return RequestToBeSentAction.continueWith(request);
        }
        try {
            String plaintext = body == null ? "" : body.trim();
            HttpRequest encrypted = UltimusRequestMutator.applyBodyPlaintext(
                    request, plaintext, session, crypto, rToken);
            return RequestToBeSentAction.continueWith(encrypted);
        } catch (Exception exception) {
            api.logging().logToError("Ultimus auto-encrypt failed: " + exception.getMessage());
            return RequestToBeSentAction.continueWith(request);
        }
    }

    private static boolean shouldAttemptSessionCapture(HttpResponseReceived response) {
        if (response == null) {
            return false;
        }
        String contentType = response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .map(h -> h.value())
                .findFirst()
                .orElse("");
        String lower = contentType.toLowerCase();
        if (lower.contains("image/")
                || lower.contains("multipart/")
                || lower.contains("application/octet-stream")
                || lower.contains("application/pdf")
                || lower.contains("video/")
                || lower.contains("audio/")
                || lower.contains("font/")) {
            return false;
        }
        // body().length() is byte length; cheap and avoids bodyToString() on huge payloads
        return response.body().length() > 0 && response.body().length() <= MAX_SESSION_INGEST_BODY_CHARS;
    }
}
