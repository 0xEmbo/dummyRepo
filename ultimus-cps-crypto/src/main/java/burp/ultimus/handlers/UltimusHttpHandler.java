package burp.ultimus.handlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
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
    /**
     * Session pages are small. Anything larger is almost certainly an upload/HTML shell with
     * embedded images — never run ingest on those (Repeater hang).
     */
    private static final int MAX_SESSION_INGEST_BODY_BYTES = 512 * 1024;

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
        try {
            maybeCaptureSession(response);
        } catch (Throwable throwable) {
            // Never block Burp's HTTP pipeline — a hang here = Repeater spinning forever.
            api.logging().logToError("Ultimus session capture skipped: " + throwable.getMessage());
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private void maybeCaptureSession(HttpResponseReceived response) {
        if (response == null) {
            return;
        }
        // Session keys come from browsing /UltimusCPS/ through Proxy — never from Repeater uploads.
        if (response.toolSource() != null && !response.toolSource().isFromTool(ToolType.PROXY)) {
            return;
        }
        if (!shouldAttemptSessionCapture(response)) {
            return;
        }
        String body = response.bodyToString();
        if (body == null || body.length() > MAX_SESSION_INGEST_BODY_BYTES) {
            return;
        }
        if (!UltimusMessageParser.isUltimusHtml(body)) {
            return;
        }
        int before = keyCache.size();
        keyCache.ingestFromHtml(body, crypto);
        if (keyCache.size() > before) {
            api.logging().logToOutput("Ultimus session captured (cache size: " + keyCache.size() + ")");
        }
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            return maybeAutoEncrypt(request);
        } catch (Throwable throwable) {
            api.logging().logToError("Ultimus auto-encrypt skipped: " + throwable.getMessage());
            return RequestToBeSentAction.continueWith(request);
        }
    }

    private RequestToBeSentAction maybeAutoEncrypt(HttpRequestToBeSent request) {
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        if (UltimusMessageParser.isMultipartOrBinary(request)) {
            return RequestToBeSentAction.continueWith(request);
        }
        // Cheap byte-length guard BEFORE bodyToString()/regex.
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
        String plaintext = body == null ? "" : body.trim();
        HttpRequest encrypted = UltimusRequestMutator.applyBodyPlaintext(
                request, plaintext, session, crypto, rToken);
        return RequestToBeSentAction.continueWith(encrypted);
    }

    private static boolean shouldAttemptSessionCapture(HttpResponseReceived response) {
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
                || lower.contains("font/")
                || lower.contains("json")) {
            return false;
        }
        int bodyLen = response.body().length();
        return bodyLen > 0 && bodyLen <= MAX_SESSION_INGEST_BODY_BYTES;
    }
}
