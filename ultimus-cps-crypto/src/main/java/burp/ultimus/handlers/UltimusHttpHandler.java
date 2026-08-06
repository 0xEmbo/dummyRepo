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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HTTP handler that must never block Burp's send/receive pipeline.
 * Session ingest runs on a background thread; auto-encrypt is limited to tiny JSON bodies.
 */
public class UltimusHttpHandler implements HttpHandler {
    /** Only tiny HTML session pages — never upload responses. */
    private static final int MAX_SESSION_INGEST_BODY_BYTES = 64 * 1024;

    /** Auto-encrypt only small plaintext JSON; image uploads must pass through untouched. */
    private static final int MAX_AUTO_ENCRYPT_BODY_BYTES = 64 * 1024;

    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;
    private final MontoyaApi api;
    private final ExecutorService ingestExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "ultimus-session-ingest");
        thread.setDaemon(true);
        return thread;
    });

    public UltimusHttpHandler(KeyCache keyCache, UltimusCrypto crypto, UltimusRToken rToken, MontoyaApi api) {
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.rToken = rToken;
        this.api = api;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        // ALWAYS return immediately — never AES/regex on this thread.
        try {
            scheduleSessionCapture(response);
        } catch (Throwable throwable) {
            api.logging().logToError("Ultimus session schedule skipped: " + throwable.getMessage());
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private void scheduleSessionCapture(HttpResponseReceived response) {
        if (response == null) {
            return;
        }
        if (response.toolSource() != null && !response.toolSource().isFromTool(ToolType.PROXY)) {
            return;
        }
        if (!looksLikeSmallHtml(response)) {
            return;
        }
        int bodyLen = response.body().length();
        if (bodyLen <= 0 || bodyLen > MAX_SESSION_INGEST_BODY_BYTES) {
            return;
        }
        // Copy body off the request object, then process async.
        final String body = response.bodyToString();
        if (body == null || body.length() > MAX_SESSION_INGEST_BODY_BYTES) {
            return;
        }
        if (!UltimusMessageParser.isUltimusHtml(body)) {
            return;
        }
        ingestExecutor.execute(() -> {
            try {
                int before = keyCache.size();
                keyCache.ingestFromHtml(body, crypto);
                if (keyCache.size() > before) {
                    api.logging().logToOutput("Ultimus session captured (cache size: " + keyCache.size() + ")");
                }
            } catch (Throwable throwable) {
                api.logging().logToError("Ultimus session ingest failed: " + throwable.getMessage());
            }
        });
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        // Default: pass through. Only tiny plaintext Ultimus JSON is auto-encrypted.
        try {
            HttpRequest maybeEncrypted = maybeAutoEncrypt(request);
            return RequestToBeSentAction.continueWith(maybeEncrypted);
        } catch (Throwable throwable) {
            api.logging().logToError("Ultimus auto-encrypt skipped: " + throwable.getMessage());
            return RequestToBeSentAction.continueWith(request);
        }
    }

    private HttpRequest maybeAutoEncrypt(HttpRequestToBeSent request) {
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            return request;
        }
        if (UltimusMessageParser.isMultipartOrBinary(request)) {
            return request;
        }
        int bodyLen = request.body().length();
        // Image uploads and large encrprm JSON — do nothing.
        if (bodyLen <= 0 || bodyLen > MAX_AUTO_ENCRYPT_BODY_BYTES) {
            return request;
        }
        if (UltimusMessageParser.hasEncrprmInBody(request)) {
            return request;
        }
        if (!UltimusMessageParser.looksLikePlaintextJson(request)) {
            return request;
        }
        String rsid = UltimusMessageParser.rsidFromRequest(request).orElse(null);
        if (rsid == null) {
            return request;
        }
        SessionMaterial session = keyCache.getSession(rsid).orElse(null);
        if (session == null) {
            return request;
        }
        String body = request.bodyToString();
        String plaintext = body == null ? "" : body.trim();
        return UltimusRequestMutator.applyBodyPlaintext(request, plaintext, session, crypto, rToken);
    }

    private static boolean looksLikeSmallHtml(HttpResponseReceived response) {
        String contentType = response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .map(h -> h.value())
                .findFirst()
                .orElse("");
        String lower = contentType.toLowerCase();
        if (lower.isEmpty()) {
            return true; // may still be HTML without header
        }
        return lower.contains("text/html")
                || lower.contains("text/plain")
                || lower.contains("application/xhtml");
    }
}
