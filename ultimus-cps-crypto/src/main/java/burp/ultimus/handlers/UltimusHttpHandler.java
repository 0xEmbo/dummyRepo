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
import burp.ultimus.crypto.UltimusSessionCapture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HTTP handler that must never block Burp's send/receive pipeline.
 * Session ingest runs on a background thread; auto-encrypt is limited to tiny JSON bodies.
 */
public class UltimusHttpHandler implements HttpHandler {
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
        // Prefer Proxy (browser). Also accept Repeater/other for small Ultimus HTML so
        // "open /UltimusCPS/ in Repeater" still caches keys — ingest is async + image-safe.
        boolean fromProxy = response.toolSource() == null || response.toolSource().isFromTool(ToolType.PROXY);
        if (!looksLikeCapturableResponse(response)) {
            return;
        }
        int bodyLen = response.body().length();
        if (bodyLen <= 0 || bodyLen > UltimusSessionCapture.MAX_ASYNC_INGEST_BODY_BYTES) {
            return;
        }
        // For non-Proxy tools, only attempt on clearly small pages to avoid upload responses.
        if (!fromProxy && bodyLen > 256 * 1024) {
            return;
        }
        final String body = response.bodyToString();
        if (body == null || body.length() > UltimusSessionCapture.MAX_ASYNC_INGEST_BODY_BYTES) {
            return;
        }
        if (!UltimusSessionCapture.looksLikeUltimusHtml(body)) {
            return;
        }
        // Skip scheduling pure image-upload HTML shells with no octet-stream session marker.
        if (body.toLowerCase().contains("data:image") && !body.toLowerCase().contains("octet-stream")) {
            return;
        }
        ingestExecutor.execute(() -> {
            try {
                int added = UltimusSessionCapture.capture(body, keyCache, crypto);
                if (added > 0) {
                    api.logging().logToOutput("Ultimus session captured (cache size: " + keyCache.size() + ")");
                } else if (UltimusSessionCapture.looksLikeUltimusHtml(body)) {
                    api.logging().logToOutput(
                            "Ultimus HTML seen but no session blob decrypted yet (cache size: "
                                    + keyCache.size() + "). Open the /UltimusCPS/ response Ultimus tab.");
                }
            } catch (Throwable throwable) {
                api.logging().logToError("Ultimus session ingest failed: " + throwable.getMessage());
            }
        });
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
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

    private static boolean looksLikeCapturableResponse(HttpResponseReceived response) {
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
                || lower.contains("application/json")
                || lower.contains("video/")
                || lower.contains("audio/")
                || lower.contains("font/")) {
            return false;
        }
        if (lower.isEmpty()) {
            return true;
        }
        return lower.contains("text/html")
                || lower.contains("text/plain")
                || lower.contains("application/xhtml")
                || lower.contains("javascript");
    }
}
