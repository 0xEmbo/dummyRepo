package burp.ultimus.crypto;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UltimusMessageParser {
    private static final Pattern ENCRPRM_QUERY = Pattern.compile("[?&]encrprm=([^&#\\s]+)");
    private static final Pattern ENCRPRM_BODY = Pattern.compile("\"encrprm\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ENCRDATA_BODY = Pattern.compile("\"encrdata\"\\s*:\\s*\"([^\"]+)\"");

    /** Soft cap for editor pretty-print / expand; larger bodies stay compact to avoid UI freezes. */
    public static final int MAX_EDITOR_PRETTY_CHARS = 256 * 1024;

    /** Soft cap for showing Ultimus editor tabs / decrypting ciphertext in the UI. */
    public static final int MAX_EDITOR_BODY_BYTES = 256 * 1024;

    /** Soft cap for encrprm/encrdata ciphertext length before decrypt-in-editor. */
    public static final int MAX_EDITOR_CIPHERTEXT_CHARS = 128 * 1024;

    /** Soft cap for auto-encrypt in the HTTP handler (Repeater/proxy path). */
    public static final int MAX_AUTO_ENCRYPT_CHARS = 64 * 1024;

    private UltimusMessageParser() {
    }

    public static boolean isUltimusRequest(HttpRequest request) {
        return request != null && request.url().contains("/UltimusCPS/");
    }

    public static boolean isUltimusHtml(String body) {
        return UltimusSessionCapture.looksLikeUltimusHtml(body);
    }

    public static boolean isMultipartOrBinary(HttpRequest request) {
        if (request == null) {
            return false;
        }
        return isBinaryContentTypeValue(headerValue(request, "Content-Type"));
    }

    public static boolean isBinaryContentType(HttpResponse response) {
        if (response == null) {
            return false;
        }
        String contentType = response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                .map(h -> h.value())
                .findFirst()
                .orElse(null);
        return isBinaryContentTypeValue(contentType);
    }

    private static boolean isBinaryContentTypeValue(String contentType) {
        if (contentType == null) {
            return false;
        }
        String lower = contentType.toLowerCase();
        return lower.contains("multipart/")
                || lower.contains("application/octet-stream")
                || lower.contains("image/")
                || lower.contains("application/pdf")
                || lower.contains("video/")
                || lower.contains("audio/");
    }

    public static Optional<String> rsidFromRequest(HttpRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("rsid"))
                .map(h -> h.value())
                .findFirst();
    }

    public static Optional<String> cpssidFromRequest(HttpRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("cpssid"))
                .map(h -> h.value())
                .findFirst();
    }

    private static String headerValue(HttpRequest request, String name) {
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst()
                .orElse(null);
    }

    public static Optional<String> extractEncrprmFromQuery(HttpRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        Matcher matcher = ENCRPRM_QUERY.matcher(request.path());
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    public static Optional<String> extractEncrprmFromBody(HttpRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        String body = request.bodyToString();
        if (body != null && !body.isBlank()) {
            Matcher matcher = ENCRPRM_BODY.matcher(body);
            if (matcher.find()) {
                return Optional.of(matcher.group(1));
            }
        }
        return Optional.empty();
    }

    public static Optional<String> extractEncrprm(HttpRequest request) {
        Optional<String> fromBody = extractEncrprmFromBody(request);
        if (fromBody.isPresent()) {
            return fromBody;
        }
        return extractEncrprmFromQuery(request);
    }

    public static boolean hasEncrprmInQuery(HttpRequest request) {
        if (request == null) {
            return false;
        }
        return ENCRPRM_QUERY.matcher(request.path()).find();
    }

    public static boolean hasEncrprmInBody(HttpRequest request) {
        if (request == null) {
            return false;
        }
        String body = request.bodyToString();
        return body != null && !body.isBlank() && ENCRPRM_BODY.matcher(body).find();
    }

    public static Optional<String> extractEncrdata(String body) {
        if (body == null || body.isBlank()) {
            return Optional.empty();
        }
        Matcher matcher = ENCRDATA_BODY.matcher(body);
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    /**
     * True when {@code encrdata} is present and within the editor ciphertext budget.
     * Uses match indices so huge image-upload ciphertexts are not allocated just to reject them.
     */
    public static boolean hasEditableEncrdata(String body) {
        if (body == null || body.isBlank()) {
            return false;
        }
        Matcher matcher = ENCRDATA_BODY.matcher(body);
        if (!matcher.find()) {
            return false;
        }
        int len = matcher.end(1) - matcher.start(1);
        return len > 0 && len <= MAX_EDITOR_CIPHERTEXT_CHARS;
    }

    public static boolean hasEncrdata(String body) {
        return body != null && !body.isBlank() && ENCRDATA_BODY.matcher(body).find();
    }

    public static boolean hasEncrprm(HttpRequest request) {
        return hasEncrprmInQuery(request) || hasEncrprmInBody(request);
    }

    /**
     * True when body {@code encrprm} is present and within the editor ciphertext budget.
     * Uses match indices so huge image-upload ciphertexts are not allocated just to reject them.
     */
    public static boolean hasEditableEncrprmInBody(HttpRequest request) {
        if (request == null) {
            return false;
        }
        String body = request.bodyToString();
        if (body == null || body.isBlank()) {
            return false;
        }
        Matcher matcher = ENCRPRM_BODY.matcher(body);
        if (!matcher.find()) {
            return false;
        }
        int len = matcher.end(1) - matcher.start(1);
        return len > 0 && len <= MAX_EDITOR_CIPHERTEXT_CHARS;
    }

    public static boolean hasEditableEncrprmInQuery(HttpRequest request) {
        if (request == null) {
            return false;
        }
        Matcher matcher = ENCRPRM_QUERY.matcher(request.path());
        if (!matcher.find()) {
            return false;
        }
        int len = matcher.end(1) - matcher.start(1);
        return len > 0 && len <= MAX_EDITOR_CIPHERTEXT_CHARS;
    }

    public static boolean looksLikePlaintextJson(HttpRequest request) {
        if (request == null || isMultipartOrBinary(request)) {
            return false;
        }
        String body = request.bodyToString();
        if (body == null) {
            return false;
        }
        body = body.trim();
        return body.startsWith("{") && body.endsWith("}")
                && !body.contains("\"encrprm\"")
                && !body.contains("\"encrdata\"");
    }

    public static HttpRequest withEncryptedQuery(HttpRequest request, String encrprm) {
        String path = request.path();
        int q = path.indexOf('?');
        String base = q >= 0 ? path.substring(0, q) : path;
        String newPath = base + "?encrprm=" + urlEncodeComponent(encrprm);
        return request.withPath(newPath);
    }

    public static HttpRequest withEncryptedBody(HttpRequest request, String encrprm) {
        String body = "{\"encrprm\":\"" + jsonEscape(encrprm) + "\"}";
        HttpRequest updated = request.withBody(body);
        return updated.withUpdatedHeader("Content-Type", "application/json; charset=utf-8");
    }

    /**
     * Rebuilds an Ultimus response body with a new encrypted {@code encrdata} value.
     * Preserves sibling JSON fields when the original body is a JSON object containing {@code encrdata}.
     */
    public static String withEncryptedEncrdataBody(String originalBody, String encrdata) {
        String escaped = jsonEscape(encrdata);
        if (originalBody != null && !originalBody.isBlank()) {
            Matcher matcher = ENCRDATA_BODY.matcher(originalBody);
            if (matcher.find()) {
                return matcher.replaceFirst(Matcher.quoteReplacement("\"encrdata\":\"" + escaped + "\""));
            }
        }
        return "{\"encrdata\":\"" + escaped + "\"}";
    }

    public static String formatForEditor(String plaintext) {
        try {
            if (plaintext != null && plaintext.length() > MAX_EDITOR_PRETTY_CHARS) {
                return plaintext;
            }
            return UltimusPayloadCodec.expandForEditor(plaintext);
        } catch (RuntimeException ignored) {
            return plaintext;
        }
    }

    public static String prettyJson(String json) {
        if (json == null) {
            return "";
        }
        if (json.length() > MAX_EDITOR_PRETTY_CHARS) {
            return json.trim();
        }
        String input = json.trim();
        StringBuilder out = new StringBuilder();
        int depth = 0;
        boolean inString = false;
        boolean escape = false;
        outer:
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);
            if (escape) {
                out.append(c);
                escape = false;
                continue;
            }
            if (c == '\\' && inString) {
                out.append(c);
                escape = true;
                continue;
            }
            if (c == '"') {
                inString = !inString;
                out.append(c);
                continue;
            }
            if (inString) {
                out.append(c);
                continue;
            }
            switch (c) {
                case '{':
                case '[':
                    out.append(c).append('\n');
                    out.append("  ".repeat(++depth));
                    continue outer;
                case '}':
                case ']':
                    out.append('\n');
                    depth = Math.max(0, depth - 1);
                    out.append("  ".repeat(depth)).append(c);
                    continue outer;
                case ',':
                    out.append(c).append('\n').append("  ".repeat(depth));
                    continue outer;
                case ':':
                    out.append(": ");
                    continue outer;
                default:
                    if (Character.isWhitespace(c)) {
                        continue outer;
                    }
                    out.append(c);
            }
        }
        return out.toString().trim();
    }

    private static String urlEncodeComponent(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t");
    }
}
