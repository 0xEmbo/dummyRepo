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
    /** Skip expand/pretty above this size (keeps ~500KB ID-image JSON usable in the tab). */
    private static final int EDITOR_PRETTY_LIMIT = 128 * 1024;
    /**
     * Do not decrypt or load payloads larger than this into the Ultimus editor.
     * Typical ID-image uploads are ~0.5–2MB encrypted; only extreme sizes are blocked
     * so Burp does not freeze on Forward/Send.
     */
    public static final int EDITOR_LOAD_LIMIT = 3 * 1024 * 1024;
    /** Skip handler auto-encrypt above this size (client JS should already encrypt). */
    public static final int AUTO_ENCRYPT_LIMIT = 3 * 1024 * 1024;

    private UltimusMessageParser() {
    }

    public static int bodyLength(HttpRequest httpRequest) {
        if (httpRequest == null || httpRequest.body() == null) {
            return 0;
        }
        return httpRequest.body().length();
    }

    public static boolean isOversizedForEditor(HttpRequest httpRequest) {
        return bodyLength(httpRequest) > EDITOR_LOAD_LIMIT;
    }

    public static boolean isOversizedForEditor(String bodyOrCiphertext) {
        return bodyOrCiphertext != null && bodyOrCiphertext.length() > EDITOR_LOAD_LIMIT;
    }

    public static boolean isUltimusRequest(HttpRequest httpRequest) {
        return httpRequest != null && httpRequest.url().contains("/UltimusCPS/");
    }

    public static boolean isUltimusHtml(String str) {
        return str != null && str.contains("backgroundstyle") && str.contains("base64,") && str.contains("UltimusCPS");
    }

    public static Optional<String> rsidFromRequest(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return Optional.empty();
        }
        return httpRequest.headers().stream().filter(httpHeader -> {
            return httpHeader.name().equalsIgnoreCase("rsid");
        }).map(httpHeader2 -> {
            return httpHeader2.value();
        }).findFirst();
    }

    public static Optional<String> cpssidFromRequest(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return Optional.empty();
        }
        return httpRequest.headers().stream().filter(httpHeader -> {
            return httpHeader.name().equalsIgnoreCase("cpssid");
        }).map(httpHeader2 -> {
            return httpHeader2.value();
        }).findFirst();
    }

    public static Optional<String> extractEncrprmFromQuery(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return Optional.empty();
        }
        Matcher matcher = ENCRPRM_QUERY.matcher(httpRequest.path());
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    public static Optional<String> extractEncrprmFromBody(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return Optional.empty();
        }
        String bodyToString = httpRequest.bodyToString();
        if (bodyToString != null && !bodyToString.isBlank()) {
            Matcher matcher = ENCRPRM_BODY.matcher(bodyToString);
            if (matcher.find()) {
                return Optional.of(matcher.group(1));
            }
        }
        return Optional.empty();
    }

    public static Optional<String> extractEncrprm(HttpRequest httpRequest) {
        Optional<String> extractEncrprmFromBody = extractEncrprmFromBody(httpRequest);
        if (extractEncrprmFromBody.isPresent()) {
            return extractEncrprmFromBody;
        }
        return extractEncrprmFromQuery(httpRequest);
    }

    public static boolean hasEncrprmInQuery(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return false;
        }
        String path = httpRequest.path();
        return path != null && path.contains("encrprm=");
    }

    public static boolean hasEncrprmInBody(HttpRequest httpRequest) {
        // Presence-only: do not capture multi-MB ciphertext just to check.
        return httpRequest != null && httpRequest.contains("encrprm", false);
    }

    public static boolean hasEncrdata(String str) {
        return str != null && str.contains("encrdata");
    }

    public static Optional<String> extractEncrdata(String str) {
        if (str == null || str.isBlank()) {
            return Optional.empty();
        }
        Matcher matcher = ENCRDATA_BODY.matcher(str);
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    public static boolean hasEncrprm(HttpRequest httpRequest) {
        return hasEncrprmInQuery(httpRequest) || hasEncrprmInBody(httpRequest);
    }

    public static boolean looksLikePlaintextJson(HttpRequest httpRequest) {
        if (httpRequest == null) {
            return false;
        }
        // Fast rejects without allocating the full body string when possible.
        if (httpRequest.contains("encrprm", false) || httpRequest.contains("encrdata", false)) {
            return false;
        }
        int len = bodyLength(httpRequest);
        if (len < 2) {
            return false;
        }
        String bodyToString = httpRequest.bodyToString();
        if (bodyToString == null) {
            return false;
        }
        String trim = bodyToString.trim();
        return trim.startsWith("{") && trim.endsWith("}");
    }

    public static HttpRequest withEncryptedQuery(HttpRequest httpRequest, String str) {
        String path = httpRequest.path();
        int indexOf = path.indexOf(63);
        return httpRequest.withPath((indexOf >= 0 ? path.substring(0, indexOf) : path) + "?encrprm=" + urlEncodeComponent(str));
    }

    public static HttpRequest withEncryptedBody(HttpRequest httpRequest, String str) {
        return httpRequest.withBody("{\"encrprm\":\"" + jsonEscape(str) + "\"}");
    }

    public static HttpResponse withEncryptedEncrdata(HttpResponse httpResponse, String str) {
        if (httpResponse == null) {
            return null;
        }
        String bodyToString = httpResponse.bodyToString();
        if (bodyToString != null && !bodyToString.isBlank()) {
            Matcher matcher = ENCRDATA_BODY.matcher(bodyToString);
            if (matcher.find()) {
                return httpResponse.withBody(matcher.replaceFirst(Matcher.quoteReplacement("\"encrdata\":\"" + jsonEscape(str) + "\"")));
            }
        }
        return httpResponse.withBody("{\"encrdata\":\"" + jsonEscape(str) + "\"}");
    }

    public static String formatForEditor(String str) {
        try {
            return UltimusPayloadCodec.expandForEditor(str);
        } catch (RuntimeException e) {
            return str;
        }
    }

    /**
     * Prepare decrypted plaintext for the Ultimus editor tab.
     * Large payloads (typical of image uploads) skip expand/pretty to avoid freezing Burp's UI thread.
     */
    public static String prepareEditorText(String str) {
        if (str == null) {
            return "";
        }
        if (str.length() > EDITOR_PRETTY_LIMIT) {
            return str;
        }
        return prettyJson(formatForEditor(str));
    }

    public static String prettyJson(String str) {
        if (str == null) {
            return "";
        }
        if (str.length() > EDITOR_PRETTY_LIMIT) {
            return str.trim();
        }
        String trim = str.trim();
        StringBuilder sb = new StringBuilder(trim.length() + 64);
        int i = 0;
        boolean z = false;
        boolean z2 = false;
        for (int i2 = 0; i2 < trim.length(); i2++) {
            char charAt = trim.charAt(i2);
            if (z2) {
                sb.append(charAt);
                z2 = false;
            } else if (charAt == '\\' && z) {
                sb.append(charAt);
                z2 = true;
            } else if (charAt == '\"') {
                z = !z;
                sb.append(charAt);
            } else if (z) {
                sb.append(charAt);
            } else {
                switch (charAt) {
                    case ',':
                        sb.append(charAt).append('\n').append("  ".repeat(Math.min(i, 32)));
                        break;
                    case ':':
                        sb.append(": ");
                        break;
                    case '[':
                    case '{':
                        sb.append(charAt).append('\n');
                        i++;
                        sb.append("  ".repeat(Math.min(i, 32)));
                        break;
                    case ']':
                    case '}':
                        sb.append('\n');
                        i = Math.max(0, i - 1);
                        sb.append("  ".repeat(Math.min(i, 32))).append(charAt);
                        break;
                    default:
                        if (Character.isWhitespace(charAt)) {
                            break;
                        } else {
                            sb.append(charAt);
                            break;
                        }
                }
            }
        }
        return sb.toString().trim();
    }

    public static boolean looksLikeHtmlCandidate(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return true;
        }
        String lower = contentType.toLowerCase();
        return lower.contains("html") || lower.contains("text/plain") || lower.contains("text/html");
    }

    private static String urlEncodeComponent(String str) {
        return URLEncoder.encode(str, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String jsonEscape(String str) {
        return str.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }
}
