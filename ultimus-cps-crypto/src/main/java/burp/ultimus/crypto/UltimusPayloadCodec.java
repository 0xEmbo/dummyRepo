package burp.ultimus.crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

public final class UltimusPayloadCodec {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final Set<String> BASE64_JSON_FIELDS = Set.of("inputContextJson", "actionObjJSON");

    private UltimusPayloadCodec() {
    }

    public static String expandForEditor(String json) {
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();
        expandNode(root);
        return GSON.toJson(root);
    }

    public static String collapseForEncryption(String json) {
        String trimmed = json.trim();
        JsonObject root = JsonParser.parseString(trimmed).getAsJsonObject();
        collapseNode(root);
        return GSON.toJson(root);
    }

    private static void expandNode(JsonObject object) {
        for (String field : BASE64_JSON_FIELDS) {
            if (!object.has(field) || object.get(field).isJsonNull()) {
                continue;
            }
            JsonElement element = object.get(field);
            if (!element.isJsonPrimitive() || !element.getAsJsonPrimitive().isString()) {
                continue;
            }
            String value = element.getAsString();
            if (value == null || value.isBlank() || "null".equals(value)) {
                continue;
            }
            JsonElement decoded = decodeEmbeddedJson(value);
            if (decoded != null) {
                object.add(field, decoded);
            }
        }
        if (object.has("items") && object.get("items").isJsonPrimitive()) {
            String items = object.get("items").getAsString();
            if (items != null && items.startsWith("{")) {
                object.add("items", JsonParser.parseString(items));
            }
        }
    }

    private static void collapseNode(JsonObject object) {
        for (String field : BASE64_JSON_FIELDS) {
            if (!object.has(field) || object.get(field).isJsonNull()) {
                continue;
            }
            JsonElement element = object.get(field);
            if (!element.isJsonObject() && !element.isJsonArray()) {
                continue;
            }
            object.addProperty(field, encodeEmbeddedJson(element));
        }
        if (object.has("items") && object.get("items").isJsonObject()) {
            object.addProperty("items", GSON.toJson(object.get("items")));
        }
    }

    private static JsonElement decodeEmbeddedJson(String value) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            String asText = new String(decoded, StandardCharsets.UTF_8).trim();
            if (asText.startsWith("{") || asText.startsWith("[")) {
                return JsonParser.parseString(asText);
            }
        } catch (IllegalArgumentException ignored) {
            // not base64
        }
        if (value.startsWith("{") || value.startsWith("[")) {
            return JsonParser.parseString(value);
        }
        return null;
    }

    private static String encodeEmbeddedJson(JsonElement element) {
        if (element == null || element instanceof JsonNull) {
            return null;
        }
        return Base64.getEncoder().encodeToString(GSON.toJson(element).getBytes(StandardCharsets.UTF_8));
    }
}
