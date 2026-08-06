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

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusPayloadCodec.class */
public final class UltimusPayloadCodec {
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final Set<String> BASE64_JSON_FIELDS = Set.of("inputContextJson", "actionObjJSON");

    private UltimusPayloadCodec() {
    }

    public static String expandForEditor(String str) {
        JsonObject asJsonObject = JsonParser.parseString(str).getAsJsonObject();
        expandNode(asJsonObject);
        return GSON.toJson((JsonElement) asJsonObject);
    }

    public static String collapseForEncryption(String str) {
        JsonObject asJsonObject = JsonParser.parseString(str.trim()).getAsJsonObject();
        collapseNode(asJsonObject);
        return GSON.toJson((JsonElement) asJsonObject);
    }

    private static void expandNode(JsonObject jsonObject) {
        String asString;
        String asString2;
        JsonElement decodeEmbeddedJson;
        for (String str : BASE64_JSON_FIELDS) {
            if (jsonObject.has(str) && !jsonObject.get(str).isJsonNull()) {
                JsonElement jsonElement = jsonObject.get(str);
                if (jsonElement.isJsonPrimitive() && jsonElement.getAsJsonPrimitive().isString() && (asString2 = jsonElement.getAsString()) != null && !asString2.isBlank() && !"null".equals(asString2) && (decodeEmbeddedJson = decodeEmbeddedJson(asString2)) != null) {
                    jsonObject.add(str, decodeEmbeddedJson);
                }
            }
        }
        if (jsonObject.has("items") && jsonObject.get("items").isJsonPrimitive() && (asString = jsonObject.get("items").getAsString()) != null && asString.startsWith("{")) {
            jsonObject.add("items", JsonParser.parseString(asString));
        }
    }

    private static void collapseNode(JsonObject jsonObject) {
        for (String str : BASE64_JSON_FIELDS) {
            if (jsonObject.has(str) && !jsonObject.get(str).isJsonNull()) {
                JsonElement jsonElement = jsonObject.get(str);
                if (jsonElement.isJsonObject() || jsonElement.isJsonArray()) {
                    jsonObject.addProperty(str, encodeEmbeddedJson(jsonElement));
                }
            }
        }
        if (jsonObject.has("items") && jsonObject.get("items").isJsonObject()) {
            jsonObject.addProperty("items", GSON.toJson(jsonObject.get("items")));
        }
    }

    private static JsonElement decodeEmbeddedJson(String str) {
        try {
            String trim = new String(Base64.getDecoder().decode(str), StandardCharsets.UTF_8).trim();
            if (trim.startsWith("{") || trim.startsWith("[")) {
                return JsonParser.parseString(trim);
            }
        } catch (IllegalArgumentException e) {
        }
        if (str.startsWith("{") || str.startsWith("[")) {
            return JsonParser.parseString(str);
        }
        return null;
    }

    private static String encodeEmbeddedJson(JsonElement jsonElement) {
        if (jsonElement == null || (jsonElement instanceof JsonNull)) {
            return null;
        }
        return Base64.getEncoder().encodeToString(GSON.toJson(jsonElement).getBytes(StandardCharsets.UTF_8));
    }
}
