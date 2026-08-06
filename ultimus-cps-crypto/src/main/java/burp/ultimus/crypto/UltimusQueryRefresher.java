package burp.ultimus.crypto;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/crypto/UltimusQueryRefresher.class */
public final class UltimusQueryRefresher {
    private static final Gson GSON = new Gson();

    private UltimusQueryRefresher() {
    }

    public static String refreshEncryptedQuery(String str, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken, SessionMaterial sessionMaterial) {
        JsonObject asJsonObject = JsonParser.parseString(str).getAsJsonObject();
        String stringField = stringField(asJsonObject, "CPSSID");
        String stringField2 = stringField(asJsonObject, "RSID");
        if (stringField2 == null || stringField2.isBlank()) {
            stringField2 = sessionMaterial.rsid();
        }
        String valueOf = String.valueOf(System.currentTimeMillis());
        String queryToken = ultimusRToken.queryToken(sessionMaterial.otk(), sessionMaterial.sessionToken(), buildSearchForHash(stringField, valueOf));
        JsonObject jsonObject = new JsonObject();
        if (stringField != null) {
            jsonObject.addProperty("CPSSID", stringField);
        }
        jsonObject.addProperty("cache", valueOf);
        jsonObject.addProperty("RToken", queryToken);
        jsonObject.addProperty("RSID", stringField2);
        return ultimusCrypto.encrypt(GSON.toJson((JsonElement) jsonObject), sessionMaterial.otk());
    }

    private static String buildSearchForHash(String str, String str2) {
        if (str == null || str.isBlank()) {
            return "";
        }
        return "CPSSID=" + URLEncoder.encode(str, StandardCharsets.UTF_8) + "&cache=" + str2;
    }

    private static String stringField(JsonObject jsonObject, String str) {
        if (!jsonObject.has(str) || jsonObject.get(str).isJsonNull()) {
            return null;
        }
        return jsonObject.get(str).getAsString();
    }
}
