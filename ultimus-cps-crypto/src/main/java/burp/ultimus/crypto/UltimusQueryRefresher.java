package burp.ultimus.crypto;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class UltimusQueryRefresher {
    private static final Gson GSON = new Gson();

    private UltimusQueryRefresher() {
    }

    public static String refreshEncryptedQuery(String decryptedQueryJson, UltimusCrypto crypto, UltimusRToken rToken, SessionMaterial session) {
        JsonObject parsed = JsonParser.parseString(decryptedQueryJson).getAsJsonObject();
        String cpssid = stringField(parsed, "CPSSID");
        String rsid = stringField(parsed, "RSID");
        if (rsid == null || rsid.isBlank()) {
            rsid = session.rsid();
        }
        String cache = String.valueOf(System.currentTimeMillis());
        String searchForHash = buildSearchForHash(cpssid, cache);
        String queryRToken = rToken.queryToken(session.otk(), session.sessionToken(), searchForHash);
        JsonObject refreshed = new JsonObject();
        if (cpssid != null) {
            refreshed.addProperty("CPSSID", cpssid);
        }
        refreshed.addProperty("cache", cache);
        refreshed.addProperty("RToken", queryRToken);
        refreshed.addProperty("RSID", rsid);
        return crypto.encrypt(GSON.toJson(refreshed), session.otk());
    }

    private static String buildSearchForHash(String cpssid, String cache) {
        if (cpssid == null || cpssid.isBlank()) {
            return "";
        }
        return "CPSSID=" + URLEncoder.encode(cpssid, StandardCharsets.UTF_8) + "&cache=" + cache;
    }

    private static String stringField(JsonObject object, String name) {
        if (!object.has(name) || object.get(name).isJsonNull()) {
            return null;
        }
        return object.get(name).getAsString();
    }
}
