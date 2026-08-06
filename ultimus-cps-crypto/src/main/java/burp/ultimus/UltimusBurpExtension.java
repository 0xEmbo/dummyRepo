package burp.ultimus;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.handlers.UltimusHttpHandler;
import burp.ultimus.providers.UltimusRequestEditorProvider;
import burp.ultimus.providers.UltimusResponseEditorProvider;

public class UltimusBurpExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Ultimus CPS Crypto");
        KeyCache keyCache = new KeyCache();
        UltimusCrypto crypto = new UltimusCrypto();
        UltimusRToken rToken = new UltimusRToken(crypto);
        api.http().registerHttpHandler(new UltimusHttpHandler(keyCache, crypto, rToken, api));
        api.userInterface().registerHttpRequestEditorProvider(
                new UltimusRequestEditorProvider(api, keyCache, crypto, rToken));
        api.userInterface().registerHttpResponseEditorProvider(
                new UltimusResponseEditorProvider(api, keyCache, crypto));
        api.logging().logToOutput("Ultimus CPS Crypto loaded. Browse /UltimusCPS/ once to capture session keys.");
    }
}
