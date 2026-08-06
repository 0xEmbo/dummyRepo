package burp.ultimus;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.handlers.UltimusHttpHandler;
import burp.ultimus.providers.UltimusRequestEditorProvider;
import burp.ultimus.providers.UltimusResponseEditorProvider;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/UltimusBurpExtension.class */
public class UltimusBurpExtension implements BurpExtension {
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Ultimus CPS Crypto");
        KeyCache keyCache = new KeyCache();
        UltimusCrypto ultimusCrypto = new UltimusCrypto();
        UltimusRToken ultimusRToken = new UltimusRToken(ultimusCrypto);
        montoyaApi.http().registerHttpHandler(new UltimusHttpHandler(keyCache, ultimusCrypto, ultimusRToken, montoyaApi));
        montoyaApi.userInterface().registerHttpRequestEditorProvider(new UltimusRequestEditorProvider(montoyaApi, keyCache, ultimusCrypto, ultimusRToken));
        montoyaApi.userInterface().registerHttpResponseEditorProvider(new UltimusResponseEditorProvider(montoyaApi, keyCache, ultimusCrypto));
        montoyaApi.logging().logToOutput("Ultimus CPS Crypto loaded. Browse /UltimusCPS/ once to capture session keys.");
    }
}
