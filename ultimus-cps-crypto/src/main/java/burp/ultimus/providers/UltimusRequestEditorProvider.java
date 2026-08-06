package burp.ultimus.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.editors.UltimusRequestEditor;

public class UltimusRequestEditorProvider implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;

    public UltimusRequestEditorProvider(MontoyaApi api, KeyCache keyCache, UltimusCrypto crypto, UltimusRToken rToken) {
        this.api = api;
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.rToken = rToken;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new UltimusRequestEditor(api, keyCache, crypto, rToken, creationContext.editorMode());
    }
}
