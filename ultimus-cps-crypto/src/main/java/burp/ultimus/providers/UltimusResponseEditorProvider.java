package burp.ultimus.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.editors.UltimusResponseEditor;

public class UltimusResponseEditorProvider implements HttpResponseEditorProvider {
    private final MontoyaApi api;
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;

    public UltimusResponseEditorProvider(MontoyaApi api, KeyCache keyCache, UltimusCrypto crypto) {
        this.api = api;
        this.keyCache = keyCache;
        this.crypto = crypto;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new UltimusResponseEditor(api, keyCache, crypto);
    }
}
