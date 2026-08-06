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

    public UltimusResponseEditorProvider(MontoyaApi montoyaApi, KeyCache keyCache, UltimusCrypto ultimusCrypto) {
        this.api = montoyaApi;
        this.keyCache = keyCache;
        this.crypto = ultimusCrypto;
    }

    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
        return new UltimusResponseEditor(this.api, this.keyCache, this.crypto, editorCreationContext.editorMode());
    }
}
