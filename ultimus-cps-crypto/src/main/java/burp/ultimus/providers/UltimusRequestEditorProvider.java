package burp.ultimus.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.editors.UltimusRequestEditor;

/* loaded from: ultimus-cps-crypto.jar:burp/ultimus/providers/UltimusRequestEditorProvider.class */
public class UltimusRequestEditorProvider implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;

    public UltimusRequestEditorProvider(MontoyaApi montoyaApi, KeyCache keyCache, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken) {
        this.api = montoyaApi;
        this.keyCache = keyCache;
        this.crypto = ultimusCrypto;
        this.rToken = ultimusRToken;
    }

    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
        return new UltimusRequestEditor(this.api, this.keyCache, this.crypto, this.rToken, editorCreationContext.editorMode());
    }
}
