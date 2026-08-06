package burp.ultimus.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusMessageParser;
import burp.ultimus.crypto.UltimusResponseMutator;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class UltimusResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final MontoyaApi api;
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final boolean readOnly;
    private HttpRequestResponse requestResponse;
    private String otk;
    private final JPanel panel = new JPanel(new BorderLayout(4, 4));
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    public UltimusResponseEditor(MontoyaApi api, KeyCache keyCache, UltimusCrypto crypto, EditorMode editorMode) {
        this.api = api;
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.readOnly = editorMode == EditorMode.READ_ONLY;
        this.editor = this.readOnly
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();
        if (!this.readOnly) {
            this.editor.setEditable(true);
        }
        this.panel.add(this.statusLabel, BorderLayout.NORTH);
        this.panel.add(this.editor.uiComponent(), BorderLayout.CENTER);
    }

    @Override
    public HttpResponse getResponse() {
        if (requestResponse == null || requestResponse.response() == null) {
            return null;
        }
        HttpResponse response = requestResponse.response();
        if (readOnly || otk == null || !editor.isModified()) {
            return response;
        }
        try {
            String plaintext = new String(editor.getContents().getBytes(), StandardCharsets.UTF_8);
            return UltimusResponseMutator.applyPlaintext(response, plaintext, otk, crypto);
        } catch (Exception exception) {
            api.logging().logToError("Ultimus response re-encrypt failed: " + exception.getMessage());
            return response;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.otk = null;
        if (requestResponse == null || requestResponse.response() == null) {
            editor.setContents(ByteArray.byteArray(""));
            statusLabel.setText("No response.");
            return;
        }
        HttpResponse response = requestResponse.response();
        if (response.body().length() > UltimusMessageParser.MAX_EDITOR_BODY_BYTES) {
            editor.setContents(ByteArray.byteArray(
                    "Response body too large to decrypt in editor ("
                            + response.body().length() + " bytes)."));
            statusLabel.setText("Body too large.");
            return;
        }
        String body = response.bodyToString();
        if (!UltimusMessageParser.hasEditableEncrdata(body)) {
            if (!UltimusMessageParser.hasEncrdata(body)) {
                editor.setContents(ByteArray.byteArray("No encrdata field in response."));
                statusLabel.setText("Nothing to decrypt.");
            } else {
                editor.setContents(ByteArray.byteArray(
                        "encrdata too large to decrypt in editor.\n"
                                + "Use the Raw tab for large image-upload payloads."));
                statusLabel.setText("encrdata too large.");
            }
            return;
        }
        Optional<String> encrdata = UltimusMessageParser.extractEncrdata(body);
        if (encrdata.isEmpty()) {
            editor.setContents(ByteArray.byteArray("No encrdata field in response."));
            statusLabel.setText("Nothing to decrypt.");
            return;
        }
        if (requestResponse.request() == null) {
            editor.setContents(ByteArray.byteArray("Need matching request (RSID header) to decrypt."));
            statusLabel.setText("Missing request.");
            return;
        }
        Optional<String> rsid = UltimusMessageParser.rsidFromRequest(requestResponse.request());
        if (rsid.isEmpty()) {
            editor.setContents(ByteArray.byteArray("Missing RSID header on request."));
            statusLabel.setText("No RSID.");
            return;
        }
        Optional<String> otkOpt = keyCache.getOtk(rsid.get());
        if (otkOpt.isEmpty()) {
            editor.setContents(ByteArray.byteArray(
                    "No OTK cached for RSID: " + rsid.get()
                            + "\n\nLoad /UltimusCPS/ through Burp first."));
            statusLabel.setText("OTK missing.");
            return;
        }
        this.otk = otkOpt.get();
        try {
            String decrypted = crypto.decrypt(encrdata.get(), otk);
            String formatted = UltimusMessageParser.formatForEditor(decrypted);
            editor.setContents(ByteArray.byteArray(UltimusMessageParser.prettyJson(formatted)));
            statusLabel.setText(readOnly
                    ? "Decrypted response (read-only). RSID=" + rsid.get()
                    : "Decrypted response — edit then forward/send to re-encrypt. RSID=" + rsid.get());
        } catch (Exception exception) {
            this.otk = null;
            editor.setContents(ByteArray.byteArray("Decrypt failed: " + exception.getMessage()));
            statusLabel.setText("Decrypt error.");
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }
        // Prefer byte length — avoids bodyToString() on huge binary/image responses.
        int bodyBytes = requestResponse.response().body().length();
        if (bodyBytes <= 0 || bodyBytes > UltimusMessageParser.MAX_EDITOR_BODY_BYTES) {
            return false;
        }
        if (UltimusMessageParser.isBinaryContentType(requestResponse.response())) {
            return false;
        }
        String body = requestResponse.response().bodyToString();
        // Skip enabling the tab when ciphertext alone would freeze decrypt/pretty-print.
        return UltimusMessageParser.hasEditableEncrdata(body);
    }

    @Override
    public String caption() {
        return "Ultimus";
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        return editor.selection().orElse(null);
    }

    @Override
    public boolean isModified() {
        return !readOnly && editor.isModified();
    }
}
