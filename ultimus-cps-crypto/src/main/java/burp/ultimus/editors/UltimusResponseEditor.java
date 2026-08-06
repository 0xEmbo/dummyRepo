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
import burp.ultimus.crypto.UltimusPayloadCodec;
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
    private boolean passThroughLarge;
    private final JPanel panel = new JPanel(new BorderLayout(4, 4));
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    public UltimusResponseEditor(MontoyaApi montoyaApi, KeyCache keyCache, UltimusCrypto ultimusCrypto, EditorMode editorMode) {
        this.api = montoyaApi;
        this.keyCache = keyCache;
        this.crypto = ultimusCrypto;
        this.readOnly = editorMode == EditorMode.READ_ONLY;
        if (this.readOnly) {
            this.editor = montoyaApi.userInterface().createRawEditor(new EditorOptions[]{EditorOptions.READ_ONLY});
        } else {
            this.editor = montoyaApi.userInterface().createRawEditor(new EditorOptions[0]);
            this.editor.setEditable(true);
        }
        this.panel.add(this.statusLabel, "North");
        this.panel.add(this.editor.uiComponent(), "Center");
    }

    public HttpResponse getResponse() {
        if (this.requestResponse == null || this.requestResponse.response() == null) {
            return null;
        }
        HttpResponse response = this.requestResponse.response();
        if (this.passThroughLarge || this.readOnly || !this.editor.isModified() || this.otk == null) {
            return response;
        }
        try {
            String plaintext = new String(this.editor.getContents().getBytes(), StandardCharsets.UTF_8);
            String encrypted = this.crypto.encrypt(UltimusPayloadCodec.collapseForEncryption(plaintext), this.otk);
            return UltimusMessageParser.withEncryptedEncrdata(response, encrypted);
        } catch (Exception e) {
            this.api.logging().logToError("Ultimus response re-encrypt failed: " + e.getMessage());
            return response;
        }
    }

    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.requestResponse = httpRequestResponse;
        this.otk = null;
        this.passThroughLarge = false;
        if (httpRequestResponse == null || httpRequestResponse.response() == null) {
            this.editor.setContents(ByteArray.byteArray(""));
            this.statusLabel.setText("No response.");
            return;
        }
        HttpResponse response = httpRequestResponse.response();
        int bodyLen = response.body() == null ? 0 : response.body().length();
        if (!response.contains("encrdata", false)) {
            this.editor.setContents(ByteArray.byteArray("No encrdata field in response."));
            this.statusLabel.setText("Nothing to decrypt.");
            return;
        }
        if (bodyLen > UltimusMessageParser.EDITOR_LOAD_LIMIT) {
            this.passThroughLarge = true;
            this.editor.setContents(ByteArray.byteArray(
                    "Large Ultimus response (" + bodyLen + " bytes) — not decrypted in UI to avoid freezing Burp.\n\n"
                            + "Forward will pass the original response through. Use the Raw tab to inspect."));
            this.statusLabel.setText("Large response pass-through (" + bodyLen + " bytes).");
            return;
        }
        Optional<String> extractEncrdata = UltimusMessageParser.extractEncrdata(response.bodyToString());
        if (extractEncrdata.isEmpty()) {
            this.editor.setContents(ByteArray.byteArray("No encrdata field in response."));
            this.statusLabel.setText("Nothing to decrypt.");
            return;
        }
        if (UltimusMessageParser.isOversizedForEditor(extractEncrdata.get())) {
            this.passThroughLarge = true;
            this.editor.setContents(ByteArray.byteArray(
                    "Large encrdata ciphertext — not decrypted in UI to avoid freezing Burp.\n\n"
                            + "Forward will pass the original response through."));
            this.statusLabel.setText("Large encrdata pass-through.");
            return;
        }
        if (httpRequestResponse.request() == null) {
            this.editor.setContents(ByteArray.byteArray("Need matching request (RSID header) to decrypt."));
            this.statusLabel.setText("Missing request.");
            return;
        }
        Optional<String> rsidFromRequest = UltimusMessageParser.rsidFromRequest(httpRequestResponse.request());
        if (rsidFromRequest.isEmpty()) {
            this.editor.setContents(ByteArray.byteArray("Missing RSID header on request."));
            this.statusLabel.setText("No RSID.");
            return;
        }
        Optional<String> otkOpt = this.keyCache.getOtk(rsidFromRequest.get());
        if (otkOpt.isEmpty()) {
            this.editor.setContents(ByteArray.byteArray("No OTK cached for RSID: " + rsidFromRequest.get() + "\n\nLoad /UltimusCPS/ through Burp first."));
            this.statusLabel.setText("OTK missing.");
            return;
        }
        this.otk = otkOpt.get();
        try {
            String decrypted = this.crypto.decrypt(extractEncrdata.get(), this.otk);
            if (UltimusMessageParser.isOversizedForEditor(decrypted)) {
                this.passThroughLarge = true;
                this.otk = null;
                this.editor.setContents(ByteArray.byteArray(
                        "Decrypted response is too large for the Ultimus editor (" + decrypted.length() + " chars).\n\n"
                                + "Forward will pass the original response through."));
                this.statusLabel.setText("Large decrypted pass-through.");
                return;
            }
            this.editor.setContents(ByteArray.byteArray(UltimusMessageParser.prepareEditorText(decrypted)));
            this.statusLabel.setText("Decrypted response. RSID=" + rsidFromRequest.get() + (this.readOnly ? " [read-only]" : " [editable]"));
        } catch (Exception e) {
            this.otk = null;
            this.editor.setContents(ByteArray.byteArray("Decrypt failed: " + e.getMessage()));
            this.statusLabel.setText("Decrypt error.");
        }
    }

    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || httpRequestResponse.response() == null) {
            return false;
        }
        // Presence-only — do not extract multi-MB encrdata just to enable the tab.
        return httpRequestResponse.response().contains("encrdata", false);
    }

    public String caption() {
        return "Ultimus";
    }

    public Component uiComponent() {
        return this.panel;
    }

    public Selection selectedData() {
        return (Selection) this.editor.selection().orElse(null);
    }

    public boolean isModified() {
        return !this.passThroughLarge && !this.readOnly && this.editor.isModified();
    }
}
