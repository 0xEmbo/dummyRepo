package burp.ultimus.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.SessionMaterial;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusMessageParser;
import burp.ultimus.crypto.UltimusRToken;
import burp.ultimus.crypto.UltimusRequestMutator;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class UltimusRequestEditor implements ExtensionProvidedHttpRequestEditor {
    private final MontoyaApi api;
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private final UltimusRToken rToken;
    private final boolean readOnly;
    private HttpRequestResponse requestResponse;
    private boolean encryptedInQuery;
    private SessionMaterial session;
    private final JPanel panel = new JPanel(new BorderLayout(4, 4));
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    public UltimusRequestEditor(MontoyaApi montoyaApi, KeyCache keyCache, UltimusCrypto ultimusCrypto, UltimusRToken ultimusRToken, EditorMode editorMode) {
        this.api = montoyaApi;
        this.keyCache = keyCache;
        this.crypto = ultimusCrypto;
        this.rToken = ultimusRToken;
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

    public HttpRequest getRequest() {
        if (this.requestResponse == null || this.requestResponse.request() == null) {
            return null;
        }
        HttpRequest request = this.requestResponse.request();
        if (this.session == null) {
            return request;
        }
        // Unmodified: only refresh tokens on the original wire request (avoids re-encrypting huge image payloads on Send).
        if (this.readOnly || !this.editor.isModified()) {
            try {
                return UltimusRequestMutator.refreshTokens(request, this.session, this.crypto, this.rToken);
            } catch (Exception e) {
                this.api.logging().logToError("Ultimus token refresh failed: " + e.getMessage());
                return request;
            }
        }
        try {
            String str = new String(this.editor.getContents().getBytes(), StandardCharsets.UTF_8);
            if (this.encryptedInQuery) {
                return UltimusRequestMutator.applyQueryPlaintext(request, str, this.session, this.crypto, this.rToken);
            }
            return UltimusRequestMutator.applyBodyPlaintext(request, str, this.session, this.crypto, this.rToken);
        } catch (Exception e) {
            this.api.logging().logToError("Ultimus re-encrypt failed: " + e.getMessage());
            return request;
        }
    }

    public void setRequestResponse(HttpRequestResponse httpRequestResponse) {
        this.requestResponse = httpRequestResponse;
        this.encryptedInQuery = false;
        this.session = null;
        if (httpRequestResponse == null || httpRequestResponse.request() == null) {
            this.editor.setContents(ByteArray.byteArray(""));
            this.statusLabel.setText("No request.");
            return;
        }
        HttpRequest request = httpRequestResponse.request();
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            this.editor.setContents(ByteArray.byteArray("Not an Ultimus CPS request."));
            this.statusLabel.setText("Disabled.");
            return;
        }
        Optional<String> rsidFromRequest = UltimusMessageParser.rsidFromRequest(request);
        if (rsidFromRequest.isEmpty()) {
            this.editor.setContents(ByteArray.byteArray("Missing RSID header."));
            this.statusLabel.setText("No RSID.");
            return;
        }
        Optional<SessionMaterial> sessionOpt = this.keyCache.getSession(rsidFromRequest.get());
        if (sessionOpt.isEmpty()) {
            this.editor.setContents(ByteArray.byteArray("No session cached for RSID: " + rsidFromRequest.get() + "\n\nBrowse https://<host>/UltimusCPS/ through Burp once, then reopen this request."));
            this.statusLabel.setText("Session missing.");
            return;
        }
        this.session = sessionOpt.get();
        Optional<String> extractEncrprmFromBody = UltimusMessageParser.extractEncrprmFromBody(request);
        Optional<String> extractEncrprmFromQuery = UltimusMessageParser.extractEncrprmFromQuery(request);
        if (extractEncrprmFromBody.isEmpty() && extractEncrprmFromQuery.isEmpty()) {
            if (UltimusMessageParser.looksLikePlaintextJson(request)) {
                this.editor.setContents(ByteArray.byteArray(UltimusMessageParser.prepareEditorText(request.bodyToString())));
                this.statusLabel.setText("Plaintext body." + (this.readOnly ? " [read-only]" : " [editable]"));
                return;
            } else {
                this.editor.setContents(ByteArray.byteArray("No encrprm found."));
                this.statusLabel.setText("Nothing to decrypt.");
                return;
            }
        }
        try {
            if (extractEncrprmFromBody.isPresent()) {
                this.encryptedInQuery = false;
                String decrypted = this.crypto.decrypt(extractEncrprmFromBody.get(), this.session.otk());
                this.editor.setContents(ByteArray.byteArray(UltimusMessageParser.prepareEditorText(decrypted)));
                String sizeNote = decrypted.length() > 512 * 1024 ? " (large payload; pretty-print skipped)" : "";
                this.statusLabel.setText("POST body decrypted." + sizeNote + (this.readOnly ? " [read-only]" : " [editable]"));
            } else {
                this.encryptedInQuery = true;
                String decrypted = this.crypto.decrypt(extractEncrprmFromQuery.get(), this.session.otk());
                this.editor.setContents(ByteArray.byteArray(UltimusMessageParser.prepareEditorText(decrypted)));
                this.statusLabel.setText("URL query decrypted." + (this.readOnly ? " [read-only]" : " [editable]"));
            }
        } catch (Exception e) {
            this.editor.setContents(ByteArray.byteArray("Decrypt failed: " + e.getMessage()));
            this.statusLabel.setText("Decrypt error.");
        }
    }

    public boolean isEnabledFor(HttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || httpRequestResponse.request() == null) {
            return false;
        }
        HttpRequest request = httpRequestResponse.request();
        if (UltimusMessageParser.isUltimusRequest(request)) {
            return UltimusMessageParser.hasEncrprm(request) || UltimusMessageParser.looksLikePlaintextJson(request);
        }
        return false;
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
        return !this.readOnly && this.editor.isModified();
    }
}
