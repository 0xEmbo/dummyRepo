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
    private boolean passThroughLarge;
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
        // Large ID-image uploads: never re-encrypt from the editor; only refresh tokens on the original wire request.
        if (this.passThroughLarge || this.readOnly || !this.editor.isModified()) {
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
        this.passThroughLarge = false;
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

        int bodyLen = UltimusMessageParser.bodyLength(request);
        boolean hasBodyEncr = UltimusMessageParser.hasEncrprmInBody(request);
        boolean hasQueryEncr = UltimusMessageParser.hasEncrprmInQuery(request);

        // Oversized bodies (typical ID-image upload): do not decrypt or load into the editor.
        // Decrypt + setContents of multi-MB payloads freezes Burp and blocks Forward/Send.
        if (hasBodyEncr && UltimusMessageParser.isOversizedForEditor(request)) {
            this.passThroughLarge = true;
            this.encryptedInQuery = false;
            this.editor.setContents(ByteArray.byteArray(
                    "Large Ultimus payload (" + bodyLen + " bytes) — not decrypted in UI to avoid freezing Burp.\n\n"
                            + "Forward/Send will pass the original encrypted body through and only refresh x-RToken.\n"
                            + "Use the Raw tab to inspect the wire request."));
            this.statusLabel.setText("Large payload pass-through (" + bodyLen + " bytes).");
            return;
        }

        if (!hasBodyEncr && !hasQueryEncr) {
            if (UltimusMessageParser.looksLikePlaintextJson(request)) {
                if (UltimusMessageParser.isOversizedForEditor(request)) {
                    this.passThroughLarge = true;
                    this.editor.setContents(ByteArray.byteArray(
                            "Large plaintext Ultimus JSON (" + bodyLen + " bytes) — not loaded in UI.\n\n"
                                    + "Forward/Send passes the original body through (handler may auto-encrypt if under limit)."));
                    this.statusLabel.setText("Large plaintext pass-through (" + bodyLen + " bytes).");
                    return;
                }
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
            if (hasBodyEncr) {
                this.encryptedInQuery = false;
                Optional<String> extractEncrprmFromBody = UltimusMessageParser.extractEncrprmFromBody(request);
                if (extractEncrprmFromBody.isEmpty()) {
                    this.editor.setContents(ByteArray.byteArray("No encrprm found in body."));
                    this.statusLabel.setText("Nothing to decrypt.");
                    return;
                }
                if (UltimusMessageParser.isOversizedForEditor(extractEncrprmFromBody.get())) {
                    this.passThroughLarge = true;
                    this.editor.setContents(ByteArray.byteArray(
                            "Large encrprm ciphertext — not decrypted in UI to avoid freezing Burp.\n\n"
                                    + "Forward/Send will pass the original encrypted body through and only refresh x-RToken."));
                    this.statusLabel.setText("Large encrprm pass-through.");
                    return;
                }
                String decrypted = this.crypto.decrypt(extractEncrprmFromBody.get(), this.session.otk());
                if (UltimusMessageParser.isOversizedForEditor(decrypted)) {
                    this.passThroughLarge = true;
                    this.editor.setContents(ByteArray.byteArray(
                            "Decrypted payload is too large for the Ultimus editor (" + decrypted.length() + " chars).\n\n"
                                    + "Forward/Send will pass the original encrypted body through and only refresh x-RToken."));
                    this.statusLabel.setText("Large decrypted pass-through.");
                    return;
                }
                this.editor.setContents(ByteArray.byteArray(UltimusMessageParser.prepareEditorText(decrypted)));
                this.statusLabel.setText("POST body decrypted." + (this.readOnly ? " [read-only]" : " [editable]"));
            } else {
                this.encryptedInQuery = true;
                Optional<String> extractEncrprmFromQuery = UltimusMessageParser.extractEncrprmFromQuery(request);
                if (extractEncrprmFromQuery.isEmpty()) {
                    this.editor.setContents(ByteArray.byteArray("No encrprm found in query."));
                    this.statusLabel.setText("Nothing to decrypt.");
                    return;
                }
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
        // Large pass-through must never report modified, or Burp may try to rebuild from the notice text.
        return !this.passThroughLarge && !this.readOnly && this.editor.isModified();
    }
}
