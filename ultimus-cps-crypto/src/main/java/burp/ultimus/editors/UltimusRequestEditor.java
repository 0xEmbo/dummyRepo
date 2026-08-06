package burp.ultimus.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
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
    private HttpRequestResponse requestResponse;
    private boolean encryptedInQuery;
    private SessionMaterial session;
    private final JPanel panel = new JPanel(new BorderLayout(4, 4));
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    public UltimusRequestEditor(MontoyaApi api, KeyCache keyCache, UltimusCrypto crypto,
            UltimusRToken rToken, EditorMode editorMode) {
        this.api = api;
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.rToken = rToken;
        this.editor = api.userInterface().createRawEditor();
        this.editor.setEditable(true);
        this.panel.add(this.statusLabel, BorderLayout.NORTH);
        this.panel.add(this.editor.uiComponent(), BorderLayout.CENTER);
    }

    @Override
    public HttpRequest getRequest() {
        if (requestResponse == null || requestResponse.request() == null || session == null) {
            return requestResponse != null ? requestResponse.request() : null;
        }
        HttpRequest request = requestResponse.request();
        // Never block Repeater Send on uploads / huge bodies — pass through unchanged.
        if (UltimusMessageParser.isMultipartOrBinary(request)
                || request.body().length() > UltimusMessageParser.MAX_AUTO_ENCRYPT_CHARS) {
            return request;
        }
        if (!editor.isModified()) {
            try {
                return UltimusRequestMutator.refreshTokens(request, session, crypto, rToken);
            } catch (Exception exception) {
                api.logging().logToError("Ultimus token refresh failed: " + exception.getMessage());
                return request;
            }
        }
        try {
            byte[] editorBytes = editor.getContents().getBytes();
            if (editorBytes.length > UltimusMessageParser.MAX_AUTO_ENCRYPT_CHARS) {
                api.logging().logToError("Ultimus: editor payload too large to re-encrypt; sending original request.");
                return request;
            }
            String plaintext = new String(editorBytes, StandardCharsets.UTF_8);
            if (encryptedInQuery) {
                return UltimusRequestMutator.applyQueryPlaintext(request, plaintext, session, crypto, rToken);
            }
            return UltimusRequestMutator.applyBodyPlaintext(request, plaintext, session, crypto, rToken);
        } catch (Exception exception) {
            api.logging().logToError("Ultimus re-encrypt failed: " + exception.getMessage());
            return request;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        this.encryptedInQuery = false;
        this.session = null;
        if (requestResponse == null || requestResponse.request() == null) {
            editor.setContents(ByteArray.byteArray(""));
            statusLabel.setText("No request.");
            return;
        }
        HttpRequest request = requestResponse.request();
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            editor.setContents(ByteArray.byteArray("Not an Ultimus CPS request."));
            statusLabel.setText("Disabled.");
            return;
        }
        Optional<String> rsid = UltimusMessageParser.rsidFromRequest(request);
        if (rsid.isEmpty()) {
            editor.setContents(ByteArray.byteArray("Missing RSID header."));
            statusLabel.setText("No RSID.");
            return;
        }
        Optional<SessionMaterial> sessionOpt = keyCache.getSession(rsid.get());
        if (sessionOpt.isEmpty()) {
            editor.setContents(ByteArray.byteArray(
                    "No session cached for RSID: " + rsid.get()
                            + "\n\nBrowse https://<host>/UltimusCPS/ through Burp once, then reopen this request."));
            statusLabel.setText("Session missing.");
            return;
        }
        this.session = sessionOpt.get();
        Optional<String> bodyEncrprm = UltimusMessageParser.extractEncrprmFromBody(request);
        Optional<String> queryEncrprm = UltimusMessageParser.extractEncrprmFromQuery(request);
        if (bodyEncrprm.isEmpty() && queryEncrprm.isEmpty()) {
            if (UltimusMessageParser.looksLikePlaintextJson(request)) {
                String body = request.bodyToString();
                editor.setContents(ByteArray.byteArray(
                        UltimusMessageParser.prettyJson(UltimusMessageParser.formatForEditor(body))));
                statusLabel.setText("Plaintext body.");
            } else {
                editor.setContents(ByteArray.byteArray("No encrprm found."));
                statusLabel.setText("Nothing to decrypt.");
            }
            return;
        }
        String ciphertext = bodyEncrprm.orElseGet(queryEncrprm::get);
        if (ciphertext.length() > UltimusMessageParser.MAX_EDITOR_CIPHERTEXT_CHARS) {
            editor.setContents(ByteArray.byteArray(
                    "encrprm too large to decrypt in editor ("
                            + ciphertext.length() + " chars).\n"
                            + "Large image-upload payloads stay on the Raw tab."));
            statusLabel.setText("encrprm too large.");
            return;
        }
        try {
            if (bodyEncrprm.isPresent()) {
                encryptedInQuery = false;
                String decrypted = crypto.decrypt(bodyEncrprm.get(), session.otk());
                String formatted = UltimusMessageParser.formatForEditor(decrypted);
                editor.setContents(ByteArray.byteArray(UltimusMessageParser.prettyJson(formatted)));
                statusLabel.setText("POST body decrypted.");
            } else {
                encryptedInQuery = true;
                String decrypted = crypto.decrypt(queryEncrprm.get(), session.otk());
                editor.setContents(ByteArray.byteArray(UltimusMessageParser.prettyJson(decrypted)));
                statusLabel.setText("URL query decrypted.");
            }
        } catch (Exception exception) {
            editor.setContents(ByteArray.byteArray("Decrypt failed: " + exception.getMessage()));
            statusLabel.setText("Decrypt error.");
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }
        HttpRequest request = requestResponse.request();
        if (!UltimusMessageParser.isUltimusRequest(request)) {
            return false;
        }
        if (UltimusMessageParser.isMultipartOrBinary(request)) {
            return false;
        }
        // Avoid decrypt on multi-MB image-upload JSON; body byte length is checked first.
        if (request.body().length() > UltimusMessageParser.MAX_EDITOR_BODY_BYTES) {
            return false;
        }
        if (UltimusMessageParser.hasEncrprmInBody(request)) {
            return UltimusMessageParser.hasEditableEncrprmInBody(request);
        }
        if (UltimusMessageParser.hasEncrprmInQuery(request)) {
            return UltimusMessageParser.hasEditableEncrprmInQuery(request);
        }
        return UltimusMessageParser.looksLikePlaintextJson(request);
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
        return editor.isModified();
    }
}
