package burp.ultimus.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.ultimus.crypto.KeyCache;
import burp.ultimus.crypto.UltimusCrypto;
import burp.ultimus.crypto.UltimusMessageParser;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.Optional;
import javax.swing.JLabel;
import javax.swing.JPanel;

public class UltimusResponseEditor implements ExtensionProvidedHttpResponseEditor {
    private final KeyCache keyCache;
    private final UltimusCrypto crypto;
    private HttpRequestResponse requestResponse;
    private final JPanel panel = new JPanel(new BorderLayout(4, 4));
    private final JLabel statusLabel = new JLabel(" ");
    private final RawEditor editor;

    public UltimusResponseEditor(MontoyaApi api, KeyCache keyCache, UltimusCrypto crypto) {
        this.keyCache = keyCache;
        this.crypto = crypto;
        this.editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        this.panel.add(this.statusLabel, BorderLayout.NORTH);
        this.panel.add(this.editor.uiComponent(), BorderLayout.CENTER);
    }

    @Override
    public HttpResponse getResponse() {
        if (requestResponse == null) {
            return null;
        }
        return requestResponse.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        if (requestResponse == null || requestResponse.response() == null) {
            editor.setContents(ByteArray.byteArray(""));
            statusLabel.setText("No response.");
            return;
        }
        HttpResponse response = requestResponse.response();
        String body = response.bodyToString();
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
        Optional<String> otk = keyCache.getOtk(rsid.get());
        if (otk.isEmpty()) {
            editor.setContents(ByteArray.byteArray(
                    "No OTK cached for RSID: " + rsid.get()
                            + "\n\nLoad /UltimusCPS/ through Burp first."));
            statusLabel.setText("OTK missing.");
            return;
        }
        try {
            String decrypted = crypto.decrypt(encrdata.get(), otk.get());
            String formatted = UltimusMessageParser.formatForEditor(decrypted);
            editor.setContents(ByteArray.byteArray(UltimusMessageParser.prettyJson(formatted)));
            statusLabel.setText("Decrypted response. RSID=" + rsid.get());
        } catch (Exception exception) {
            editor.setContents(ByteArray.byteArray("Decrypt failed: " + exception.getMessage()));
            statusLabel.setText("Decrypt error.");
        }
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.response() == null) {
            return false;
        }
        String body = requestResponse.response().bodyToString();
        if (body == null || body.length() > UltimusMessageParser.MAX_EDITOR_PRETTY_CHARS * 4) {
            return false;
        }
        return UltimusMessageParser.extractEncrdata(body).isPresent();
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
        return false;
    }
}
