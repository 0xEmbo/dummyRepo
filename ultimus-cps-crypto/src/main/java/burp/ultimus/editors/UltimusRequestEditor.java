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
import java.util.Optional;

/**
 * Request editor for UltimusCPS encrypted traffic.
 * <p>
 * Prefer body re-encryption when the body carries {@code encrprm} (typical RunAction).
 * Treat the editor as modified only when contents differ from the last loaded plaintext —
 * Burp often marks {@code isModified()} after {@code setContents} even when the user did not edit.
 */
public class UltimusRequestEditor implements ExtensionProvidedHttpRequestEditor {
  private static final String OVERSIZE_NOTICE =
      "[UltimusCPS] Payload too large to decrypt in this tab.\n"
          + "Edit the raw request instead, then Forward/Send.\n"
          + "This extension will still encrypt/decrypt on the wire when possible.";

  private final MontoyaApi api;
  private final KeyCache keyCache;
  private final UltimusCrypto crypto;
  private final UltimusRToken rToken;
  private final RawEditor editor;
  private HttpRequestResponse currentMessage;
  private boolean bodyEncrypted;
  private boolean queryEncrypted;
  private boolean oversized;
  private String loadedPlaintext;

  public UltimusRequestEditor(
      MontoyaApi api,
      KeyCache keyCache,
      UltimusCrypto crypto,
      UltimusRToken rToken,
      EditorMode editorMode) {
    this.api = api;
    this.keyCache = keyCache;
    this.crypto = crypto;
    this.rToken = rToken;
    this.editor = editorMode == EditorMode.READ_ONLY
        ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
        : api.userInterface().createRawEditor();
  }

  @Override
  public HttpRequest getRequest() {
    HttpRequest request = currentMessage.request();
    if (oversized) {
      return request;
    }

    if (!isEditorEffectivelyModified()) {
      // Already-encrypted body: return exact wire bytes — never rewrite query-only or lone RToken.
      if (bodyEncrypted || UltimusMessageParser.hasEncrprmInBody(request)) {
        return request;
      }
      Optional<String> rsid = UltimusMessageParser.rsidFromRequest(request);
      if (rsid.isEmpty()) {
        return request;
      }
      Optional<SessionMaterial> session = keyCache.getSession(rsid.get());
      if (session.isEmpty()) {
        return request;
      }
      try {
        return UltimusRequestMutator.refreshTokens(request, session.get(), crypto, rToken);
      } catch (Exception ex) {
        api.logging().logToError("UltimusCPS refreshTokens failed: " + ex.getMessage());
        return request;
      }
    }

    Optional<String> rsid = UltimusMessageParser.rsidFromRequest(request);
    if (rsid.isEmpty()) {
      return request;
    }
    Optional<SessionMaterial> session = keyCache.getSession(rsid.get());
    if (session.isEmpty()) {
      return request;
    }

    String plaintext = editor.getContents().toString();
    if (plaintext.length() > UltimusMessageParser.AUTO_ENCRYPT_LIMIT) {
      api.logging().logToError(
          "UltimusCPS editor encrypt skipped: plaintext too large (" + plaintext.length() + " bytes)");
      return request;
    }

    try {
      if (shouldEncryptBody(request, plaintext)) {
        return UltimusRequestMutator.applyBodyPlaintext(
            request, plaintext, session.get(), crypto, rToken);
      }
      return UltimusRequestMutator.applyQueryPlaintext(
          request, plaintext, session.get(), crypto, rToken);
    } catch (Exception ex) {
      api.logging().logToError("UltimusCPS editor encrypt failed: " + ex.getMessage());
      return request;
    }
  }

  @Override
  public void setRequestResponse(HttpRequestResponse requestResponse) {
    currentMessage = requestResponse;
    bodyEncrypted = false;
    queryEncrypted = false;
    oversized = false;
    loadedPlaintext = null;

    HttpRequest request = requestResponse.request();
    boolean bodyHas = UltimusMessageParser.hasEncrprmInBody(request);
    boolean queryHas = UltimusMessageParser.hasEncrprmInQuery(request);
    int bodyLen = request.body().length();

    if ((bodyHas || queryHas)
        && bodyLen > UltimusMessageParser.EDITOR_LOAD_LIMIT) {
      oversized = true;
      bodyEncrypted = bodyHas;
      queryEncrypted = queryHas;
      loadedPlaintext = OVERSIZE_NOTICE;
      editor.setContents(ByteArray.byteArray(OVERSIZE_NOTICE));
      api.logging().logToOutput(
          "UltimusCPS editor: skipped decrypt of oversized request body ("
              + bodyLen
              + " bytes)");
      return;
    }

    // Prefer body ciphertext when both query and body carry encrprm (RunAction pattern).
    Optional<String> ciphertext = Optional.empty();
    if (bodyHas) {
      ciphertext = UltimusMessageParser.extractEncrprmFromBody(request);
      bodyEncrypted = ciphertext.isPresent();
    }
    if (ciphertext.isEmpty() && queryHas) {
      ciphertext = UltimusMessageParser.extractEncrprmFromQuery(request);
      queryEncrypted = ciphertext.isPresent();
    }

    Optional<String> rsid = UltimusMessageParser.rsidFromRequest(request);
    if (ciphertext.isEmpty() || rsid.isEmpty()) {
      loadedPlaintext = request.bodyToString();
      editor.setContents(ByteArray.byteArray(loadedPlaintext));
      return;
    }

    Optional<SessionMaterial> session = keyCache.getSession(rsid.get());
    if (session.isEmpty()) {
      loadedPlaintext = "[UltimusCPS] Missing session for RSID=" + rsid.get();
      editor.setContents(ByteArray.byteArray(loadedPlaintext));
      return;
    }

    try {
      loadedPlaintext = crypto.decrypt(ciphertext.get(), session.get().otk());
      editor.setContents(ByteArray.byteArray(loadedPlaintext));
    } catch (Exception ex) {
      loadedPlaintext = "[UltimusCPS] Decrypt failed: " + ex.getMessage();
      editor.setContents(ByteArray.byteArray(loadedPlaintext));
    }
  }

  @Override
  public boolean isEnabledFor(HttpRequestResponse requestResponse) {
    HttpRequest request = requestResponse.request();
    return UltimusMessageParser.hasEncrprmInQuery(request)
        || UltimusMessageParser.hasEncrprmInBody(request)
        || UltimusMessageParser.rsidFromRequest(request).isPresent();
  }

  @Override
  public String caption() {
    return "UltimusCPS";
  }

  @Override
  public java.awt.Component uiComponent() {
    return editor.uiComponent();
  }

  @Override
  public Selection selectedData() {
    return editor.selection().orElse(null);
  }

  @Override
  public boolean isModified() {
    return isEditorEffectivelyModified();
  }

  /**
   * Burp often reports {@code editor.isModified()} after {@code setContents} even when the user
   * did not edit. Prefer comparing current contents to the last loaded plaintext.
   */
  private boolean isEditorEffectivelyModified() {
    if (oversized || loadedPlaintext == null) {
      return false;
    }
    String current = editor.getContents().toString();
    if (current.equals(loadedPlaintext)) {
      return false;
    }
    // Fallback: trust Burp's flag when contents differ (covers edge encoding cases).
    return editor.isModified() || !current.equals(loadedPlaintext);
  }

  /**
   * Prefer body encryption for RunAction-style requests where the body holds encrprm / JSON.
   * Only use query encryption for query-only Ultimus requests.
   */
  private boolean shouldEncryptBody(HttpRequest request, String plaintext) {
    if (bodyEncrypted || UltimusMessageParser.hasEncrprmInBody(request)) {
      return true;
    }
    if (queryEncrypted && !UltimusMessageParser.hasEncrprmInBody(request)) {
      return false;
    }
    String trimmed = plaintext == null ? "" : plaintext.trim();
    return trimmed.startsWith("{") || trimmed.startsWith("[");
  }
}
