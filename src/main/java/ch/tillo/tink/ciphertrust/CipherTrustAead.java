// Copyright 2026 Martino Dell'Ambrogio
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ch.tillo.tink.ciphertrust;

import com.google.crypto.tink.Aead;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * An {@link Aead} that forwards encryption and decryption to a key held in Thales CipherTrust
 * Manager, via the {@code /api/v1/crypto} REST service in AES-GCM mode.
 *
 * <p>The ciphertext produced by {@link #encrypt} is a small self-describing JSON envelope carrying
 * the CipherTrust key id and key version alongside the GCM parameters:
 *
 * <pre>{@code {"v":1,"id":"<key id>","ver":<key version>,"iv":"<b64>","tag":"<b64>","ct":"<b64>"}}</pre>
 *
 * <p>Because the envelope pins the key version used at encryption time, decryption keeps working
 * after the CipherTrust key is rotated (rotation only changes which version new encryptions use).
 * Decryption always addresses the key by the name this {@code Aead} was configured with — the id
 * recorded in the envelope is informational only and is never used to select the key — so a
 * ciphertext produced under a different CipherTrust key fails the GCM tag check rather than being
 * silently decrypted.
 *
 * <p>Associated data is forwarded to CipherTrust's {@code aad} field and is cryptographically
 * bound by the server-side GCM operation: decryption with different associated data fails.
 */
public final class CipherTrustAead implements Aead {

  /** Version tag of the JSON ciphertext envelope produced by this class. */
  static final int ENVELOPE_VERSION = 1;

  private final CipherTrustRestClient client;
  private final String keyName;

  CipherTrustAead(CipherTrustRestClient client, String keyName) {
    this.client = client;
    this.keyName = keyName;
  }

  @Override
  public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    CipherTrustRestClient.EncryptResult result =
        client.encrypt(keyName, plaintext, associatedData);
    JsonObject envelope = new JsonObject();
    envelope.addProperty("v", ENVELOPE_VERSION);
    envelope.addProperty("id", result.keyId);
    envelope.addProperty("ver", result.keyVersion);
    envelope.addProperty("iv", result.iv);
    envelope.addProperty("tag", result.tag);
    envelope.addProperty("ct", result.ciphertext);
    return envelope.toString().getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
    JsonObject envelope;
    try {
      JsonElement parsed = JsonParser.parseString(new String(ciphertext, StandardCharsets.UTF_8));
      if (!parsed.isJsonObject()) {
        throw new GeneralSecurityException("malformed CipherTrust ciphertext envelope");
      }
      envelope = parsed.getAsJsonObject();
    } catch (JsonSyntaxException | IllegalStateException | StackOverflowError e) {
      // StackOverflowError guards against a maliciously deep-nested ciphertext (gson parses
      // recursively); the Aead contract requires decrypt of any foreign input to throw
      // GeneralSecurityException, never let an Error escape.
      throw new GeneralSecurityException("malformed CipherTrust ciphertext envelope");
    }
    if (!envelope.has("v")
        || !envelope.has("ver")
        || !envelope.has("iv")
        || !envelope.has("tag")
        || !envelope.has("ct")) {
      throw new GeneralSecurityException("malformed CipherTrust ciphertext envelope");
    }
    final int version;
    final long keyVersion;
    final String iv;
    final String tag;
    final String ct;
    try {
      version = envelope.get("v").getAsInt();
      keyVersion = envelope.get("ver").getAsLong();
      iv = envelope.get("iv").getAsString();
      tag = envelope.get("tag").getAsString();
      ct = envelope.get("ct").getAsString();
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("malformed CipherTrust ciphertext envelope");
    }
    if (version != ENVELOPE_VERSION) {
      throw new GeneralSecurityException(
          "unsupported CipherTrust ciphertext envelope version " + version);
    }
    // Decrypt by the configured key name, not the envelope's recorded id, so decryption is bound
    // to this Aead's key and cannot be redirected to another key by a crafted ciphertext.
    return client.decrypt(keyName, keyVersion, iv, tag, ct, associatedData);
  }
}
