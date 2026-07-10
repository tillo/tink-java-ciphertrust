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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.KmsEnvelopeAead;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/**
 * Integration tests against a real CipherTrust Manager. Enabled only when the environment
 * provides:
 *
 * <ul>
 *   <li>{@code CIPHERTRUST_TEST_KEY_URI} — e.g. {@code ciphertrust://cm.example.com/my-test-kek}
 *   <li>{@code CIPHERTRUST_USERNAME} / {@code CIPHERTRUST_PASSWORD} (or {@code
 *       CIPHERTRUST_REFRESH_TOKEN})
 * </ul>
 */
@EnabledIfEnvironmentVariable(named = "CIPHERTRUST_TEST_KEY_URI", matches = ".+")
final class LiveCipherTrustTest {

  @BeforeAll
  static void registerTink() throws Exception {
    AeadConfig.register();
  }

  private static Aead liveAead() throws GeneralSecurityException {
    String uri = System.getenv("CIPHERTRUST_TEST_KEY_URI");
    return CipherTrustKmsClient.create(uri, CipherTrustCredentials.fromEnvironment()).getAead(uri);
  }

  @Test
  void roundtripWithAssociatedData() throws Exception {
    Aead aead = liveAead();
    byte[] plaintext = "live roundtrip".getBytes(UTF_8);
    byte[] associatedData = "live-ad".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt(ciphertext, "wrong-ad".getBytes(UTF_8)));
  }

  @Test
  void roundtripWithEmptyAssociatedData() throws Exception {
    Aead aead = liveAead();
    byte[] plaintext = "live empty-ad roundtrip".getBytes(UTF_8);
    assertArrayEquals(plaintext, aead.decrypt(aead.encrypt(plaintext, new byte[0]), new byte[0]));
  }

  @Test
  void emptyPlaintextRoundtrip() throws Exception {
    Aead aead = liveAead();
    byte[] associatedData = "ad".getBytes(UTF_8);
    assertArrayEquals(new byte[0], aead.decrypt(aead.encrypt(new byte[0], associatedData), associatedData));
  }

  @Test
  void kmsEnvelopeAeadRoundtrip() throws Exception {
    Aead envelope = KmsEnvelopeAead.create(PredefinedAeadParameters.AES256_GCM, liveAead());
    byte[] plaintext = "live envelope".getBytes(UTF_8);
    byte[] associatedData = "ad".getBytes(UTF_8);
    assertArrayEquals(plaintext, envelope.decrypt(envelope.encrypt(plaintext, associatedData), associatedData));
  }

  @Test
  void encryptedKeysetWrapUnwrap() throws Exception {
    Aead remote = liveAead();
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"));
    byte[] keysetAssociatedData = new byte[0];
    String wrapped =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(handle, remote, keysetAssociatedData);
    KeysetHandle restored =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(wrapped, remote, keysetAssociatedData);
    Aead original = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    Aead reloaded = restored.getPrimitive(RegistryConfiguration.get(), Aead.class);
    byte[] plaintext = "wrapped keyset payload".getBytes(UTF_8);
    assertArrayEquals(plaintext, reloaded.decrypt(original.encrypt(plaintext, new byte[0]), new byte[0]));
  }
}
