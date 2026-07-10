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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Exercises the two integration patterns a host application actually uses: envelope encryption
 * with the CipherTrust KEK, and wrapping/unwrapping an encrypted Tink keyset (the pattern CLM-type
 * applications use for their vault master key).
 */
final class TinkInteropTest {

  private FakeCipherTrust fake;
  private Aead remote;

  @BeforeAll
  static void registerTink() throws Exception {
    AeadConfig.register();
  }

  @BeforeEach
  void setUp() throws Exception {
    fake = new FakeCipherTrust();
    fake.registerKey("interop-kek");
    String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/interop-kek";
    remote = new CipherTrustKmsClient(uri)
        .usingInsecureHttpForTests()
        .withCredentials(
            CipherTrustCredentials.usernamePassword(FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD))
        .getAead(uri);
  }

  @AfterEach
  void tearDown() {
    fake.close();
  }

  @Test
  void kmsEnvelopeAeadRoundtrip() throws Exception {
    Aead envelope = KmsEnvelopeAead.create(PredefinedAeadParameters.AES256_GCM, remote);
    byte[] plaintext = "envelope-encrypted payload".getBytes(UTF_8);
    byte[] associatedData = "context".getBytes(UTF_8);
    byte[] ciphertext = envelope.encrypt(plaintext, associatedData);
    assertArrayEquals(plaintext, envelope.decrypt(ciphertext, associatedData));
    assertThrows(GeneralSecurityException.class,
        () -> envelope.decrypt(ciphertext, "other-context".getBytes(UTF_8)));
  }

  @Test
  void encryptedKeysetWrapUnwrap() throws Exception {
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"));
    byte[] keysetAssociatedData = "keyset-ad".getBytes(UTF_8);

    // Wrap the keyset with the CipherTrust KEK (what a vault does with its master key)...
    String wrapped =
        TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(handle, remote, keysetAssociatedData);

    // ...then unwrap and verify the restored keyset decrypts data produced by the original.
    KeysetHandle restored =
        TinkJsonProtoKeysetFormat.parseEncryptedKeyset(wrapped, remote, keysetAssociatedData);
    Aead original = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
    Aead reloaded = restored.getPrimitive(RegistryConfiguration.get(), Aead.class);

    byte[] plaintext = "data encrypted with the wrapped keyset".getBytes(UTF_8);
    byte[] associatedData = "ad".getBytes(UTF_8);
    assertArrayEquals(plaintext, reloaded.decrypt(original.encrypt(plaintext, associatedData), associatedData));

    // Unwrapping with the wrong keyset AD must fail.
    assertThrows(GeneralSecurityException.class,
        () -> TinkJsonProtoKeysetFormat.parseEncryptedKeyset(wrapped, remote, "wrong".getBytes(UTF_8)));
  }
}
