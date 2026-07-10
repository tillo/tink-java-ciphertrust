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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.security.GeneralSecurityException;
import java.util.Random;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class CipherTrustAeadTest {

  private FakeCipherTrust fake;

  @BeforeEach
  void setUp() throws Exception {
    fake = new FakeCipherTrust();
    fake.registerKey("aead-kek");
  }

  @AfterEach
  void tearDown() {
    fake.close();
  }

  private Aead aead() throws GeneralSecurityException {
    return aeadWithCredentials(
        CipherTrustCredentials.usernamePassword(FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD));
  }

  private Aead aeadWithCredentials(CipherTrustCredentials credentials)
      throws GeneralSecurityException {
    String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/aead-kek";
    return new CipherTrustKmsClient(uri)
        .usingInsecureHttpForTests()
        .withCredentials(credentials)
        .getAead(uri);
  }

  @Test
  void roundtripWithAssociatedData() throws Exception {
    Aead aead = aead();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    byte[] associatedData = "associated".getBytes(UTF_8);
    assertArrayEquals(plaintext, aead.decrypt(aead.encrypt(plaintext, associatedData), associatedData));
  }

  @Test
  void roundtripWithEmptyAssociatedData() throws Exception {
    Aead aead = aead();
    byte[] plaintext = "plaintext".getBytes(UTF_8);
    assertArrayEquals(plaintext, aead.decrypt(aead.encrypt(plaintext, new byte[0]), new byte[0]));
  }

  @Test
  void emptyPlaintextRoundtrip() throws Exception {
    Aead aead = aead();
    byte[] associatedData = "ad".getBytes(UTF_8);
    assertArrayEquals(new byte[0], aead.decrypt(aead.encrypt(new byte[0], associatedData), associatedData));
  }

  @Test
  void largePlaintextRoundtrip() throws Exception {
    Aead aead = aead();
    byte[] plaintext = new byte[1 << 20];
    new Random(42).nextBytes(plaintext);
    assertArrayEquals(plaintext, aead.decrypt(aead.encrypt(plaintext, new byte[0]), new byte[0]));
  }

  @Test
  void decryptWithWrongAssociatedDataFails() throws Exception {
    Aead aead = aead();
    byte[] ciphertext = aead.encrypt("plaintext".getBytes(UTF_8), "right".getBytes(UTF_8));
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt(ciphertext, "wrong".getBytes(UTF_8)));
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(ciphertext, new byte[0]));
  }

  @Test
  void decryptOfTamperedEnvelopeFails() throws Exception {
    Aead aead = aead();
    byte[] ciphertext = aead.encrypt("plaintext".getBytes(UTF_8), new byte[0]);
    JsonObject envelope = JsonParser.parseString(new String(ciphertext, UTF_8)).getAsJsonObject();

    // Flip a character inside the base64 ciphertext.
    String ct = envelope.get("ct").getAsString();
    JsonObject tampered = envelope.deepCopy();
    tampered.addProperty("ct", (ct.charAt(0) == 'A' ? "B" : "A") + ct.substring(1));
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt(tampered.toString().getBytes(UTF_8), new byte[0]));

    // Unknown envelope version.
    JsonObject wrongVersion = envelope.deepCopy();
    wrongVersion.addProperty("v", 2);
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt(wrongVersion.toString().getBytes(UTF_8), new byte[0]));

    // Missing field.
    JsonObject missing = envelope.deepCopy();
    missing.remove("iv");
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt(missing.toString().getBytes(UTF_8), new byte[0]));

    // Not JSON at all.
    assertThrows(GeneralSecurityException.class,
        () -> aead.decrypt("garbage".getBytes(UTF_8), new byte[0]));
  }

  @Test
  void oldCiphertextsSurviveKeyRotation() throws Exception {
    Aead aead = aead();
    byte[] plaintext = "pre-rotation".getBytes(UTF_8);
    byte[] before = aead.encrypt(plaintext, new byte[0]);

    fake.rotate("aead-kek");
    byte[] after = aead.encrypt(plaintext, new byte[0]);

    long versionBefore = JsonParser.parseString(new String(before, UTF_8))
        .getAsJsonObject().get("ver").getAsLong();
    long versionAfter = JsonParser.parseString(new String(after, UTF_8))
        .getAsJsonObject().get("ver").getAsLong();
    assertNotEquals(versionBefore, versionAfter);

    assertArrayEquals(plaintext, aead.decrypt(before, new byte[0]));
    assertArrayEquals(plaintext, aead.decrypt(after, new byte[0]));
  }

  @Test
  void expiredTokenIsRenewedTransparently() throws Exception {
    fake.tokenDurationSeconds = 1;
    Aead aead = aead();
    aead.encrypt("one".getBytes(UTF_8), new byte[0]);
    assertEquals(1, fake.authCalls());
    Thread.sleep(1200);
    aead.encrypt("two".getBytes(UTF_8), new byte[0]);
    assertEquals(2, fake.authCalls());
  }

  @Test
  void revokedTokenTriggersOneReauthRetry() throws Exception {
    Aead aead = aead();
    aead.encrypt("one".getBytes(UTF_8), new byte[0]);
    assertEquals(1, fake.authCalls());
    fake.revokeAllTokens();
    byte[] plaintext = "two".getBytes(UTF_8);
    byte[] ciphertext = aead.encrypt(plaintext, new byte[0]);
    assertEquals(2, fake.authCalls());
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, new byte[0]));
  }

  @Test
  void badCredentialsFailWithAuthenticationError() throws Exception {
    Aead aead = aeadWithCredentials(CipherTrustCredentials.usernamePassword("svc", "wrong"));
    GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
        () -> aead.encrypt("plaintext".getBytes(UTF_8), new byte[0]));
    assertTrue(e.getMessage().contains("authentication failed"));
  }

  @Test
  void refreshTokenGrantWorks() throws Exception {
    Aead aead = aeadWithCredentials(
        CipherTrustCredentials.ofRefreshToken(FakeCipherTrust.REFRESH_TOKEN));
    byte[] plaintext = "via refresh token".getBytes(UTF_8);
    assertArrayEquals(plaintext, aead.decrypt(aead.encrypt(plaintext, new byte[0]), new byte[0]));
  }

  @Test
  void decryptDoesNotHonorForeignKeyIdInEnvelope() throws Exception {
    // Register a second key and encrypt under it; then rewrite the envelope's "id" to that key and
    // hand it to the key-A Aead. Decryption must bind to the configured key name (aead-kek), so
    // the foreign ciphertext fails rather than being decrypted through key B.
    fake.registerKey("aead-kek-b");
    Aead aeadA = aead();

    String uriB = "ciphertrust://127.0.0.1:" + fake.port() + "/aead-kek-b";
    Aead aeadB = new CipherTrustKmsClient(uriB)
        .usingInsecureHttpForTests()
        .withCredentials(
            CipherTrustCredentials.usernamePassword(FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD))
        .getAead(uriB);

    byte[] secretUnderB = "secret owned by key B".getBytes(UTF_8);
    byte[] envelopeFromB = aeadB.encrypt(secretUnderB, new byte[0]);
    // Sanity: key B's own Aead round-trips it.
    assertArrayEquals(secretUnderB, aeadB.decrypt(envelopeFromB, new byte[0]));

    // Key A's Aead must NOT decrypt key B's ciphertext (no cross-key oracle).
    assertThrows(GeneralSecurityException.class, () -> aeadA.decrypt(envelopeFromB, new byte[0]));
  }

  @Test
  void decryptOfDeeplyNestedJsonThrowsGeneralSecurityException() throws Exception {
    Aead aead = aead();
    StringBuilder deep = new StringBuilder();
    for (int i = 0; i < 100_000; i++) {
      deep.append('[');
    }
    byte[] hostile = deep.toString().getBytes(UTF_8);
    // Must be a GeneralSecurityException, never a StackOverflowError escaping decrypt().
    assertThrows(GeneralSecurityException.class, () -> aead.decrypt(hostile, new byte[0]));
  }

  @Test
  void unknownKeyFailsCleanly() throws Exception {
    String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/no-such-key";
    Aead aead = new CipherTrustKmsClient(uri)
        .usingInsecureHttpForTests()
        .withCredentials(
            CipherTrustCredentials.usernamePassword(FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD))
        .getAead(uri);
    GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
        () -> aead.encrypt("plaintext".getBytes(UTF_8), new byte[0]));
    assertTrue(e.getMessage().contains("404") || e.getMessage().contains("ResourceNotFound"));
  }
}
