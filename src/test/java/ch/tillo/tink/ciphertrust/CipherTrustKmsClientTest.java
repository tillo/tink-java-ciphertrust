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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class CipherTrustKmsClientTest {

  @Test
  void unboundClientSupportsAnyCiphertrustUri() {
    CipherTrustKmsClient client = new CipherTrustKmsClient();
    assertTrue(client.doesSupport("ciphertrust://cm.example.com/some-kek"));
    assertTrue(client.doesSupport("CIPHERTRUST://cm.example.com/some-kek"));
    assertFalse(client.doesSupport("gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"));
    assertFalse(client.doesSupport("hcvault://vault.example.com/keys/k"));
    assertFalse(client.doesSupport(null));
  }

  @Test
  void boundClientSupportsExactlyItsUri() {
    String uri = "ciphertrust://cm.example.com/my-kek";
    CipherTrustKmsClient client = new CipherTrustKmsClient(uri);
    assertTrue(client.doesSupport(uri));
    assertFalse(client.doesSupport("ciphertrust://cm.example.com/other-kek"));
    assertFalse(client.doesSupport("ciphertrust://other.example.com/my-kek"));
  }

  @Test
  void bindingToForeignUriThrows() {
    assertThrows(IllegalArgumentException.class,
        () -> new CipherTrustKmsClient("gcp-kms://projects/p"));
  }

  @Test
  void parseKeyUriExtractsHostPortAndName() throws Exception {
    CipherTrustKmsClient.KeyUriParts parts =
        CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com:8443/team/my-kek");
    assertEquals("cm.example.com", parts.host);
    assertEquals(8443, parts.port);
    assertEquals("team/my-kek", parts.keyName);

    CipherTrustKmsClient.KeyUriParts noPort =
        CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com/my-kek");
    assertEquals(-1, noPort.port);
    assertEquals("my-kek", noPort.keyName);
  }

  @Test
  void parseKeyUriRejectsMalformedUris() {
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com/"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust:///my-kek"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com/my-kek?version=2"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("https://cm.example.com/my-kek"));
  }

  @Test
  void parseKeyUriRejectsUserinfoHostSpoofing() {
    // The real host of this URI is evil.com, not cm.example.com — must be rejected so credentials
    // are never POSTed to an attacker host named via userinfo.
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://cm.example.com@evil.com/my-kek"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://user:pass@evil.com/my-kek"));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustKmsClient.parseKeyUri("ciphertrust://@evil.com/my-kek"));
  }

  @Test
  void getAeadWithoutCredentialsThrows() {
    CipherTrustKmsClient client = new CipherTrustKmsClient();
    GeneralSecurityException e = assertThrows(GeneralSecurityException.class,
        () -> client.getAead("ciphertrust://cm.example.com/my-kek"));
    assertTrue(e.getMessage().contains("credentials"));
  }

  @Test
  void getAeadForUnsupportedUriThrows() {
    CipherTrustKmsClient client =
        CipherTrustKmsClient.create(
            "ciphertrust://cm.example.com/my-kek",
            CipherTrustCredentials.usernamePassword("u", "p"));
    assertThrows(GeneralSecurityException.class,
        () -> client.getAead("ciphertrust://cm.example.com/other-kek"));
  }

  @Test
  void credentialsFromJsonFilePassword(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("creds.json");
    Files.write(file, "{\"username\":\"svc\",\"password\":\"pw\"}".getBytes(StandardCharsets.UTF_8));
    CipherTrustCredentials credentials = CipherTrustCredentials.fromJsonFile(file);
    assertFalse(credentials.isRefreshToken());
    assertEquals("svc", credentials.username());
  }

  @Test
  void credentialsFromJsonFileRefreshToken(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("creds.json");
    Files.write(file, "{\"refresh_token\":\"tok\"}".getBytes(StandardCharsets.UTF_8));
    CipherTrustCredentials credentials = CipherTrustCredentials.fromJsonFile(file);
    assertTrue(credentials.isRefreshToken());
  }

  @Test
  void credentialsFromJsonFileRejectsBadContent(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("creds.json");
    Files.write(file, "{\"something\":\"else\"}".getBytes(StandardCharsets.UTF_8));
    assertThrows(GeneralSecurityException.class, () -> CipherTrustCredentials.fromJsonFile(file));
    assertThrows(GeneralSecurityException.class,
        () -> CipherTrustCredentials.fromJsonFile(dir.resolve("missing.json")));
  }

  @Test
  void credentialsFromJsonFileErrorNeverLeaksFileContent(@TempDir Path dir) throws Exception {
    // Classic misconfiguration: a bare secret written into the file instead of the JSON wrapper.
    String secret = "super-secret-refresh-token-hunter2";
    Path bare = dir.resolve("bare.json");
    Files.write(bare, secret.getBytes(StandardCharsets.UTF_8));
    GeneralSecurityException e1 = assertThrows(GeneralSecurityException.class,
        () -> CipherTrustCredentials.fromJsonFile(bare));
    assertFalse(fullChain(e1).contains(secret));

    // Same for a JSON array carrying secrets.
    Path array = dir.resolve("array.json");
    Files.write(array, ("[\"" + secret + "\"]").getBytes(StandardCharsets.UTF_8));
    GeneralSecurityException e2 = assertThrows(GeneralSecurityException.class,
        () -> CipherTrustCredentials.fromJsonFile(array));
    assertFalse(fullChain(e2).contains(secret));
  }

  private static String fullChain(Throwable t) {
    StringBuilder sb = new StringBuilder();
    for (Throwable c = t; c != null; c = c.getCause()) {
      sb.append(c.getClass().getName()).append(':').append(String.valueOf(c.getMessage())).append('\n');
    }
    return sb.toString();
  }

  @Test
  void credentialsToStringLeaksNoSecrets() {
    String s = CipherTrustCredentials.usernamePassword("svc", "hunter2-secret").toString();
    assertFalse(s.contains("hunter2-secret"));
    String t = CipherTrustCredentials.ofRefreshToken("very-secret-token").toString();
    assertFalse(t.contains("very-secret-token"));
  }

  @Test
  void fullRoundtripThroughKmsClientAgainstFake() throws Exception {
    try (FakeCipherTrust fake = new FakeCipherTrust()) {
      fake.registerKey("unit-kek");
      String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/unit-kek";
      KmsClient client =
          new CipherTrustKmsClient(uri)
              .usingInsecureHttpForTests()
              .withCredentials(
                  CipherTrustCredentials.usernamePassword(
                      FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD));
      Aead aead = client.getAead(uri);
      byte[] plaintext = "hello ciphertrust".getBytes(StandardCharsets.UTF_8);
      byte[] associatedData = "context".getBytes(StandardCharsets.UTF_8);
      byte[] ciphertext = aead.encrypt(plaintext, associatedData);
      assertArrayEquals(plaintext, aead.decrypt(ciphertext, associatedData));
    }
  }

  @Test
  void registerAddsClientToGlobalRegistry(@TempDir Path dir) throws Exception {
    try (FakeCipherTrust fake = new FakeCipherTrust()) {
      fake.registerKey("registry-kek");
      // Unique per-run URI: KmsClients is a process-global registry.
      String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/registry-kek";
      Path file = dir.resolve("creds.json");
      Files.write(file,
          ("{\"username\":\"" + FakeCipherTrust.USERNAME + "\",\"password\":\""
              + FakeCipherTrust.PASSWORD + "\"}").getBytes(StandardCharsets.UTF_8));
      CipherTrustKmsClient.register(Optional.of(uri), Optional.of(file.toString()));
      KmsClient fromRegistry = KmsClients.get(uri);
      assertTrue(fromRegistry.doesSupport(uri));
    }
  }
}
