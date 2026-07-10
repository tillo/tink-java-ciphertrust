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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.crypto.tink.Aead;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Failure-envelope tests: transient CipherTrust failures are retried, deterministic errors are
 * not, and an unreachable or stalled CipherTrust Manager surfaces as a bounded {@link
 * GeneralSecurityException} rather than a hang — the property a caller's boot path relies on.
 */
final class CipherTrustTransportTest {

  private FakeCipherTrust fake;

  @BeforeEach
  void setUp() throws Exception {
    fake = new FakeCipherTrust();
    fake.registerKey("transport-kek");
  }

  @AfterEach
  void tearDown() {
    fake.close();
  }

  private Aead aead(CipherTrustTransport transport) throws GeneralSecurityException {
    String uri = "ciphertrust://127.0.0.1:" + fake.port() + "/transport-kek";
    return new CipherTrustKmsClient(uri)
        .usingInsecureHttpForTests()
        .withCredentials(
            CipherTrustCredentials.usernamePassword(
                FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD))
        .withTransport(transport)
        .getAead(uri);
  }

  private static CipherTrustTransport fastRetries(int attempts) {
    return CipherTrustTransport.of(
        Duration.ofSeconds(2), Duration.ofSeconds(2), attempts, Duration.ofMillis(10));
  }

  @Test
  void transient503IsRetriedToSuccess() throws Exception {
    Aead aead = aead(fastRetries(3));
    byte[] plaintext = "retry me".getBytes(UTF_8);
    fake.failNextCrypto(2); // two 503s, third call succeeds — within the 3-attempt budget
    byte[] ciphertext = aead.encrypt(plaintext, null);
    assertArrayEquals(plaintext, aead.decrypt(ciphertext, null));
  }

  @Test
  void retriesExhaustedSurfaceTheGatewayStatus() throws Exception {
    Aead aead = aead(fastRetries(2));
    fake.failNextCrypto(5); // more failures than the retry budget
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {1}, null));
    assertTrue(e.getMessage().contains("503"), e.getMessage());
    assertEquals(2, fake.cryptoCalls(), "should have stopped after the configured attempts");
  }

  @Test
  void deterministic4xxIsNotRetried() throws Exception {
    Aead aead = aead(fastRetries(3));
    fake.failNextCryptoStatus = 400;
    fake.failNextCrypto(1);
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {1}, null));
    assertEquals(1, fake.cryptoCalls(), "a 400 is a deterministic answer; retrying would only add latency");
  }

  @Test
  void singleAttemptDisablesRetries() throws Exception {
    Aead aead = aead(fastRetries(1));
    fake.failNextCrypto(1);
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {1}, null));
    assertEquals(1, fake.cryptoCalls());
  }

  @Test
  void connectionRefusedFailsBounded() throws Exception {
    // Reserve a port and close it again: connections to it are refused immediately, so the
    // failure must surface well inside the retry budget instead of hanging.
    final int closedPort;
    try (ServerSocket socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }
    String uri = "ciphertrust://127.0.0.1:" + closedPort + "/no-such-kek";
    Aead aead =
        new CipherTrustKmsClient(uri)
            .usingInsecureHttpForTests()
            .withCredentials(
                CipherTrustCredentials.usernamePassword(
                    FakeCipherTrust.USERNAME, FakeCipherTrust.PASSWORD))
            .withTransport(fastRetries(3))
            .getAead(uri);
    long start = System.nanoTime();
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {1}, null));
    long elapsedMs = (System.nanoTime() - start) / 1_000_000;
    assertTrue(e.getMessage().contains("after 3 attempt(s)"), e.getMessage());
    assertTrue(elapsedMs < 10_000, "failure took " + elapsedMs + " ms; expected a bounded fast-fail");
  }

  @Test
  void stalledServerHitsTheRequestTimeout() throws Exception {
    CipherTrustTransport tight =
        CipherTrustTransport.of(
            Duration.ofSeconds(2), Duration.ofMillis(400), 1, Duration.ofMillis(10));
    Aead aead = aead(tight);
    // Prime the JWT cache with a normal call so the stall hits the crypto exchange itself.
    byte[] warmup = aead.encrypt("warmup".getBytes(UTF_8), null);
    aead.decrypt(warmup, null);
    fake.stallNextCryptoMs = 5_000;
    long start = System.nanoTime();
    assertThrows(GeneralSecurityException.class, () -> aead.encrypt(new byte[] {1}, null));
    long elapsedMs = (System.nanoTime() - start) / 1_000_000;
    assertTrue(elapsedMs < 4_000, "timed out after " + elapsedMs + " ms; expected ~400 ms budget");
  }

  @Test
  void ofRejectsInvalidSettings() {
    assertThrows(
        IllegalArgumentException.class,
        () -> CipherTrustTransport.of(Duration.ZERO, Duration.ofSeconds(1), 1, Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () -> CipherTrustTransport.of(Duration.ofSeconds(1), Duration.ZERO, 1, Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CipherTrustTransport.of(
                Duration.ofSeconds(1), Duration.ofSeconds(1), 0, Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CipherTrustTransport.of(
                Duration.ofSeconds(1), Duration.ofSeconds(1), 1, Duration.ofMillis(-1)));
  }
}
