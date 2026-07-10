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

import java.time.Duration;

/**
 * Immutable transport settings for CipherTrust Manager calls: connection/request timeouts and the
 * retry policy for transient failures.
 *
 * <p>The defaults ({@link #DEFAULT}) bound any single operation to roughly {@code attempts ×
 * (connect + request timeout) + backoff} — about two minutes worst case — which matters most when
 * the first CipherTrust call sits on an application's boot path (e.g. unwrapping a vault keyset):
 * an unreachable CipherTrust Manager then surfaces as a clear exception instead of an indefinite
 * hang.
 *
 * <p>Instances are created with {@link #of} and passed to {@link
 * CipherTrustKmsClient#withTransport}:
 *
 * <pre>{@code
 * CipherTrustKmsClient.create(credentials)
 *     .withTransport(CipherTrustTransport.of(
 *         Duration.ofSeconds(5),   // connect timeout
 *         Duration.ofSeconds(15),  // request timeout
 *         3,                       // attempts (1 = no retries)
 *         Duration.ofMillis(300))) // initial backoff, doubled per retry
 * }</pre>
 */
public final class CipherTrustTransport {

  /** 10 s connect, 30 s request, 3 attempts, 300 ms initial backoff. */
  public static final CipherTrustTransport DEFAULT =
      new CipherTrustTransport(
          Duration.ofSeconds(10), Duration.ofSeconds(30), 3, Duration.ofMillis(300));

  private final Duration connectTimeout;
  private final Duration requestTimeout;
  private final int attempts;
  private final Duration initialBackoff;

  private CipherTrustTransport(
      Duration connectTimeout, Duration requestTimeout, int attempts, Duration initialBackoff) {
    this.connectTimeout = connectTimeout;
    this.requestTimeout = requestTimeout;
    this.attempts = attempts;
    this.initialBackoff = initialBackoff;
  }

  /**
   * Creates transport settings.
   *
   * @param connectTimeout TCP/TLS connect timeout (applies to the lazily created default {@code
   *     HttpClient}; a client supplied via {@link CipherTrustKmsClient#withHttpClient} keeps its
   *     own connect timeout)
   * @param requestTimeout timeout for one full HTTP exchange, connection included
   * @param attempts total tries per operation for transient failures (I/O errors, HTTP
   *     502/503/504); {@code 1} disables retries
   * @param initialBackoff delay before the first retry, doubled for each further retry
   * @throws IllegalArgumentException if a timeout is not positive, {@code attempts < 1}, or {@code
   *     initialBackoff} is negative
   */
  public static CipherTrustTransport of(
      Duration connectTimeout, Duration requestTimeout, int attempts, Duration initialBackoff) {
    if (connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()) {
      throw new IllegalArgumentException("connectTimeout must be positive");
    }
    if (requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()) {
      throw new IllegalArgumentException("requestTimeout must be positive");
    }
    if (attempts < 1) {
      throw new IllegalArgumentException("attempts must be >= 1");
    }
    if (initialBackoff == null || initialBackoff.isNegative()) {
      throw new IllegalArgumentException("initialBackoff must not be negative");
    }
    return new CipherTrustTransport(connectTimeout, requestTimeout, attempts, initialBackoff);
  }

  Duration connectTimeout() {
    return connectTimeout;
  }

  Duration requestTimeout() {
    return requestTimeout;
  }

  int attempts() {
    return attempts;
  }

  Duration initialBackoff() {
    return initialBackoff;
  }

  @Override
  public String toString() {
    return "CipherTrustTransport{connect="
        + connectTimeout
        + ", request="
        + requestTimeout
        + ", attempts="
        + attempts
        + ", backoff="
        + initialBackoff
        + "}";
  }
}
