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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Minimal client for the CipherTrust Manager REST API ({@code /api/v1}): token acquisition with
 * transparent caching/renewal, and the symmetric {@code crypto/encrypt} / {@code crypto/decrypt}
 * service in AES-GCM mode.
 *
 * <p>CipherTrust JWTs are short-lived (300 s by default); this client caches the token and
 * re-authenticates ahead of expiry, plus once reactively if the server answers 401 (e.g. after a
 * server-side revocation). Concurrent callers that all observe the same expiry/401 collapse to a
 * single re-authentication.
 *
 * <p><b>Failure semantics.</b> Every call is bounded: connections respect the client's connect
 * timeout, each HTTP exchange respects {@link CipherTrustTransport#requestTimeout()}, and
 * transient transport failures (I/O errors and HTTP 502/503/504 — a CipherTrust node restarting
 * behind its front-end) are retried up to {@link CipherTrustTransport#attempts()} times with
 * exponential backoff. Everything else (4xx, 500, malformed bodies) fails immediately: those
 * are deterministic answers, and all crypto operations here are pure, so retrying them can only
 * add latency. The worst-case wall time of one operation is therefore roughly {@code attempts ×
 * (connect timeout + request timeout) + total backoff} — callers on a boot path (e.g. unwrapping a
 * vault keyset) get a clear exception within that envelope instead of a hang.
 */
final class CipherTrustRestClient {

  /** Renew the cached JWT this long before its nominal expiry. */
  private static final long EXPIRY_SAFETY_MARGIN_MS = 30_000;

  private final String baseUrl;
  private final CipherTrustCredentials credentials;
  private final CipherTrustTransport transport;
  private final HttpClient http;

  private final Object tokenLock = new Object();
  private String jwt;
  private long jwtExpiresAtMs;

  CipherTrustRestClient(
      String baseUrl,
      CipherTrustCredentials credentials,
      CipherTrustTransport transport,
      HttpClient http) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.credentials = credentials;
    this.transport = transport;
    this.http =
        http != null
            ? http
            : HttpClient.newBuilder().connectTimeout(transport.connectTimeout()).build();
  }

  /** Result of a {@code crypto/encrypt} call; all payload fields are base64 strings as returned. */
  static final class EncryptResult {
    final String keyId;
    final long keyVersion;
    final String iv;
    final String tag;
    final String ciphertext;

    EncryptResult(String keyId, long keyVersion, String iv, String tag, String ciphertext) {
      this.keyId = keyId;
      this.keyVersion = keyVersion;
      this.iv = iv;
      this.tag = tag;
      this.ciphertext = ciphertext;
    }
  }

  /**
   * Encrypts {@code plaintext} under the named key's latest version with AES-GCM. An empty or null
   * {@code associatedData} is sent as no AAD at all (and must be absent again on decrypt).
   */
  EncryptResult encrypt(String keyName, byte[] plaintext, byte[] associatedData)
      throws GeneralSecurityException {
    JsonObject body = new JsonObject();
    body.addProperty("id", keyName);
    body.addProperty("type", "name");
    body.addProperty("plaintext", Base64.getEncoder().encodeToString(plaintext));
    body.addProperty("mode", "gcm");
    if (associatedData != null && associatedData.length > 0) {
      body.addProperty("aad", Base64.getEncoder().encodeToString(associatedData));
    }
    JsonObject resp = postAuthorized("/api/v1/crypto/encrypt", body);
    try {
      return new EncryptResult(
          resp.get("id").getAsString(),
          resp.get("version").getAsLong(),
          resp.get("iv").getAsString(),
          resp.get("tag").getAsString(),
          resp.get("ciphertext").getAsString());
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("unexpected CipherTrust encrypt response shape", e);
    }
  }

  /**
   * Decrypts a payload with the given key <em>version</em> of the key named {@code keyName}.
   *
   * <p>The key is addressed by name (not by the id embedded in the ciphertext), so decryption is
   * bound to the configured key: a ciphertext produced under a different CipherTrust key fails the
   * GCM tag check even when the same credentials can access that other key. Pinning the version
   * keeps decryption working after the key is rotated (rotation adds a version under the same
   * name).
   */
  byte[] decrypt(
      String keyName,
      long keyVersion,
      String ivBase64,
      String tagBase64,
      String ciphertextBase64,
      byte[] associatedData)
      throws GeneralSecurityException {
    JsonObject body = new JsonObject();
    body.addProperty("id", keyName);
    body.addProperty("type", "name");
    body.addProperty("ciphertext", ciphertextBase64);
    body.addProperty("iv", ivBase64);
    body.addProperty("tag", tagBase64);
    body.addProperty("mode", "gcm");
    body.addProperty("version", keyVersion);
    if (associatedData != null && associatedData.length > 0) {
      body.addProperty("aad", Base64.getEncoder().encodeToString(associatedData));
    }
    JsonObject resp = postAuthorized("/api/v1/crypto/decrypt", body);
    try {
      return Base64.getDecoder().decode(resp.get("plaintext").getAsString());
    } catch (RuntimeException e) {
      throw new GeneralSecurityException("unexpected CipherTrust decrypt response shape", e);
    }
  }

  private JsonObject postAuthorized(String path, JsonObject body) throws GeneralSecurityException {
    String usedToken = token();
    HttpResponse<String> response = send(path, body, usedToken);
    if (response.statusCode() == 401) {
      // Cached token no longer accepted (revoked / clock skew): re-authenticate once. If another
      // thread already refreshed after this token was issued, reauthenticate() reuses that result
      // instead of hitting the auth endpoint again.
      response = send(path, body, reauthenticate(usedToken));
    }
    if (response.statusCode() / 100 != 2) {
      throw new GeneralSecurityException(
          "CipherTrust " + path + " failed: HTTP " + response.statusCode() + errorDetail(response));
    }
    return parseObject(response.body(), path);
  }

  /** Returns a valid JWT, re-authenticating (once, under the lock) if the cached one is stale. */
  private String token() throws GeneralSecurityException {
    synchronized (tokenLock) {
      if (jwt != null && System.currentTimeMillis() < jwtExpiresAtMs) {
        return jwt;
      }
      return authenticateLocked();
    }
  }

  /**
   * Re-authenticates after a 401, unless another thread has already replaced {@code staleToken}
   * with a fresh valid token (in which case that one is returned) — collapsing a post-revocation
   * herd into a single auth call.
   */
  private String reauthenticate(String staleToken) throws GeneralSecurityException {
    synchronized (tokenLock) {
      if (jwt != null
          && !jwt.equals(staleToken)
          && System.currentTimeMillis() < jwtExpiresAtMs) {
        return jwt;
      }
      return authenticateLocked();
    }
  }

  /** Performs the auth round trip and updates the cache. Must be called while holding tokenLock. */
  private String authenticateLocked() throws GeneralSecurityException {
    long now = System.currentTimeMillis();
    JsonObject body = new JsonObject();
    if (credentials.isRefreshToken()) {
      body.addProperty("grant_type", "refresh_token");
      body.addProperty("refresh_token", credentials.refreshToken());
    } else {
      body.addProperty("grant_type", "password");
      body.addProperty("username", credentials.username());
      body.addProperty("password", credentials.password());
    }
    HttpResponse<String> response = send("/api/v1/auth/tokens", body, null);
    if (response.statusCode() != 200) {
      throw new GeneralSecurityException(
          "CipherTrust authentication failed: HTTP "
              + response.statusCode()
              + errorDetail(response));
    }
    JsonObject json = parseObject(response.body(), "/api/v1/auth/tokens");
    if (!json.has("jwt")) {
      throw new GeneralSecurityException("CipherTrust token response contains no jwt");
    }
    long durationSeconds = json.has("duration") ? json.get("duration").getAsLong() : 300;
    jwt = json.get("jwt").getAsString();
    jwtExpiresAtMs = now + Math.max(durationSeconds * 1000 - EXPIRY_SAFETY_MARGIN_MS, 1000);
    return jwt;
  }

  /**
   * Sends one POST, retrying transient transport failures per the configured {@link
   * CipherTrustTransport}. Retryable: {@link IOException} (connect refused/timed out, reset,
   * response timeout) and HTTP 502/503/504. Anything else — including 401, other 4xx and 500 — is
   * returned to the caller unchanged: protocol-level handling (the single 401 re-auth) lives in
   * {@link #postAuthorized}, and deterministic errors must not be amplified by retries.
   *
   * <p>All requests this client issues (token grant, encrypt, decrypt) are safe to repeat: a
   * duplicate token grant just mints another short-lived JWT, and the crypto operations are pure.
   */
  private HttpResponse<String> send(String path, JsonObject body, String bearer)
      throws GeneralSecurityException {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(transport.requestTimeout())
            .header("Content-Type", "application/json")
            // CipherTrust's crypto endpoints reject requests without an Accept header.
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8));
    if (bearer != null) {
      request.header("Authorization", "Bearer " + bearer);
    }
    HttpRequest built = request.build();

    IOException lastFailure = null;
    for (int attempt = 1; attempt <= transport.attempts(); attempt++) {
      if (attempt > 1) {
        sleepBackoff(attempt, path);
      }
      try {
        HttpResponse<String> response = http.send(built, HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();
        if ((status == 502 || status == 503 || status == 504) && attempt < transport.attempts()) {
          lastFailure = null;
          continue;
        }
        return response;
      } catch (IOException e) {
        lastFailure = e;
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new GeneralSecurityException("CipherTrust request to " + path + " interrupted", e);
      }
    }
    if (lastFailure != null) {
      throw new GeneralSecurityException(
          "CipherTrust request to " + baseUrl + path + " failed after " + transport.attempts()
              + " attempt(s)",
          lastFailure);
    }
    // Retries exhausted on a 502/503/504 without a fresh response in hand only happens when the
    // last attempt also gated on `attempt < attempts()`, which it never does — but keep a
    // defensive throw so a future refactor cannot fall through silently.
    throw new GeneralSecurityException(
        "CipherTrust request to " + baseUrl + path + " failed after " + transport.attempts()
            + " attempt(s)");
  }

  /** Exponential backoff before retry number {@code attempt} (2, 3, ...). */
  private void sleepBackoff(int attempt, String path) throws GeneralSecurityException {
    long delayMs = transport.initialBackoff().toMillis() * (1L << (attempt - 2));
    try {
      Thread.sleep(delayMs);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new GeneralSecurityException(
          "CipherTrust request to " + path + " interrupted during retry backoff", e);
    }
  }

  /**
   * Parses a response expected to be a JSON object. Never chains the parsed element (which may
   * contain token or plaintext material) into the exception on a non-object body.
   */
  private static JsonObject parseObject(String body, String path) throws GeneralSecurityException {
    final JsonElement element;
    try {
      element = JsonParser.parseString(body);
    } catch (JsonSyntaxException | StackOverflowError e) {
      // JsonSyntaxException messages carry only line/column, not payload; the deliberately narrow
      // catch of StackOverflowError guards against a pathologically nested body.
      throw new GeneralSecurityException("CipherTrust " + path + " returned malformed JSON");
    }
    if (element == null || !element.isJsonObject()) {
      throw new GeneralSecurityException("CipherTrust " + path + " returned a non-object body");
    }
    return element.getAsJsonObject();
  }

  /** Extracts the CipherTrust error envelope (code/codeDesc/message) without echoing payloads. */
  private static String errorDetail(HttpResponse<String> response) {
    try {
      JsonElement element = JsonParser.parseString(response.body());
      if (!element.isJsonObject()) {
        return "";
      }
      JsonObject error = element.getAsJsonObject();
      StringBuilder sb = new StringBuilder();
      if (error.has("codeDesc")) {
        sb.append(' ').append(error.get("codeDesc").getAsString());
      }
      if (error.has("message")) {
        sb.append(" — ").append(error.get("message").getAsString());
      }
      String detail = sb.toString();
      return detail.length() > 300 ? detail.substring(0, 300) : detail;
    } catch (RuntimeException | StackOverflowError e) {
      return "";
    }
  }
}
