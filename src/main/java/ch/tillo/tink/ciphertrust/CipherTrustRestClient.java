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
import java.time.Duration;
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
 */
final class CipherTrustRestClient {

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
  /** Renew the cached JWT this long before its nominal expiry. */
  private static final long EXPIRY_SAFETY_MARGIN_MS = 30_000;

  private final String baseUrl;
  private final CipherTrustCredentials credentials;
  private final HttpClient http;

  private final Object tokenLock = new Object();
  private String jwt;
  private long jwtExpiresAtMs;

  CipherTrustRestClient(String baseUrl, CipherTrustCredentials credentials, HttpClient http) {
    this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    this.credentials = credentials;
    this.http =
        http != null ? http : HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
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

  private HttpResponse<String> send(String path, JsonObject body, String bearer)
      throws GeneralSecurityException {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(REQUEST_TIMEOUT)
            .header("Content-Type", "application/json")
            // CipherTrust's crypto endpoints reject requests without an Accept header.
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8));
    if (bearer != null) {
      request.header("Authorization", "Bearer " + bearer);
    }
    try {
      return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new GeneralSecurityException("CipherTrust request to " + path + " failed", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new GeneralSecurityException("CipherTrust request to " + path + " interrupted", e);
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
