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

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * In-process imitation of the CipherTrust Manager endpoints this library uses, faithful to
 * behavior verified against a live CM 2.22 instance: strict Accept-header checking, 300 s JWTs,
 * 401 for missing/expired/revoked tokens, AES-GCM with 12-byte IV / 16-byte tag / enforced AAD,
 * versioned keys addressed by name (encrypt) or opaque id (decrypt).
 */
final class FakeCipherTrust implements AutoCloseable {

  static final String USERNAME = "svc-test";
  static final String PASSWORD = "Fake-Password1!";
  static final String REFRESH_TOKEN = "fake-refresh-token";

  private final HttpServer server;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, FakeKey> keysByName = new ConcurrentHashMap<>();
  private final Map<String, FakeKey> keysById = new ConcurrentHashMap<>();
  private final Map<String, Long> validTokens = new ConcurrentHashMap<>();
  private final AtomicInteger authCalls = new AtomicInteger();
  private final AtomicInteger cryptoCalls = new AtomicInteger();
  // Transient-failure injection for retry tests: the next N crypto calls answer with this
  // status before any other processing (mimicking a CM node restarting behind its front-end).
  private final AtomicInteger failNextCryptoCount = new AtomicInteger();

  volatile long tokenDurationSeconds = 300;
  volatile int failNextCryptoStatus = 503;
  /** The next crypto call stalls this long before answering (for request-timeout tests). */
  volatile long stallNextCryptoMs = 0;

  private static final class FakeKey {
    final String name;
    final String id = UUID.randomUUID().toString();
    final List<SecretKey> versions = new ArrayList<>();

    FakeKey(String name) {
      this.name = name;
    }
  }

  FakeCipherTrust() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/api/v1/auth/tokens", this::handleAuth);
    server.createContext("/api/v1/crypto/encrypt", exchange -> handleCrypto(exchange, true));
    server.createContext("/api/v1/crypto/decrypt", exchange -> handleCrypto(exchange, false));
    server.start();
  }

  int port() {
    return server.getAddress().getPort();
  }

  int authCalls() {
    return authCalls.get();
  }

  int cryptoCalls() {
    return cryptoCalls.get();
  }

  /** Makes the next {@code count} crypto calls fail with {@link #failNextCryptoStatus}. */
  void failNextCrypto(int count) {
    failNextCryptoCount.set(count);
  }

  void revokeAllTokens() {
    validTokens.clear();
  }

  String registerKey(String name) {
    FakeKey key = new FakeKey(name);
    key.versions.add(newAesKey());
    keysByName.put(name, key);
    keysById.put(key.id, key);
    return key.id;
  }

  /** Adds a new key version; subsequent encrypts use it, old ciphertexts stay decryptable. */
  void rotate(String name) {
    keysByName.get(name).versions.add(newAesKey());
  }

  private SecretKey newAesKey() {
    try {
      KeyGenerator generator = KeyGenerator.getInstance("AES");
      generator.init(256);
      return generator.generateKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private void handleAuth(HttpExchange exchange) throws IOException {
    authCalls.incrementAndGet();
    JsonObject body = readJson(exchange);
    if (body == null) {
      return;
    }
    String grant = optString(body, "grant_type");
    boolean ok;
    if ("password".equals(grant)) {
      ok = USERNAME.equals(optString(body, "username")) && PASSWORD.equals(optString(body, "password"));
    } else if ("refresh_token".equals(grant)) {
      ok = REFRESH_TOKEN.equals(optString(body, "refresh_token"));
    } else {
      ok = false;
    }
    if (!ok) {
      sendError(exchange, 401, 1, "NCERRUnauthorized: invalid credentials");
      return;
    }
    String jwt = "fake-jwt-" + UUID.randomUUID();
    validTokens.put(jwt, System.currentTimeMillis() + tokenDurationSeconds * 1000);
    JsonObject response = new JsonObject();
    response.addProperty("jwt", jwt);
    response.addProperty("duration", tokenDurationSeconds);
    response.addProperty("token_type", "Bearer");
    response.addProperty("refresh_token", REFRESH_TOKEN);
    send(exchange, 200, response);
  }

  private void handleCrypto(HttpExchange exchange, boolean encrypt) throws IOException {
    cryptoCalls.incrementAndGet();
    long stall = stallNextCryptoMs;
    if (stall > 0) {
      stallNextCryptoMs = 0;
      try {
        Thread.sleep(stall);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    if (failNextCryptoCount.getAndUpdate(n -> n > 0 ? n - 1 : 0) > 0) {
      sendError(exchange, failNextCryptoStatus, 0, "injected transient failure");
      return;
    }
    // Live CM rejects crypto calls without an Accept header.
    if (exchange.getRequestHeaders().getFirst("Accept") == null) {
      sendError(exchange, 400, 15, "NCERRBadRequest: Accept header is invalid.");
      return;
    }
    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
    String token = authorization != null && authorization.startsWith("Bearer ")
        ? authorization.substring("Bearer ".length())
        : null;
    Long expiry = token != null ? validTokens.get(token) : null;
    if (expiry == null || expiry < System.currentTimeMillis()) {
      sendError(exchange, 401, 1, "NCERRUnauthorized: token missing, expired, or revoked");
      return;
    }
    JsonObject body = readJson(exchange);
    if (body == null) {
      return;
    }
    String keyRef = optString(body, "id");
    FakeKey key = keysByName.containsKey(keyRef) ? keysByName.get(keyRef) : keysById.get(keyRef);
    if (key == null) {
      sendError(exchange, 404, 16, "NCERRResourceNotFound: Resource not found");
      return;
    }
    if (!"gcm".equals(optString(body, "mode"))) {
      sendError(exchange, 400, 9, "NCERRInvalidParamValue: unsupported mode");
      return;
    }
    byte[] aad = body.has("aad") ? Base64.getDecoder().decode(body.get("aad").getAsString()) : null;
    try {
      if (encrypt) {
        int version = key.versions.size() - 1;
        SecretKey secretKey = key.versions.get(version);
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        if (aad != null) {
          cipher.updateAAD(aad);
        }
        byte[] out = cipher.doFinal(Base64.getDecoder().decode(body.get("plaintext").getAsString()));
        byte[] ciphertext = Arrays.copyOfRange(out, 0, out.length - 16);
        byte[] tag = Arrays.copyOfRange(out, out.length - 16, out.length);
        JsonObject response = new JsonObject();
        response.addProperty("id", key.id);
        response.addProperty("version", version);
        response.addProperty("iv", Base64.getEncoder().encodeToString(iv));
        response.addProperty("tag", Base64.getEncoder().encodeToString(tag));
        response.addProperty("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        response.addProperty("mode", "gcm");
        send(exchange, 200, response);
      } else {
        int version = body.has("version") ? body.get("version").getAsInt() : key.versions.size() - 1;
        if (version < 0 || version >= key.versions.size()) {
          sendError(exchange, 404, 16, "NCERRResourceNotFound: no such key version");
          return;
        }
        SecretKey secretKey = key.versions.get(version);
        byte[] iv = Base64.getDecoder().decode(body.get("iv").getAsString());
        byte[] tag = Base64.getDecoder().decode(body.get("tag").getAsString());
        byte[] ciphertext = Base64.getDecoder().decode(body.get("ciphertext").getAsString());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        if (aad != null) {
          cipher.updateAAD(aad);
        }
        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
        byte[] plaintext = cipher.doFinal(combined);
        JsonObject response = new JsonObject();
        response.addProperty("plaintext", Base64.getEncoder().encodeToString(plaintext));
        send(exchange, 200, response);
      }
    } catch (Exception e) {
      sendError(exchange, 400, 106,
          "NCERRCryptoOperationFailed: Cryptographic operation failed in cipher operation");
    }
  }

  private JsonObject readJson(HttpExchange exchange) throws IOException {
    try (InputStream in = exchange.getRequestBody()) {
      byte[] raw = in.readAllBytes();
      return JsonParser.parseString(new String(raw, StandardCharsets.UTF_8)).getAsJsonObject();
    } catch (RuntimeException e) {
      sendError(exchange, 400, 15, "NCERRBadRequest: malformed JSON");
      return null;
    }
  }

  private static String optString(JsonObject json, String field) {
    return json.has(field) ? json.get(field).getAsString() : null;
  }

  private void sendError(HttpExchange exchange, int status, int code, String codeDesc)
      throws IOException {
    JsonObject error = new JsonObject();
    error.addProperty("code", code);
    error.addProperty("codeDesc", codeDesc);
    error.addProperty("requestID", UUID.randomUUID().toString());
    send(exchange, status, error);
  }

  private void send(HttpExchange exchange, int status, JsonObject body) throws IOException {
    byte[] raw = body.toString().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, raw.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(raw);
    }
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
