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
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Locale;
import java.util.Optional;

/**
 * A {@link KmsClient} for Thales CipherTrust Manager.
 *
 * <p>Key URIs have the form {@code ciphertrust://<host[:port]>/<key-name>}, e.g. {@code
 * ciphertrust://cm.example.com/my-kek}, where {@code <key-name>} is the name of an AES key in
 * CipherTrust Manager with the Encrypt and Decrypt usages. The connection always uses HTTPS.
 *
 * <p>Recommended usage is the factory-and-{@code getAead} pattern:
 *
 * <pre>{@code
 * KmsClient client = CipherTrustKmsClient.create(
 *     CipherTrustCredentials.usernamePassword("tink-service", password));
 * Aead kek = client.getAead("ciphertrust://cm.example.com/my-kek");
 * }</pre>
 *
 * <p>A {@link #register} helper is provided for applications that resolve KMS-backed keysets
 * through the global {@link KmsClients} registry.
 */
public final class CipherTrustKmsClient implements KmsClient {

  /** The scheme prefix of CipherTrust key URIs. */
  public static final String PREFIX = "ciphertrust://";

  private final String boundKeyUri;
  private CipherTrustCredentials credentials;
  private CipherTrustTransport transport = CipherTrustTransport.DEFAULT;
  private String urlScheme = "https";
  // Shared across every Aead produced by this client (JDK HttpClient is thread-safe); lazily
  // created so that repeated getAead() calls do not each spawn selector threads + a socket pool.
  private HttpClient httpClient;

  /** Constructs a client that supports every {@code ciphertrust://} key URI. */
  public CipherTrustKmsClient() {
    this.boundKeyUri = null;
  }

  /**
   * Constructs a client bound to a single key URI: {@link #doesSupport} accepts exactly {@code
   * keyUri} and nothing else.
   *
   * @throws IllegalArgumentException if {@code keyUri} does not start with {@link #PREFIX}
   */
  public CipherTrustKmsClient(String keyUri) {
    if (!keyUri.toLowerCase(Locale.US).startsWith(PREFIX)) {
      throw new IllegalArgumentException("key URI must start with " + PREFIX + ": " + keyUri);
    }
    this.boundKeyUri = keyUri;
  }

  /** Creates an unbound client with the given credentials. */
  public static CipherTrustKmsClient create(CipherTrustCredentials credentials) {
    return new CipherTrustKmsClient().withCredentials(credentials);
  }

  /** Creates a client bound to {@code keyUri} with the given credentials. */
  public static CipherTrustKmsClient create(String keyUri, CipherTrustCredentials credentials) {
    return new CipherTrustKmsClient(keyUri).withCredentials(credentials);
  }

  @Override
  public boolean doesSupport(String keyUri) {
    if (boundKeyUri != null) {
      return boundKeyUri.equals(keyUri);
    }
    return keyUri != null && keyUri.toLowerCase(Locale.US).startsWith(PREFIX);
  }

  /**
   * Loads credentials from a JSON file containing {@code username}+{@code password} or {@code
   * refresh_token} fields; with a null path, falls back to {@link #withDefaultCredentials}.
   */
  @Override
  public KmsClient withCredentials(String credentialPath) throws GeneralSecurityException {
    if (credentialPath == null) {
      return withDefaultCredentials();
    }
    this.credentials = CipherTrustCredentials.fromJsonFile(Paths.get(credentialPath));
    return this;
  }

  /** Sets credentials programmatically. */
  public CipherTrustKmsClient withCredentials(CipherTrustCredentials credentials) {
    if (credentials == null) {
      throw new IllegalArgumentException("credentials must not be null");
    }
    this.credentials = credentials;
    return this;
  }

  /**
   * Loads credentials from the environment ({@code CIPHERTRUST_REFRESH_TOKEN}, or {@code
   * CIPHERTRUST_USERNAME}/{@code CIPHERTRUST_PASSWORD}).
   */
  @Override
  public KmsClient withDefaultCredentials() throws GeneralSecurityException {
    this.credentials = CipherTrustCredentials.fromEnvironment();
    return this;
  }

  /**
   * Supplies the {@link HttpClient} used for all CipherTrust calls — e.g. one configured with a
   * custom {@code SSLContext} to trust a private-CA CipherTrust Manager certificate. If not set, a
   * default client is created lazily and shared across every {@link Aead} this client produces.
   *
   * <p>A supplied client keeps its own connect timeout; the request timeout and retry policy from
   * {@link #withTransport} still apply.
   */
  public CipherTrustKmsClient withHttpClient(HttpClient httpClient) {
    if (httpClient == null) {
      throw new IllegalArgumentException("httpClient must not be null");
    }
    this.httpClient = httpClient;
    return this;
  }

  /**
   * Overrides the default timeouts and retry policy ({@link CipherTrustTransport#DEFAULT}) for
   * every {@link Aead} this client produces. Must be called before the first {@link #getAead} if a
   * custom connect timeout is wanted, since the shared {@code HttpClient} is created on first use.
   */
  public CipherTrustKmsClient withTransport(CipherTrustTransport transport) {
    if (transport == null) {
      throw new IllegalArgumentException("transport must not be null");
    }
    this.transport = transport;
    return this;
  }

  @Override
  public Aead getAead(String keyUri) throws GeneralSecurityException {
    if (!doesSupport(keyUri)) {
      throw new GeneralSecurityException(
          "this client does not support key URI " + keyUri
              + (boundKeyUri != null ? " (bound to " + boundKeyUri + ")" : ""));
    }
    if (credentials == null) {
      throw new GeneralSecurityException(
          "credentials not set; call withCredentials() or withDefaultCredentials() first");
    }
    KeyUriParts parts = parseKeyUri(keyUri);
    String baseUrl =
        urlScheme + "://" + parts.host + (parts.port > 0 ? ":" + parts.port : "");
    return new CipherTrustAead(
        new CipherTrustRestClient(baseUrl, credentials, transport, sharedHttpClient()),
        parts.keyName);
  }

  private synchronized HttpClient sharedHttpClient() {
    if (httpClient == null) {
      httpClient = HttpClient.newBuilder().connectTimeout(transport.connectTimeout()).build();
    }
    return httpClient;
  }

  /**
   * Registers a new client in the global {@link KmsClients} registry, bound to {@code keyUri} if
   * present, with credentials from {@code credentialPath} if present (environment otherwise).
   *
   * <p>Only needed by applications that resolve KMS-backed keysets through the registry; prefer
   * {@link #create} and {@link #getAead} elsewhere.
   */
  public static void register(Optional<String> keyUri, Optional<String> credentialPath)
      throws GeneralSecurityException {
    CipherTrustKmsClient client =
        keyUri.isPresent() ? new CipherTrustKmsClient(keyUri.get()) : new CipherTrustKmsClient();
    if (credentialPath.isPresent()) {
      client.withCredentials(credentialPath.get());
    } else {
      client.withDefaultCredentials();
    }
    KmsClients.add(client);
  }

  static final class KeyUriParts {
    final String host;
    final int port;
    final String keyName;

    KeyUriParts(String host, int port, String keyName) {
      this.host = host;
      this.port = port;
      this.keyName = keyName;
    }
  }

  static KeyUriParts parseKeyUri(String keyUri) throws GeneralSecurityException {
    final URI uri;
    try {
      uri = new URI(keyUri);
    } catch (URISyntaxException e) {
      throw new GeneralSecurityException("invalid CipherTrust key URI: " + keyUri, e);
    }
    if (uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase("ciphertrust")) {
      throw new GeneralSecurityException("invalid CipherTrust key URI scheme: " + keyUri);
    }
    if (uri.getHost() == null || uri.getHost().isEmpty()) {
      throw new GeneralSecurityException("CipherTrust key URI has no host: " + keyUri);
    }
    if (uri.getRawUserInfo() != null) {
      // Reject e.g. ciphertrust://cm.example.com@evil.com/kek, whose real host is evil.com: the
      // host determines where credentials are POSTed, so userinfo host-spoofing must not pass.
      throw new GeneralSecurityException(
          "CipherTrust key URI must not contain userinfo: " + keyUri);
    }
    if (uri.getQuery() != null || uri.getFragment() != null) {
      throw new GeneralSecurityException(
          "CipherTrust key URI must not contain a query or fragment: " + keyUri);
    }
    String path = uri.getPath();
    if (path == null || path.length() < 2 || !path.startsWith("/")) {
      throw new GeneralSecurityException("CipherTrust key URI has no key name: " + keyUri);
    }
    // The key name is the full remaining path (CipherTrust key names are addressed in the JSON
    // request body, so no further escaping is needed here).
    return new KeyUriParts(uri.getHost(), uri.getPort(), path.substring(1));
  }

  // Test hook (package-private): use plain HTTP so the in-process fake needs no TLS.
  CipherTrustKmsClient usingInsecureHttpForTests() {
    this.urlScheme = "http";
    return this;
  }
}
