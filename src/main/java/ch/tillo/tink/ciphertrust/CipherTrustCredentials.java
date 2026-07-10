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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Credentials for the CipherTrust Manager {@code POST /api/v1/auth/tokens} endpoint.
 *
 * <p>Two grant types are supported: {@code password} (a CipherTrust local user, e.g. a dedicated
 * service account) and {@code refresh_token} (a pre-issued long-lived refresh token). The
 * short-lived JWT obtained from either grant is cached and refreshed transparently by the client.
 */
public final class CipherTrustCredentials {

  /** Environment variable holding the CipherTrust username for {@link #fromEnvironment()}. */
  public static final String ENV_USERNAME = "CIPHERTRUST_USERNAME";

  /** Environment variable holding the CipherTrust password for {@link #fromEnvironment()}. */
  public static final String ENV_PASSWORD = "CIPHERTRUST_PASSWORD";

  /** Environment variable holding a CipherTrust refresh token for {@link #fromEnvironment()}. */
  public static final String ENV_REFRESH_TOKEN = "CIPHERTRUST_REFRESH_TOKEN";

  private final String username;
  private final String password;
  private final String refreshToken;

  private CipherTrustCredentials(String username, String password, String refreshToken) {
    this.username = username;
    this.password = password;
    this.refreshToken = refreshToken;
  }

  /** Creates credentials using the {@code password} grant. */
  public static CipherTrustCredentials usernamePassword(String username, String password) {
    if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
      throw new IllegalArgumentException("username and password must be non-empty");
    }
    return new CipherTrustCredentials(username, password, null);
  }

  /** Creates credentials using the {@code refresh_token} grant. */
  public static CipherTrustCredentials ofRefreshToken(String refreshToken) {
    if (refreshToken == null || refreshToken.isEmpty()) {
      throw new IllegalArgumentException("refreshToken must be non-empty");
    }
    return new CipherTrustCredentials(null, null, refreshToken);
  }

  /**
   * Loads credentials from the environment: {@code CIPHERTRUST_REFRESH_TOKEN} if set, otherwise
   * {@code CIPHERTRUST_USERNAME} / {@code CIPHERTRUST_PASSWORD}.
   *
   * @throws GeneralSecurityException if neither variable set is present
   */
  public static CipherTrustCredentials fromEnvironment() throws GeneralSecurityException {
    String refreshToken = System.getenv(ENV_REFRESH_TOKEN);
    if (refreshToken != null && !refreshToken.isEmpty()) {
      return ofRefreshToken(refreshToken);
    }
    String username = System.getenv(ENV_USERNAME);
    String password = System.getenv(ENV_PASSWORD);
    if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
      return usernamePassword(username, password);
    }
    throw new GeneralSecurityException(
        "no CipherTrust credentials found in environment; set "
            + ENV_USERNAME
            + "/"
            + ENV_PASSWORD
            + " or "
            + ENV_REFRESH_TOKEN);
  }

  /**
   * Loads credentials from a JSON file containing either {@code {"username": "...", "password":
   * "..."}} or {@code {"refresh_token": "..."}}.
   *
   * @throws GeneralSecurityException if the file cannot be read or has neither shape
   */
  public static CipherTrustCredentials fromJsonFile(Path path) throws GeneralSecurityException {
    JsonObject json;
    try {
      String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
      // Do NOT attach the parsed element as the exception cause: a file holding a bare secret
      // instead of a JSON object parses to a JsonPrimitive whose getAsJsonObject() message would
      // echo the secret. Check the shape and throw a content-free error instead.
      JsonElement element = JsonParser.parseString(content);
      if (!element.isJsonObject()) {
        throw new GeneralSecurityException(
            "credentials file " + path + " is not a JSON object");
      }
      json = element.getAsJsonObject();
    } catch (IOException e) {
      throw new GeneralSecurityException("cannot read CipherTrust credentials from " + path, e);
    } catch (JsonSyntaxException e) {
      // Gson syntax-error messages carry only line/column, never the file content.
      throw new GeneralSecurityException(
          "credentials file " + path + " is not valid JSON");
    }
    if (json.has("refresh_token")) {
      return ofRefreshToken(json.get("refresh_token").getAsString());
    }
    if (json.has("username") && json.has("password")) {
      return usernamePassword(json.get("username").getAsString(), json.get("password").getAsString());
    }
    throw new GeneralSecurityException(
        "credentials file "
            + path
            + " must contain either username+password or refresh_token fields");
  }

  boolean isRefreshToken() {
    return refreshToken != null;
  }

  String username() {
    return username;
  }

  String password() {
    return password;
  }

  String refreshToken() {
    return refreshToken;
  }

  @Override
  public String toString() {
    // Never include secret material.
    return "CipherTrustCredentials{grant="
        + (isRefreshToken() ? "refresh_token" : "password")
        + (username != null ? ", username=" + username : "")
        + "}";
  }
}
