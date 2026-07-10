# Tink CipherTrust Manager Extension

A [Google Tink](https://developers.google.com/tink) KMS extension for
[Thales CipherTrust Manager](https://cpl.thalesgroup.com/encryption/ciphertrust-manager):
a `KmsClient`/`Aead` pair that keeps your key-encryption key (KEK) inside
CipherTrust Manager and forwards all wrap/unwrap operations to its REST API
(`/api/v1/crypto`, AES-GCM with associated data).

Structured after the official out-of-repo Tink extensions
([tink-java-hcvault](https://github.com/tink-crypto/tink-java-hcvault),
[tink-java-awskms](https://github.com/tink-crypto/tink-java-awskms)). The Tink
maintainers [do not accept new KMS backends upstream](https://github.com/google/tink/issues/158#issuecomment-1883424313),
so this lives as a standalone extension, as they recommend.

## Key URI format

```
ciphertrust://<host[:port]>/<key-name>
```

Example: `ciphertrust://cm.example.com/my-kek`, where `my-kek` is the name of
an AES key in CipherTrust Manager with the Encrypt and Decrypt usages
(`usageMask: 12`). Connections always use HTTPS. The key does not need to be
exportable — mark it `unexportable` so the KEK can never leave the appliance.

## Usage

```java
import ch.tillo.tink.ciphertrust.CipherTrustCredentials;
import ch.tillo.tink.ciphertrust.CipherTrustKmsClient;
import com.google.crypto.tink.Aead;

String keyUri = "ciphertrust://cm.example.com/my-kek";
Aead kek = CipherTrustKmsClient
    .create(keyUri, CipherTrustCredentials.usernamePassword("svc-tink", password))
    .getAead(keyUri);
```

Envelope encryption (KEK stays remote, data keys are local):

```java
Aead envelope = KmsEnvelopeAead.create(PredefinedAeadParameters.AES256_GCM, kek);
byte[] ciphertext = envelope.encrypt(plaintext, associatedData);
```

Wrapping a Tink keyset with the CipherTrust KEK (the "vault master key"
pattern used by CLM/secret-store applications):

```java
String wrapped = TinkJsonProtoKeysetFormat.serializeEncryptedKeyset(handle, kek, ad);
KeysetHandle restored = TinkJsonProtoKeysetFormat.parseEncryptedKeyset(wrapped, kek, ad);
```

Applications that resolve KMS-backed keysets through Tink's global registry
can use the registration helper instead:

```java
CipherTrustKmsClient.register(Optional.of(keyUri), Optional.of("/etc/ciphertrust-creds.json"));
```

## Credentials

Two grant types of `POST /api/v1/auth/tokens` are supported; the short-lived
JWT (300 s by default) is cached and renewed transparently, including one
reactive re-authentication if the server answers 401.

| Source | Password grant | Refresh-token grant |
|---|---|---|
| Programmatic | `CipherTrustCredentials.usernamePassword(u, p)` | `CipherTrustCredentials.ofRefreshToken(t)` |
| Environment (`withDefaultCredentials()`) | `CIPHERTRUST_USERNAME` + `CIPHERTRUST_PASSWORD` | `CIPHERTRUST_REFRESH_TOKEN` |
| JSON file (`withCredentials(path)`) | `{"username": "...", "password": "..."}` | `{"refresh_token": "..."}` |

Use a dedicated CipherTrust service user that owns (or is granted) only the
KEK — key *usage* does not require any admin group membership.

## Ciphertext format

`Aead.encrypt` returns a small self-describing JSON envelope:

```json
{"v":1,"id":"<opaque key id>","ver":<key version>,"iv":"<b64>","tag":"<b64>","ct":"<b64>"}
```

The envelope pins the key **version** used at encryption time, so **decryption
keeps working after the KEK is rotated** (rotation only affects which version
new encryptions use). Decryption always addresses the key by the **name the
`Aead` was configured with** — the `id` in the envelope is informational only
and is never used to select the key — so a ciphertext produced under a
different CipherTrust key fails the GCM tag check instead of being silently
decrypted, even when the same credentials can access that other key.
Associated data is forwarded to CipherTrust's `aad` field and enforced by the
server-side GCM operation.

## Timeouts and retries

Every operation is bounded in time. The defaults (10 s connect, 30 s per HTTP
exchange, 3 attempts with exponential backoff starting at 300 ms) can be tuned
with `CipherTrustTransport`:

```java
CipherTrustKmsClient client = CipherTrustKmsClient.create(keyUri, credentials)
    .withTransport(CipherTrustTransport.of(
        Duration.ofSeconds(5),    // connect timeout
        Duration.ofSeconds(15),   // request timeout
        3,                        // attempts (1 = no retries)
        Duration.ofMillis(300))); // initial backoff, doubled per retry
```

Only transient transport failures are retried: I/O errors and HTTP
502/503/504 (a CipherTrust node restarting behind its front-end).
Deterministic answers — bad credentials, unknown key, AAD mismatch, any other
4xx and 500 — fail immediately. All operations this library issues are safe to
repeat, so retries never duplicate effects.

An unreachable CipherTrust Manager therefore surfaces as a
`GeneralSecurityException` within roughly `attempts x (connect + request
timeout) + backoff` — never as an indefinite hang. This matters when the first
call sits on an application's boot path, e.g. unwrapping a vault keyset.

## Private-CA / custom TLS

If the CipherTrust Manager presents a certificate from a private CA, supply a
pre-configured client:

```java
HttpClient httpClient = HttpClient.newBuilder().sslContext(myTrustingContext).build();
CipherTrustKmsClient client = CipherTrustKmsClient.create(keyUri, credentials)
    .withHttpClient(httpClient);
```

A single `HttpClient` (the one you supply, or a lazily-created default) is
shared across every `Aead` the client produces.

## Compatibility

- Java 11+.
- Compiled against `com.google.crypto.tink:tink` **1.21.0**; the `KmsClient`,
  `Aead`, and `KmsClients` surfaces used here are stable since Tink 1.0.0, so
  the artifact also runs against newer cores on the host application's
  classpath.
- Verified against CipherTrust Manager **2.22.0** (also exercised by the
  live-integration test suite below). The key-management and crypto REST
  services used here are included in the free
  [Community Edition](https://cpl.thalesgroup.com/encryption/ciphertrust-platform-community-edition).
- Only runtime dependencies: `tink` itself and `gson` (which is already a
  transitive dependency of `tink`).

## Building and testing

```
mvn verify
```

Unit tests run against an in-process fake that mimics CipherTrust Manager
behavior verified on a live 2.22 instance (strict `Accept` header checking,
token expiry/revocation, versioned keys, AAD enforcement).

Live integration tests are enabled automatically when the environment defines:

```
CIPHERTRUST_TEST_KEY_URI=ciphertrust://cm.example.com/my-test-kek
CIPHERTRUST_USERNAME=svc-tink
CIPHERTRUST_PASSWORD=...          # or CIPHERTRUST_REFRESH_TOKEN=...
```

## License

[Apache License 2.0](LICENSE)
