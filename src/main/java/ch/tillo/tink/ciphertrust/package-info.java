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

/**
 * A <a href="https://developers.google.com/tink">Google Tink</a> KMS extension backed by <a
 * href="https://cpl.thalesgroup.com/encryption/ciphertrust-manager">Thales CipherTrust
 * Manager</a>, speaking the {@code /api/v1} REST interface (token auth + AES-GCM crypto service).
 *
 * <p>Key URIs: {@code ciphertrust://<host[:port]>/<key-name>}.
 *
 * <p><b>Entry point.</b> {@link ch.tillo.tink.ciphertrust.CipherTrustKmsClient} — create with
 * {@link ch.tillo.tink.ciphertrust.CipherTrustCredentials}, then {@code getAead(keyUri)} yields a
 * remote-KEK {@link com.google.crypto.tink.Aead} suitable for Tink envelope encryption or
 * encrypted-keyset wrapping.
 *
 * <p><b>Failure semantics.</b> Every operation is bounded in time: timeouts and a small retry
 * budget for transient transport failures are governed by {@link
 * ch.tillo.tink.ciphertrust.CipherTrustTransport} (override with {@code withTransport}). An
 * unreachable CipherTrust Manager surfaces as a {@link java.security.GeneralSecurityException}
 * within that envelope — never as an indefinite hang — which matters when the first call sits on
 * an application's boot path. Deterministic rejections (bad credentials, unknown key, AAD
 * mismatch) fail immediately without retries.
 *
 * <p><b>Thread safety.</b> A {@code CipherTrustKmsClient} is intended to be configured once and
 * then shared; the {@code Aead}s it produces are thread-safe and share one {@code HttpClient} and
 * a cached, automatically renewed CipherTrust JWT.
 */
package ch.tillo.tink.ciphertrust;
