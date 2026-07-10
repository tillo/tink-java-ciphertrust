# Releasing to Maven Central

Releases are published to Maven Central through the
[Central Publisher Portal](https://central.sonatype.com) as
`ch.tillo.tink:tink-ciphertrust`.

## One-time setup

1. **Portal account + namespace** — sign in at
   [central.sonatype.com](https://central.sonatype.com), add the `ch.tillo`
   namespace, and verify it via the DNS TXT record the portal issues for
   `tillo.ch`.
2. **User token** — Account → *Generate User Token*. Expose it to CI as the
   `CENTRAL_TOKEN_USERNAME` / `CENTRAL_TOKEN_PASSWORD` variables (masked).
3. **Signing key** — releases are signed with the project's GPG release key
   (`7411868B8C33B15FB906669996F383B91D500D2B`,
   `Martino Dell'Ambrogio (Maven Central) <tillo@tillo.ch>`, RSA-4096,
   expires 2030-07-09). The public key is published on
   `keyserver.ubuntu.com`, which Central uses for signature validation.
   CI needs it as `GPG_PRIVATE_KEY_B64` (base64 of the armored, passphrase-
   protected secret key) and `GPG_PASSPHRASE` (both masked).

## Release flow

1. Set the release version and tag it:

   ```sh
   mvn versions:set -DnewVersion=X.Y.Z -DgenerateBackupPoms=false
   git commit -am "Release X.Y.Z"
   git tag vX.Y.Z
   ```

2. Push branch and tag; run the manual `publish-central` job on the tag
   pipeline. It builds, signs, and uploads the deployment bundle, which stops
   in the portal's **VALIDATED** state (`autoPublish=false`).
3. Review the deployment at central.sonatype.com → *Deployments* and press
   **Publish**. Propagation to `repo1.maven.org` takes up to ~30 minutes;
   search indexing can lag a few hours.
4. Bump back to the next snapshot:

   ```sh
   mvn versions:set -DnewVersion=X.Y.(Z+1)-SNAPSHOT -DgenerateBackupPoms=false
   git commit -am "Back to development"
   git push
   ```

## Local publish (without CI)

```sh
export MAVEN_GPG_PASSPHRASE=...   # release key passphrase
mvn -Pcentral-release deploy -DskipTests \
  -Dcentral.username=... -Dcentral.password=...   # or a `central` server in ~/.m2/settings.xml
```

Notes:

- Snapshots are **not** published to Central — they only go to the internal
  registry via the regular `publish` job.
- The `central-release` profile attaches signatures at `verify`, so
  `mvn -Pcentral-release verify` is a dry-run that exercises signing without
  uploading anything.
