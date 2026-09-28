# OTP Harbor security model

## Reporting vulnerabilities

Use the repository's **Security → Report a vulnerability** flow (GitHub private vulnerability reporting). Do not open a public issue for an undisclosed vulnerability.

Do not include real TOTP secrets, QR images, API keys, OTPs, database files, or master keys. Reproduce with synthetic credentials and include affected versions, impact, prerequisites, and a minimal reproduction. Coordinate disclosure until a fix is available.

## Assets and trust boundaries

Protected assets are TOTP seeds, generated OTPs, API keys, the master encryption key, and sensitive account metadata. The host kernel, root administrator, Docker daemon, application image provenance, and Python dependency supply chain are trusted. API clients are mutually untrusted and receive only explicitly assigned credentials.

The master key and database must have separate storage and backup paths. AES-GCM protects confidentiality and integrity of credential secrets at rest; it does not make a compromised running process safe.

## Threat model

1. **Database theft:** ciphertext remains protected without the master key. Issuers, account names, clients, permissions, and audit metadata are exposed.
2. **Image theft:** the image contains code and dependency versions but no deployment secret or database.
3. **API-key theft:** an attacker receives the stolen client's permissions until revocation/expiration. Strong random keys resist guessing but cannot prevent replay after theft.
4. **Another container compromised:** separate mounts, non-root execution, dropped capabilities, and `no-new-privileges` reduce exposure. Shared volumes, host namespaces, privileged mode, or Docker-socket access invalidate this boundary.
5. **Reachable API port:** authentication, authorization, rate limiting, generic errors, and loopback binding reduce risk. They do not replace TLS on an untrusted network.
6. **Backup theft:** equivalent to database theft when the key is backed up separately. Co-locating recovery key material defeats this protection.
7. **Read-only host filesystem access:** a TPM-bound systemd credential can protect an offline disk copy. While the service runs, a decrypted, narrowly permissioned copy exists in `/run`; sufficiently privileged reads can obtain it. A plain-file fallback does not mitigate arbitrary filesystem disclosure.
8. **Host root compromise:** not mitigated. Root can inspect process memory, runtime credentials, API traffic, SQLite, and generated OTPs. Application-layer encryption cannot provide complete protection while OTP Harbor is unlocked.

## Implemented controls

- AES-256-GCM, 96-bit random nonces, and authenticated credential metadata.
- Strict `otpauth://totp` parsing, bounded URI/image input, image dimension limits, exactly one QR code, and no URL fetching.
- 256-bit random API-key secrets; only constant-time-compared verifiers are stored.
- Separate admin/OTP roles and a many-to-many permission table.
- Identical missing/unauthorized OTP responses to reduce credential enumeration.
- Bounded per-client OTP throttling and per-source failed-authentication throttling.
- Structured audit events containing identifiers only.
- No access log, API schema endpoint, secret export, decrypted-secret cache, or permissive CORS.
- Server-side web sessions, HttpOnly/SameSite cookies, single-use login nonces, CSRF tokens, restrictive CSP, and no browser key storage.
- SQLite foreign keys, WAL, full synchronization, transactions, and a consistent backup command.
- Non-root/read-only container, capability drop, `no-new-privileges`, resource limits, loopback publishing, and health checks.

## Residual risks

- The in-memory limiter resets on restart and is suitable only for the documented single worker.
- Source-address throttling assumes direct connections. Proxy headers are intentionally ignored by default.
- Python cannot guarantee immediate memory zeroization; immutable secret strings may remain until reclaimed.
- Loopback HTTP cannot use a `Secure` session cookie. Set `OTP_HARBOR_UI_SECURE_COOKIE=true` whenever the UI is served through HTTPS; the default is solely for the local-only deployment.
- API-key verification performs an indexed public key-ID lookup before constant-time verifier comparison. Key IDs are not secrets.
- Metadata and audit records are not encrypted.
- SQLite does not erase deleted encrypted pages immediately.
- A malicious or compromised administrator can enroll credentials, issue clients, and change permissions.
- Supply-chain compromise of the base image or a dependency is outside application cryptography's protection.
- Host clock manipulation can produce invalid OTPs. Keep time synchronized through a trusted host service.

## MFA limitation

OTP Harbor automates a second factor. If it runs on the same host as the relying application, compromise of that host can collapse the intended factor separation. OTP Harbor is not more secure than a hardware-backed authenticator and should not be represented as such.

## Operational assumptions

- Keep Docker and the host patched; never mount the Docker socket into OTP Harbor.
- Permit access to the administrator key only from an isolated operator workflow.
- Keep callers from logging Authorization headers or OTP response bodies.
- Verify backups and recovery keys separately.
- Review dependencies with `pip-audit` and rebuild the image regularly.
- Treat unexplained authentication failures, permission changes, or OTP volume as security events.
