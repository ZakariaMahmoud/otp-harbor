# TotpVault

**A self-hosted, least-privilege TOTP service for trusted local applications.**

TotpVault imports a TOTP QR code once, encrypts its seed at rest, and generates short-lived one-time passwords through an authenticated API or a small local web interface. It is designed for controlled automation without placing plaintext TOTP seeds, API keys, or generated codes in the database or logs.

> [!CAUTION]
> TotpVault automates a second authentication factor. Running it beside the application consuming the OTP reduces the separation normally provided by a phone. It is not a replacement for FIDO2/WebAuthn or hardware-backed MFA.

## Why TotpVault?

Some private automations need a TOTP but cannot use an interactive phone authenticator. Copying seeds into scripts, environment variables, or CI settings makes those long-lived credentials difficult to control. TotpVault provides a narrow alternative:

- enroll a QR code or `otpauth://totp/...` URI once;
- encrypt the seed with a deployment key stored separately from SQLite;
- issue independent, revocable API keys to applications;
- explicitly grant each client access to specific credentials;
- generate codes only when requested, without persisting them.

## Security properties

- AES-256-GCM with a fresh 96-bit nonce for every credential.
- Authenticated metadata binds ciphertext to its credential and TOTP parameters.
- 256-bit random API keys; only domain-separated SHA-256 verifiers are stored.
- Separate administrator and OTP-client roles.
- Explicit client-to-credential permissions prevent cross-client access.
- Strict `otpauth` and QR validation with bounded input and no URL fetching.
- Server-side web sessions, CSRF protection, HttpOnly/SameSite cookies, and restrictive CSP.
- Generic unauthorized responses, bounded rate limiting, and secret-free audit events.
- Non-root, read-only container with dropped capabilities and loopback-only publishing.
- Transactional SQLite backup and master-key rotation commands.

See [SECURITY.md](SECURITY.md) for the threat model, assumptions, and residual risks.

## Architecture

```text
Browser / trusted app
        │ API key or short-lived web session
        ▼
  FastAPI authorization ──────► safe audit events
        │ explicit permission
        ▼
  encrypted credential in SQLite
        │ AES-256-GCM decrypts only in memory
        ▼
      PyOTP ──────► current OTP (never persisted)

Master key: separate runtime secret, never stored in SQLite or the image
```

TotpVault intentionally runs as one worker in v1. SQLite and the in-memory rate limiter are not designed for multiple replicas.

## Requirements

- Linux
- Docker Engine with Docker Compose v2
- A trusted host time-synchronization service
- Python 3.12 only for local development or host-side tooling

## Quick start

### 1. Build the image

```sh
docker build -t totpvault:1.0.0 .
```

### 2. Create the master key outside the repository

```sh
install -d -m 0700 /etc/totpvault
docker run --rm --entrypoint totpvault \
  -v /etc/totpvault:/keys \
  totpvault:1.0.0 generate-key --output /keys/master.key
chown 10001:10001 /etc/totpvault/master.key
chmod 0400 /etc/totpvault/master.key
```

Never place this file in the repository, image, database volume, environment, or routine database backup.

### 3. Configure Compose

```sh
cp .env.example .env
```

Set the absolute host path in `.env`:

```dotenv
TOTPVault_MASTER_KEY_HOST_PATH=/etc/totpvault/master.key
```

`.env` and key files are ignored by Git. Verify that before every public commit.

### 4. Initialize the database and administrator

```sh
docker compose run --rm --entrypoint totpvault totpvault init-db
docker compose run --rm --entrypoint totpvault totpvault \
  bootstrap-admin --name operator
```

The second command prints the administrator API key once. Store it in a separate password or secret manager.

### 5. Start TotpVault

```sh
docker compose up -d
curl --fail http://127.0.0.1:8787/health/ready
```

Compose publishes only `127.0.0.1:8787`. Do not change this to `0.0.0.0` without TLS, network controls, trusted-host configuration, and a separate review.

## Web interface

Open [http://127.0.0.1:8787/ui/](http://127.0.0.1:8787/ui/) on the host and sign in with an API key.

Administrators can import QR images or URIs, create and revoke clients, grant permissions, and delete credentials. OTP clients see only assigned credentials. The OTP view counts down and refreshes automatically at the next period.

The browser never keeps API keys in local storage. Login exchanges the key for a random, short-lived server-side session. Restarting TotpVault invalidates all web sessions.

### HTTPS deployments

For a trusted reverse proxy terminating HTTPS, configure:

```dotenv
TOTPVault_UI_SECURE_COOKIE=true
TOTPVault_ALLOWED_HOSTS=vault.example.internal
```

Keep the application port private behind the proxy. Do not enable the secure cookie on plain HTTP because the browser will correctly refuse to send it.

## API usage

Avoid placing keys or real `otpauth` URIs in shell history:

```sh
read -rsp 'Administrator key: ' ADMIN_KEY; echo
```

### Enroll a QR image

```sh
curl --fail-with-body -X POST \
  http://127.0.0.1:8787/api/v1/admin/credentials \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: image/png' \
  --data-binary @credential-qr.png
```

Use `Content-Type: image/jpeg` for JPEG input.

### Create and authorize an OTP client

```sh
curl --fail-with-body -X POST \
  http://127.0.0.1:8787/api/v1/admin/clients \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"name":"github-consumer","role":"otp"}'

curl --fail-with-body -X PUT \
  http://127.0.0.1:8787/api/v1/admin/clients/CLIENT_ID/permissions/CREDENTIAL_ID \
  -H "Authorization: Bearer $ADMIN_KEY"
```

Save the returned client ID and one-time API key.

### Generate an OTP

```sh
read -rsp 'Client key: ' CLIENT_KEY; echo
curl --fail-with-body \
  http://127.0.0.1:8787/api/v1/otp/CREDENTIAL_ID \
  -H "Authorization: Bearer $CLIENT_KEY"
```

```json
{
  "code": "123456",
  "expires_in": 18
}
```

Callers must not log the Authorization header or response body.

## Administration

```sh
# Revoke a client
curl --fail-with-body -X POST \
  http://127.0.0.1:8787/api/v1/admin/clients/CLIENT_ID/revoke \
  -H "Authorization: Bearer $ADMIN_KEY"

# Delete a credential
curl --fail-with-body -X DELETE \
  http://127.0.0.1:8787/api/v1/admin/credentials/CREDENTIAL_ID \
  -H "Authorization: Bearer $ADMIN_KEY"
```

Deletion cascades permissions. SQLite free pages may retain encrypted bytes until vacuumed; plaintext seeds are never written to those pages.

## Backups and recovery

Create a consistent SQLite backup:

```sh
docker compose run --rm --entrypoint totpvault totpvault \
  backup --output /data/vault-backup.db
```

Copy the backup to protected storage separately from master-key recovery material. A database backup alone must not be enough to recover TOTP seeds.

To restore safely:

1. Stop TotpVault and preserve the current volume.
2. Copy a verified backup to a new volume as `vault.db`.
3. Set owner `10001:10001` and mode `0600`.
4. Provide the matching master key through the normal secret mount.
5. Start the service and verify readiness plus one authorized OTP.

Losing the master key makes the encrypted credentials unrecoverable.

## Master-key rotation

Stop callers and take a verified backup first:

```sh
docker compose run --rm \
  -v /secure/path/new.key:/run/secrets/new.key:ro \
  --entrypoint totpvault totpvault \
  rotate-key --new-key-file /run/secrets/new.key
```

Rotation is one database transaction. Activate the new runtime secret before restarting. Retain the old key under offline protection until pre-rotation backups expire.

## Stronger Linux key storage

Production deployments should consider a systemd encrypted credential, optionally TPM2-bound, instead of a persistent plaintext key file. Load the credential into `/run`, copy it with owner UID `10001` and mode `0400`, and bind-mount that runtime path into the container.

This protects an offline filesystem copy better than a normal key file. It does not protect against host root while TotpVault is unlocked. Always maintain a separately protected recovery plan.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest --cov=app
.venv/bin/pip-audit --skip-editable
docker build -t totpvault:1.0.0 .
```

Runtime dependencies and artifact hashes are pinned in `requirements.lock`. Regenerate it only during an intentional dependency update with `pip-compile --generate-hashes --strip-extras --output-file=requirements.lock pyproject.toml`, then rerun the full audit. The v1 schema is initialized explicitly with `init-db`; startup never performs an implicit migration.

## Before publishing

```sh
git status --ignored
git ls-files | grep -E '(\.env|\.key|\.pem|\.db)$' && exit 1 || true
.venv/bin/pytest
.venv/bin/pip-audit --skip-editable
```

Also run a current container/OS vulnerability scanner in the release pipeline. No review can prove software vulnerability-free; keep the host, Docker engine, base image, and dependencies patched.

## Contributing

Security-sensitive changes should stay small and reviewable. New cryptography, authentication methods, remote exposure, secret export, multiple workers, or distributed deployment require an updated threat model and dedicated tests.

Report vulnerabilities privately according to [SECURITY.md](SECURITY.md), not through a public issue.
