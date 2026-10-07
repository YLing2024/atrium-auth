[English](README.en.md) | [简体中文](README.md)

# atrium-auth

A self-hosted unified authentication center (OIDC Provider): one TOTP code governs login across the whole stack.

## What it does

- **TOTP code login**: 6 digits, rotates every 30 seconds, ±1 step tolerance; no account, no static password.
- **Redis sliding-expiry sessions**: login tokens are stored in Redis, and every verification refreshes the TTL; by default a session expires after 7 days of inactivity.
- **Standard OIDC Provider**: discovery / authorize / token / userinfo / jwks / introspect / end_session / revoke, with PKCE S256.
- **ES256 tokens**: both id_token and access_token are ES256 JWTs (P-256, with `kid`), with public keys published at `/jwks.json`; access_token defaults to 15 minutes, refresh_token to 30 days and rotates on every renewal, and replaying an old value invalidates the whole chain.
- **First-party silent SSO**: clients marked `first_party` have the code→token exchange done inside auth-server, issuing only an HttpOnly session cookie, so sub-site frontends need zero SSO code.
- **Login device management**: list / rename / kick out logged-in devices, with source GeoIP.
- **Two-stage TOTP reset**: a new secret goes to pending first and is promoted only after verification; a failure or timeout does not affect the old secret, and already-logged-in users are not locked out.
- **Stepped per-IP rate limiting**: 5 consecutive failures locks for 60s, 5 more for 300s, 5 more for 900s.

## Quick start

```bash
npm install
npm start            # = node src/index.ts, listens on 0.0.0.0:3200 by default
npm run check        # = typecheck (tsc --noEmit) + lint + test
```

A local Redis is required (default `127.0.0.1:6379`). On first start it generates `oidc-keys.json`, `jwt-secret` and `internal-token` in `DATA_DIR`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3200` | Listening port |
| `HOST` | `0.0.0.0` | Listening address (production sets `127.0.0.1` explicitly via systemd) |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | Session and token storage |
| `REDIS_DB` | `0` | Redis database index (a test instance can isolate with `15`) |
| `DATA_DIR` | project root | Directory for keys and the client registry |
| `ISSUER` | `http://127.0.0.1:3200` | OIDC issuer; all endpoint URLs are built from it; set the real public address in production |
| `SSO_SUBJECT` | `linden` | Stable user identifier (`sub` / `preferred_username`) |
| `SSO_DISPLAY_NAME` | same as `SSO_SUBJECT` | Display name (`name`) |
| `SESSION_DAYS` | `7` | Session sliding-expiry days |
| `ACCESS_TTL_SEC` | `900` | access_token seconds, lower bound 60 |
| `JWT_SECRET` | reads the `jwt-secret` file | Session JWT signing key |
| `INTERNAL_TOKEN_FILE` | `<DATA_DIR>/internal-token` | Shared token file for internal endpoints (0600, auto-generated) |
| `INTERNAL_TOKEN` | none | Explicit internal token value, overriding the file |
| `AUTH_GEOIP_URL` | `https://ip-api.com/json/{ip}?fields=status,country,regionName,city` | Login source resolution endpoint |
| `ALLOWED_REDIRECT_ROOTS` | empty (same-origin only) | Domain roots allowed as cross-origin `?redirect=` targets on the login page, comma-separated (example `example.com,example.org`); only these roots and their subdomains may be used. When unset, only same-origin returns are allowed and cross-origin targets are rejected with a readable notice |

## Interfaces

Login and compatibility endpoints:

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/auth` | none | login page (`?redirect=` return, with a whitelist) |
| GET | `/config.js` | none | login page runtime config: injects only the redirect whitelist roots (`ALLOWED_REDIRECT_ROOTS`), no credentials |
| POST | `/api/login` | none | `{code}` → verify TOTP → issue a Redis session token |
| GET | `/api/verify` | none | **kept for compatibility**: session token / first-party SSO token / API token; on success returns `X-Auth-User` and refreshes the TTL |
| POST | `/api/logout` | none | `{token}` or Bearer → delete the session (and revoke associated SSO tokens) |
| POST | `/api/totp/setup` | none (first start only) | generate a TOTP secret |
| POST | `/api/totp/reset` | Bearer | two-stage step ①: create a pending secret (5 minutes) without overwriting the active one |
| POST | `/api/totp/confirm` | Bearer | two-stage step ②: promote pending only after its code verifies |
| GET | `/api/sessions` | Bearer | list logged-in device sessions |
| PUT | `/api/sessions/:id/name` | Bearer | rename a session |
| DELETE | `/api/sessions/:id` | Bearer | kick a device offline |

OIDC (mounted at the root path, issuer from `ISSUER`):

| Method | Path | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/authorize` | authorization endpoint (PKCE S256) |
| POST | `/token` | code / refresh (refresh rotates; replaying invalidates the whole chain) |
| GET/POST | `/userinfo` | Bearer access_token |
| GET | `/jwks.json` | ES256 public key set |
| POST/GET | `/introspect` | RFC 7662 |
| GET/POST | `/end_session` | RP-Initiated Logout (return whitelist) |
| POST | `/revoke` | RFC 7009 |
| GET | `/auth` | login page (`?redirect=` legacy flow + whitelist) |

Internal endpoints (local services only, shared token `X-Internal-Token`, not session-authenticated): `GET /api/internal/sessions?sub=`, `PUT /api/internal/sessions/:id/name`, `DELETE /api/internal/sessions/:id`, `POST /api/internal/totp/reset?sub=`, `POST /api/internal/totp/confirm?sub=`. `sub` must equal this instance's `SSO_SUBJECT` (missing → 400, not this user → 404).

## Deployment

Managed by the systemd unit `auth-server.service`, listening on `127.0.0.1:3200` with the project root as the working directory.
nginx only does TLS and routing: the login state is handled by the separate project **Auth Gateway**, where site nginx forwards `/_auth/*` to the gateway (`127.0.0.1:18920`), which injects `X-Auth-User` into the backend; OIDC endpoints are called by the gateway server-side over loopback. The nginx `auth_request` probe and `/auth-check` are no longer used. Real domains and public addresses are always provided by `ISSUER` / reverse proxy configuration and are never written into code.

The login page's cross-origin `?redirect=` whitelist comes from the `ALLOWED_REDIRECT_ROOTS` environment variable (comma-separated domain roots, example `example.com,example.org`), injected into the page via `GET /config.js` (`window.__AUTH_CONFIG__.allowedRedirectRoots`); only those roots and their subdomains may be used. When unset, only same-origin returns are allowed and cross-origin targets are rejected with a readable notice — it never falls back to allowing any domain.

## Authentication and security

- **The only user credential is a TOTP code**: there is no static password, and the login page accepts no account; the verification window is ±1 step.
- **redirect_uri is matched exactly**: only strings exactly equal to those in the `clients.json` registry are accepted; wildcards and prefix matching are forbidden.
- **id_token and access_token use ES256 only**; revocation is authoritative in Redis records (`/introspect`, `/revoke` take effect) rather than lasting forever because a signature is valid.
- **Two-stage TOTP reset**: `reset` only writes pending and never overwrites the active secret; `confirm` promotes only after the pending code verifies.
- **Internal token**: generated on first start into `INTERNAL_TOKEN_FILE` (0600); the value is not printed and not returned to clients.
- **Rate limiting uses the real client IP** (`X-Forwarded-For` → `X-Real-IP` → socket), with a failure ladder of 60s → 300s → 900s.
- Keys and the registry (`totp-secret.json`, `oidc-keys.json`, `clients.json`, `jwt-secret`, `internal-token`) are all blocked by `.gitignore` and not committed.

## License

MIT, see `LICENSE`.
