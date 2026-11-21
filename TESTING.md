# Formal test plan

Scope: the `krb-jwt-issuer` service (`main.go`) and the claims in `README.md`.
Every requirement has an ID. Each ID maps to at least one automated test, and the
`TestREQ_*` function names carry the ID so a failure points straight at the
requirement.

Run:

```bash
go vet ./... && go test -race -count=1 ./...          # full suite (~6 s)
go test -short ./...                                   # skips 3072-bit key generation
go test -run xxx -fuzz FuzzMintBody -fuzztime 60s      # fuzz the mint decoder
go test -coverprofile=c.out ./... && go tool cover -func=c.out
```

Current result: all pass under `-race`; statement coverage 75.4% (was 56.1%).
Uncovered: `main()` and the systemd socket-activation branch of `listener()`, which
are covered only by the deployed integration run.

## Requirements and traceability

| ID | Requirement | Test(s) |
| --- | --- | --- |
| REQ-CFG-1 | Issuer must be canonical HTTPS (no userinfo, query, fragment, trailing or double slash, encoded path). Key path absolute. Lifetime 30–900 s. Every subject has explicit non-wildcard audiences. | `TestREQ_CFG_1_ValidationTable`, `TestInvalidConfiguration` |
| REQ-CFG-2 | Config file is strict: unknown fields, trailing data, wrong types, oversize input are rejected. Shipped `config.example.json` is valid. | `TestREQ_CFG_2_ReadConfigStrict` |
| REQ-KEY-1 | Key rotation: old tokens verify after rotation, new tokens use a new `kid`, active key listed first, duplicates collapse. | `TestREQ_KEY_1_RotationOverlapVerifiesOldTokens`, `TestKeyPersistsAndRotationRetainsPublicKeys` |
| REQ-KEY-2 | Bad previous-key files (private key, non-PEM, garbage DER, wrong PEM type, <2048-bit) abort startup. Non-`.pem` files and a missing directory are ignored. | `TestREQ_KEY_2_PreviousKeyValidation` |
| REQ-KEY-3 | Startup never creates a key; a missing or bad key stops the service. Signing key load is fail-closed: garbage, empty, weak, symlink, directory, group/other-readable are refused and never overwritten. PKCS#1 and PKCS#8 accepted. | `TestREQ_KEY_3_KeyLoadingFailsClosed` |
| REQ-KEY-5 | Key creation is atomic (temp file, sync, hard link), never replaces an existing key, cleans up stale temp files; read-only loading (`-print-public-key`) never creates a key. | `TestREQ_KEY_5_AtomicCreationAndReadOnlyLoad` |
| REQ-KEY-4 | `-init-key` generates a 3072-bit PKCS#8 key, file 0600, directory 0700. Key is reused on restart. | `TestREQ_KEY_4_GeneratedKeyProperties`, `TestKeyPersistsAndRotationRetainsPublicKeys` |
| REQ-JWK-1 | `kid` equals the RFC 7638 thumbprint (checked against the RFC's published vector). | `TestREQ_JWK_1_ThumbprintMatchesRFC7638Vector` |
| REQ-JWK-2 | JWKS contains complete public members and no private RSA members. | `TestREQ_JWK_2_JWKSPublicOnly`, `TestMintAndVerifyWithPublishedKey` |
| REQ-DISC-1 | Discovery `issuer` equals the config byte for byte, `jwks_uri` is served by the same handler, only RS256 advertised, no OAuth endpoints, and issuers with no path or a deep path work. | `TestREQ_DISC_1_DiscoveryConsistency`, `TestDiscoveryDoesNotClaimUnsupportedFlows` |
| REQ-TOK-1 | Header is exactly `alg,kid,typ`. Claims are exactly `iss,sub,aud[],iat,nbf,exp,jti`, and `aud` is an array. | `TestREQ_TOK_1_TokenStructure` |
| REQ-TOK-2 | `jti` is unique across 200 concurrent mints. | `TestREQ_TOK_2_JTIUniqueUnderConcurrency` |
| REQ-TOK-3 | Lifetime equals configuration at both bounds. | `TestREQ_TOK_3_ConfiguredLifetimeHonoured` |
| REQ-TOK-4 | A verifier that pins RS256 rejects `alg:none`, HS256 key confusion, and foreign-key tokens. | `TestREQ_TOK_4_AlgorithmConfusionRejected` |
| REQ-TOK-5 | Audience matching is exact (case, whitespace, prefix, NUL, wildcard, empty, non-string). Tamper, wrong audience and expiry are rejected. | `TestREQ_TOK_5_AudienceMatchingIsExact`, `TestMintAndVerifyWithPublishedKey` |
| REQ-AUTHZ-1 | Subjects only get their own audiences. Principal comparison is case- and whitespace-sensitive. | `TestREQ_AUTHZ_1_PerSubjectAudienceIsolation`, `TestMintRejectsUntrustedRequests` |
| REQ-HTTP-1 | Mint requires JSON content type, `X-Token-Request: 1`, same-origin or absent `Origin`, no query string, and a single identity header. Exact path only. | `TestREQ_HTTP_1_MintRequestControls`, `TestMintRejectsUntrustedRequests` |
| REQ-HTTP-2 | Only `POST` mints. Other methods never return a token. | `TestREQ_HTTP_2_MethodsAndNoTokenLeak` |
| REQ-HTTP-3 | All responses are `application/json` and `nosniff`; dynamic ones `no-store`, the two public documents `max-age=300`; no CORS headers. | `TestREQ_HTTP_3_ResponseHeaders` |
| REQ-HTTP-4 | `/whoami` reports identity only for configured subjects and does not echo unauthorised input. | `TestREQ_HTTP_4_Whoami` |
| REQ-HTTP-5 | `GET /issuer` redirects to discovery; nothing else near it does. | `TestREQ_HTTP_5_IssuerRootRedirectsToDiscovery` |
| REQ-RATE-1 | Per-principal token bucket: burst 10, 0.5/s refill, 429 + `Retry-After`, isolation, idle cap, rejected requests consume nothing. | `TestREQ_RATE_1_MintRateLimit` |
| REQ-NET-1 | Listener is Unix-only, mode 0600, and serves real HTTP. | `TestREQ_NET_1_UnixSocketOnly` |
| REQ-OBS-1 | Mint log entries identify subject, audience and jti, and never contain the JWT, its signature, or key material. | `TestREQ_OBS_1_LogsContainNoSecrets` |
| REQ-OBS-2 | Denials (401/403/429 and malformed requests) are logged at WARN with a code and a bounded subject, never bodies or tokens. | `TestREQ_OBS_2_DenialsAreLogged` |
| REQ-HTTP-6 | Wrong method on `/mint` is 405 with `Allow: POST`. | `TestREQ_HTTP_6_MintMethodNotAllowed` |
| REQ-ROB-1 | The mint decoder never panics, never returns 5xx, and never mints unless the body is valid JSON for the permitted audience. | `FuzzMintBody` |
| REQ-ROB-2 | Malformed, duplicate or smuggled identity headers never mint. | `TestREQ_ROB_2_IdentityHeaderValues` |

## Self-check (`krb-jwt-issuer check`)

The operator-facing check in `check.go` is itself tested in `check_test.go`
against a fake nginx that can reproduce each misconfiguration: no Kerberos
requirement, trusting a client identity header, failing to overwrite it, broken
login, an unauthorized principal, an issuer URL mismatch and an unreachable host.
A healthy deployment must pass with no warnings, and every broken variant must
fail with a fix hint. Consumer-side token verification is tested against
tampering, unknown `kid`, wrong audience or issuer, expiry and not-yet-valid.
The live equivalent, run by users, is documented in the README.

## Not covered by unit tests (needs the deployed stack)

These are verified by `integration/` against the live Pi and are manual or
environment-dependent:

| Area | Check | Where |
| --- | --- | --- |
| nginx overwrites `X-Authenticated-Principal` | Spoofed header is replaced by `$remote_user` | `integration/main.go` |
| Kerberos negotiation, `auth_gss_authorized_principal` | Anonymous gets 401 | `integration/main.go` |
| nginx limit counts only Negotiate-bearing requests | Not testable offline; send 12 rapid authenticated mints and expect 429 | none |
| nginx no longer filters principals | A realm principal not in `subjects` gets 403 from the issuer | none (gap) |
| Public metadata served without Kerberos | Discovery and JWKS | `integration/main.go` |
| systemd socket permissions, sandbox, `MemoryMax` | Not tested (gap) | none |
| Third-party verifier interop | `coreos/go-oidc` | `integration/main.go` (live only; no offline variant) |
| Restart keeps `kid` and old tokens valid | | `integration/main.go` |
| Documented 6.1 MiB RSS | Observed, not asserted | none |

## Known limitations of this plan

- No mutation testing has been run.
- Clock skew is not modelled: the issuer sets `nbf == iat` with no leeway, so
  verifiers need a small tolerance (the README already says so).
- The new nginx configuration has not been run through `nginx -t` or deployed:
  nginx is not installed in the development environment.
