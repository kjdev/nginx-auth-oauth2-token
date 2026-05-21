# Changelog

## [42a4813](../../commit/42a4813) - 2026-05-21

### Fixed

- Skip `auth_oauth2_token_require` when introspection is disabled
  - In exchange-only mode (`introspect=off, exchange=on`) the require block ran with no introspection result, so `auth_oauth2_token_claim_set`-derived variables were empty and even valid tokens were rejected with 401/403
  - Guard the require evaluation with `lcf->introspect` so it only runs after a successful Introspection (`active: true`), matching the documented contract

## [0a7ceab](../../commit/0a7ceab) - 2026-05-21

### Added

- Add the `auth_oauth2_token_require` directive
  - Mirrors `auth_jwt_require`: in the ACCESS phase, evaluates one or more variables after Introspection completes with `active: true`, and rejects the request if any variable is empty or `"0"`
  - Optional `error=code` selects the rejection status code (default `401`); the value must be `400-599`, excluding `444` / `499`
  - Multiple variables on a single directive and multiple directives in the same scope are AND-combined
  - Enables the MCP Resource Server pattern (`map`-based `aud` / `scope` checks returning 401 / 403) without the broken `if`-based workaround that runs in the REWRITE phase before introspection populates the variables

## [c23840d](../../commit/c23840d) - 2026-05-21

### Added

- Add the `auth_oauth2_token_claim_set` directive
  - Binds an arbitrary JSON field from the Introspection response to a nginx variable
  - Strings are emitted verbatim, arrays are comma-joined, and other types (numbers, booleans, null, objects) are rendered as their compact JSON representation
  - Useful for claims not covered by built-in variables, e.g. audience binding on MCP Resource Servers ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707))
  - The parsed JSON is retained for the request lifetime via pool cleanup, so cache-hit paths also reconstruct the variable

## [ec3a924](../../commit/ec3a924) - 2026-04-27

### Security

- Tighten the IdP response size cap from 1 MiB back down to 64 KiB
  - Replace the direct use of `nxe-json`'s `NXE_JSON_MAX_SIZE` (1 MiB) with the module-defined `NGX_AUTH_OAUTH2_TOKEN_HTTP_RESPONSE_MAX_SIZE` (64 KiB)
  - RFC 7662 / RFC 8693 responses are typically a few KiB, so the previous cap left an unnecessarily large memory amplification surface
  - Short-circuit during chain traversal in `ngx_auth_oauth2_token_http_response_body()` so oversize responses are rejected before allocating and copying into a request-pool buffer
  - Drop the `nxe_json.h` include from `http.c`, which was only kept for the size constant

## [d291fac](../../commit/d291fac) - 2026-04-24

### Changed

- Replace 2-step typed-field extraction on IdP responses with `nxe_json_object_get_integer` / `nxe_json_object_get_boolean`
  - Introspection response `active` / `exp`
  - Token Exchange response `expires_in`
  - Drops the intermediate `nxe_json_t *` locals and shortens each call site to a single condition

## [217687f](../../commit/217687f) - 2026-04-24

### Changed

- Bump the `nxe-json` submodule to 0.2.0
  - Add `nxe_json_object_get_integer` / `nxe_json_object_get_boolean` helpers
  - Zero-clear extractor out-params on failure as a defensive safeguard

## [0ee1506](../../commit/0ee1506) - 2026-04-21

### Security

- Parse IdP responses with `nxe_json_parse_untrusted()`
  - Apply structural limits (depth / array size / string length / object key count) to network-sourced JSON
  - Harden against structural DoS from a malicious or compromised IdP

## [1953cfb](../../commit/1953cfb) - 2026-04-21

### Changed

- Replace in-tree JSON handling with the `nxe_json_*` API
  - Remove the bundled `src/ngx_auth_oauth2_token_json.{c,h}`
  - Raise the IdP response size cap from 64 KiB to 1 MiB

## [718a2bd](../../commit/718a2bd) - 2026-04-21

### Added

- Add the `nxe-json` submodule (v0.1.0, `https://github.com/kjdev/nxe-json`)
  - `git submodule update --init` is required before building

## [4e6a5ae](../../commit/4e6a5ae) - 2026-04-02

### Added

- Token Introspection (RFC 7662): Validate Bearer Token via IdP introspection endpoint
  - Request body construction and response parsing (active, sub, scope, client_id, exp)
  - Subrequest callback with raw response preservation for caching
- Token Exchange (RFC 8693): Exchange for scope-constrained token and forward to downstream services
  - Request body construction (grant_type, subject_token, subject_token_type, audience, scope)
  - Response parsing (access_token, token_type, expires_in)
  - Authorization header replacement with exchanged token
- Shared memory cache using `ngx_slab_pool_t`
  - Red-black tree (`ngx_str_rbtree`) for O(log n) lookups
  - TTL-based expiration with automatic purge
  - Independent zones for introspection and exchange
- IdP communication via `ngx_http_subrequest()` with client credentials (Basic auth)
- 10 directives (`auth_oauth2_token_*`) for client auth, introspection, exchange, and cache configuration
- 7 nginx variables: `$oauth2_token_active`, `$oauth2_token_sub`, `$oauth2_token_scope`, etc.
- 3 operation modes: introspect only / exchange only / introspect + exchange
