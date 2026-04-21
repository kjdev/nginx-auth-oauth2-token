# Changelog

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
