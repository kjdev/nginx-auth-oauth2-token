# Security Considerations

Security guidelines for safely operating the nginx auth_oauth2_token module.

## Client Secret Management

Embedding the secret directly in the nginx configuration via `auth_oauth2_token_client_secret` exposes client credentials if the configuration file is leaked. In production, use `auth_oauth2_token_client_secret_file` and restrict file permissions appropriately.

```nginx
# Recommended: load secret from file
auth_oauth2_token_client_secret_file /etc/nginx/secrets/client_secret;
```

```bash
# File permission example
chmod 600 /etc/nginx/secrets/client_secret
chown nginx:nginx /etc/nginx/secrets/client_secret
```

## Internal Location Best Practices

Internal locations configured for `auth_oauth2_token_introspect_endpoint` and `auth_oauth2_token_token_endpoint` **must** include the `internal` directive. Without `internal`, external clients can directly access the IdP endpoint proxy, potentially abusing client credentials or sending unauthorized requests to the IdP.

```nginx
# Correct: internal prevents external client access
location = /_introspect {
    internal;
    proxy_pass https://idp.example.com/oauth2/introspect;
}

# Wrong: accessible by external clients
location = /_introspect {
    proxy_pass https://idp.example.com/oauth2/introspect;
}
```

## Cache Configuration

Caching involves a trade-off between security and availability. In production, caching **must** be configured, with `max_ttl` tuned for the appropriate balance.

**Risks without cache**:

- Overload on the IdP (every request queries the IdP)
- Increased latency (network round-trip on every request)
- Complete service outage if the IdP becomes unavailable

**Risks with cache**:

- Token revocation detection is delayed by up to `max_ttl` seconds. During this period, revoked tokens are still accepted
- With Exchange cache, permission changes on the IdP side are not reflected until `max_ttl` elapses, and the old token continues to be used

`max_ttl` guidelines:

| Requirement | Introspection `max_ttl` | Exchange `max_ttl` |
|-------------|------------------------|-------------------|
| Security-focused (immediate revocation) | 10s--30s | 30s--60s |
| Balanced | 60s | 300s |
| Performance-focused | 300s | 600s |

### Introspection Cache

```nginx
auth_oauth2_token_introspect_cache zone=introspect:10m max_ttl=60s;
```

- Cache key: Bearer Token value
- TTL: `min(max_ttl, exp - now)`. If `exp` is not present in the Introspection response, `max_ttl` is used as-is
- `active: false` responses are not cached (no negative cache)

### Exchange Cache

```nginx
auth_oauth2_token_exchange_cache zone=exchange:10m max_ttl=300s;
```

- Cache key: combination of `token|audience|scope`. Different audience or scope values for the same token result in separate cache entries
- TTL: `min(max_ttl, expires_in)`. If `expires_in` is not present in the Exchange response, `max_ttl` is used as-is

### Cache Independence

Introspection cache and Exchange cache are managed independently (no coordinated invalidation). Even if a token is determined invalid by Introspection, existing Exchange cache entries are not invalidated. This is a design decision to avoid the complexity of cache key association management, based on the premise that Exchange tokens have their own expiration managed independently by the IdP.

## DoS Protection

| Limit | Value | Description |
|-------|-------|-------------|
| Max JSON response size | 64KB | Upper limit for IdP response body. Parse error on exceeding |

## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [DIRECTIVES.md](DIRECTIVES.md): Directives and variables reference
- [INSTALL.md](INSTALL.md): Installation guide
