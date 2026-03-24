# Directives and Variables Reference

Reference for directives and embedded variables provided by `ngx_http_auth_oauth2_token_module`.


## Directives

| Directive | Description | Context |
|---|---|---|
| [auth_oauth2_token_client_id](#auth_oauth2_token_client_id) | Client ID | http |
| [auth_oauth2_token_client_secret](#auth_oauth2_token_client_secret) | Client secret | http |
| [auth_oauth2_token_client_secret_file](#auth_oauth2_token_client_secret_file) | Client secret file path | http |
| [auth_oauth2_token_introspect](#auth_oauth2_token_introspect) | Enable/disable Introspection | http, server, location |
| [auth_oauth2_token_introspect_endpoint](#auth_oauth2_token_introspect_endpoint) | Introspection endpoint URI | http, server, location |
| [auth_oauth2_token_introspect_cache](#auth_oauth2_token_introspect_cache) | Introspection cache settings | http, server, location |
| [auth_oauth2_token_exchange](#auth_oauth2_token_exchange) | Enable/disable Exchange | http, server, location |
| [auth_oauth2_token_token_endpoint](#auth_oauth2_token_token_endpoint) | Token endpoint URI | http, server, location |
| [auth_oauth2_token_audience](#auth_oauth2_token_audience) | Exchange target audience | http, server, location |
| [auth_oauth2_token_scope](#auth_oauth2_token_scope) | Exchange requested scope | http, server, location |
| [auth_oauth2_token_exchange_cache](#auth_oauth2_token_exchange_cache) | Exchange cache settings | http, server, location |


### Client Authentication

Client credentials used for communication with the IdP. When `client_id` and `client_secret` (or `client_secret_file`) are configured, an `Authorization: Basic <base64(client_id:client_secret)>` header is automatically added to IdP requests.

#### auth_oauth2_token_client_id

```
Syntax:  auth_oauth2_token_client_id string;
Default: ---
Context: http
```

Specifies the client ID for authenticating with the IdP.

#### auth_oauth2_token_client_secret

```
Syntax:  auth_oauth2_token_client_secret string;
Default: ---
Context: http
```

Specifies the client secret for authenticating with the IdP directly in the configuration.

Cannot be used together with `auth_oauth2_token_client_secret_file`. Using `auth_oauth2_token_client_secret_file` is recommended for production environments.

#### auth_oauth2_token_client_secret_file

```
Syntax:  auth_oauth2_token_client_secret_file path;
Default: ---
Context: http
```

Specifies the path to a file containing the client secret. The file contents are read at nginx startup. Trailing newlines (`\n`, `\r`) are automatically stripped.

Cannot be used together with `auth_oauth2_token_client_secret`.

```nginx
auth_oauth2_token_client_secret_file /etc/nginx/secrets/client_secret;
```

### Token Introspection

Validates Bearer Tokens by querying the IdP's Introspection endpoint ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)).

When the IdP returns `active: false`, the module returns `401 Unauthorized` (`WWW-Authenticate: Bearer error="invalid_token"`). When `active: true`, claims from the response are exposed as nginx variables.

#### auth_oauth2_token_introspect

```
Syntax:  auth_oauth2_token_introspect on | off;
Default: off
Context: http, server, location
```

Enables Token Introspection. When enabled, `auth_oauth2_token_introspect_endpoint` must also be configured.

#### auth_oauth2_token_introspect_endpoint

```
Syntax:  auth_oauth2_token_introspect_endpoint uri;
Default: ---
Context: http, server, location
```

Specifies the URI of an internal location to send Introspection requests to.

The specified URI must point to an `internal` location with `proxy_pass` configured to the IdP's Introspection endpoint. The module automatically sets the POST request headers (`Content-Type: application/x-www-form-urlencoded`, `Authorization: Basic <credentials>`) and body (`token=<bearer_token>&token_type_hint=access_token`), so no additional configuration is needed on the internal location.

```nginx
location = /_introspect {
    internal;
    proxy_pass https://idp.example.com/oauth2/introspect;
}

auth_oauth2_token_introspect_endpoint /_introspect;
```

#### auth_oauth2_token_introspect_cache

```
Syntax:  auth_oauth2_token_introspect_cache zone=name:size [max_ttl=time];
Default: ---
Context: http, server, location
```

Enables caching of Introspection results. Uses shared memory (`ngx_slab_pool_t`).

**Parameters**:

- `zone`: Shared memory zone name and size (e.g., `zone=introspect:10m`)
- `max_ttl`: Maximum cache TTL (default: `300s`). Setting `0` disables cache lookup/store (the shared memory zone is allocated but not used)

**Cache behavior**:

- Cache key: Bearer Token value
- Actual TTL: `min(max_ttl, exp - now)`. If `exp` is not present in the Introspection response, `max_ttl` is used as-is
- `active: false` responses are not cached (no negative cache)
- Token revocation detection delay is at most `max_ttl` seconds

```nginx
auth_oauth2_token_introspect_cache zone=introspect:10m max_ttl=60s;
```

> **Note**: Without cache configuration, an Introspection subrequest is issued to the IdP for every incoming request. Cache configuration is recommended for production. See [SECURITY.md](SECURITY.md) for security trade-offs of caching.

### Token Exchange

Exchanges Bearer Tokens for new tokens with reduced scope ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).

When exchange succeeds, the upstream request's `Authorization` header is automatically replaced with the new token. When exchange fails (IdP returns an error), the module returns `500 Internal Server Error`.

#### auth_oauth2_token_exchange

```
Syntax:  auth_oauth2_token_exchange on | off;
Default: off
Context: http, server, location
```

Enables Token Exchange. When enabled, `auth_oauth2_token_token_endpoint` must also be configured.

#### auth_oauth2_token_token_endpoint

```
Syntax:  auth_oauth2_token_token_endpoint uri;
Default: ---
Context: http, server, location
```

Specifies the URI of an internal location to send Token Exchange requests to.

As with `auth_oauth2_token_introspect_endpoint`, an `internal` location must be configured. The module automatically sets the following body:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<bearer_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=<audience>
&scope=<scope>
```

```nginx
location = /_token {
    internal;
    proxy_pass https://idp.example.com/oauth2/token;
}

auth_oauth2_token_token_endpoint /_token;
```

#### auth_oauth2_token_audience

```
Syntax:  auth_oauth2_token_audience string;
Default: ---
Context: http, server, location
```

The `audience` parameter for Token Exchange requests. Specifies the target service for the exchanged token.

#### auth_oauth2_token_scope

```
Syntax:  auth_oauth2_token_scope string;
Default: ---
Context: http, server, location
```

The `scope` parameter for Token Exchange requests. Specifies the scope to request for the exchanged token.

#### auth_oauth2_token_exchange_cache

```
Syntax:  auth_oauth2_token_exchange_cache zone=name:size [max_ttl=time];
Default: ---
Context: http, server, location
```

Enables caching of Exchange results. Managed independently from the Introspection cache (no coordinated invalidation).

**Parameters**:

- `zone`: Shared memory zone name and size (e.g., `zone=exchange:10m`)
- `max_ttl`: Maximum cache TTL (default: `300s`). Setting `0` disables cache lookup/store (the shared memory zone is allocated but not used)

**Cache behavior**:

- Cache key: combination of `token|audience|scope`. Different audience or scope values for the same token result in separate cache entries
- Actual TTL: `min(max_ttl, expires_in)`. If `expires_in` is not present in the Exchange response, `max_ttl` is used as-is

```nginx
auth_oauth2_token_exchange_cache zone=exchange:10m max_ttl=300s;
```

> **Note**: Without cache configuration, a Token Exchange subrequest is issued to the IdP for every incoming request. Cache configuration is recommended for production. See [SECURITY.md](SECURITY.md) for security trade-offs of caching.


## Embedded Variables

nginx variables provided by the module. Can be used with `proxy_set_header`, `add_header`, `log_format`, etc.

| Variable | Description |
|---|---|
| [$oauth2_token_active](#oauth2_token_active) | Introspection result (`1` or `0`) |
| [$oauth2_token_sub](#oauth2_token_sub) | Token subject |
| [$oauth2_token_scope](#oauth2_token_scope) | Token scopes |
| [$oauth2_token_client_id](#oauth2_token_client_id) | Client ID that issued the token |
| [$oauth2_token_exp](#oauth2_token_exp) | Token expiration |
| [$oauth2_token_new_token](#oauth2_token_new_token) | Exchanged new token |
| [$oauth2_token_new_token_type](#oauth2_token_new_token_type) | New token type |

### Introspection Results

Variables set when Introspection is enabled. Undefined when Introspection has not been executed.

#### $oauth2_token_active

The Introspection result. `1` if the token is valid, `0` if invalid.

Set when `auth_oauth2_token_introspect` is enabled and Introspection has completed successfully. Undefined in the following cases:

- Introspection has not been executed (e.g., Exchange-only mode)
- Introspection completed with an error (IdP communication failure, response parse error, etc.)

```nginx
# Log the variable value
log_format token '$remote_addr - $oauth2_token_active';
```

#### $oauth2_token_sub

The token subject (owner identifier). Corresponds to the `sub` field of the Introspection response. Undefined if the IdP response does not include `sub`.

```nginx
proxy_set_header X-User-Sub $oauth2_token_sub;
```

#### $oauth2_token_scope

The token scopes as a space-separated string. Corresponds to the `scope` field of the Introspection response.

```nginx
proxy_set_header X-User-Scope $oauth2_token_scope;
```

#### $oauth2_token_client_id

The ID of the client that issued the token. Corresponds to the `client_id` field of the Introspection response.

#### $oauth2_token_exp

The token expiration as a UNIX timestamp (seconds) string. Corresponds to the `exp` field of the Introspection response.

### Token Exchange Results

Variables set when Exchange is enabled. Undefined when Exchange has not been executed.

#### $oauth2_token_new_token

The new access token after exchange. Corresponds to the `access_token` field of the Exchange response.

When exchange succeeds, the upstream `Authorization` header is automatically replaced with `Bearer <new_token>`, so explicit `proxy_set_header` configuration is not necessary. This variable can be used for logging or additional header configuration.

```nginx
# Forward the exchanged token via custom header (normally not needed)
add_header X-Debug-New-Token $oauth2_token_new_token;
```

#### $oauth2_token_new_token_type

The type of the exchanged token. Corresponds to the `token_type` field of the Exchange response (typically `Bearer`).


## Related Documentation

- [README.md](../README.md): Module overview and quick start
- [INSTALL.md](INSTALL.md): Installation guide
- [SECURITY.md](SECURITY.md): Security considerations (cache settings included)
