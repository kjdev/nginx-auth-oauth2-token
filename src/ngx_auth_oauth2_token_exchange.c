/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_oauth2_token_exchange.h"
#include "ngx_auth_oauth2_token_http.h"
#include "nxe_json.h"


#define NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_GRANT_TYPE \
        "urn:ietf:params:oauth:grant-type:token-exchange"

#define NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE \
        "urn:ietf:params:oauth:token-type:access_token"


ngx_int_t
ngx_auth_oauth2_token_exchange_build_body(ngx_pool_t *pool,
    ngx_str_t *subject_token, ngx_str_t *audience,
    ngx_str_t *scope, ngx_str_t *body)
{
    size_t len;
    uintptr_t token_escape, audience_escape, scope_escape;
    u_char *p;

    /*
     * RFC 8693 Token Exchange request:
     *
     *   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
     *   &subject_token=<token>
     *   &subject_token_type=urn:ietf:params:oauth:token-type:access_token
     *   &audience=<audience>       (optional)
     *   &scope=<scope>             (optional)
     */

    token_escape = ngx_escape_uri(NULL, subject_token->data,
                                  subject_token->len,
                                  NGX_ESCAPE_ARGS);

    audience_escape = 0;
    scope_escape = 0;

    len = sizeof("grant_type=") - 1
          + sizeof(NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_GRANT_TYPE) - 1
          + sizeof("&subject_token=") - 1
          + subject_token->len + 2 * token_escape
          + sizeof("&subject_token_type=") - 1
          + sizeof(NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE) - 1;

    if (audience->len > 0) {
        audience_escape = ngx_escape_uri(NULL, audience->data,
                                         audience->len,
                                         NGX_ESCAPE_ARGS);
        len += sizeof("&audience=") - 1
               + audience->len + 2 * audience_escape;
    }

    if (scope->len > 0) {
        scope_escape = ngx_escape_uri(NULL, scope->data,
                                      scope->len,
                                      NGX_ESCAPE_ARGS);
        len += sizeof("&scope=") - 1
               + scope->len + 2 * scope_escape;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    body->data = p;

    p = ngx_cpymem(p, "grant_type=",
                   sizeof("grant_type=") - 1);
    p = ngx_cpymem(p, NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_GRANT_TYPE,
                   sizeof(NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_GRANT_TYPE) - 1);

    p = ngx_cpymem(p, "&subject_token=",
                   sizeof("&subject_token=") - 1);

    if (token_escape) {
        p = (u_char *) ngx_escape_uri(p, subject_token->data,
                                      subject_token->len,
                                      NGX_ESCAPE_ARGS);
    } else {
        p = ngx_cpymem(p, subject_token->data, subject_token->len);
    }

    p = ngx_cpymem(p, "&subject_token_type=",
                   sizeof("&subject_token_type=") - 1);
    p = ngx_cpymem(p,
                   NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE,
                   sizeof(NGX_AUTH_OAUTH2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE)
                   - 1);

    if (audience->len > 0) {
        p = ngx_cpymem(p, "&audience=",
                       sizeof("&audience=") - 1);

        if (audience_escape) {
            p = (u_char *) ngx_escape_uri(p, audience->data,
                                          audience->len,
                                          NGX_ESCAPE_ARGS);
        } else {
            p = ngx_cpymem(p, audience->data, audience->len);
        }
    }

    if (scope->len > 0) {
        p = ngx_cpymem(p, "&scope=",
                       sizeof("&scope=") - 1);

        if (scope_escape) {
            p = (u_char *) ngx_escape_uri(p, scope->data,
                                          scope->len,
                                          NGX_ESCAPE_ARGS);
        } else {
            p = ngx_cpymem(p, scope->data, scope->len);
        }
    }

    body->len = p - body->data;

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_exchange_parse_response(ngx_pool_t *pool,
    ngx_str_t *body, ngx_http_auth_oauth2_token_ctx_t *ctx,
    ngx_log_t *log)
{
    nxe_json_t *json, *expires_in;
    ngx_str_t issued_token_type;
    int64_t expires_in_int;
    ngx_int_t rc;

    json = nxe_json_parse_untrusted(body, pool);
    if (json == NULL) {
        return NGX_ERROR;
    }

    if (!nxe_json_is_object(json)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: "
                      "JSON root is not an object");
        nxe_json_free(json);
        return NGX_ERROR;
    }

    /*
     * RFC 8693 response:
     *   access_token (REQUIRED)
     *   issued_token_type (REQUIRED)
     *   token_type (REQUIRED)
     *   expires_in (RECOMMENDED)
     *   scope (OPTIONAL)
     *   refresh_token (OPTIONAL)
     */

    rc = nxe_json_object_get_string(
        json, "access_token", &ctx->new_token, pool);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: "
                      "exchange response missing "
                      "\"access_token\" field");
        nxe_json_free(json);
        return NGX_ERROR;
    }

    /* issued_token_type (REQUIRED per RFC 8693) */
    ngx_str_null(&issued_token_type);

    if (nxe_json_object_get_string(
            json, "issued_token_type", &issued_token_type, pool)
        != NGX_OK
        || issued_token_type.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_oauth2_token: "
                      "exchange response missing "
                      "\"issued_token_type\" field");
    }

    /* token_type (REQUIRED per RFC 8693) */
    rc = nxe_json_object_get_string(
        json, "token_type", &ctx->new_token_type, pool);

    if (rc != NGX_OK || ctx->new_token_type.len == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_oauth2_token: "
                      "exchange response missing "
                      "\"token_type\" field");

    } else if (ctx->new_token_type.len != sizeof("Bearer") - 1
               || ngx_strncasecmp(ctx->new_token_type.data,
                                  (u_char *) "Bearer",
                                  sizeof("Bearer") - 1)
               != 0)
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "auth_oauth2_token: "
                      "exchange response token_type "
                      "is \"%V\", expected \"Bearer\"",
                      &ctx->new_token_type);
    }

    expires_in = nxe_json_object_get(json, "expires_in");
    if (expires_in != NULL
        && nxe_json_integer(expires_in, &expires_in_int) == NGX_OK)
    {
        ctx->exchange_expires_in = (time_t) expires_in_int;
    }

    nxe_json_free(json);

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_exchange_subrequest_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx = data;
    ngx_str_t body;
    ngx_uint_t status;

    ctx->exchange_done = 1;

    status = ngx_auth_oauth2_token_http_response_status(r);
    ctx->subrequest_status = status;

    if (status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "exchange endpoint returned %ui",
                      status);
        return NGX_OK;
    }

    if (ngx_auth_oauth2_token_http_response_body(r, &body,
                                                 r->connection->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "failed to read exchange response");
        return NGX_OK;
    }

    if (body.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "empty exchange response");
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_oauth2_token: "
                   "exchange response received, len=%uz",
                   body.len);

    if (ngx_auth_oauth2_token_exchange_parse_response(
            r->parent->pool, &body, ctx, r->connection->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "failed to parse exchange response");
        return NGX_OK;
    }

    /* store raw response for caching */
    if (ctx->new_token.len > 0 && body.len > 0) {
        ctx->exchange_response.data = ngx_pnalloc(
            r->parent->pool, body.len);
        if (ctx->exchange_response.data != NULL) {
            ngx_memcpy(ctx->exchange_response.data,
                       body.data, body.len);
            ctx->exchange_response.len = body.len;
        }
    }

    return NGX_OK;
}
