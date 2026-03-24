/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_oauth2_token_introspect.h"
#include "ngx_auth_oauth2_token_json.h"
#include "ngx_auth_oauth2_token_http.h"


ngx_int_t
ngx_auth_oauth2_token_introspect_build_body(ngx_pool_t *pool,
    ngx_str_t *token, ngx_str_t *body)
{
    size_t len;
    uintptr_t token_escape;
    u_char *p;

    /*
     * RFC 7662: token=<value>&token_type_hint=access_token
     */

    token_escape = ngx_escape_uri(NULL, token->data, token->len,
                                  NGX_ESCAPE_ARGS);

    len = sizeof("token=") - 1
          + token->len + 2 * token_escape
          + sizeof("&token_type_hint=access_token") - 1;

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    body->data = p;

    p = ngx_cpymem(p, "token=", sizeof("token=") - 1);

    if (token_escape) {
        p = (u_char *) ngx_escape_uri(p, token->data, token->len,
                                      NGX_ESCAPE_ARGS);
    } else {
        p = ngx_cpymem(p, token->data, token->len);
    }

    p = ngx_cpymem(p, "&token_type_hint=access_token",
                   sizeof("&token_type_hint=access_token") - 1);

    body->len = p - body->data;

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_introspect_parse_response(ngx_pool_t *pool,
    ngx_str_t *body, ngx_http_auth_oauth2_token_ctx_t *ctx,
    ngx_log_t *log)
{
    ngx_auth_oauth2_token_json_t *json;
    ngx_int_t rc;
    time_t exp;

    json = ngx_auth_oauth2_token_json_parse(body->data,
                                            body->len, log);
    if (json == NULL) {
        return NGX_ERROR;
    }

    /* "active" field is REQUIRED per RFC 7662 */
    rc = ngx_auth_oauth2_token_json_get_bool(json, "active");
    if (rc == NGX_DECLINED || rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: "
                      "introspection response missing "
                      "\"active\" field");
        ngx_auth_oauth2_token_json_free(json);
        return NGX_ERROR;
    }

    ctx->active = (rc == 1) ? 1 : 0;

    if (!ctx->active) {
        ngx_auth_oauth2_token_json_free(json);
        return NGX_OK;
    }

    /* extract optional fields */

    ngx_auth_oauth2_token_json_get_string(json, "sub",
                                          pool, &ctx->sub);

    ngx_auth_oauth2_token_json_get_string(json, "scope",
                                          pool, &ctx->scope);

    ngx_auth_oauth2_token_json_get_string(json, "client_id",
                                          pool, &ctx->client_id);

    if (ngx_auth_oauth2_token_json_get_integer(json, "exp",
                                               &exp)
        == NGX_OK)
    {
        ctx->exp.data = ngx_pnalloc(pool, NGX_TIME_T_LEN);
        if (ctx->exp.data != NULL) {
            ctx->exp.len = ngx_sprintf(ctx->exp.data, "%T", exp)
                           - ctx->exp.data;
        }
    }

    ngx_auth_oauth2_token_json_free(json);

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_introspect_subrequest_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx = data;
    ngx_str_t body;
    ngx_uint_t status;

    ctx->introspect_done = 1;

    status = ngx_auth_oauth2_token_http_response_status(r);
    ctx->subrequest_status = status;

    if (status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "introspection endpoint returned %ui",
                      status);
        ctx->introspect_error = 1;
        return NGX_OK;
    }

    if (ngx_auth_oauth2_token_http_response_body(r, &body,
                                                 r->connection->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "failed to read introspection response");
        ctx->introspect_error = 1;
        return NGX_OK;
    }

    if (body.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "empty introspection response");
        ctx->introspect_error = 1;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_oauth2_token: "
                   "introspection response received, len=%uz",
                   body.len);

    if (ngx_auth_oauth2_token_introspect_parse_response(
            r->parent->pool, &body, ctx, r->connection->log)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth_oauth2_token: "
                      "failed to parse introspection response");
        ctx->introspect_error = 1;
        return NGX_OK;
    }

    /* store raw response for caching */
    if (ctx->active && body.len > 0) {
        ctx->introspect_response.data = ngx_pnalloc(
            r->parent->pool, body.len);
        if (ctx->introspect_response.data != NULL) {
            ngx_memcpy(ctx->introspect_response.data,
                       body.data, body.len);
            ctx->introspect_response.len = body.len;
        }
    }

    return NGX_OK;
}
