/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_oauth2_token_introspect.h"
#include "ngx_auth_oauth2_token_http.h"
#include "nxe_json.h"


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
    nxe_json_t *json, *active;
    nxe_json_t *exp_value;
    ngx_flag_t active_flag;
    int64_t exp_int;

    json = nxe_json_parse(body, pool);
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

    /* "active" field is REQUIRED per RFC 7662 */
    active = nxe_json_object_get(json, "active");
    if (active == NULL
        || nxe_json_boolean(active, &active_flag) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: "
                      "introspection response missing "
                      "\"active\" field");
        nxe_json_free(json);
        return NGX_ERROR;
    }

    ctx->active = active_flag ? 1 : 0;

    if (!ctx->active) {
        nxe_json_free(json);
        return NGX_OK;
    }

    /* extract optional fields */

    nxe_json_object_get_string(json, "sub", &ctx->sub, pool);

    nxe_json_object_get_string(json, "scope", &ctx->scope, pool);

    nxe_json_object_get_string(json, "client_id",
                               &ctx->client_id, pool);

    exp_value = nxe_json_object_get(json, "exp");
    if (exp_value != NULL
        && nxe_json_integer(exp_value, &exp_int) == NGX_OK)
    {
        ctx->exp.data = ngx_pnalloc(pool, NGX_TIME_T_LEN);
        if (ctx->exp.data != NULL) {
            ctx->exp.len = ngx_sprintf(ctx->exp.data, "%T",
                                       (time_t) exp_int)
                           - ctx->exp.data;
        }
    }

    nxe_json_free(json);

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
