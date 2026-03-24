/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_oauth2_token_module.h"
#include "ngx_auth_oauth2_token_introspect.h"
#include "ngx_auth_oauth2_token_exchange.h"
#include "ngx_auth_oauth2_token_http.h"
#include "ngx_auth_oauth2_token_cache.h"


static ngx_int_t ngx_http_auth_oauth2_token_pre_conf(
    ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_oauth2_token_post_conf(
    ngx_conf_t *cf);
static void *ngx_http_auth_oauth2_token_create_main_conf(
    ngx_conf_t *cf);
static char *ngx_http_auth_oauth2_token_init_main_conf(
    ngx_conf_t *cf, void *conf);
static void *ngx_http_auth_oauth2_token_create_loc_conf(
    ngx_conf_t *cf);
static char *ngx_http_auth_oauth2_token_merge_loc_conf(
    ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_auth_oauth2_token_handler(
    ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_oauth2_token_unauthorized(
    ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_oauth2_token_extract_token(
    ngx_http_request_t *r,
    ngx_http_auth_oauth2_token_ctx_t *ctx);

static char *ngx_http_auth_oauth2_token_client_secret_file(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_auth_oauth2_token_cache_conf(
    ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_oauth2_token_variable_active(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_auth_oauth2_token_variable_sub(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_auth_oauth2_token_variable_scope(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t
ngx_http_auth_oauth2_token_variable_client_id(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t ngx_http_auth_oauth2_token_variable_exp(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t
ngx_http_auth_oauth2_token_variable_new_token(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);
static ngx_int_t
ngx_http_auth_oauth2_token_variable_new_token_type(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data);


static ngx_command_t ngx_http_auth_oauth2_token_commands[] = {

    { ngx_string("auth_oauth2_token_client_id"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_main_conf_t,
               client_id),
      NULL },

    { ngx_string("auth_oauth2_token_client_secret"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_main_conf_t,
               client_secret),
      NULL },

    { ngx_string("auth_oauth2_token_client_secret_file"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_oauth2_token_client_secret_file,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_oauth2_token_introspect"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               introspect),
      NULL },

    { ngx_string("auth_oauth2_token_introspect_endpoint"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               introspect_endpoint),
      NULL },

    { ngx_string("auth_oauth2_token_exchange"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               exchange),
      NULL },

    { ngx_string("auth_oauth2_token_token_endpoint"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               token_endpoint),
      NULL },

    { ngx_string("auth_oauth2_token_audience"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               audience),
      NULL },

    { ngx_string("auth_oauth2_token_scope"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               scope),
      NULL },

    { ngx_string("auth_oauth2_token_introspect_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_1MORE,
      ngx_http_auth_oauth2_token_cache_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               introspect_cache),
      NULL },

    { ngx_string("auth_oauth2_token_exchange_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF
      | NGX_CONF_1MORE,
      ngx_http_auth_oauth2_token_cache_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_oauth2_token_loc_conf_t,
               exchange_cache),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_auth_oauth2_token_module_ctx = {
    ngx_http_auth_oauth2_token_pre_conf,
    ngx_http_auth_oauth2_token_post_conf,
    ngx_http_auth_oauth2_token_create_main_conf,
    ngx_http_auth_oauth2_token_init_main_conf,
    NULL,
    NULL,
    ngx_http_auth_oauth2_token_create_loc_conf,
    ngx_http_auth_oauth2_token_merge_loc_conf
};


ngx_module_t ngx_http_auth_oauth2_token_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_oauth2_token_module_ctx,
    ngx_http_auth_oauth2_token_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_auth_oauth2_token_vars[] = {

    { ngx_string("oauth2_token_active"),
      NULL,
      ngx_http_auth_oauth2_token_variable_active,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_sub"),
      NULL,
      ngx_http_auth_oauth2_token_variable_sub,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_scope"),
      NULL,
      ngx_http_auth_oauth2_token_variable_scope,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_client_id"),
      NULL,
      ngx_http_auth_oauth2_token_variable_client_id,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_exp"),
      NULL,
      ngx_http_auth_oauth2_token_variable_exp,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_new_token"),
      NULL,
      ngx_http_auth_oauth2_token_variable_new_token,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("oauth2_token_new_token_type"),
      NULL,
      ngx_http_auth_oauth2_token_variable_new_token_type,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    ngx_http_null_variable
};


static ngx_int_t
ngx_http_auth_oauth2_token_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_auth_oauth2_token_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_post_conf(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_core_module);

    h = ngx_array_push(
        &cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_oauth2_token_handler;

    return NGX_OK;
}


static void *
ngx_http_auth_oauth2_token_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_oauth2_token_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auth_oauth2_token_init_main_conf(ngx_conf_t *cf,
    void *conf)
{
    ngx_http_auth_oauth2_token_main_conf_t *mcf = conf;
    ngx_str_t plain, encoded;
    u_char *p;

    if ((mcf->client_id.data == NULL)
        != (mcf->client_secret.data == NULL))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"auth_oauth2_token_client_id\" and "
                           "\"auth_oauth2_token_client_secret\" / "
                           "\"auth_oauth2_token_client_secret_file\" "
                           "must be set together");
        return NGX_CONF_ERROR;
    }

    if (mcf->client_id.data == NULL) {
        return NGX_CONF_OK;
    }

    /* encode client_id:client_secret as Base64 */

    plain.len = mcf->client_id.len + 1 + mcf->client_secret.len;
    plain.data = ngx_pnalloc(cf->pool, plain.len);
    if (plain.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(plain.data, mcf->client_id.data,
                   mcf->client_id.len);
    *p++ = ':';
    ngx_memcpy(p, mcf->client_secret.data, mcf->client_secret.len);

    encoded.len = ngx_base64_encoded_length(plain.len);
    encoded.data = ngx_pnalloc(cf->pool, encoded.len);
    if (encoded.data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_encode_base64(&encoded, &plain);

    /* build "Basic <encoded>" */

    mcf->client_credentials.len = sizeof("Basic ") - 1
                                  + encoded.len;
    mcf->client_credentials.data = ngx_pnalloc(
        cf->pool, mcf->client_credentials.len);
    if (mcf->client_credentials.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(mcf->client_credentials.data, "Basic ",
                   sizeof("Basic ") - 1);
    ngx_memcpy(p, encoded.data, encoded.len);

    return NGX_CONF_OK;
}


static void *
ngx_http_auth_oauth2_token_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_oauth2_token_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->introspect = NGX_CONF_UNSET;
    conf->exchange = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_auth_oauth2_token_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_auth_oauth2_token_loc_conf_t *prev = parent;
    ngx_http_auth_oauth2_token_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->introspect,
                         prev->introspect, 0);
    ngx_conf_merge_str_value(conf->introspect_endpoint,
                             prev->introspect_endpoint, "");

    if (conf->introspect_cache.zone == NULL) {
        conf->introspect_cache = prev->introspect_cache;
    }

    ngx_conf_merge_value(conf->exchange,
                         prev->exchange, 0);
    ngx_conf_merge_str_value(conf->token_endpoint,
                             prev->token_endpoint, "");
    ngx_conf_merge_str_value(conf->audience,
                             prev->audience, "");
    ngx_conf_merge_str_value(conf->scope,
                             prev->scope, "");

    if (conf->exchange_cache.zone == NULL) {
        conf->exchange_cache = prev->exchange_cache;
    }

    if (conf->introspect
        && conf->introspect_endpoint.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"auth_oauth2_token_introspect_endpoint\""
                           " is required when "
                           "\"auth_oauth2_token_introspect\" is on");
        return NGX_CONF_ERROR;
    }

    if (conf->exchange && conf->token_endpoint.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"auth_oauth2_token_token_endpoint\""
                           " is required when "
                           "\"auth_oauth2_token_exchange\" is on");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_handler(ngx_http_request_t *r)
{
    ngx_http_auth_oauth2_token_loc_conf_t *lcf;
    ngx_http_auth_oauth2_token_main_conf_t *mcf;
    ngx_http_auth_oauth2_token_ctx_t *ctx;
    ngx_str_t body, cached;
    ngx_str_t cache_key;
    ngx_int_t rc;
    time_t ttl, exp;
    u_char *p;

    /* skip subrequests */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    lcf = ngx_http_get_module_loc_conf(r,
                                       ngx_http_auth_oauth2_token_module);

    /* skip if module is not enabled */
    if (!lcf->introspect && !lcf->exchange) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r,
                                        ngx_http_auth_oauth2_token_module);

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx,
                         ngx_http_auth_oauth2_token_module);

        /* extract bearer token */
        rc = ngx_http_auth_oauth2_token_extract_token(r, ctx);
        if (rc != NGX_OK) {
            return ngx_http_auth_oauth2_token_unauthorized(r);
        }
    }

    /* Phase 1: Token Introspection */

    if (lcf->introspect) {
        if (ctx->introspect_done) {
            if (ctx->introspect_error) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            if (!ctx->active) {
                return ngx_http_auth_oauth2_token_unauthorized(
                    r);
            }

            /* store in cache if not from cache */
            if (!ctx->introspect_from_cache
                && lcf->introspect_cache.zone
                && lcf->introspect_cache.max_ttl > 0
                && ctx->introspect_response.len > 0)
            {
                ttl = lcf->introspect_cache.max_ttl;

                if (ctx->exp.len > 0) {
                    exp = ngx_atotm(ctx->exp.data,
                                    ctx->exp.len);
                    if (exp > ngx_time()
                        && (exp - ngx_time()) < ttl)
                    {
                        ttl = exp - ngx_time();
                    }
                }

                /* cache key: <len>:<endpoint>|<len>:<token> */
                cache_key.len = NGX_OFF_T_LEN + 1
                                + lcf->introspect_endpoint.len
                                + 1
                                + NGX_OFF_T_LEN + 1
                                + ctx->token.len;
                cache_key.data = ngx_pnalloc(r->pool,
                                             cache_key.len);
                if (cache_key.data != NULL) {
                    p = ngx_sprintf(cache_key.data,
                                    "%uz:%V|%uz:%V",
                                    lcf->introspect_endpoint.len,
                                    &lcf->introspect_endpoint,
                                    ctx->token.len,
                                    &ctx->token);
                    cache_key.len = p - cache_key.data;

                    ngx_auth_oauth2_token_cache_store(
                        lcf->introspect_cache.zone,
                        &cache_key,
                        &ctx->introspect_response, ttl);
                }
            }

            /* introspection passed, continue */

        } else if (!ctx->introspect_sent) {
            ctx->introspect_sent = 1;

            /* check cache first */
            if (lcf->introspect_cache.zone
                && lcf->introspect_cache.max_ttl > 0)
            {
                /* cache key: <len>:<endpoint>|<len>:<token> */
                cache_key.len = NGX_OFF_T_LEN + 1
                                + lcf->introspect_endpoint.len
                                + 1
                                + NGX_OFF_T_LEN + 1
                                + ctx->token.len;
                cache_key.data = ngx_pnalloc(r->pool,
                                             cache_key.len);
                if (cache_key.data == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                p = ngx_sprintf(cache_key.data,
                                "%uz:%V|%uz:%V",
                                lcf->introspect_endpoint.len,
                                &lcf->introspect_endpoint,
                                ctx->token.len,
                                &ctx->token);
                cache_key.len = p - cache_key.data;

                rc = ngx_auth_oauth2_token_cache_lookup(
                    lcf->introspect_cache.zone,
                    &cache_key, &cached, r->pool);

                if (rc == NGX_OK) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                   r->connection->log, 0,
                                   "auth_oauth2_token: "
                                   "introspection cache hit");

                    ctx->introspect_from_cache = 1;
                    ctx->introspect_done = 1;

                    rc = ngx_auth_oauth2_token_introspect_parse_response(
                        r->pool, &cached, ctx,
                        r->connection->log);
                    if (rc != NGX_OK) {
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    if (!ctx->active) {
                        return
                            ngx_http_auth_oauth2_token_unauthorized(
                            r);
                    }

                    goto exchange;
                }
            }

            if (lcf->introspect_endpoint.len == 0) {
                ngx_log_error(NGX_LOG_ERR,
                              r->connection->log, 0,
                              "auth_oauth2_token: "
                              "introspect_endpoint not configured");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rc = ngx_auth_oauth2_token_introspect_build_body(
                r->pool, &ctx->token, &body);
            if (rc != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rc = ngx_auth_oauth2_token_http_subrequest(
                r, &lcf->introspect_endpoint, &body,
                &mcf->client_credentials,
                ngx_auth_oauth2_token_introspect_subrequest_done,
                ctx);
            if (rc == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;

        } else {
            /* subrequest in progress */
            return NGX_AGAIN;
        }
    }

exchange:

    /* Phase 2: Token Exchange */

    if (lcf->exchange) {
        if (ctx->exchange_done) {
            if (ctx->new_token.len == 0) {
                ngx_log_error(NGX_LOG_ERR,
                              r->connection->log, 0,
                              "auth_oauth2_token: "
                              "exchange failed, no new token");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /* store in cache if not from cache */
            if (!ctx->exchange_from_cache
                && lcf->exchange_cache.zone
                && lcf->exchange_cache.max_ttl > 0
                && ctx->exchange_response.len > 0)
            {
                ttl = lcf->exchange_cache.max_ttl;

                if (ctx->exchange_expires_in > 0
                    && ctx->exchange_expires_in < ttl)
                {
                    ttl = ctx->exchange_expires_in;
                }

                /* cache key: <len>:<endpoint>|<len>:<token>|<len>:<audience>|<len>:<scope> */
                cache_key.len = NGX_OFF_T_LEN + 1
                                + lcf->token_endpoint.len + 1
                                + NGX_OFF_T_LEN + 1
                                + ctx->token.len + 1
                                + NGX_OFF_T_LEN + 1
                                + lcf->audience.len + 1
                                + NGX_OFF_T_LEN + 1
                                + lcf->scope.len;
                cache_key.data = ngx_pnalloc(r->pool,
                                             cache_key.len);
                if (cache_key.data != NULL) {
                    p = ngx_sprintf(cache_key.data,
                                    "%uz:%V|%uz:%V|%uz:%V|%uz:%V",
                                    lcf->token_endpoint.len,
                                    &lcf->token_endpoint,
                                    ctx->token.len,
                                    &ctx->token,
                                    lcf->audience.len,
                                    &lcf->audience,
                                    lcf->scope.len,
                                    &lcf->scope);
                    cache_key.len = p - cache_key.data;

                    ngx_auth_oauth2_token_cache_store(
                        lcf->exchange_cache.zone,
                        &cache_key,
                        &ctx->exchange_response, ttl);
                }
            }

            /* replace Authorization header with new token */
            if (r->headers_in.authorization) {
                r->headers_in.authorization->value.len =
                    sizeof("Bearer ") - 1 + ctx->new_token.len;
                r->headers_in.authorization->value.data =
                    ngx_pnalloc(r->pool,
                                r->headers_in.authorization->value.len);
                if (r->headers_in.authorization->value.data
                    == NULL)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                ngx_memcpy(
                    r->headers_in.authorization->value.data,
                    "Bearer ", sizeof("Bearer ") - 1);
                ngx_memcpy(
                    r->headers_in.authorization->value.data
                    + sizeof("Bearer ") - 1,
                    ctx->new_token.data, ctx->new_token.len);
            }

        } else if (!ctx->exchange_sent) {
            ctx->exchange_sent = 1;

            /* check cache first */
            if (lcf->exchange_cache.zone
                && lcf->exchange_cache.max_ttl > 0)
            {
                /* build cache key: <len>:<endpoint>|<len>:<token>|<len>:<audience>|<len>:<scope> */
                cache_key.len = NGX_OFF_T_LEN + 1
                                + lcf->token_endpoint.len + 1
                                + NGX_OFF_T_LEN + 1
                                + ctx->token.len + 1
                                + NGX_OFF_T_LEN + 1
                                + lcf->audience.len + 1
                                + NGX_OFF_T_LEN + 1
                                + lcf->scope.len;
                cache_key.data = ngx_pnalloc(r->pool,
                                             cache_key.len);
                if (cache_key.data != NULL) {
                    p = ngx_sprintf(cache_key.data,
                                    "%uz:%V|%uz:%V|%uz:%V|%uz:%V",
                                    lcf->token_endpoint.len,
                                    &lcf->token_endpoint,
                                    ctx->token.len,
                                    &ctx->token,
                                    lcf->audience.len,
                                    &lcf->audience,
                                    lcf->scope.len,
                                    &lcf->scope);
                    cache_key.len = p - cache_key.data;

                    rc = ngx_auth_oauth2_token_cache_lookup(
                        lcf->exchange_cache.zone,
                        &cache_key, &cached, r->pool);

                    if (rc == NGX_OK) {
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP,
                                       r->connection->log, 0,
                                       "auth_oauth2_token: "
                                       "exchange cache hit");

                        ctx->exchange_from_cache = 1;
                        ctx->exchange_done = 1;

                        rc =
                            ngx_auth_oauth2_token_exchange_parse_response(
                                r->pool, &cached, ctx,
                                r->connection->log);
                        if (rc != NGX_OK) {
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }

                        /* re-enter to handle exchange_done */
                        goto exchange;
                    }
                }
            }

            if (lcf->token_endpoint.len == 0) {
                ngx_log_error(NGX_LOG_ERR,
                              r->connection->log, 0,
                              "auth_oauth2_token: "
                              "token_endpoint not configured");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rc = ngx_auth_oauth2_token_exchange_build_body(
                r->pool, &ctx->token,
                &lcf->audience, &lcf->scope, &body);
            if (rc != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            rc = ngx_auth_oauth2_token_http_subrequest(
                r, &lcf->token_endpoint, &body,
                &mcf->client_credentials,
                ngx_auth_oauth2_token_exchange_subrequest_done,
                ctx);
            if (rc == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;

        } else {
            /* subrequest in progress */
            return NGX_AGAIN;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_unauthorized(ngx_http_request_t *r)
{
    ngx_table_elt_t *h;

    r->headers_out.www_authenticate = ngx_list_push(
        &r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = r->headers_out.www_authenticate;

    h->hash = 1;
    ngx_str_set(&h->key, "WWW-Authenticate");
    ngx_str_set(&h->value,
                "Bearer error=\"invalid_token\"");

    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
ngx_http_auth_oauth2_token_extract_token(ngx_http_request_t *r,
    ngx_http_auth_oauth2_token_ctx_t *ctx)
{
    ngx_str_t value;

    if (r->headers_in.authorization == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth_oauth2_token: "
                       "no Authorization header");
        return NGX_DECLINED;
    }

    value = r->headers_in.authorization->value;

    if (value.len <= sizeof("Bearer ") - 1
        || ngx_strncasecmp(value.data, (u_char *) "Bearer ",
                           sizeof("Bearer ") - 1) != 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth_oauth2_token: "
                       "Authorization is not Bearer");
        return NGX_DECLINED;
    }

    ctx->token.data = value.data + sizeof("Bearer ") - 1;
    ctx->token.len = value.len - (sizeof("Bearer ") - 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth_oauth2_token: "
                   "bearer token length: %uz", ctx->token.len);

    return NGX_OK;
}


static char *
ngx_http_auth_oauth2_token_client_secret_file(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_oauth2_token_main_conf_t *mcf = conf;

    ngx_str_t *value;
    ngx_file_t file;
    ngx_int_t n;
    off_t size;

    if (mcf->client_secret.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name = value[1];
    file.log = cf->log;

    file.fd = ngx_open_file(value[1].data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(file.fd, &file.info) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed",
                           &value[1]);
        ngx_close_file(file.fd);
        return NGX_CONF_ERROR;
    }

    size = ngx_file_size(&file.info);

    mcf->client_secret.data = ngx_pnalloc(cf->pool, size);
    if (mcf->client_secret.data == NULL) {
        ngx_close_file(file.fd);
        return NGX_CONF_ERROR;
    }

    n = ngx_read_file(&file, mcf->client_secret.data, size, 0);

    ngx_close_file(file.fd);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    mcf->client_secret.len = n;

    /* trim trailing whitespace */
    while (mcf->client_secret.len > 0
           && (mcf->client_secret.data[mcf->client_secret.len - 1]
               == '\n'
               || mcf->client_secret.data[
                   mcf->client_secret.len - 1]
               == '\r'))
    {
        mcf->client_secret.len--;
    }

    return NGX_CONF_OK;
}


/* variable getters */


static ngx_int_t
ngx_http_auth_oauth2_token_variable_active(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || !ctx->introspect_done
        || ctx->introspect_error)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->active ? (u_char *) "1" : (u_char *) "0";
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_sub(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->sub.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->sub.data;
    v->len = ctx->sub.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_scope(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->scope.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->scope.data;
    v->len = ctx->scope.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_client_id(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->client_id.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->client_id.data;
    v->len = ctx->client_id.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_exp(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->exp.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->exp.data;
    v->len = ctx->exp.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_new_token(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->new_token.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->new_token.data;
    v->len = ctx->new_token.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_oauth2_token_variable_new_token_type(
    ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_auth_oauth2_token_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r,
                                  ngx_http_auth_oauth2_token_module);

    if (ctx == NULL || ctx->new_token_type.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->new_token_type.data;
    v->len = ctx->new_token_type.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


/*
 * Parse cache directive:
 *   zone=name:size max_ttl=time
 */

static char *
ngx_http_auth_oauth2_token_cache_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_auth_oauth2_token_cache_conf_t *cache;
    ngx_str_t *value, name, s;
    ssize_t size;
    ngx_uint_t i;
    ngx_flag_t seen_zone, seen_max_ttl;
    u_char *p;

    cache = (ngx_auth_oauth2_token_cache_conf_t *)
            ((u_char *) conf + cmd->offset);

    if (cache->zone) {
        return "is duplicate";
    }

    value = cf->args->elts;
    seen_zone = 0;
    seen_max_ttl = 0;

    /* parse arguments */
    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=",
                        sizeof("zone=") - 1)
            == 0)
        {
            if (seen_zone) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate \"zone\" "
                                   "parameter");
                return NGX_CONF_ERROR;
            }

            seen_zone = 1;

            s.data = value[i].data + sizeof("zone=") - 1;
            s.len = value[i].len - (sizeof("zone=") - 1);

            p = (u_char *) ngx_strchr(s.data, ':');
            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            name.data = s.data;
            name.len = p - s.data;

            s.data = p + 1;
            s.len = s.len - (p - name.data) - 1;

            size = ngx_parse_size(&s);
            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &name);
                return NGX_CONF_ERROR;
            }

            cache->zone = ngx_shared_memory_add(
                cf, &name, size,
                &ngx_http_auth_oauth2_token_module);
            if (cache->zone == NULL) {
                return NGX_CONF_ERROR;
            }

            cache->zone->init =
                ngx_auth_oauth2_token_cache_init_zone;

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_ttl=",
                        sizeof("max_ttl=") - 1)
            == 0)
        {
            if (seen_max_ttl) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "duplicate \"max_ttl\" "
                                   "parameter");
                return NGX_CONF_ERROR;
            }

            seen_max_ttl = 1;

            s.data = value[i].data + sizeof("max_ttl=") - 1;
            s.len = value[i].len - (sizeof("max_ttl=") - 1);

            cache->max_ttl = ngx_parse_time(&s, 1);
            if (cache->max_ttl == (time_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_ttl \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (cache->zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"zone\" parameter is required");
        return NGX_CONF_ERROR;
    }

    if (!seen_max_ttl) {
        cache->max_ttl = 300;   /* default: 5 minutes */
    }

    return NGX_CONF_OK;
}
