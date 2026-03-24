/*
 * Copyright (C) Takeshi Kamijo
 */

#ifndef _NGX_AUTH_OAUTH2_TOKEN_INTROSPECT_H_INCLUDED_
#define _NGX_AUTH_OAUTH2_TOKEN_INTROSPECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_oauth2_token_module.h"


ngx_int_t ngx_auth_oauth2_token_introspect_build_body(
    ngx_pool_t *pool, ngx_str_t *token, ngx_str_t *body);

ngx_int_t ngx_auth_oauth2_token_introspect_parse_response(
    ngx_pool_t *pool, ngx_str_t *body,
    ngx_http_auth_oauth2_token_ctx_t *ctx, ngx_log_t *log);

ngx_int_t ngx_auth_oauth2_token_introspect_subrequest_done(
    ngx_http_request_t *r, void *data, ngx_int_t rc);


#endif /* _NGX_AUTH_OAUTH2_TOKEN_INTROSPECT_H_INCLUDED_ */
