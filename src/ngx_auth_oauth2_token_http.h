/*
 * Copyright (C) Takeshi Kamijo
 */

#ifndef _NGX_AUTH_OAUTH2_TOKEN_HTTP_H_INCLUDED_
#define _NGX_AUTH_OAUTH2_TOKEN_HTTP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_auth_oauth2_token_http_handler_pt)(
    ngx_http_request_t *r, void *data, ngx_int_t rc);


ngx_int_t ngx_auth_oauth2_token_http_subrequest(
    ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *body,
    ngx_str_t *authorization,
    ngx_auth_oauth2_token_http_handler_pt handler, void *data);

ngx_int_t ngx_auth_oauth2_token_http_response_body(
    ngx_http_request_t *r, ngx_str_t *body, ngx_log_t *log);

ngx_uint_t ngx_auth_oauth2_token_http_response_status(
    ngx_http_request_t *r);


#endif /* _NGX_AUTH_OAUTH2_TOKEN_HTTP_H_INCLUDED_ */
