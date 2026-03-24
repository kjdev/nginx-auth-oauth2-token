/*
 * Copyright (C) Takeshi Kamijo
 */

#ifndef _NGX_AUTH_OAUTH2_TOKEN_JSON_H_INCLUDED_
#define _NGX_AUTH_OAUTH2_TOKEN_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_AUTH_OAUTH2_TOKEN_JSON_MAX_SIZE    (64 * 1024)


typedef void ngx_auth_oauth2_token_json_t;


ngx_auth_oauth2_token_json_t *ngx_auth_oauth2_token_json_parse(
    u_char *data, size_t len, ngx_log_t *log);

void ngx_auth_oauth2_token_json_free(
    ngx_auth_oauth2_token_json_t *json);

ngx_int_t ngx_auth_oauth2_token_json_get_bool(
    ngx_auth_oauth2_token_json_t *json, const char *key);

ngx_int_t ngx_auth_oauth2_token_json_get_string(
    ngx_auth_oauth2_token_json_t *json, const char *key,
    ngx_pool_t *pool, ngx_str_t *value);

ngx_int_t ngx_auth_oauth2_token_json_get_integer(
    ngx_auth_oauth2_token_json_t *json, const char *key,
    time_t *value);


#endif /* _NGX_AUTH_OAUTH2_TOKEN_JSON_H_INCLUDED_ */
