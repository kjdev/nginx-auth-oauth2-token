/*
 * Copyright (C) Takeshi Kamijo
 */

#ifndef _NGX_HTTP_AUTH_OAUTH2_TOKEN_MODULE_H_INCLUDED_
#define _NGX_HTTP_AUTH_OAUTH2_TOKEN_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t  client_id;
    ngx_str_t  client_secret;
    ngx_str_t  client_credentials;                   /* "Basic <b64>" */
} ngx_http_auth_oauth2_token_main_conf_t;


typedef struct {
    ngx_shm_zone_t *zone;
    time_t          max_ttl;
} ngx_auth_oauth2_token_cache_conf_t;


typedef struct {
    ngx_flag_t                          introspect;
    ngx_str_t                           introspect_endpoint;
    ngx_auth_oauth2_token_cache_conf_t  introspect_cache;

    ngx_flag_t                          exchange;
    ngx_str_t                           token_endpoint;
    ngx_str_t                           audience;
    ngx_str_t                           scope;
    ngx_auth_oauth2_token_cache_conf_t  exchange_cache;
} ngx_http_auth_oauth2_token_loc_conf_t;


typedef struct {
    /* bearer token from Authorization header */
    ngx_str_t  token;

    /* introspection results */
    unsigned   introspect_sent:1;
    unsigned   introspect_done:1;
    unsigned   introspect_error:1;
    unsigned   active:1;
    ngx_str_t  sub;
    ngx_str_t  scope;
    ngx_str_t  client_id;
    ngx_str_t  exp;

    /* exchange results */
    unsigned   exchange_sent:1;
    unsigned   exchange_done:1;
    ngx_str_t  new_token;
    ngx_str_t  new_token_type;
    time_t     exchange_expires_in;

    /* cache state */
    unsigned   introspect_from_cache:1;
    unsigned   exchange_from_cache:1;
    ngx_str_t  introspect_response;
    ngx_str_t  exchange_response;

    /* subrequest status */
    ngx_int_t  subrequest_status;
} ngx_http_auth_oauth2_token_ctx_t;


extern ngx_module_t ngx_http_auth_oauth2_token_module;


#endif /* _NGX_HTTP_AUTH_OAUTH2_TOKEN_MODULE_H_INCLUDED_ */
