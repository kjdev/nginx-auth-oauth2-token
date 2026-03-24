/*
 * Copyright (C) Takeshi Kamijo
 */

#ifndef _NGX_AUTH_OAUTH2_TOKEN_CACHE_H_INCLUDED_
#define _NGX_AUTH_OAUTH2_TOKEN_CACHE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_auth_oauth2_token_cache_init_zone(
    ngx_shm_zone_t *shm_zone, void *data);

ngx_int_t ngx_auth_oauth2_token_cache_lookup(
    ngx_shm_zone_t *zone, ngx_str_t *key,
    ngx_str_t *value, ngx_pool_t *pool);

ngx_int_t ngx_auth_oauth2_token_cache_store(
    ngx_shm_zone_t *zone, ngx_str_t *key,
    ngx_str_t *value, time_t ttl);


#endif /* _NGX_AUTH_OAUTH2_TOKEN_CACHE_H_INCLUDED_ */
