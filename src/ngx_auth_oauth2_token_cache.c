/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_oauth2_token_cache.h"


typedef struct {
    ngx_rbtree_node_t  node;     /* must be first */
    ngx_str_t          str;      /* must be second (ngx_str_rbtree) */
    u_char            *data;
    size_t             data_len;
    time_t             expires;
    ngx_queue_t        queue;
} ngx_auth_oauth2_token_cache_node_t;


typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        expire_queue;
} ngx_auth_oauth2_token_cache_shctx_t;


static void ngx_auth_oauth2_token_cache_expire(
    ngx_auth_oauth2_token_cache_shctx_t *shctx,
    ngx_slab_pool_t *shpool);
static void ngx_auth_oauth2_token_cache_free_node(
    ngx_slab_pool_t *shpool,
    ngx_auth_oauth2_token_cache_node_t *cn);
static ngx_auth_oauth2_token_cache_node_t *
ngx_auth_oauth2_token_cache_find(
    ngx_auth_oauth2_token_cache_shctx_t *shctx,
    ngx_str_t *key);


ngx_int_t
ngx_auth_oauth2_token_cache_init_zone(ngx_shm_zone_t *shm_zone,
    void *data)
{
    ngx_auth_oauth2_token_cache_shctx_t *shctx;
    ngx_slab_pool_t *shpool;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    shctx = ngx_slab_alloc(shpool, sizeof(*shctx));
    if (shctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&shctx->rbtree, &shctx->sentinel,
                    ngx_str_rbtree_insert_value);

    ngx_queue_init(&shctx->expire_queue);

    shm_zone->data = shctx;

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_cache_lookup(ngx_shm_zone_t *zone,
    ngx_str_t *key, ngx_str_t *value, ngx_pool_t *pool)
{
    ngx_auth_oauth2_token_cache_shctx_t *shctx;
    ngx_auth_oauth2_token_cache_node_t *cn;
    ngx_slab_pool_t *shpool;

    shctx = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* evict expired entries */
    ngx_auth_oauth2_token_cache_expire(shctx, shpool);

    cn = ngx_auth_oauth2_token_cache_find(shctx, key);

    if (cn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    /* check expiration */
    if (cn->expires <= ngx_time()) {
        ngx_queue_remove(&cn->queue);
        ngx_rbtree_delete(&shctx->rbtree, &cn->node);
        ngx_auth_oauth2_token_cache_free_node(shpool, cn);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    /* copy value to pool memory */
    value->data = ngx_pnalloc(pool, cn->data_len);
    if (value->data == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(value->data, cn->data, cn->data_len);
    value->len = cn->data_len;

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_cache_store(ngx_shm_zone_t *zone,
    ngx_str_t *key, ngx_str_t *value, time_t ttl)
{
    ngx_auth_oauth2_token_cache_shctx_t *shctx;
    ngx_auth_oauth2_token_cache_node_t *cn;
    ngx_slab_pool_t *shpool;
    uint32_t hash;

    if (ttl <= 0) {
        return NGX_OK;
    }

    shctx = zone->data;
    shpool = (ngx_slab_pool_t *) zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);

    /* evict expired entries */
    ngx_auth_oauth2_token_cache_expire(shctx, shpool);

    /* check if key already exists */
    cn = ngx_auth_oauth2_token_cache_find(shctx, key);

    if (cn != NULL) {
        /* update existing entry */
        ngx_queue_remove(&cn->queue);

        if (cn->data_len != value->len) {
            ngx_slab_free_locked(shpool, cn->data);

            cn->data = ngx_slab_alloc_locked(shpool, value->len);
            if (cn->data == NULL) {
                /* remove the node if alloc fails */
                ngx_rbtree_delete(&shctx->rbtree, &cn->node);
                ngx_slab_free_locked(shpool, cn->str.data);
                ngx_slab_free_locked(shpool, cn);
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_ERROR;
            }
        }

        ngx_memcpy(cn->data, value->data, value->len);
        cn->data_len = value->len;
        cn->expires = ngx_time() + ttl;

        ngx_queue_insert_head(&shctx->expire_queue, &cn->queue);

        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    /* allocate new node */
    cn = ngx_slab_alloc_locked(shpool, sizeof(*cn));
    if (cn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    cn->str.data = ngx_slab_alloc_locked(shpool, key->len);
    if (cn->str.data == NULL) {
        ngx_slab_free_locked(shpool, cn);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    cn->data = ngx_slab_alloc_locked(shpool, value->len);
    if (cn->data == NULL) {
        ngx_slab_free_locked(shpool, cn->str.data);
        ngx_slab_free_locked(shpool, cn);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    ngx_memcpy(cn->str.data, key->data, key->len);
    cn->str.len = key->len;

    ngx_memcpy(cn->data, value->data, value->len);
    cn->data_len = value->len;
    cn->expires = ngx_time() + ttl;

    hash = ngx_crc32_short(key->data, key->len);
    cn->node.key = hash;

    ngx_rbtree_insert(&shctx->rbtree, &cn->node);
    ngx_queue_insert_head(&shctx->expire_queue, &cn->queue);

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}


static void
ngx_auth_oauth2_token_cache_expire(
    ngx_auth_oauth2_token_cache_shctx_t *shctx,
    ngx_slab_pool_t *shpool)
{
    ngx_auth_oauth2_token_cache_node_t *cn;
    ngx_queue_t *q, *last;
    time_t now;

    now = ngx_time();

    /*
     * Walk the entire queue and remove all expired entries.
     * Entries may have different TTLs, so we cannot stop at the
     * first non-expired entry.
     */
    last = ngx_queue_last(&shctx->expire_queue);

    while (last != ngx_queue_sentinel(&shctx->expire_queue)) {
        cn = ngx_queue_data(last,
                            ngx_auth_oauth2_token_cache_node_t, queue);

        q = last;
        last = ngx_queue_prev(last);

        if (cn->expires <= now) {
            ngx_queue_remove(q);
            ngx_rbtree_delete(&shctx->rbtree, &cn->node);
            ngx_auth_oauth2_token_cache_free_node(shpool, cn);
        }
    }
}


static void
ngx_auth_oauth2_token_cache_free_node(ngx_slab_pool_t *shpool,
    ngx_auth_oauth2_token_cache_node_t *cn)
{
    if (cn->str.data) {
        ngx_slab_free_locked(shpool, cn->str.data);
    }

    if (cn->data) {
        ngx_slab_free_locked(shpool, cn->data);
    }

    ngx_slab_free_locked(shpool, cn);
}


static ngx_auth_oauth2_token_cache_node_t *
ngx_auth_oauth2_token_cache_find(
    ngx_auth_oauth2_token_cache_shctx_t *shctx,
    ngx_str_t *key)
{
    ngx_str_node_t *sn;
    uint32_t hash;

    hash = ngx_crc32_short(key->data, key->len);

    sn = ngx_str_rbtree_lookup(&shctx->rbtree, key, hash);
    if (sn == NULL) {
        return NULL;
    }

    return (ngx_auth_oauth2_token_cache_node_t *) sn;
}
