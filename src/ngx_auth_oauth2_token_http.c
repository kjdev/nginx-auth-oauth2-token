/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_auth_oauth2_token_http.h"
#include "ngx_auth_oauth2_token_json.h"


typedef struct {
    ngx_auth_oauth2_token_http_handler_pt  handler;
    void                                  *data;
} ngx_auth_oauth2_token_http_ctx_t;


static ngx_int_t ngx_auth_oauth2_token_http_subrequest_done(
    ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_auth_oauth2_token_http_set_header(
    ngx_http_request_t *sr, ngx_str_t *key, ngx_str_t *value);


ngx_int_t
ngx_auth_oauth2_token_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *body, ngx_str_t *authorization,
    ngx_auth_oauth2_token_http_handler_pt handler, void *data)
{
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_auth_oauth2_token_http_ctx_t *ctx;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_str_t content_type;
    ngx_int_t rc;

    ctx = ngx_palloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->handler = handler;
    ctx->data = data;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_auth_oauth2_token_http_subrequest_done;
    ps->data = ctx;

    rc = ngx_http_subrequest(r, uri, NULL, &sr, ps,
                             NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* set POST method */
    sr->method = NGX_HTTP_POST;
    ngx_str_set(&sr->method_name, "POST");

    /* set request body */
    sr->request_body = ngx_pcalloc(r->pool,
                                   sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        return NGX_ERROR;
    }

    b = ngx_create_temp_buf(r->pool, body->len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_cpymem(b->pos, body->data, body->len);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    sr->request_body->bufs = cl;
    sr->request_body->buf = b;

    sr->headers_in.content_length_n = body->len;

    /* reinitialize headers to avoid inheriting parent headers */
    if (ngx_list_init(&sr->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    sr->headers_in.content_type = NULL;
    sr->headers_in.authorization = NULL;

    /* set Content-Type */
    ngx_str_set(&content_type,
                "application/x-www-form-urlencoded");

    if (ngx_auth_oauth2_token_http_set_header(
            sr, &(ngx_str_t) ngx_string("Content-Type"),
            &content_type)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* set Authorization for client credentials */
    if (authorization != NULL && authorization->len > 0) {
        if (ngx_auth_oauth2_token_http_set_header(
                sr, &(ngx_str_t) ngx_string("Authorization"),
                authorization)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_AGAIN;
}


ngx_int_t
ngx_auth_oauth2_token_http_response_body(ngx_http_request_t *r,
    ngx_str_t *body, ngx_log_t *log)
{
    ngx_buf_t *b;
    ngx_chain_t *cl;
    size_t len;
    u_char *p;

    body->data = NULL;
    body->len = 0;

    /* try r->out chain first (postpone filter output) */
    if (r->out) {
        len = 0;

        for (cl = r->out; cl; cl = cl->next) {
            if (cl->buf) {
                len += ngx_buf_size(cl->buf);
            }
        }

        if (len > 0) {
            if (len > NGX_AUTH_OAUTH2_TOKEN_JSON_MAX_SIZE) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "auth_oauth2_token: "
                              "response too large: %uz", len);
                return NGX_ERROR;
            }

            body->data = ngx_pnalloc(r->pool, len);
            if (body->data == NULL) {
                return NGX_ERROR;
            }

            p = body->data;

            for (cl = r->out; cl; cl = cl->next) {
                if (cl->buf && ngx_buf_size(cl->buf) > 0) {
                    p = ngx_cpymem(p, cl->buf->pos,
                                   ngx_buf_size(cl->buf));
                }
            }

            body->len = len;
            return NGX_OK;
        }
    }

    /* fallback: upstream buffer */
    if (r->upstream) {
        b = &r->upstream->buffer;

        if (b->pos && b->last > b->pos) {
            len = b->last - b->pos;

            if (len > NGX_AUTH_OAUTH2_TOKEN_JSON_MAX_SIZE) {
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "auth_oauth2_token: "
                              "response too large: %uz", len);
                return NGX_ERROR;
            }

            body->data = b->pos;
            body->len = len;
            return NGX_OK;
        }

        /* try upstream out_bufs */
        if (r->upstream->out_bufs) {
            len = 0;

            for (cl = r->upstream->out_bufs; cl; cl = cl->next) {
                if (cl->buf && ngx_buf_size(cl->buf) > 0) {
                    len += ngx_buf_size(cl->buf);
                }
            }

            if (len > 0) {
                if (len > NGX_AUTH_OAUTH2_TOKEN_JSON_MAX_SIZE) {
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "auth_oauth2_token: "
                                  "response too large: %uz", len);
                    return NGX_ERROR;
                }

                body->data = ngx_pnalloc(r->pool, len);
                if (body->data == NULL) {
                    return NGX_ERROR;
                }

                p = body->data;

                for (cl = r->upstream->out_bufs; cl;
                     cl = cl->next)
                {
                    if (cl->buf
                        && ngx_buf_size(cl->buf) > 0)
                    {
                        p = ngx_cpymem(p, cl->buf->pos,
                                       ngx_buf_size(cl->buf));
                    }
                }

                body->len = len;
                return NGX_OK;
            }
        }
    }

    return NGX_OK;
}


ngx_uint_t
ngx_auth_oauth2_token_http_response_status(ngx_http_request_t *r)
{
    if (r->headers_out.status) {
        return r->headers_out.status;
    }

    if (r->upstream && r->upstream->headers_in.status_n) {
        return r->upstream->headers_in.status_n;
    }

    return 0;
}


static ngx_int_t
ngx_auth_oauth2_token_http_subrequest_done(ngx_http_request_t *r,
    void *data, ngx_int_t rc)
{
    ngx_auth_oauth2_token_http_ctx_t *ctx = data;
    ngx_http_request_t *pr;

    pr = r->parent;

    if (ctx->handler) {
        rc = ctx->handler(r, ctx->data, rc);
    }

    pr->write_event_handler = ngx_http_core_run_phases;

    return rc;
}


static ngx_int_t
ngx_auth_oauth2_token_http_set_header(ngx_http_request_t *sr,
    ngx_str_t *key, ngx_str_t *value)
{
    ngx_table_elt_t *h;

    h = ngx_list_push(&sr->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key = *key;
    h->value = *value;
    h->lowcase_key = ngx_pnalloc(sr->pool, key->len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, key->data, key->len);
    h->hash = ngx_hash_key(h->lowcase_key, key->len);

    /* set shortcut pointers */
    if (key->len == sizeof("Content-Type") - 1
        && ngx_strncasecmp(key->data, (u_char *) "Content-Type",
                           key->len) == 0)
    {
        sr->headers_in.content_type = h;

    } else if (key->len == sizeof("Authorization") - 1
               && ngx_strncasecmp(key->data,
                                  (u_char *) "Authorization",
                                  key->len) == 0)
    {
        sr->headers_in.authorization = h;
    }

    return NGX_OK;
}
