/*
 * Copyright (C) Takeshi Kamijo
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <jansson.h>

#include "ngx_auth_oauth2_token_json.h"


ngx_auth_oauth2_token_json_t *
ngx_auth_oauth2_token_json_parse(u_char *data, size_t len,
    ngx_log_t *log)
{
    json_t *root;
    json_error_t error;

    if (len > NGX_AUTH_OAUTH2_TOKEN_JSON_MAX_SIZE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: JSON too large: %uz",
                      len);
        return NULL;
    }

    root = json_loadb((const char *) data, len, 0, &error);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: JSON parse error: "
                      "%s at line %d", error.text, error.line);
        return NULL;
    }

    if (!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auth_oauth2_token: "
                      "JSON root is not an object");
        json_decref(root);
        return NULL;
    }

    return root;
}


void
ngx_auth_oauth2_token_json_free(ngx_auth_oauth2_token_json_t *json)
{
    if (json != NULL) {
        json_decref((json_t *) json);
    }
}


ngx_int_t
ngx_auth_oauth2_token_json_get_bool(
    ngx_auth_oauth2_token_json_t *json, const char *key)
{
    json_t *value;

    value = json_object_get((json_t *) json, key);
    if (value == NULL) {
        return NGX_DECLINED;
    }

    if (!json_is_boolean(value)) {
        return NGX_ERROR;
    }

    return json_is_true(value) ? 1 : 0;
}


ngx_int_t
ngx_auth_oauth2_token_json_get_string(
    ngx_auth_oauth2_token_json_t *json, const char *key,
    ngx_pool_t *pool, ngx_str_t *result)
{
    json_t *value;
    const char *str;
    size_t len;

    value = json_object_get((json_t *) json, key);
    if (value == NULL) {
        return NGX_DECLINED;
    }

    if (!json_is_string(value)) {
        return NGX_ERROR;
    }

    str = json_string_value(value);
    len = json_string_length(value);

    result->data = ngx_pnalloc(pool, len);
    if (result->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(result->data, str, len);
    result->len = len;

    return NGX_OK;
}


ngx_int_t
ngx_auth_oauth2_token_json_get_integer(
    ngx_auth_oauth2_token_json_t *json, const char *key,
    time_t *result)
{
    json_t *value;

    value = json_object_get((json_t *) json, key);
    if (value == NULL) {
        return NGX_DECLINED;
    }

    if (!json_is_integer(value)) {
        return NGX_ERROR;
    }

    *result = (time_t) json_integer_value(value);

    return NGX_OK;
}
