
/*
 * Copyright (C) CloudFlare Inc.
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if !(NGX_HTTP_SSL)
#error "SSL is disabled in your nginx build"
#endif


#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <ngx_event_openssl.h>


static void *ngx_http_lua_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_lua_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_lua_ssl_create_main_conf(ngx_conf_t *cf);



typedef struct {
    int  dummy;
} ngx_http_lua_ssl_srv_conf_t;


typedef struct {
    ngx_array_t             ctx_list;   /* of SSL_CTX* */
} ngx_http_lua_ssl_main_conf_t;


static ngx_http_module_t ngx_http_lua_ssl_module_ctx = {
    NULL,                                    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    ngx_http_lua_ssl_create_main_conf,       /* create main configuration */
    NULL,                                    /* init main configuration */

    ngx_http_lua_ssl_create_srv_conf,        /* create server configuration */
    ngx_http_lua_ssl_merge_srv_conf,         /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};


ngx_module_t ngx_http_lua_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_ssl_module_ctx,   /* module context */
    NULL,                              /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_lua_ssl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_lua_ssl_main_conf_t    *lmcf;

    lmcf = ngx_palloc(cf->pool, sizeof(ngx_http_lua_ssl_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    ngx_array_init(&lmcf->ctx_list, cf->pool, 4, sizeof(SSL_CTX *));

    return lmcf;
}


static void *
ngx_http_lua_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_lua_ssl_srv_conf_t     *lscf;

    lscf = ngx_palloc(cf->pool, sizeof(ngx_http_lua_ssl_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    /* ignmore the dummy field in lscf */

    return lscf;
}


static char *
ngx_http_lua_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    SSL_CTX                         **pctx;
    ngx_uint_t                        i;
    ngx_http_ssl_srv_conf_t          *sscf;
    ngx_http_lua_ssl_main_conf_t     *lmcf;

    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
        return NGX_CONF_OK;
    }

    if (sscf->ssl.ctx) {
        lmcf = ngx_http_conf_get_module_main_conf(cf,
                                                  ngx_http_lua_ssl_module);

        pctx = lmcf->ctx_list.elts;
        for (i = 0; i < lmcf->ctx_list.nelts; i++) {
            if (pctx[i] == sscf->ssl.ctx) {
                return NGX_CONF_OK;
            }
        }

        pctx = ngx_array_push(&lmcf->ctx_list);
        if (pctx == NULL) {
            return NGX_CONF_ERROR;
        }

        *pctx = sscf->ssl.ctx;
    }

    return NGX_CONF_OK;
}


int
ngx_http_lua_ffi_get_ssl_ctx_count(void)
{
    ngx_http_lua_ssl_main_conf_t    *lmcf;

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_lua_ssl_module);
    if (lmcf == NULL) {
        return 0;
    }

    return (int) lmcf->ctx_list.nelts;
}


int
ngx_http_lua_ffi_get_ssl_ctx_list(SSL_CTX **buf)
{
    SSL_CTX                             **pctx;
    ngx_uint_t                            i;
    ngx_http_lua_ssl_main_conf_t         *lmcf;

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_lua_ssl_module);

    if (lmcf == NULL) {
        return NGX_OK;
    }

    pctx = lmcf->ctx_list.elts;

    for (i = 0; i < lmcf->ctx_list.nelts; i++) {
        dd("pctx[i] = %p", pctx[i]);
        buf[i] = pctx[i];
    }

    return NGX_OK;
}


int
ngx_http_lua_ffi_update_ticket_encryption_key(SSL_CTX *ctx,
    const unsigned char  *key, const ngx_uint_t nkeys,  char **err)
{
#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

    ngx_uint_t                          i;
    ngx_array_t                        *keys;
    ngx_ssl_session_ticket_key_t       *pkey;


    /* Insert key into the beginning of ticket key array as the
     * encryption key. Keep only nkeys keys so the array will not grow
     * arbitrarily. */
    dd("start updating a encryption ticket key");
    if (nkeys <= 0) {
        *err = "invalid key list size";
        return NGX_ERROR;
    }

    keys = SSL_CTX_get_ex_data(ctx, ngx_ssl_session_ticket_keys_index);

    if (keys == NULL) {
        dd("initialize ticket key array");
        /* initialize keys */
        keys = ngx_array_create(ngx_cycle->pool, nkeys,
                                sizeof(ngx_ssl_session_ticket_key_t));
        if (keys == NULL) {
            *err = "failed to allocate ticket key array";
            return NGX_ERROR;
        }

        if (SSL_CTX_set_ex_data(ctx, ngx_ssl_session_ticket_keys_index, keys)
            == 0)
        {
            *err = "failed to set ticket keys";
            return NGX_ERROR;
        }
    }


    /* Skip update if the incoming key is a duplicate of the current encrytion
     * key. */
    if (keys->nelts > 0) {
        pkey = keys->elts;
        if (ngx_memcmp(pkey->name, key, 16) == 0
            && ngx_memcmp(pkey->aes_key, key + 16, 16) == 0
            && ngx_memcmp(pkey->hmac_key, key + 32, 16) == 0)
        {
            dd("duplicate ticket key");
            return NGX_OK;
        }
    }

    /* push the new key at the beginning of the list. */

    /* the key list is not full, allocate for new key */
    if (keys->nelts < nkeys) {
        dd("prepend ticket key");
        pkey = ngx_array_push(keys);
        if (pkey == NULL) {
            *err = "key allocation failure in ticket key array";
            return NGX_ERROR;
        }
    }

    dd("rotate ticket keys");
    pkey = keys->elts;
    for (i = keys->nelts - 1; i >= 1; i--) {
        dd("pkeys[i] = %p", &pkey[i - 1]);
        pkey[i] = pkey[i - 1];
    }

    /* copy the new key */
    ngx_memcpy(pkey->name, key, 16);
    ngx_memcpy(pkey->aes_key, key + 16, 16);
    ngx_memcpy(pkey->hmac_key, key + 32, 16);

    return NGX_OK;

#else

    *err = "ssl session ticket key is not supported";
    return NGX_ERROR;

#endif
}


int
ngx_http_lua_ffi_update_last_ticket_decryption_key(SSL_CTX *ctx,
    const unsigned char *key, char **err)
{
    ngx_array_t                        *keys;
    ngx_ssl_session_ticket_key_t       *pkey;

#ifdef SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

    /* Insert key into the end of ticket key array as the decrytpion key.*/
    dd("start adding extra decryption ticket key");
    keys = SSL_CTX_get_ex_data(ctx, ngx_ssl_session_ticket_keys_index);

    if (keys == NULL) {
        *err = "uninitialized ticket key list";
        return NGX_ERROR;
    }

    /* do not overwrite the existing encryption key */
    if (keys->nelts <= 1) {
        dd("append to ticket list");
        pkey = ngx_array_push(keys);
        if (pkey == NULL) {
            *err = "key allocation failure in ticket key array";
            return NGX_ERROR;
        }
    }

    /* pkey points to the last one of the keys */
    pkey = keys->elts;
    pkey = &pkey[keys->nelts - 1];

    dd("replace the last key");
    ngx_memcpy(pkey->name, key, 16);
    ngx_memcpy(pkey->aes_key, key + 16, 16);
    ngx_memcpy(pkey->hmac_key, key + 32, 16);

    return NGX_OK;

#else

    *err = "ssl session ticket key is not supported";
    return NGX_ERROR;

#endif
}
