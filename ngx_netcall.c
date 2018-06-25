/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_netcall.h"


static void
ngx_netcall_cleanup(void *data)
{
    ngx_netcall_ctx_t          *nctx;
    ngx_http_request_t         *hcr;
    ngx_http_client_ctx_t      *ctx;

    hcr = data;
    ctx = hcr->ctx[0];
    nctx = ctx->request;

    if (nctx) {
        nctx->hcr = NULL;
    }
}

static void
ngx_netcall_destroy(ngx_netcall_ctx_t *nctx)
{
    ngx_http_request_t         *hcr;
    ngx_http_client_ctx_t      *ctx;

    if (nctx->ev.timer_set) {
        ngx_del_timer(&nctx->ev);
    }

    if (nctx->ev.posted) {
        ngx_delete_posted_event(&nctx->ev);
    }

    nctx->handler = NULL;
    nctx->data = NULL;

    hcr = nctx->hcr;
    if (hcr) {
        ctx = hcr->ctx[0];
        ctx->request = NULL;
    }

    ngx_destroy_pool(nctx->pool);
}

static void
ngx_netcall_timeout(ngx_event_t *ev)
{
    ngx_netcall_ctx_t          *nctx;
    ngx_http_request_t         *hcr;

    nctx = ev->data;
    hcr = nctx->hcr;

    if (nctx->handler) {
        nctx->handler(nctx, NGX_ERROR);
        nctx->hcr = NULL;
    } else {
        ngx_netcall_destroy(nctx);
    }

    if (hcr) {
        ngx_http_client_finalize_request(hcr, 1);
    }
}

static void
ngx_netcall_handler(void *data, ngx_http_request_t *hcr)
{
    ngx_netcall_ctx_t          *nctx;
    ngx_int_t                   code;

    nctx = data;
    if (nctx->ev.timer_set) {
        ngx_del_timer(&nctx->ev);
    }

    code = ngx_http_client_status_code(hcr);

    if (nctx->handler) {
        nctx->handler(nctx, code);
        nctx->hcr = NULL;
    } else {
        ngx_netcall_destroy(nctx);
    }

    ngx_http_client_finalize_request(hcr, 1);
}

ngx_netcall_ctx_t *
ngx_netcall_create_ctx(ngx_uint_t type, ngx_str_t *groupid, ngx_uint_t stage,
    ngx_msec_t timeout, ngx_int_t retries, ngx_msec_t update, ngx_uint_t idx)
{
    ngx_netcall_ctx_t          *ctx;
    ngx_pool_t                 *pool;

    pool = ngx_create_pool(4096, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_netcall_ctx_t));
    if (ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ctx->pool = pool;

    ctx->idx = idx;
    ctx->type = type;

    ctx->groupid.len = groupid->len;
    ctx->groupid.data = ngx_pcalloc(pool, ctx->groupid.len);
    if (ctx->groupid.data == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    ngx_memcpy(ctx->groupid.data, groupid->data, groupid->len);

    ctx->ev.log = ngx_cycle->log;
    ctx->ev.data = ctx;

    ctx->stage = stage;
    ctx->timeout = timeout;
    ctx->retries = retries;
    ctx->update = update;

    return ctx;
}

void
ngx_netcall_create(ngx_netcall_ctx_t *nctx, ngx_log_t *log)
{
    ngx_client_session_t       *cs;
    ngx_client_init_t          *ci;
    ngx_http_client_ctx_t      *ctx;
    ngx_http_request_t         *hcr;
    ngx_http_cleanup_t         *cln;

    hcr = ngx_http_client_create_request(&nctx->url, NGX_HTTP_CLIENT_GET,
            NGX_HTTP_CLIENT_VERSION_10, NULL, log, ngx_netcall_handler, NULL);
    if (hcr == NULL) {
        return;
    }

    ctx = hcr->ctx[0];

    ci = ngx_client_init(&ctx->url.host, NULL, 0, log);
    if (ci == NULL) {
        return;
    }
    ci->port = ngx_request_port(&ctx->url.scheme, &ctx->url.port);
    ci->max_retries = nctx->retries;

    cs = ngx_client_connect(ci, log);
    if (cs == NULL) {
        return;
    }

    ngx_http_client_send(hcr, cs, nctx, log);

    cln = ngx_http_cleanup_add(hcr, 0);
    if (cln == NULL) {
        ngx_http_client_finalize_request(hcr, 1);
        return;
    }
    cln->handler = ngx_netcall_cleanup;
    cln->data = hcr;

    if (nctx->hcr) {
        ngx_http_client_finalize_request(nctx->hcr, 1);
    }

    nctx->hcr = hcr;
    nctx->ev.handler = ngx_netcall_timeout;
    ngx_add_timer(&nctx->ev, nctx->timeout);
}

void
ngx_netcall_detach(ngx_netcall_ctx_t *nctx)
{
    if (nctx->ev.timer_set) {
        ngx_del_timer(&nctx->ev);
    }
    nctx->ev.handler = ngx_netcall_timeout;
    nctx->handler = NULL;
}

ngx_str_t *
ngx_netcall_header(ngx_netcall_ctx_t *nctx, ngx_str_t *key)
{
    ngx_http_request_t         *hcr;

    hcr = nctx->hcr;

    return ngx_http_client_header_in(hcr, key);
}
