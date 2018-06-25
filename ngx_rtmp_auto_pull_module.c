/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_stream_zone_module.h"
#include "ngx_multiport.h"


static ngx_rtmp_push_pt                 next_push;
static ngx_rtmp_pull_pt                 next_pull;
static ngx_rtmp_close_stream_pt         next_close_stream;


static void *ngx_rtmp_auto_pull_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_auto_pull_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_auto_pull_postconfiguration(ngx_conf_t *cf);


typedef struct {
    ngx_flag_t                          auto_pull;
    ngx_str_t                           auto_pull_port;
} ngx_rtmp_auto_pull_app_conf_t;


static ngx_command_t  ngx_rtmp_auto_pull_commands[] = {

    { ngx_string("rtmp_auto_pull"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_auto_pull_app_conf_t, auto_pull),
      NULL },

    { ngx_string("rtmp_auto_pull_port"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_auto_pull_app_conf_t, auto_pull_port),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_auto_pull_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_auto_pull_postconfiguration,   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_auto_pull_create_app_conf,     /* create app configuration */
    ngx_rtmp_auto_pull_merge_app_conf       /* merge app configuration */
};


ngx_module_t  ngx_rtmp_auto_pull_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auto_pull_module_ctx,         /* module context */
    ngx_rtmp_auto_pull_commands,            /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_auto_pull_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_auto_pull_app_conf_t      *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_auto_pull_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->auto_pull = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_rtmp_auto_pull_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_auto_pull_app_conf_t      *prev = parent;
    ngx_rtmp_auto_pull_app_conf_t      *conf = child;

    ngx_conf_merge_value(conf->auto_pull, prev->auto_pull, 1);
    ngx_conf_merge_str_value(conf->auto_pull_port, prev->auto_pull_port,
                             "unix:/tmp/rtmp_auto_pull.sock");

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_auto_pull_target(ngx_rtmp_session_t *s,
        ngx_rtmp_relay_target_t *target, ngx_int_t pslot, unsigned publishing)
{
    ngx_rtmp_auto_pull_app_conf_t      *apcf;
    ngx_url_t                          *u;
    ngx_str_t                           port;

    apcf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auto_pull_module);

    ngx_memzero(target, sizeof(ngx_rtmp_relay_target_t));

    u = &target->url;
    target->name = s->name;
    target->app = s->app;
    target->tc_url = s->tc_url;
    target->page_url = s->page_url;
    target->swf_url = s->swf_url;
    target->flash_ver = s->flashver;
    target->tag = &ngx_rtmp_auto_pull_module;
    target->publishing = publishing;

    ngx_memzero(u, sizeof(ngx_url_t));
    ngx_memzero(&port, sizeof(ngx_str_t));

    if (ngx_multiport_get_port(s->connection->pool, &port,
            &apcf->auto_pull_port, pslot) == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "auto pull, get mulitport error: %V", &apcf->auto_pull_port);
        return NGX_ERROR;
    }

    u->url = port;
    u->no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "auto pull, parse url failed '%V'", &u->url);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_auto_pull_push(ngx_rtmp_session_t *s)
{
    ngx_rtmp_auto_pull_app_conf_t      *apcf;
    ngx_int_t                           pslot;
    ngx_rtmp_relay_target_t             target;
    ngx_rtmp_relay_ctx_t               *ctx;

    apcf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auto_pull_module);

    if (!apcf->auto_pull || s->relay) {
        goto next;
    }

    ctx = s->live_stream->auto_pull_ctx;
    if (ctx == NGX_CONF_UNSET_PTR) {
        --s->live_stream->push_count;
        s->live_stream->auto_pull_ctx = NULL;
    }

    ctx = s->live_stream->auto_pull_ctx;
    if (ctx && ctx->relay_completion) { /* relay push already complete */
        goto next;
    }

    pslot = ngx_stream_zone_insert_stream(&s->stream);
    if (pslot == NGX_ERROR) {
        goto next;
    }
    s->live_stream->pslot = pslot;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "auto push, stream %V not in current process, "
            "pslot:%i ngx_process_slot:%i",
            &s->stream, pslot, ngx_process_slot);

    if (pslot == ngx_process_slot) {
        if (s->live_stream->auto_pull_ctx) {
            ngx_rtmp_finalize_session(s->live_stream->auto_pull_ctx->session);
        }

        goto next;
    }

    if (ngx_rtmp_auto_pull_target(s, &target, pslot, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_relay_push(s, &s->name, &target);
    if (ctx == NULL) {
        s->live_stream->auto_pull_ctx = NGX_CONF_UNSET_PTR;
        ++s->live_stream->push_count;
        return NGX_OK;
    }

    if (s->live_stream->auto_pull_ctx) {
        ngx_rtmp_finalize_session(s->live_stream->auto_pull_ctx->session);
    }
    s->live_stream->auto_pull_ctx = ctx;

next:
    return next_push(s);
}


static ngx_int_t
ngx_rtmp_auto_pull_pull(ngx_rtmp_session_t *s)
{
    ngx_rtmp_auto_pull_app_conf_t      *apcf;
    ngx_int_t                           pslot;
    ngx_rtmp_relay_target_t             target;
    ngx_rtmp_relay_ctx_t               *ctx;

    apcf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auto_pull_module);

    if (!apcf->auto_pull || s->relay) {
        goto next;
    }

    if (s->live_stream->pslot != -1) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "auto pull, stream %V already in current process", &s->stream);
        if (s->live_stream->pslot == ngx_process_slot) {
            goto next;
        }
        return NGX_OK;
    } else { /* first access for stream */
        pslot = ngx_stream_zone_insert_stream(&s->stream);
        if (pslot == NGX_ERROR) {
            goto next;
        }
        s->live_stream->pslot = pslot;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "auto pull, stream %V not in current process, "
                "pslot:%i ngx_process_slot:%i",
                &s->stream, pslot, ngx_process_slot);
    }

    if (pslot == ngx_process_slot) {
        goto next;
    }

    if (ngx_rtmp_auto_pull_target(s, &target, pslot, 1) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ctx = ngx_relay_pull(s, &s->name, &target);
    if (ctx == NULL) {
        s->live_stream->pslot = -1;
    }

    return NGX_AGAIN;

next:
    return next_pull(s);
}


static ngx_int_t
ngx_rtmp_auto_pull_close_stream(ngx_rtmp_session_t *s,
        ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->tag != &ngx_rtmp_auto_pull_module || s->publishing) {
        goto next;
    }

    if (ctx == s->live_stream->auto_pull_ctx) {
        s->live_stream->auto_pull_ctx = NULL;
    }

    if (!ctx->relay_completion) {
        --s->live_stream->push_count;
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_auto_pull_postconfiguration(ngx_conf_t *cf)
{
    /* chain handlers */

    next_push = ngx_rtmp_push;
    ngx_rtmp_push = ngx_rtmp_auto_pull_push;

    next_pull = ngx_rtmp_pull;
    ngx_rtmp_pull = ngx_rtmp_auto_pull_pull;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_auto_pull_close_stream;

    return NGX_OK;
}
