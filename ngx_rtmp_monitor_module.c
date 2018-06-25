/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_rtmp_monitor_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_variables.h"


static ngx_rtmp_close_stream_pt         next_close_stream;


static ngx_int_t ngx_rtmp_monitor_preconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_monitor_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_monitor_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_monitor_postconfiguration(ngx_conf_t *cf);

static char *ngx_rtmp_monitor_dump(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_monitor_buffered_log(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_monitor_vars_min_fps(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_monitor_vars_buf_frams(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);


#define NGX_RTMP_MONITOR_BUFFER_SIZE    61


typedef struct {
    ngx_str_t                   dump_path;
    ngx_flag_t                  monitor;
    ngx_log_t                  *buffered_log;
} ngx_rtmp_monitor_app_conf_t;


typedef struct {
    ngx_event_t                 consume;
    ngx_msec_t                  buffered;
    ngx_uint_t                  nbuffered;

    double                      frame_rate;
    double                      nframes;

    double                      buffers[NGX_RTMP_MONITOR_BUFFER_SIZE];
    ngx_int_t                   fps[NGX_RTMP_MONITOR_BUFFER_SIZE];

    ngx_flag_t                  dump;

    unsigned                    publishing:1;
} ngx_rtmp_monitor_ctx_t;


static ngx_rtmp_variable_t  ngx_rtmp_monitor_variables[] = {

    { ngx_string("min_fps"), NULL,
        ngx_rtmp_monitor_vars_min_fps, 0, 0, 0 },

    { ngx_string("buf_frams"), NULL,
        ngx_rtmp_monitor_vars_buf_frams, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t  ngx_rtmp_monitor_commands[] = {

    { ngx_string("dump"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_monitor_dump,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("buffered_log"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_monitor_buffered_log,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_monitor_module_ctx = {
    ngx_rtmp_monitor_preconfiguration,      /* preconfiguration */
    ngx_rtmp_monitor_postconfiguration,     /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_monitor_create_app_conf,       /* create app configuration */
    ngx_rtmp_monitor_merge_app_conf         /* merge app configuration */
};


ngx_module_t  ngx_rtmp_monitor_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_monitor_module_ctx,           /* module context */
    ngx_rtmp_monitor_commands,              /* module directives */
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


static ngx_int_t
ngx_rtmp_monitor_vars_min_fps(ngx_rtmp_session_t *s,
        ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_monitor_ctx_t         *ctx;
    ngx_uint_t                      i;
    u_char                         *p, *q;

    p = ngx_pnalloc(s->connection->pool,
        (NGX_INT_T_LEN + sizeof(",")) * (NGX_RTMP_MONITOR_BUFFER_SIZE - 1));
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_monitor_module);

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    q = p;

    for (i = NGX_RTMP_MONITOR_BUFFER_SIZE - 1; i > 0; i--) {
        p = ngx_sprintf(p, "%i,", ctx->fps[i]);
    }

    v->len = p - q;
    v->data = q;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_monitor_vars_buf_frams(ngx_rtmp_session_t *s,
        ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_monitor_ctx_t         *ctx;
    ngx_uint_t                      i;
    u_char                         *p, *q;

    p = ngx_pnalloc(s->connection->pool,
        (NGX_INT64_LEN + sizeof(",")) * (NGX_RTMP_MONITOR_BUFFER_SIZE - 1));
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_monitor_module);

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    q = p;

    for (i = NGX_RTMP_MONITOR_BUFFER_SIZE - 1; i > 0; i--) {
        p = ngx_sprintf(p, "%f,", ctx->buffers[i]);
    }

    v->len = p - q;
    v->data = q;

    return NGX_OK;
}


static void
ngx_rtmp_monitor_dump_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
}

static void
ngx_rtmp_monitor_consume(ngx_event_t *ev)
{
    ngx_rtmp_session_t             *s, *ps;
    ngx_rtmp_monitor_ctx_t         *ctx;
    ngx_rtmp_codec_ctx_t           *cctx;
    ngx_rtmp_monitor_app_conf_t    *macf;
    u_char                          peer[NGX_SOCKADDR_STRLEN];
    u_char                          local[NGX_SOCKADDR_STRLEN];
    struct sockaddr                 paddr, laddr;
    socklen_t                       plen, llen;
    ngx_int_t                       i;

    s = ev->data;

    macf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_monitor_module);

    if (macf->monitor == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_monitor_module);
    if (ctx == NULL) {
        return;
    }

    if (ctx->publishing) {
        ps = s;
    } else {
        if (s->live_stream->publish_ctx) {
            ps = s->live_stream->publish_ctx->session;
        } else {
            goto next;
        }
    }

    cctx = ngx_rtmp_get_module_ctx(ps, ngx_rtmp_codec_module);
    if (cctx == NULL) {
        goto next;
    }

    if (cctx->frame_rate != 0) {
        ctx->frame_rate = cctx->frame_rate;
    }

next:
    if (ctx->frame_rate == 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "monitor, frame rate error, stream: %V, frame rate: %.2f",
                &s->stream, ctx->frame_rate);
        return;
    }

    ctx->nframes -= ctx->frame_rate;

    if (ctx->nframes <= 0) {
        ctx->nframes = 0;
        if (ctx->buffered == 0) {
            ++ctx->nbuffered;
        }
        ++ctx->buffered;

        ngx_memzero(local, sizeof(local));
        ngx_memzero(peer, sizeof(peer));
        plen = sizeof(paddr);
        llen = sizeof(laddr);

        if (getpeername(s->connection->fd, &paddr, &plen) == -1) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                           "monitor: getpeername() failed");
            return;
        }

        if (getsockname(s->connection->fd, &laddr, &llen) == -1) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "monitor: getsockname() failed");
            return;
        }
        ngx_sock_ntop(&paddr, plen, peer, NGX_SOCKADDR_STRLEN, 1);
        ngx_sock_ntop(&laddr, llen, local, NGX_SOCKADDR_STRLEN, 1);

        ngx_log_error(NGX_LOG_ERR, macf->buffered_log, 0,
                "%p %s, peer: %s, local: %s, "
                "stream: %V, buffered: %ui, time: %uis",
                s, ctx->publishing ? "publisher" : "player", peer, local,
                &s->stream, ctx->nbuffered, ctx->buffered);
    } else {
        ctx->buffered = 0;
    }

    ctx->buffers[0] = ctx->nframes;

    for (i = NGX_RTMP_MONITOR_BUFFER_SIZE - 1; i > 0; i--) {
        ctx->fps[i] = ctx->fps[i - 1];
        ctx->buffers[i] = ctx->buffers[i - 1];
    }

    ctx->fps[0] = 0;
    ctx->buffers[0] = 0;

    ngx_add_timer(&ctx->consume, 1000);
}

static ngx_int_t
ngx_rtmp_monitor_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_monitor_frame(s, h, in, ngx_rtmp_is_codec_header(in), 1);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_monitor_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_monitor_ctx_t     *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_monitor_module);

    if (ctx == NULL) {
        goto next;
    }

    if (ctx->consume.timer_set) {
        ngx_del_timer(&ctx->consume);
    }

next:
    return next_close_stream(s, v);
}

void
ngx_rtmp_monitor_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in, ngx_flag_t is_header, ngx_flag_t publishing)
{
    ngx_rtmp_monitor_app_conf_t    *macf;
    ngx_rtmp_monitor_ctx_t         *ctx;

    if (h->type != NGX_RTMP_MSG_VIDEO) {
        return;
    }

    macf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_monitor_module);

    if (macf->monitor == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_monitor_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_monitor_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_monitor_module);

        ctx->dump = macf->dump_path.len > 0;
        ctx->publishing = publishing;
        ngx_memset(ctx->fps, -1,
            sizeof(ngx_int_t) * NGX_RTMP_MONITOR_BUFFER_SIZE);

        ctx->consume.data = s;
        ctx->consume.log = s->connection->log;
        ctx->consume.handler = ngx_rtmp_monitor_consume;
        ngx_add_timer(&ctx->consume, 1000);
    }

    if (publishing && ctx->dump) {
        ngx_rtmp_monitor_dump_frame(s, h, in);
    }

    if (is_header) {
        return;
    }

    ++ctx->nframes;
    ++ctx->fps[0];

}


static ngx_int_t
ngx_rtmp_monitor_preconfiguration(ngx_conf_t * cf)
{
    ngx_rtmp_variable_t        *cv, *v;

    for (cv = ngx_rtmp_monitor_variables; cv->name.len; cv++) {
        v = ngx_rtmp_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


static void *
ngx_rtmp_monitor_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_monitor_app_conf_t	   *macf;

    macf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_monitor_app_conf_t));
    if (macf == NULL) {
        return NULL;
    }

    macf->monitor = NGX_CONF_UNSET;

    return macf;
}

static char *
ngx_rtmp_monitor_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_monitor_app_conf_t    *prev = parent;
    ngx_rtmp_monitor_app_conf_t    *conf = child;

    if (conf->dump_path.data == NULL) {
        conf->dump_path = prev->dump_path;
    }

    ngx_conf_merge_value(conf->monitor, prev->monitor, 0);

    if (conf->buffered_log == NULL) {
        if (prev->buffered_log) {
            conf->buffered_log = prev->buffered_log;
        } else {
            conf->buffered_log = &cf->cycle->new_log;
        }
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_monitor_dump(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_monitor_app_conf_t    *macf;
    ngx_str_t                      *value;

    macf = conf;

    if (macf->dump_path.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    macf->dump_path = value[1];

    if (macf->dump_path.len > 0 &&
            macf->dump_path.data[macf->dump_path.len - 1] == '/')
    {
        --macf->dump_path.len;
    }

    if (ngx_conf_full_name(cf->cycle, &macf->dump_path, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_monitor_buffered_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_monitor_app_conf_t    *macf;

    macf = conf;

    macf->monitor = 1;

    return ngx_log_set_log(cf, &macf->buffered_log);
}

static ngx_int_t
ngx_rtmp_monitor_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_monitor_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_monitor_av;


    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_monitor_close_stream;

    return NGX_OK;
}
