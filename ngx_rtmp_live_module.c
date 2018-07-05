
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_dynamic_conf.h"
#include "ngx_rtmp_dynamic.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_pause_pt                next_pause;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;


static ngx_int_t ngx_rtmp_live_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_live_create_app_dconf(ngx_conf_t *cf);
static char * ngx_rtmp_live_init_app_dconf(ngx_conf_t *cf, void *conf);
static char *ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static void ngx_rtmp_live_start(ngx_rtmp_session_t *s);
static void ngx_rtmp_live_stop(ngx_rtmp_session_t *s);


static ngx_command_t  ngx_rtmp_live_commands[] = {
      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_live_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_live_postconfiguration,        /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


static ngx_command_t  ngx_rtmp_live_dcommands[] = {

    { ngx_string("live"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, live),
      NULL },

    { ngx_string("buffer"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, buflen),
      NULL },

    { ngx_string("sync"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, sync),
      NULL },

    { ngx_string("interleave"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, interleave),
      NULL },

    { ngx_string("wait_key"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, wait_key),
      NULL },

    { ngx_string("wait_video"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, wait_video),
      NULL },

    { ngx_string("publish_notify"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, publish_notify),
      NULL },

    { ngx_string("play_restart"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, play_restart),
      NULL },

    { ngx_string("idle_streams"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, idle_streams),
      NULL },

    { ngx_string("drop_idle_publisher"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_live_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, idle_timeout),
      NULL },

    { ngx_string("drop_frame_threshold"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, drop_frame_threshold),
      NULL },

    { ngx_string("play_send_gop"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_live_app_dconf_t, play_send_gop),
      NULL },

      ngx_null_command
};


static ngx_rtmp_dynamic_module_t  ngx_rtmp_live_module_dctx = {
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* init server configuration */

    ngx_rtmp_live_create_app_dconf,         /* create app configuration */
    ngx_rtmp_live_init_app_dconf            /* init app configuration */
};



ngx_module_t  ngx_rtmp_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_live_module_ctx,              /* module context */
    ngx_rtmp_live_commands,                 /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    (uintptr_t) &ngx_rtmp_live_module_dctx, /* module dynamic context */
    (uintptr_t) ngx_rtmp_live_dcommands,    /* module dynamic directives */
    NGX_MODULE_V1_DYNAMIC_PADDING
};


static void *
ngx_rtmp_live_create_app_dconf(ngx_conf_t *cf)
{
    ngx_rtmp_live_app_dconf_t      *ldcf;

    ldcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_live_app_dconf_t));
    if (ldcf == NULL) {
        return NULL;
    }

    ldcf->live = NGX_CONF_UNSET;
    ldcf->buflen = NGX_CONF_UNSET_MSEC;
    ldcf->sync = NGX_CONF_UNSET_MSEC;
    ldcf->idle_timeout = NGX_CONF_UNSET_MSEC;
    ldcf->interleave = NGX_CONF_UNSET;
    ldcf->wait_key = NGX_CONF_UNSET;
    ldcf->wait_video = NGX_CONF_UNSET;
    ldcf->publish_notify = NGX_CONF_UNSET;
    ldcf->play_restart = NGX_CONF_UNSET;
    ldcf->idle_streams = NGX_CONF_UNSET;
    ldcf->drop_frame_threshold = NGX_CONF_UNSET;
    ldcf->play_send_gop = NGX_CONF_UNSET;

    return ldcf;
}


static char *
ngx_rtmp_live_init_app_dconf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_live_app_dconf_t *ldcf = conf;

    ngx_conf_init_value(ldcf->live, 0);
    ngx_conf_init_msec_value(ldcf->buflen, 0);
    ngx_conf_init_msec_value(ldcf->sync, 300);
    ngx_conf_init_msec_value(ldcf->idle_timeout, 0);
    ngx_conf_init_value(ldcf->interleave, 0);
    ngx_conf_init_value(ldcf->wait_key, 1);
    ngx_conf_init_value(ldcf->wait_video, 0);
    ngx_conf_init_value(ldcf->publish_notify, 0);
    ngx_conf_init_value(ldcf->play_restart, 0);
    ngx_conf_init_value(ldcf->idle_streams, 1);
    ngx_conf_init_value(ldcf->drop_frame_threshold, 0);
    ngx_conf_init_value(ldcf->play_send_gop, 0);

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_live_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *p = conf;
    ngx_str_t                  *value;
    ngx_msec_t                 *msp;

    msp = (ngx_msec_t *) (p + cmd->offset);

    value = cf->args->elts;

    if (value[1].len == sizeof("off") - 1 &&
        ngx_strncasecmp(value[1].data, (u_char *) "off", value[1].len) == 0)
    {
        *msp = 0;
        return NGX_CONF_OK;
    }

    return ngx_conf_set_msec_slot(cf, cmd, conf);
}


static void
ngx_rtmp_live_idle(ngx_event_t *pev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;

    c = pev->data;
    s = c->data;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                  "live: drop idle publisher");

    ngx_rtmp_finalize_session(s);
}


static void
ngx_rtmp_live_set_status(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *control,
                         ngx_rtmp_frame_t **status, size_t nstatus,
                         unsigned active)
{
    ngx_rtmp_live_ctx_t        *ctx, *pctx;
    ngx_rtmp_frame_t          **frame;
    ngx_event_t                *e;
    size_t                      n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: set active=%ui", active);

    if (ctx->active == active) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: unchanged active=%ui", active);
        return;
    }

    ctx->active = active;

    if (ctx->publishing) {

        /* publisher */

        if (ctx->idle_timeout) {
            e = &ctx->idle_evt;

            if (active && !ctx->idle_evt.timer_set) {
                e->data = s->connection;
                e->log = s->connection->log;
                e->handler = ngx_rtmp_live_idle;

                ngx_add_timer(e, ctx->idle_timeout);

            } else if (!active && ctx->idle_evt.timer_set) {
                ngx_del_timer(e);
            }
        }

        ctx->stream->active = active;

        for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
            if (pctx->publishing == 0) {
                ngx_rtmp_live_set_status(pctx->session, control, status,
                                         nstatus, active);
            }
        }

        return;
    }

    /* subscriber */

    if (control && ngx_rtmp_send_message(s, control, 0) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (!ctx->silent) {
        frame = status;

        for (n = 0; n < nstatus; ++n, ++frame) {
            if (*frame && ngx_rtmp_send_message(s, *frame, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
                return;
            }
        }
    }

    ctx->cs[0].active = 0;
    ctx->cs[0].dropped = 0;

    ctx->cs[1].active = 0;
    ctx->cs[1].dropped = 0;
}


static void
ngx_rtmp_live_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_app_dconf_t  *ldcf;
    ngx_rtmp_frame_t           *control;
    ngx_rtmp_frame_t           *status[3];
    size_t                      n, nstatus;

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_begin(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (ldcf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Start",
                                                   "status", "Start live");
        status[nstatus++] = ngx_rtmp_create_sample_access(s);
    }

    if (ldcf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                                 "NetStream.Play.PublishNotify",
                                                 "status", "Start publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 1);

    if (control) {
        ngx_rtmp_shared_free_frame(control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_shared_free_frame(status[n]);
    }
}


static void
ngx_rtmp_live_stop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_live_app_dconf_t  *ldcf;
    ngx_rtmp_frame_t           *control;
    ngx_rtmp_frame_t           *status[3];
    size_t                      n, nstatus;

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);

    control = ngx_rtmp_create_stream_eof(s, NGX_RTMP_MSID);

    nstatus = 0;

    if (ldcf->play_restart) {
        status[nstatus++] = ngx_rtmp_create_status(s, "NetStream.Play.Stop",
                                                   "status", "Stop live");
    }

    if (ldcf->publish_notify) {
        status[nstatus++] = ngx_rtmp_create_status(s,
                                               "NetStream.Play.UnpublishNotify",
                                               "status", "Stop publishing");
    }

    ngx_rtmp_live_set_status(s, control, status, nstatus, 0);

    if (control) {
        ngx_rtmp_shared_free_frame(control);
    }

    for (n = 0; n < nstatus; ++n) {
        ngx_rtmp_shared_free_frame(status[n]);
    }
}


static ngx_int_t
ngx_rtmp_live_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL || ctx->stream == NULL || !ctx->publishing) {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_begin");

    ngx_rtmp_live_start(s);

next:
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_live_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_live_ctx_t    *ctx;
    ngx_rtmp_core_ctx_t    *core_ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    core_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_core_module);

    if (ctx == NULL ||
        ctx->stream == NULL ||
        !ctx->publishing ||
        core_ctx == NULL ||
        core_ctx != ctx->stream->publish_ctx ||
        core_ctx->next != NULL)
    {
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: stream_eof");

    ngx_rtmp_live_stop(s);

next:
    return next_stream_eof(s, v);
}


static void
ngx_rtmp_live_join(ngx_rtmp_session_t *s, u_char *name, unsigned publisher)
{
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_live_stream_t             **stream;
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_int_t                       rc;

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    if (ldcf == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx && ctx->stream) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: already joined");
        return;
    }

    if (publisher) {
        rc = ngx_rtmp_push_filter(s);
    } else {
        rc = ngx_rtmp_pull_filter(s);
    }

    if (rc == NGX_ERROR) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (ctx == NULL) {
        ctx = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_live_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_live_module);

        ctx->idle_timeout = ldcf->idle_timeout;
        ctx->interleave = ldcf->interleave;
    }

    ngx_memzero(ctx, sizeof(*ctx));

    ctx->session = s;

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: join '%s'", name);

    stream = &(s->live_stream);

    if (stream == NULL ||
        !(publisher || (*stream)->publishing ||
            ldcf->idle_streams || rc == NGX_AGAIN))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "live: stream not found");

        s->status = 404;
        ngx_rtmp_send_status(s, "NetStream.Play.StreamNotFound", "error",
                             "No such stream");

        ngx_rtmp_finalize_session(s);

        return;
    }

    if (publisher) {
        if ((*stream)->publishing && s->priority == 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "live: already publishing");

            ngx_rtmp_send_status(s, "NetStream.Publish.BadName", "error",
                                 "Already publishing");

            return;
        }

        (*stream)->publishing = 1;
    }

    ctx->stream = *stream;
    ctx->publishing = publisher;
    ctx->next = (*stream)->ctx;

    (*stream)->ctx = ctx;

    if (ldcf->buflen) {
        s->out_buffer = 1;
    }

    ctx->cs[0].csid = NGX_RTMP_CSID_VIDEO;
    ctx->cs[1].csid = NGX_RTMP_CSID_AUDIO;

    if (!ctx->publishing && ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }
}


static ngx_int_t
ngx_rtmp_live_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_live_ctx_t            *ctx, **cctx, *pctx;
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_rtmp_core_ctx_t            *core_ctx;

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    if (ldcf == NULL) {
        goto next;
    }

    core_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_core_module);
    if (core_ctx == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->stream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: not joined");
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: leave '%s'", ctx->stream->name);

    if (ctx->stream->publishing &&
        ctx->publishing &&
        core_ctx == ctx->stream->publish_ctx &&
        core_ctx->next == NULL)
    {
        ctx->stream->publishing = 0;
    }

    for (cctx = &ctx->stream->ctx; *cctx; cctx = &(*cctx)->next) {
        if (*cctx == ctx) {
            *cctx = ctx->next;
            break;
        }
    }

    if ((ctx->publishing || ctx->stream->active) &&
        (core_ctx == ctx->stream->publish_ctx && core_ctx->next == NULL))
    {
        ngx_rtmp_live_stop(s);
    }

    if (ctx->publishing &&
        core_ctx == ctx->stream->publish_ctx &&
        core_ctx->next == NULL)
    {
        ngx_rtmp_send_status(s, "NetStream.Unpublish.Success",
                             "status", "Stop publishing");
        if (!ldcf->idle_streams) {
            for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
                if (pctx->publishing == 0) {
                    ss = pctx->session;
					if(ss->static_pull_fake) {
						continue;
					}
                    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                                   "live: no publisher");
                    ngx_rtmp_finalize_session(ss);
                }
            }
        }
    }

    if (ctx->stream->ctx) {
        ctx->stream = NULL;
        goto next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: delete empty stream '%s'",
                   ctx->stream->name);

    ctx->stream = NULL;

    if (!ctx->silent && !ctx->publishing && !ldcf->play_restart) {
        ngx_rtmp_send_status(s, "NetStream.Play.Stop", "status", "Stop live");
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_live_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    ngx_rtmp_live_ctx_t            *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL || ctx->stream == NULL) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: pause=%i timestamp=%f",
                   (ngx_int_t) v->pause, v->position);

    if (v->pause) {
        if (ngx_rtmp_send_status(s, "NetStream.Pause.Notify", "status",
                                 "Paused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 1;

        ngx_rtmp_live_stop(s);

    } else {
        if (ngx_rtmp_send_status(s, "NetStream.Unpause.Notify", "status",
                                 "Unpaused live")
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->paused = 0;

        ngx_rtmp_live_start(s);
    }

next:
    return next_pause(s, v);
}


static ngx_int_t
ngx_rtmp_live_frame_filter(ngx_int_t av_type,ngx_rtmp_session_t *s)
{
    if (av_type == NGX_RTMP_MSG_VIDEO
        && s->filter == NGX_RTMP_FILTER_KEEPAUDIO)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                 ngx_chain_t *in)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_core_ctx_t            *core_ctx;
    ngx_rtmp_frame_t               *header, *coheader, *meta, *avframe, *dummy;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch, lh, clh;
    ngx_int_t                       rc, mandatory, dummy_audio;
    ngx_uint_t                      prio;
    ngx_uint_t                      peers;
    ngx_uint_t                      meta_version;
    ngx_uint_t                      csidx;
    uint32_t                        delta;
    ngx_rtmp_live_chunk_stream_t   *cs;
    const char                     *type_s;

    type_s = (h->type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    if (ldcf == NULL) {
        return NGX_ERROR;
    }

    if (!ldcf->live || in == NULL  || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (h->type == NGX_RTMP_MSG_VIDEO) {
        ngx_rtmp_update_frames(&s->framestat, 1);
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: %s from non-publisher", type_s);
        return NGX_OK;
    }

    if (!ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

    if (ctx->idle_evt.timer_set) {
        ngx_add_timer(&ctx->idle_evt, ctx->idle_timeout);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: %s packet timestamp=%uD",
                   type_s, h->timestamp);

    s->current_time = h->timestamp;

    peers = 0;
    header = NULL;
    coheader = NULL;
    meta = NULL;
    dummy = NULL;
    meta_version = 0;
    mandatory = 0;

    prio = (h->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    csidx = !(ctx->interleave || h->type == NGX_RTMP_MSG_VIDEO);

    cs  = &ctx->cs[csidx];

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = cs->csid;
    ch.type = h->type;
    ch.qqhdrtype = h->qqhdrtype;
    switch (h->qqhdrtype) {
    case NGX_RTMP_HEADER_TYPE_QQ_FLV:
        ch.qqflvhdr = h->qqflvhdr;
        break;
        
    case NGX_RTMP_HEADER_TYPE_QQ_HLS:
        break;
    }

    /* fix timestamp */
    ch.timestamp = ngx_rtmp_timestamp_fix(s, ch.timestamp, 1);

    lh = ch;

    if (cs->active) {
        lh.timestamp = cs->timestamp;
    }

    clh = lh;
    clh.type = (h->type == NGX_RTMP_MSG_AUDIO ? NGX_RTMP_MSG_VIDEO :
                                                NGX_RTMP_MSG_AUDIO);

    cs->active = 1;
    cs->timestamp = ch.timestamp;

    delta = ch.timestamp - lh.timestamp;
/*
    if (delta >> 31) {
        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: clipping non-monotonical timestamp %uD->%uD",
                       lh.timestamp, ch.timestamp);

        delta = 0;

        ch.timestamp = lh.timestamp;
    }
*/
    avframe = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, in, 0);
    ch.mlen = h->mlen;
    avframe->hdr = ch;

    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    if (codec_ctx) {

        if (h->type == NGX_RTMP_MSG_AUDIO) {
            header = codec_ctx->aac_header;

            if (ctx->interleave) {
                coheader = codec_ctx->avc_header;
            }

            if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
                ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "live: Recv AAC header");
            }

        } else {
            header = codec_ctx->avc_header;

            if (ctx->interleave) {
                coheader = codec_ctx->aac_header;
            }

            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
                ngx_rtmp_is_codec_header(in))
            {
                prio = 0;
                mandatory = 1;
                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                              "live: Recv H264 header");
            }
        }

        if (codec_ctx->meta) {
            meta = codec_ctx->meta;
            meta_version = codec_ctx->meta_version;
        }
    }

    if (ngx_rtmp_gop_cache(s, avframe) == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* for low priority stream*/
    core_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_core_module);
    if (core_ctx && core_ctx != s->live_stream->publish_ctx) {
        goto broadcast_done;
    }

    /* broadcast to all subscribers */

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused || pctx->publishing) {
            continue;
        }
        
        ss = pctx->session;
        cs = &pctx->cs[csidx];

        if (ss->quick_play.posted) {
            ngx_delete_posted_event(&ss->quick_play);
        }

        ss->publish_epoch = s->epoch;
        if (ss->filter == 0) {
            ss->filter = s->filter;
        }

        /* send gop cache is set */
        switch (ngx_rtmp_gop_send(s, ss)) {
        case NGX_DECLINED:
            break;
        case NGX_ERROR:
            ngx_rtmp_finalize_session(ss);
            continue;
        default:
            continue;
        }

        /* send metadata */

        if (meta && meta_version != pctx->meta_version) {
            ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                          "live: send metadata");

            ngx_rtmp_codec_construct_sub_meta(s, ss);

            if (ngx_rtmp_send_message(ss, ss->sub_meta, 0) == NGX_OK) {
                pctx->meta_version = meta_version;
            }

            if (ss->meta_epoch == 0) {
                ss->meta_epoch = ngx_current_msec;
            }
        }

        /* sync stream */

        if (cs->active && (ldcf->sync && cs->dropped > ldcf->sync)) {
            ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                           "live: sync %s dropped=%uD", type_s, cs->dropped);

            cs->active = 0;
            cs->dropped = 0;
        }

        /* absolute packet */

        if (!cs->active) {

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skipping header");
                continue;
            }

            if (ldcf->wait_video && h->type == NGX_RTMP_MSG_AUDIO &&
                !pctx->cs[0].active)
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: waiting for video");
                continue;
            }

            if (ldcf->wait_key && prio != NGX_RTMP_VIDEO_KEY_FRAME &&
               (ctx->interleave || h->type == NGX_RTMP_MSG_VIDEO))
            {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: skip non-key");
                continue;
            }

            dummy_audio = 0;
            if (ldcf->wait_video && h->type == NGX_RTMP_MSG_VIDEO &&
                !pctx->cs[1].active)
            {
                dummy_audio = 1;
                if (dummy == NULL) {
                    dummy = ngx_rtmp_shared_alloc_frame(cscf->chunk_size,
                                                        NULL, 1);
                    dummy->hdr = clh;
                }
            }

            if (ngx_rtmp_live_frame_filter(h->type, ss) != NGX_OK) {
                continue;
            }

            if (header || coheader) {

                /* send absolute codec header */

                ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: abs %s header timestamp=%uD",
                               type_s, lh.timestamp);

                if (header) {
                    header->hdr = lh;
                    rc = ngx_rtmp_send_message(ss, header, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }

                    ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                                  "live: send %s header,timestamp:%uD",
                                  type_s, lh.timestamp);
                }

                if (coheader) {
                    coheader->hdr = clh;
                    rc = ngx_rtmp_send_message(ss, coheader, 0);
                    if (rc != NGX_OK) {
                        continue;
                    }

                } else if (dummy_audio) {
                    ngx_rtmp_send_message(ss, dummy, 0);
                }

                cs->timestamp = lh.timestamp;
                cs->active = 1;
                ss->current_time = cs->timestamp;

            }
        }

        /* send av packet */

        ss->droprate.packets++;

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                       "live: rel %s packet delta=%uD",
                       type_s, delta);

        if (ngx_rtmp_send_message(ss, avframe, prio) != NGX_OK) {
            ++pctx->ndropped;
            ++ss->droprate.droppackets;

            cs->dropped += delta;

            if (mandatory) {
                ngx_log_debug0(NGX_LOG_DEBUG_RTMP, ss->connection->log, 0,
                               "live: mandatory packet failed");
                ngx_rtmp_finalize_session(ss);
            }

            continue;
        }

        cs->timestamp += delta;
        ++peers;
        ss->current_time = cs->timestamp;

        ngx_rtmp_update_droprate(&ss->droprate);

    }

broadcast_done:

    if (avframe) {
        ngx_rtmp_shared_free_frame(avframe);
    }

    if (dummy) {
        ngx_rtmp_shared_free_frame(dummy);
    }

    ngx_rtmp_update_bandwidth(&ctx->stream->bw_in, h->mlen);
    ngx_rtmp_update_bandwidth(&ctx->stream->bw_out, h->mlen * peers);

    ngx_rtmp_update_bandwidth(h->type == NGX_RTMP_MSG_AUDIO ?
                              &ctx->stream->bw_in_audio :
                              &ctx->stream->bw_in_video,
                              h->mlen);
    ngx_rtmp_update_bandwidth(h->type == NGX_RTMP_MSG_AUDIO ?
                              &s->bw_audio : &s->bw_video, h->mlen);

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_live_amf_data_send(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in, u_char *func)
{
    ngx_rtmp_live_ctx_t            *ctx, *pctx;
    ngx_rtmp_core_ctx_t            *core_ctx;
    ngx_rtmp_frame_t               *avframe;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_header_t               ch;
    ngx_uint_t                      peers;
    ngx_uint_t                      m;
    ngx_str_t                      *var;
    size_t                          len;

    if (h->type != NGX_RTMP_MSG_AMF_META) {
        return NGX_OK;
    }

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    len = ngx_strlen(func);
    if (cmcf->custom_message_flag == NGX_RTMP_CUSTOM_MESSAGE_NONE) {
        return NGX_OK;
    } else if (cmcf->custom_message_flag == NGX_RTMP_CUSTOM_MESSAGE_PART) {
        var = cmcf->message_name.elts;
        for (m = 0; m < cmcf->message_name.nelts; m++, var++) {
            if (len == var->len
                && ngx_strncasecmp(func, var->data, var->len) == 0)
            {
                break;
            }
            return NGX_OK;
        }
    }

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    if (ldcf == NULL) {
        return NGX_ERROR;
    }

    if (!ldcf->live || in == NULL  || in->buf == NULL) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || ctx->stream == NULL) {
        return NGX_OK;
    }

    if (ctx->publishing == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "live: h->type=%ui from non-publisher",
                       (ngx_uint_t)h->type);
        return NGX_OK;
    }

    if (!ctx->stream->active) {
        ngx_rtmp_live_start(s);
    }

    if (ctx->idle_evt.timer_set) {
        ngx_add_timer(&ctx->idle_evt, ctx->idle_timeout);
    }

    s->current_time = h->timestamp;

    peers = 0;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_memzero(&ch, sizeof(ch));

    ch.timestamp = h->timestamp;
    ch.msid = NGX_RTMP_MSID;
    ch.csid = NGX_RTMP_CSID_AMF;
    ch.type = h->type;
    ch.qqhdrtype = h->qqhdrtype;
    switch (h->qqhdrtype) {
    case NGX_RTMP_HEADER_TYPE_QQ_FLV:
        ch.qqflvhdr = h->qqflvhdr;
        break;
        
    case NGX_RTMP_HEADER_TYPE_QQ_HLS:
        break;
    }

    avframe = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, in, 0);
    ch.mlen = h->mlen;
    avframe->hdr = ch;

    /* for low priority stream*/
    core_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_core_module);
    if (core_ctx && core_ctx != s->live_stream->publish_ctx) {
        goto broadcast_done;
    }

    /* broadcast to all subscribers */

    for (pctx = ctx->stream->ctx; pctx; pctx = pctx->next) {
        if (pctx == ctx || pctx->paused) {
            continue;
        }
        ss = pctx->session;

        ss->publish_epoch = s->epoch;

        if (ss->quick_play.posted) {
            ngx_delete_posted_event(&ss->quick_play);
        }

        /* send amf packet */

        if (ngx_rtmp_send_message(ss, avframe, 0) != NGX_OK) {
            continue;
        }

        ++peers;
        ss->current_time = ch.timestamp;
    }

broadcast_done:

    if (avframe) {
        ngx_rtmp_shared_free_frame(avframe);
    }
    ngx_rtmp_update_bandwidth(&ctx->stream->bw_in, h->mlen);
    ngx_rtmp_update_bandwidth(&ctx->stream->bw_out, h->mlen * peers);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_live_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_rtmp_live_ctx_t            *ctx;

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);

    if (ldcf == NULL || !ldcf->live) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: publish: name='%s' type='%s'",
                   v->name, v->type);

    /* join stream as publisher */

    ngx_rtmp_live_join(s, v->name, 1);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL || !ctx->publishing) {
        goto next;
    }

    ctx->silent = v->silent;

    if (!ctx->silent) {
        ngx_rtmp_send_status(s, "NetStream.Publish.Start",
                             "status", "Start publishing");
    }

next:
    return next_publish(s, v);
}

static void
ngx_rtmp_live_play_send_gop(ngx_event_t *ev)
{
    ngx_rtmp_session_t         *s, *ps;

    s = ev->data;

    ps = s->live_stream->publish_ctx->session;
    if (s->filter == 0) {
        s->filter = ps->filter;
    }
    ngx_rtmp_gop_send(ps, s);
}

static ngx_int_t
ngx_rtmp_live_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_live_app_dconf_t      *ldcf;
    ngx_rtmp_live_ctx_t            *ctx;
    ngx_rtmp_core_srv_conf_t       *rcsf;
    ngx_rtmp_session_t             *ps;
    ngx_event_t                    *e;

    rcsf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);

    if (rcsf == NULL || ldcf == NULL || !ldcf->live) {
        goto next;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "live: play: name='%s' start=%uD duration=%uD reset=%d",
                   v->name, (uint32_t) v->start,
                   (uint32_t) v->duration, (uint32_t) v->reset);

    /* join stream as subscriber */
    ngx_rtmp_live_join(s, v->name, 0);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (ctx == NULL) {
        goto next;
    }

    ctx->silent = v->silent;

    if (!ctx->silent && !ldcf->play_restart) {
        ngx_rtmp_send_status(s, "NetStream.Play.Start",
                             "status", "Start live");
        ngx_rtmp_send_sample_access(s);
    }

    if (ldcf->play_send_gop) {
        if (s->live_stream->publish_ctx &&
            s->live_stream->publish_ctx->session)
        {
            e = &s->quick_play;
            e->data = s;
            e->handler = ngx_rtmp_live_play_send_gop;
            e->log = s->connection->log;

            ngx_post_event(e, &ngx_posted_events);

        }
    }

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_live_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* register raw event handlers */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_live_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_live_av;

    /* chain handlers */

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_live_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_live_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_live_close_stream;

    next_pause = ngx_rtmp_pause;
    ngx_rtmp_pause = ngx_rtmp_live_pause;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_live_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_live_stream_eof;

    return NGX_OK;
}
