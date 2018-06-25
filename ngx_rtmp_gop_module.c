/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_dynamic_conf.h"
#include "ngx_rtmp_dynamic.h"


static ngx_rtmp_close_stream_pt         next_close_stream;


static void *ngx_rtmp_gop_create_app_dconf(ngx_conf_t *cf);
static char *ngx_rtmp_gop_init_app_dconf(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_rtmp_gop_postconfiguration(ngx_conf_t *cf);

static char * ngx_rtmp_gop_set_drop_max_times(ngx_conf_t *cf,
        ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_gop_drop_gop(ngx_rtmp_session_t *s);
static void ngx_rtmp_gop_add_drop_times(ngx_rtmp_session_t *s);

#define ngx_rtmp_gop_next(s, pos) ((pos + 1) % s->out_queue)
#define ngx_rtmp_gop_prev(s, pos) (pos == 0 ? s->out_queue - 1 : pos - 1)

#define NGX_RTMP_GOP_DROP_OFF    0
#define NGX_RTMP_GOP_DROP_TIME   1
#define MAX_DROP_GOP             10
#define MAX_FRAME_TIME_INTERVAL  25


/* nginx dynamic conf */
typedef struct {
    ngx_msec_t                  cache_time;
    ngx_flag_t                  low_latency;
    ngx_flag_t                  send_all;

    ngx_msec_t                  drop_gop_time;
    ngx_uint_t                  drop_gop;
    ngx_msec_t                  drop_gop_check_interval;
    ngx_int_t                   drop_gop_max_times;
} ngx_rtmp_gop_app_dconf_t;


typedef struct {
    /* publisher: head of cache
     * player: cache send position of publisher's out
     */
    size_t                      gop_pos;
    /* tail of cache */
    size_t                      gop_last;
    /* 0 for not send, 1 for sending, 2 for sent */
    ngx_flag_t                  send_gop;

    ngx_rtmp_frame_t           *keyframe;

    ngx_rtmp_frame_t           *aac_header;
    ngx_rtmp_frame_t           *avc_header;

    ngx_uint_t                  meta_version;

    uint32_t                    first_timestamp;

    size_t                      drop_head;
    size_t                      drop_tail;
    ngx_msec_t                  drop_list[MAX_DROP_GOP];

    /* keep conf static for session */
    ngx_rtmp_gop_app_dconf_t    static_conf;

    /* only for publisher, must at last of ngx_rtmp_gop_ctx_t */
    ngx_rtmp_frame_t           *cache[];
} ngx_rtmp_gop_ctx_t;


static ngx_conf_enum_t ngx_rtmp_gop_drop_enums[] = {
    { ngx_string("off"),            NGX_RTMP_GOP_DROP_OFF      },
    { ngx_string("time"),           NGX_RTMP_GOP_DROP_TIME     },
    { ngx_null_string,              0                          }
};


static ngx_command_t  ngx_rtmp_gop_commands[] = {
      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_gop_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_gop_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


/* nginx rtmp dynamic */
static ngx_command_t  ngx_rtmp_gop_dcommands[] = {

    { ngx_string("cache_time"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_dconf_t, cache_time),
      NULL },

    { ngx_string("low_latency"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_dconf_t, low_latency),
      NULL },

    { ngx_string("send_all"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_dconf_t, send_all),
      NULL },

    { ngx_string("drop_gop"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_dconf_t, drop_gop),
      ngx_rtmp_gop_drop_enums },

    { ngx_string("drop_gop_time"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_dconf_t, drop_gop_time),
      NULL },

    { ngx_string("finalize_drop_gop_times"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
      ngx_rtmp_gop_set_drop_max_times,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_rtmp_dynamic_module_t  ngx_rtmp_gop_module_dctx = {
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_rtmp_gop_create_app_dconf,          /* create app configuration */
    ngx_rtmp_gop_init_app_dconf             /* merge app configuration */
};


ngx_module_t  ngx_rtmp_gop_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_gop_module_ctx,               /* module context */
    ngx_rtmp_gop_commands,                  /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    (uintptr_t) &ngx_rtmp_gop_module_dctx,  /* module dynamic context */
    (uintptr_t) ngx_rtmp_gop_dcommands,     /* module dynamic directives */
    NGX_MODULE_V1_DYNAMIC_PADDING
};


static void *
ngx_rtmp_gop_create_app_dconf(ngx_conf_t *cf)
{
    ngx_rtmp_gop_app_dconf_t    *gadf;

    gadf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_gop_app_dconf_t));
    if (gadf == NULL) {
        return NULL;
    }

    gadf->cache_time = NGX_CONF_UNSET_MSEC;
    gadf->low_latency = NGX_CONF_UNSET;
    gadf->send_all = NGX_CONF_UNSET;
    gadf->drop_gop_time = NGX_CONF_UNSET_MSEC;
    gadf->drop_gop = NGX_CONF_UNSET_UINT;
    gadf->drop_gop_check_interval = NGX_CONF_UNSET_MSEC;
    gadf->drop_gop_max_times = NGX_CONF_UNSET;

    return gadf;
}

static char *
ngx_rtmp_gop_init_app_dconf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_gop_app_dconf_t    *gadf = conf;

    ngx_conf_init_msec_value(gadf->cache_time, 0);
    ngx_conf_init_value(gadf->low_latency, 0);
    ngx_conf_init_value(gadf->send_all, 0);
    ngx_conf_init_uint_value(gadf->drop_gop, NGX_RTMP_GOP_DROP_OFF);
    ngx_conf_init_msec_value(gadf->drop_gop_time, 20000);
    ngx_conf_init_value(gadf->drop_gop_max_times, 0);
    ngx_conf_init_msec_value(gadf->drop_gop_check_interval, 20000);

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_gop_set_drop_max_times(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                  *value;
    ngx_rtmp_gop_app_dconf_t   *gadf = conf;

    if (gadf->drop_gop_check_interval != NGX_CONF_UNSET_MSEC ||
        gadf->drop_gop_max_times != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;
    gadf->drop_gop_max_times = ngx_atoi(value[1].data, value[1].len);
    if (gadf->drop_gop_max_times == NGX_ERROR ||
        gadf->drop_gop_max_times > MAX_DROP_GOP ||
        gadf->drop_gop_max_times <= 0) {
        return "invalid number";
    }

    gadf->drop_gop_check_interval = ngx_parse_time(&value[2], 0);
    if (gadf->drop_gop_check_interval == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static inline ngx_uint_t
ngx_rtmp_gop_get_diff(size_t gop_pos, size_t gop_last,
        size_t out_queue, ngx_uint_t prio)
{
    if (gop_pos <= gop_last) {
        return gop_last - gop_pos + prio;
    }
    return out_queue - (gop_pos - gop_last) + prio;
}


static ngx_int_t
ngx_rtmp_gop_link_frame(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame)
{
    ngx_uint_t                  nmsg;

    if (frame == NULL) {
        return NGX_OK;
    }

    if (s->filter == NGX_RTMP_FILTER_KEEPAUDIO
        && frame->hdr.type == NGX_RTMP_MSG_VIDEO)
    {
        return NGX_OK;
    }

    nmsg = ngx_rtmp_gop_get_diff(s->out_pos, s->out_last, s->out_queue, 1);
    if (nmsg >= s->out_queue) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "link frame nmsg(%ui) >= out_queue(%O)", nmsg, s->out_queue);
        return NGX_AGAIN;
    }

    s->out[s->out_last] = frame;
    s->out_last = ngx_rtmp_gop_next(s, s->out_last);

    ngx_rtmp_shared_acquire_frame(frame);

    return NGX_OK;
}

static void
ngx_rtmp_gop_set_avframe_tag(ngx_rtmp_frame_t *frame)
{
    ngx_chain_t                *cl;

    if (frame->hdr.type != NGX_RTMP_MSG_AUDIO &&
            frame->hdr.type != NGX_RTMP_MSG_VIDEO)
    {
        return;
    }

    cl = frame->chain;

    frame->av_header = ngx_rtmp_is_codec_header(cl);
    frame->keyframe = (frame->hdr.type == NGX_RTMP_MSG_VIDEO)
            ? (ngx_rtmp_get_video_frame_type(cl) == NGX_RTMP_VIDEO_KEY_FRAME)
            : 0;

    if (frame->av_header) {
        frame->mandatory = 1;
    }
}

static void
ngx_rtmp_gop_reset_avheader(ngx_rtmp_gop_ctx_t *ctx,
        ngx_rtmp_frame_t *frame)
{
    if (frame->hdr.type == NGX_RTMP_MSG_AUDIO) {
        if (ctx->aac_header) {
            ngx_rtmp_shared_free_frame(ctx->aac_header);
        }
        ctx->aac_header = frame;
    } else {
        if (ctx->avc_header) {
            ngx_rtmp_shared_free_frame(ctx->avc_header);
        }
        ctx->avc_header = frame;
    }
}

static void
ngx_rtmp_gop_reset_gop(ngx_rtmp_session_t *s, ngx_rtmp_gop_ctx_t *ctx,
        ngx_rtmp_frame_t *frame)
{
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_frame_t           *f, *next_keyframe;
    size_t                      pos;
    ngx_uint_t                  nmsg;

    /* reset av_header at the front of cache */
    for (pos = ctx->gop_pos; pos != ctx->gop_last;
            pos = ngx_rtmp_gop_next(s, pos))
    {
        if (ctx->cache[pos]->av_header) {
            ngx_rtmp_gop_reset_avheader(ctx, ctx->cache[pos]);
            ctx->gop_pos = ngx_rtmp_gop_next(s, ctx->gop_pos);
            continue;
        }

        break;
    }

    f = ctx->cache[pos];
    if (f == NULL) {
        return;
    }

    gadf = &ctx->static_conf;

    /* only audio in cache */
    if (ctx->keyframe == NULL) {
        if (frame->hdr.timestamp - ctx->cache[ctx->gop_pos]->hdr.timestamp
                > gadf->cache_time)
        {
            ngx_rtmp_shared_free_frame(f);
            ctx->cache[ctx->gop_pos] = NULL;
            ctx->gop_pos = ngx_rtmp_gop_next(s, ctx->gop_pos);
        }

        return;
    }

    /* only video of video + audio */
    next_keyframe = ctx->keyframe->next;

    /* only one gop in cache */
    if (next_keyframe == NULL) {
        return;
    }

    nmsg = ngx_rtmp_gop_get_diff(ctx->gop_pos, ctx->gop_last, s->out_queue, 2);

    if (nmsg >= s->out_queue) {
        goto reset;
    }

    if (frame->hdr.type == NGX_RTMP_MSG_AUDIO) {
        return;
    }

    if (frame->hdr.type == NGX_RTMP_MSG_VIDEO && frame->hdr.timestamp
            - next_keyframe->hdr.timestamp < gadf->cache_time)
    {
        return;
    }

reset:
    for (pos = ctx->gop_pos; ctx->cache[pos] != next_keyframe;
            pos = ngx_rtmp_gop_next(s, pos))
    {
        f = ctx->cache[pos];

        if (f->av_header) {
            ngx_rtmp_gop_reset_avheader(ctx, f);
        } else {
            ngx_rtmp_shared_free_frame(f);
        }

        ctx->cache[pos] = NULL;
    }

    ctx->keyframe = next_keyframe;
    ctx->gop_pos = pos;
}

static void
ngx_rtmp_gop_print_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_ctx_t *ctx)
{
#if (NGX_DEBUG)
    ngx_rtmp_frame_t           *frame;
    u_char                      content[10240], *p;
    size_t                      pos;

    ngx_memzero(content, sizeof(content));

    p = content;
    for (pos = ctx->gop_pos; pos != ctx->gop_last;
            pos = ngx_rtmp_gop_next(s, pos))
    {
        frame = ctx->cache[pos];
        switch (frame->hdr.type) {
        case NGX_RTMP_MSG_AUDIO:
            *p++ = 'A';
            break;
        case NGX_RTMP_MSG_VIDEO:
            *p++ = 'V';
            break;
        default:
            *p++ = 'O';
            break;
        }

        if (frame->keyframe) {
            *p++ = 'I';
        }

        if (frame->av_header) {
            *p++ = 'H';
        }

        *p++ = ' ';
    }

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "[%z %z] [%p %p] %s", ctx->gop_pos, ctx->gop_last, ctx->aac_header,
            ctx->avc_header, content);
#endif
}


static ngx_int_t
ngx_rtmp_gop_reset_full_cache(ngx_rtmp_session_t *s, ngx_rtmp_gop_ctx_t *ctx,
        ngx_rtmp_frame_t *frame)
{
    ngx_rtmp_frame_t           *f, *prv_frame, *next_keyframe = NULL;
    ngx_rtmp_frame_t          **keyframe;
    size_t                      prv_last, pos = 0;
    size_t                      keyframe_pos, release_last, mid_pos, count;
    ngx_uint_t                  nmsg;

    if (ctx->keyframe != NULL) {
        next_keyframe = ctx->keyframe->next;
    } else {
        /* audio only */
        f = ctx->cache[ctx->gop_pos];
        ngx_rtmp_shared_free_frame(f);
        ctx->cache[ctx->gop_pos] = NULL;
        ctx->gop_pos = ngx_rtmp_gop_next(s, ctx->gop_pos);
        return NGX_OK;
    }

    /* reset full cache to next_key_frame */
    if (next_keyframe != NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop_module: rest full gop cache| free gop cache to last keyframe");
        while (next_keyframe != NULL) {
            for (pos = ctx->gop_pos; ctx->cache[pos] != next_keyframe;
                    pos = ngx_rtmp_gop_next(s, pos))
            {
                f = ctx->cache[pos];

                if (f->av_header) {
                    ngx_rtmp_gop_reset_avheader(ctx, f);
                } else {
                    ngx_rtmp_shared_free_frame(f);
                }

                ctx->cache[pos] = NULL;
            }
            ctx->keyframe = next_keyframe;
            ctx->gop_pos = pos;
            next_keyframe = ctx->keyframe->next;
        }
        goto set_prv_last;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop_module: rest full gop cache| free half the cache");
    /* set ctx->pos to keyframe pos */
    for (keyframe_pos = ctx->gop_pos; ctx->cache[keyframe_pos] != ctx->keyframe;
            keyframe_pos = ngx_rtmp_gop_next(s, keyframe_pos)) {
        f = ctx->cache[keyframe_pos];

        if (f->av_header) {
            ngx_rtmp_gop_reset_avheader(ctx, f);
        } else {
            ngx_rtmp_shared_free_frame(f);
        }

        ctx->cache[keyframe_pos] = NULL;
    }
    ctx->gop_pos = keyframe_pos;

    /* release half the cache */
    nmsg = ngx_rtmp_gop_get_diff(ctx->gop_pos, ctx->gop_last, s->out_queue, 0);
    for (count = 0, mid_pos = ctx->gop_pos; count < nmsg/2; count++) {
        mid_pos = ngx_rtmp_gop_next(s, mid_pos);
    }
    for (release_last = ngx_rtmp_gop_prev(s, ctx->gop_last);
            release_last != mid_pos; release_last = ngx_rtmp_gop_prev(s, release_last)) {
        f = ctx->cache[release_last];

        if (f->av_header) {
            ngx_rtmp_gop_reset_avheader(ctx, f);
        } else {
            ngx_rtmp_shared_free_frame(f);
        }

        ctx->cache[release_last] = NULL;
    }
    ctx->gop_last = ngx_rtmp_gop_next(s, release_last);

set_prv_last:
    prv_last = ngx_rtmp_gop_prev(s, ctx->gop_last);
    if (ctx->cache[prv_last] != NULL)
    {
        prv_frame = ctx->cache[prv_last];
        ngx_rtmp_shared_free_frame(prv_frame);
        ctx->cache[prv_last] = frame;
        ngx_rtmp_shared_acquire_frame(frame);
    }

    if (frame->keyframe && !frame->av_header) {
        for (keyframe = &ctx->keyframe; *keyframe;
                keyframe = &((*keyframe)->next));
        *keyframe = frame;
    }
    return NGX_OK;
}


ngx_int_t
ngx_rtmp_gop_cache(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame)
{
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_gop_ctx_t         *ctx;
    ngx_rtmp_frame_t          **keyframe;
    ngx_uint_t                  nmsg;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_gop_ctx_t)
                          + s->out_queue * sizeof(ngx_rtmp_frame_t *));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_module);

        gadf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_gop_module);
        if (gadf == NULL) {
            return NGX_ERROR;
        }

        ctx->static_conf = *gadf;
    }

    gadf = &ctx->static_conf;
    if (gadf->cache_time == 0) {
        return NGX_OK;
    }

    ngx_rtmp_gop_set_avframe_tag(frame);

    nmsg = ngx_rtmp_gop_get_diff(ctx->gop_pos, ctx->gop_last, s->out_queue, 1);

    if (nmsg >= s->out_queue) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "cache frame nmsg(%ui) >= out_queue(%z)", nmsg, s->out_queue);
        if (frame->hdr.type == NGX_RTMP_MSG_VIDEO
            && (frame->keyframe || frame->av_header)) {
            ngx_rtmp_gop_reset_full_cache(s, ctx, frame);
        }
        return NGX_AGAIN;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "cache frame: %ud[%d %d], %ud, %ud",
            frame->hdr.type, frame->keyframe, frame->av_header,
            frame->hdr.timestamp, frame->hdr.mlen);

    /* first video frame is not intra_frame or video header */
    if (ctx->keyframe == NULL && frame->hdr.type == NGX_RTMP_MSG_VIDEO
            && !frame->keyframe && !frame->av_header)
    {
        return NGX_OK;
    }

    /* video intra_frame */
    if (frame->keyframe && !frame->av_header) {
        for (keyframe = &ctx->keyframe; *keyframe;
                keyframe = &((*keyframe)->next));
        *keyframe = frame;
    }

    ctx->cache[ctx->gop_last] = frame;
    ctx->gop_last = ngx_rtmp_gop_next(s, ctx->gop_last);

    ngx_rtmp_shared_acquire_frame(frame);

    ngx_rtmp_gop_reset_gop(s, ctx, frame);

    ngx_rtmp_gop_print_cache(s, ctx);

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_gop_send_meta_and_codec(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ss)
{
    ngx_rtmp_gop_ctx_t         *sctx, *ssctx;
    ngx_rtmp_codec_ctx_t       *cctx;
    ngx_int_t                   rc;

    sctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    ssctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_gop_module);
    cctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    /* meta */
    if (ssctx->meta_version != cctx->meta_version) {
        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                      "gop: link metadata info");
        ngx_rtmp_codec_construct_sub_meta(s, ss);
        if (ngx_rtmp_gop_link_frame(ss, ss->sub_meta) == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        ssctx->meta_version = cctx->meta_version;
    }

    /* aac codec header */
    if (sctx->aac_header && ssctx->aac_header != sctx->aac_header) {
        rc = ngx_rtmp_gop_link_frame(ss, sctx->aac_header);
        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                      "gop: link aac codec header info");
    }
    ssctx->aac_header = sctx->aac_header;

    /* avc codec header */
    if (sctx->avc_header && ssctx->avc_header != sctx->avc_header) {
        rc = ngx_rtmp_gop_link_frame(ss, sctx->avc_header);
        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                      "gop: link avc codec header info");
    }
    ssctx->avc_header = sctx->avc_header;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_gop_send_gop(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ss)
{
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_gop_ctx_t         *sctx, *ssctx;
    ngx_rtmp_frame_t           *frame;
    size_t                      pos;

    sctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    ssctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_gop_module);

    /* already send gop */
    if (ssctx->send_gop == 2) {
        return NGX_OK;
    }

    if (ngx_rtmp_gop_send_meta_and_codec(s, ss) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* link frame in s to ss */
    if (ssctx->send_gop == 0) {
        ssctx->gop_pos = sctx->gop_pos;
        if (sctx->cache[ssctx->gop_pos] == NULL) {
            return NGX_AGAIN;
        }
        ssctx->send_gop = 1;
        ssctx->first_timestamp = sctx->cache[ssctx->gop_pos]->hdr.timestamp;
    } else {
        if (sctx->cache[ssctx->gop_pos] == NULL) {
            ssctx->gop_pos = sctx->gop_pos;
        }
    }

    pos = ssctx->gop_pos;
    frame = sctx->cache[pos];
    gadf = &sctx->static_conf;
    while (frame) {
        if (!gadf->send_all &&
            frame->hdr.timestamp - ssctx->first_timestamp >= gadf->cache_time)
        {
            ssctx->send_gop = 2;
            break;
        }

        if (ngx_rtmp_gop_link_frame(ss, frame) == NGX_AGAIN) {
            break;
        }

        pos = ngx_rtmp_gop_next(s, pos);
        frame = sctx->cache[pos];
    }

    if (frame == NULL) { /* send all frame in cache */
        ssctx->send_gop = 2;
    }

    ssctx->gop_pos = pos;
    ngx_rtmp_send_message(ss, NULL, 0);

    ngx_log_error(NGX_LOG_INFO, ss->connection->log, 0,
                  "gop: send frames for the first time");

    if (ss->meta_epoch == 0) {
        ss->meta_epoch = ngx_current_msec;
    }

    return NGX_AGAIN;
}

ngx_int_t
ngx_rtmp_gop_send(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ss)
{
    ngx_rtmp_gop_app_dconf_t   *gadf, *sgadf;
    ngx_rtmp_gop_ctx_t         *sctx, *ssctx;
    ngx_rtmp_frame_t           *frame;
    size_t                      pos;

    sctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (sctx == NULL) {
        return NGX_DECLINED;
    }

    gadf = &sctx->static_conf;
    if (gadf->cache_time == 0) {
        return NGX_DECLINED;
    }

    sctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (sctx == NULL) { /* publisher doesn't publish av frame */
        return NGX_DECLINED;
    }

    ssctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_gop_module);
    if (ssctx == NULL) {
        ssctx = ngx_pcalloc(ss->connection->pool, sizeof(ngx_rtmp_gop_ctx_t));
        if (ssctx == NULL) {
            return NGX_ERROR;
        }
        ngx_rtmp_set_ctx(ss, ssctx, ngx_rtmp_gop_module);

        sgadf = ngx_rtmp_get_module_app_dconf(ss, &ngx_rtmp_gop_module);
        ssctx->static_conf = *sgadf;
    }

    if (ngx_rtmp_gop_send_gop(s, ss) == NGX_AGAIN) {
        return NGX_OK;
    }

    /* send frame by frame */
    if (ngx_rtmp_gop_send_meta_and_codec(s, ss) == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    pos = ngx_rtmp_gop_prev(s, sctx->gop_last);
    /* new frame is video key frame */
    if (sctx->cache[pos]->keyframe && !sctx->cache[pos]->av_header) {
        if (gadf->low_latency) {
            ssctx->gop_pos = pos;
        }
    } else {
        if (sctx->cache[ssctx->gop_pos] == NULL) {
            ssctx->gop_pos = sctx->gop_pos;
        }
    }

    frame = sctx->cache[ssctx->gop_pos];
    if (ngx_rtmp_gop_link_frame(ss, frame) == NGX_AGAIN) {
        return NGX_AGAIN;
    }
    ssctx->gop_pos = ngx_rtmp_gop_next(s, ssctx->gop_pos);

    ss->droprate.packets++;
    ngx_rtmp_update_droprate(&ss->droprate);

    ngx_rtmp_gop_drop_gop(ss);

    ngx_rtmp_send_message(ss, NULL, 0);

    if (ss->meta_epoch == 0) {
        ss->meta_epoch = ngx_current_msec;
    }

    return NGX_OK;
}

static ngx_flag_t
ngx_rtmp_gop_drop(ngx_rtmp_session_t *s, size_t last)
{
    size_t                      pos;
    size_t                      reserve_head;
    size_t                      reserve_tail;
    ngx_flag_t                  if_drop = 0;
    ngx_uint_t                  append_av_header_num, counter;

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
        "gop: session %p drop gop, s->out_pos=%d, s->out_last=%d, drop_last=%d",
        s, s->out_pos, s->out_last, last);

    pos = ngx_rtmp_gop_next(s, s->out_pos);
    if (s->out_pos == s->out_last || s->out_pos == last ||
        pos == s->out_last || pos == last) {
        return if_drop;
    }

    if_drop = 1;
    reserve_head = s->out_pos;
    reserve_tail = s->out_pos;
    s->out_pos = pos;
    pos = ngx_rtmp_gop_next(s, s->out_pos);
    append_av_header_num = 0;
    counter = 0;

    while (pos != s->out_last && pos != last) {
        if (s->out[s->out_pos]->mandatory == 1 ||
            s->out[s->out_pos]->hdr.type == NGX_RTMP_MSG_AMF_META)
        {
            reserve_tail = ngx_rtmp_gop_next(s, reserve_tail);
            s->out[reserve_tail] = s->out[s->out_pos];
        } else {
            ngx_rtmp_shared_free_frame(s->out[s->out_pos]);
        }

        s->out_pos = ngx_rtmp_gop_next(s, s->out_pos);

        pos = ngx_rtmp_gop_next(s, s->out_pos);
    }

    ngx_rtmp_shared_free_frame(s->out[s->out_pos]);

    append_av_header_num = reserve_tail - reserve_head;
    while (reserve_head != reserve_tail) {
        s->out[s->out_pos] = s->out[reserve_tail];
        s->out[s->out_pos]->hdr.timestamp = s->out[last]->hdr.timestamp
                - MAX_FRAME_TIME_INTERVAL * ++counter;

        reserve_tail = ngx_rtmp_gop_prev(s, reserve_tail);
        s->out_pos = ngx_rtmp_gop_prev(s, s->out_pos);
    }
    s->out[s->out_pos] = s->out[reserve_head];
    s->out[s->out_pos]->hdr.timestamp = s->out[last]->hdr.timestamp
            - (append_av_header_num + 1) * MAX_FRAME_TIME_INTERVAL;

    return if_drop;
}

static ngx_flag_t
ngx_rtmp_gop_drop_to_cache_time(ngx_rtmp_session_t *s)
{
    ngx_rtmp_frame_t           *frame, *next, *last;
    size_t                      pos, next_pos, last_pos;
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_gop_ctx_t         *ctx;
    ngx_flag_t                  if_drop = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    gadf = &ctx->static_conf;

    pos = ngx_rtmp_gop_next(s, s->out_pos);
    if (s->out_pos == s->out_last || pos == s->out_last) {
        return if_drop;
    }
    last_pos = ngx_rtmp_gop_prev(s, s->out_last);
    last = s->out[last_pos];
    next_pos = ngx_rtmp_gop_next(s, pos);

    while (next_pos != s->out_last) {
        next = s->out[next_pos];
        if (last->hdr.timestamp - next->hdr.timestamp <= gadf->cache_time) {
            break;
        }

        frame = s->out[pos];
        if (frame->keyframe && !frame->av_header
            && ngx_rtmp_gop_drop(s, pos))
        {
            if_drop = 1;
        }

        pos = next_pos;
        next_pos = ngx_rtmp_gop_next(s, next_pos);
    }

    if (if_drop) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop: after session %p drop gop to cache_time %d, s->out_pos=%d, "
            "s->out_last=%d, current_timestamp=%d, last_timestamp=%d",
            s, gadf->cache_time, s->out_pos, s->out_last,
            s->out[s->out_pos]->hdr.timestamp, last->hdr.timestamp);
    }

    return if_drop;
}

static void
ngx_rtmp_gop_drop_by_time(ngx_rtmp_session_t *s)
{
    ngx_rtmp_frame_t           *frame, *last;
    size_t                      next_pos, last_pos;
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_gop_ctx_t         *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    gadf = &ctx->static_conf;

    next_pos = ngx_rtmp_gop_next(s, s->out_pos);
    if (s->out_pos == s->out_last || next_pos == s->out_last) {
        return;
    }

    frame = s->out[next_pos];
    last_pos = ngx_rtmp_gop_prev(s, s->out_last);
    last = s->out[last_pos];
    if (last->hdr.timestamp - frame->hdr.timestamp > gadf->drop_gop_time) {
        if (!ngx_rtmp_gop_drop_to_cache_time(s)) {
            return;
        }
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop: session %p drop gop by drop_gop_time %d, s->out_pos = %d, "
            "s->out_last = %d, current_timestamp=%d, last_timestamp=%d",
            s, gadf->drop_gop_time, ngx_rtmp_gop_prev(s, next_pos), s->out_last,
            s->out[s->out_pos]->hdr.timestamp, last->hdr.timestamp);
        ngx_rtmp_gop_add_drop_times(s);

        s->droprate.droppackets++;
        ngx_rtmp_update_droprate(&s->droprate);
    }
}

static ngx_int_t
ngx_rtmp_gop_drop_gop(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_ctx_t         *ctx;
    ngx_rtmp_gop_app_dconf_t   *gadf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    gadf = &ctx->static_conf;
    switch (gadf->drop_gop) {
        case NGX_RTMP_GOP_DROP_TIME:
            ngx_rtmp_gop_drop_by_time(s);
            break;

        default:
            break;
    }

    return NGX_OK;
}

static void
ngx_rtmp_gop_add_drop_times(ngx_rtmp_session_t *s)
{
    ngx_rtmp_gop_app_dconf_t   *gadf;
    ngx_rtmp_gop_ctx_t         *ctx;
    ngx_msec_t                  current_time;
    ngx_int_t                   drop_times;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (ctx == NULL) {
        return;
    }

    gadf = &ctx->static_conf;
    if (!gadf->drop_gop_max_times) {
        return;
    }

#define DROP_NEXT(pos) ((pos + 1) % MAX_DROP_GOP)
#define DROP_TIMES(head, tail) (tail > head ? tail - head:                     \
                                tail + MAX_DROP_GOP - head)

    current_time = ngx_current_msec;
    ctx->drop_list[ctx->drop_tail] = current_time;
    ctx->drop_tail = DROP_NEXT(ctx->drop_tail);

    while (ctx->drop_tail != ctx->drop_head) {
        if (current_time - ctx->drop_list[ctx->drop_head] >
            gadf->drop_gop_check_interval)
        {
            ctx->drop_head = DROP_NEXT(ctx->drop_head);
        } else {
            break;
        }
    }

    drop_times = DROP_TIMES(ctx->drop_head, ctx->drop_tail);

#undef DROP_NEXT
#undef DROP_TIMES

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop: drop gop one more times, now drop_gop_times = %d",
            drop_times);
    if (drop_times >= gadf->drop_gop_max_times) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "gop: already drop gop %d times until %L, "
                "so finalize session %p", drop_times,
                ctx->drop_list[ctx->drop_head], s);
        ngx_rtmp_finalize_session(s);
    }
}


static ngx_int_t
ngx_rtmp_gop_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_gop_ctx_t         *ctx;
    ngx_rtmp_live_ctx_t        *lctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (ctx == NULL) {
        goto next;
    }

    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (!lctx->publishing) {
        goto next;
    }

    if (ctx->avc_header) {
        ngx_rtmp_shared_free_frame(ctx->avc_header);
    }

    if (ctx->aac_header) {
        ngx_rtmp_shared_free_frame(ctx->aac_header);
    }

    /* free cache in publisher */
    while (ctx->gop_pos != ctx->gop_last) {
        ngx_rtmp_shared_free_frame(ctx->cache[ctx->gop_pos]);
        ctx->gop_pos = ngx_rtmp_gop_next(s, ctx->gop_pos);
    }

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_gop_postconfiguration(ngx_conf_t *cf)
{
    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_gop_close_stream;

    return NGX_OK;
}
