/*
 * Copyright (C) Roman Arutyunyan
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_bitop.h"
#include "ngx_rbuf.h"
#include "ngx_rtmp_variables.h"
#include "ngx_rtmp_dynamic.h"

#define NGX_RTMP_CODEC_META_OFF     0
#define NGX_RTMP_CODEC_META_ON      1
#define NGX_RTMP_CODEC_META_COPY    2

#define NGX_RTMP_CODEC_DEFAULE_FPS           29.97
#define NGX_RTMP_CODEC_DEFAULE_VIDEO_BITRATE 2000
#define NGX_RTMP_CODEC_DEFAULE_ADUIO_BITRATE 128

static ngx_int_t ngx_rtmp_codec_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_codec_variables_localport(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_frame_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_video_width(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_video_height(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_video_bitrate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_audio_bitrate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_abnormalfps_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variables_framerate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variable_meta_av_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variable_video_codec(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variable_audio_codec(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variable_resolution(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_rtmp_codec_variable_dropframe_times(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);
static void * ngx_rtmp_codec_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_codec_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char * ngx_rtmp_codec_customize_meta(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_codec_reconstruct_meta(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_codec_copy_meta(ngx_rtmp_session_t *s,
       ngx_rtmp_header_t *h, ngx_chain_t *in);
static ngx_int_t ngx_rtmp_codec_prepare_meta(ngx_rtmp_session_t *s,
       uint32_t timestamp);
static void ngx_rtmp_codec_parse_aac_header(ngx_rtmp_session_t *s,
       ngx_chain_t *in);
static void ngx_rtmp_codec_parse_avc_header(ngx_rtmp_session_t *s,
       ngx_chain_t *in);
static void ngx_rtmp_codec_parse_hevc_header(ngx_rtmp_session_t *s,
       ngx_chain_t *in);
#if (NGX_DEBUG)
static void ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *type,
       ngx_chain_t *in);
#endif


typedef struct {
    ngx_int_t                       index;
    ngx_str_t                       name;
    ngx_flag_t                      cover;
    ngx_flag_t                      var;
    ngx_str_t                       config_str;
} ngx_rtmp_codec_extra_meta_t;


typedef struct {
    ngx_flag_t                      default_fps_bitrate;
    ngx_uint_t                      meta;
    ngx_array_t                    *meta_out;
} ngx_rtmp_codec_app_conf_t;

static ngx_rtmp_variable_t  ngx_rtmp_codec_variables[] = {

    { ngx_string("localport"), NULL,
        ngx_rtmp_codec_variables_localport, 0, 0, 0 },

    { ngx_string("frame_rate"), NULL,
        ngx_rtmp_codec_variables_frame_rate, 0, 0, 0 },

    { ngx_string("video_width"), NULL,
        ngx_rtmp_codec_variables_video_width, 0, 0, 0 },

    { ngx_string("video_height"), NULL,
        ngx_rtmp_codec_variables_video_height, 0, 0, 0 },

    { ngx_string("video_bitrate"), NULL,
        ngx_rtmp_codec_variables_video_bitrate, 0, 0, 0 },

    { ngx_string("audio_bitrate"), NULL,
        ngx_rtmp_codec_variables_audio_bitrate, 0, 0, 0 },

    { ngx_string("abnormal_fpsrate"), NULL,
          ngx_rtmp_codec_variables_abnormalfps_rate, 0, 0, 0 },

    { ngx_string("reference_fps"), NULL,
      ngx_rtmp_codec_variables_framerate, 0, 0, 0 },

    { ngx_string("meta_videobandwidth"), NULL,
      ngx_rtmp_codec_variable_meta_av_rate,
      offsetof(ngx_rtmp_codec_ctx_t, video_data_rate),
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("meta_audiobandwidth"), NULL,
      ngx_rtmp_codec_variable_meta_av_rate,
      offsetof(ngx_rtmp_codec_ctx_t, audio_data_rate),
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("videocodec"), NULL,
      ngx_rtmp_codec_variable_video_codec, 0, 0, 0 },

    { ngx_string("audiocodec"), NULL,
      ngx_rtmp_codec_variable_audio_codec, 0, 0, 0 },

    { ngx_string("resolution"), NULL,
      ngx_rtmp_codec_variable_resolution, 0,
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("dropframe_times"), NULL,
      ngx_rtmp_codec_variable_dropframe_times, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_conf_enum_t ngx_rtmp_codec_meta_slots[] = {
    { ngx_string("off"),            NGX_RTMP_CODEC_META_OFF  },
    { ngx_string("on"),             NGX_RTMP_CODEC_META_ON   },
    { ngx_string("copy"),           NGX_RTMP_CODEC_META_COPY },
    { ngx_null_string,              0 }
};


static ngx_command_t  ngx_rtmp_codec_commands[] = {

    { ngx_string("meta"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_codec_app_conf_t, meta),
      &ngx_rtmp_codec_meta_slots },

    { ngx_string("meta_out"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_codec_customize_meta,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("default_fps_bitrate"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_codec_app_conf_t, default_fps_bitrate),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_codec_module_ctx = {
    ngx_rtmp_codec_preconfiguration,        /* preconfiguration */
    ngx_rtmp_codec_postconfiguration,       /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_codec_create_app_conf,         /* create app configuration */
    ngx_rtmp_codec_merge_app_conf           /* merge app configuration */
};


ngx_module_t  ngx_rtmp_codec_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_codec_module_ctx,             /* module context */
    ngx_rtmp_codec_commands,                /* module directives */
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


static const char *
audio_codecs[] = {
    "",
    "ADPCM",
    "MP3",
    "LinearLE",
    "Nellymoser16",
    "Nellymoser8",
    "Nellymoser",
    "G711A",
    "G711U",
    "",
    "AAC",
    "Speex",
    "",
    "",
    "MP3-8K",
    "DeviceSpecific",
    "Uncompressed"
};


static const char *
video_codecs[] = {
    "",
    "Jpeg",
    "Sorenson-H263",
    "ScreenVideo",
    "On2-VP6",
    "On2-VP6-Alpha",
    "ScreenVideo2",
    "H264",
};


u_char *
ngx_rtmp_get_audio_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(audio_codecs) / sizeof(audio_codecs[0])
        ? audio_codecs[id]
        : "");
}


u_char *
ngx_rtmp_get_video_codec_name(ngx_uint_t id)
{
    return (u_char *)(id < sizeof(video_codecs) / sizeof(video_codecs[0])
        ? video_codecs[id]
        : "");
}


static ngx_uint_t
ngx_rtmp_codec_get_next_version()
{
    ngx_uint_t          v;
    static ngx_uint_t   version;

    do {
        v = ++version;
    } while (v == 0);

    return v;
}

static ngx_int_t
ngx_rtmp_codec_variables_localport(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_buf_t                      *buf;
    ngx_str_t                       localport = ngx_null_string;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx && ctx->localport) {
        buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", ctx->localport);
        localport.data = buf->pos;
        localport.len = buf->last - buf->pos;
    }
    ngx_rtmp_variables_var(&localport, v);
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_frame_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_update_frames(&s->framestat, 0);

    v->len = ngx_sprintf(p, "%.2f", s->framestat.frame_rate) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_video_width(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_buf_t                      *buf;
    ngx_str_t                       video_width = ngx_null_string;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx && ctx->width) {
        buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", ctx->width);
        video_width.data = buf->pos;
        video_width.len = buf->last - buf->pos;
    }
    ngx_rtmp_variables_var(&video_width, v);
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_video_height(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_buf_t                      *buf;
    ngx_str_t                       video_height = ngx_null_string;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx && ctx->height) {
        buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", ctx->height);
        video_height.data = buf->pos;
        video_height.len = buf->last - buf->pos;
    }
    ngx_rtmp_variables_var(&video_height, v);
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_video_bitrate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_buf_t                      *buf;
    ngx_str_t                       rate = ngx_null_string;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx && ctx->video_data_rate) {
        buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", ctx->video_data_rate);
        rate.data = buf->pos;
        rate.len = buf->last - buf->pos;
    }
    ngx_rtmp_variables_var(&rate, v);
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_audio_bitrate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_buf_t                      *buf;
    ngx_str_t                       rate = ngx_null_string;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    if (ctx && ctx->audio_data_rate) {
        buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", ctx->audio_data_rate);
        rate.data = buf->pos;
        rate.len = buf->last - buf->pos;
    }
    ngx_rtmp_variables_var(&rate, v);
    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_abnormalfps_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%0.3f", 0.000) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_codec_variables_framerate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_codec_ctx_t  *codec;
    u_char                *p;
    ngx_rtmp_session_t    *ss;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (codec && codec->frame_rate) {
        v->len = ngx_sprintf(p, "%.2f", codec->frame_rate) - p;
        v->data = p;
        return NGX_OK;
    } else if (!codec && s->live_stream->publish_ctx && !s->publishing) {
        ss = s->live_stream->publish_ctx->session;
        codec = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_codec_module);

        if (codec && codec->frame_rate) {
            v->len = ngx_sprintf(p, "%.2f", codec->frame_rate) - p;
            v->data = p;
            return NGX_OK;
        }
    }

    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_variable_meta_av_rate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                *p;
    ngx_rtmp_codec_ctx_t  *codec;
    ngx_rtmp_live_ctx_t   *ctx;
    ngx_uint_t            *uin;

    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx->publishing && codec) {
        uin =  (ngx_uint_t*)((u_char*)codec + data);
        if (*uin) {
            v->len = ngx_sprintf(p, "%ui", *uin) - p;
            v->data = p;
            return NGX_OK;
        }
    }

    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static char *
ngx_rtmp_codec_get_avc_profile(ngx_uint_t p) {
    switch (p) {
        case 66:
            return "Baseline";
        case 77:
            return "Main";
        case 100:
            return "High";
        default:
            return "";
    }
}


static ngx_int_t
ngx_rtmp_codec_variable_video_codec(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                *p, *q, *cname;
    ngx_rtmp_codec_ctx_t  *codec;
    ngx_rtmp_live_ctx_t   *ctx;

    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (ctx->publishing && codec) {
        cname = ngx_rtmp_get_video_codec_name(codec->video_codec_id);
        if (*cname) {
            // 10 is for avc_profile
            p = ngx_pnalloc(s->connection->pool,
                            NGX_INT_T_LEN * 2 + ngx_strlen(cname)+10);
            if (p == NULL) {
                return NGX_ERROR;
            }
            q = p;
            p = ngx_sprintf(p, "%s", cname);
            if (codec->avc_profile) {
                p = ngx_sprintf(p, "%s", (u_char *)
                        ngx_rtmp_codec_get_avc_profile(codec->avc_profile));
            }
            if (codec->avc_level) {
                p = ngx_sprintf(p, " %ui", codec->avc_compat);
                p = ngx_sprintf(p, " %.1f", codec->avc_level/10.);
            }
            v->len = p - q;
            v->data = q;
            return NGX_OK;
        }
    }
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static char *
ngx_rtmp_codec_get_aac_profile(ngx_uint_t p, ngx_uint_t sbr, ngx_uint_t ps) {
    switch (p) {
        case 1:
            return "Main";
        case 2:
            if (ps) {
                return "HEv2";
            }
            if (sbr) {
                return "HE";
            }
            return "LC";
        case 3:
            return "SSR";
        case 4:
            return "LTP";
        case 5:
            return "SBR";
        default:
            return "";
    }
}


static ngx_int_t
ngx_rtmp_codec_variable_audio_codec(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                *p, *q, *cname;
    ngx_rtmp_codec_ctx_t  *codec;
    ngx_rtmp_live_ctx_t   *ctx;

    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (ctx->publishing && codec) {
        cname = ngx_rtmp_get_audio_codec_name(codec->audio_codec_id);

        if (*cname) {
            // 10 is for aac_profile
            p = ngx_pnalloc(s->connection->pool,
                            NGX_INT_T_LEN * 2 + ngx_strlen(cname) + 10);
            if (p == NULL) {
                return NGX_ERROR;
            }
            q = p;

            p = ngx_sprintf(p, "%s", cname);
            if (codec->aac_profile) {
                p = ngx_sprintf(p, " %s", (u_char *)
                        ngx_rtmp_codec_get_aac_profile(codec->aac_profile,
                             codec->aac_sbr, codec->aac_ps));
            }

            if (codec->aac_chan_conf) {
                p = ngx_sprintf(p, " %ui", codec->aac_chan_conf);
            } else if (codec->audio_channels) {
                p = ngx_sprintf(p, " %ui", codec->audio_channels);
            }

            if (codec->sample_rate) {
                p = ngx_sprintf(p, " %ui", codec->sample_rate);
            }
            v->len = p - q;
            v->data = q;
            return NGX_OK;
        }
    }
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_variable_resolution(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                *p, *q;
    ngx_rtmp_codec_ctx_t  *codec;
    ngx_rtmp_live_ctx_t   *ctx;

    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN * 2 + sizeof("*"));
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ctx->publishing && codec && codec->width && codec->height) {
        q = p;
        p = ngx_sprintf(p, "%ui", codec->width);
        p = ngx_sprintf(p, "*%ui", codec->height);
        v->len = p - q;
        v->data = q;
        return NGX_OK;
    }

    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_variable_dropframe_times(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_live_app_dconf_t   *ladcf;
    ngx_rtmp_codec_ctx_t       *codec;
    float                       threshold;
    ngx_int_t                   dropframe_times, i;
    u_char                     *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ladcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    codec = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (!ladcf || !codec || codec->frame_rate == 0) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    threshold = ladcf->drop_frame_threshold >= 100 ? 99 : ladcf->drop_frame_threshold;
    threshold = threshold / 100;

    dropframe_times = 0;
    for (i = 0; i < NGX_RTMP_FRAMESTAT_MAX_COUNT; i++) {
        if (s->framestat.intl_stat[i] == -1) {
            continue;
        }
        if (s->framestat.intl_stat[i] / (1 - threshold) < codec->frame_rate) {
            dropframe_times++;
        }
    }

    v->len = ngx_sprintf(p, "%i", dropframe_times) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_disconnect(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t               *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    if (ctx->avc_header) {
        ngx_rtmp_shared_free_frame(ctx->avc_header);
        ctx->avc_header = NULL;
    }

    if (ctx->aac_header) {
        ngx_rtmp_shared_free_frame(ctx->aac_header);
        ctx->aac_header = NULL;
    }

    if (ctx->meta) {
        ngx_rtmp_shared_free_frame(ctx->meta);
        ctx->meta = NULL;
    }

    return NGX_OK;
}


static void
ngx_rtmp_codec_set_fps_bitrate(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h)
{
    ngx_rtmp_codec_ctx_t                  *cctx;
    ngx_rtmp_live_ctx_t                   *lctx;
    ngx_rtmp_codec_app_conf_t             *cacf;

    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    cctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);
    if (!cacf || !cctx || !lctx || !lctx->publishing) {
        return;
    }

    /*
     * Counalculating bit rate:
     *
     * bit rate(kb/s) = sent byte * 8 / 1024 / (time(ms) / 1000) = send byte / t * 7.81
     *
     */
    if (cctx->video_data_rate != 0 && cctx->audio_data_rate != 0
        && cctx->frame_rate != 0) {
        cctx->already_set_fps_bitrate = 1;
    }

    if (cacf->default_fps_bitrate == 1) {
        if (cctx->video_data_rate == 0) {
            cctx->video_data_rate = NGX_RTMP_CODEC_DEFAULE_VIDEO_BITRATE;
        }

        if (cctx->audio_data_rate == 0) {
            cctx->audio_data_rate = NGX_RTMP_CODEC_DEFAULE_ADUIO_BITRATE;
        }

        if (cctx->frame_rate == 0) {
            cctx->frame_rate = NGX_RTMP_CODEC_DEFAULE_FPS;
        }
    }

    if (cctx->video_data_rate == 0 &&
        h->type == NGX_RTMP_MSG_VIDEO &&
        (ngx_current_msec - s->epoch) > 1000)
    {
        cctx->video_data_rate = cctx->video_size / (ngx_current_msec - s->epoch) * 7.81 ;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "codec: set_bitrate | video_data_rate = %d", cctx->video_data_rate);
    }

    if (cctx->frame_rate == 0) {
        cctx->frame_rate = NGX_RTMP_CODEC_DEFAULE_FPS;
    }

    if (cctx->audio_data_rate == 0 &&
        h->type == NGX_RTMP_MSG_AUDIO &&
        (ngx_current_msec - s->epoch) > 1000)
    {
        cctx->audio_data_rate = cctx->audio_size / (ngx_current_msec - s->epoch) * 7.81;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "codec: set_bitrate | audio_data_rate = %d", cctx->audio_data_rate);
    }
}


static ngx_int_t
ngx_rtmp_codec_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_codec_ctx_t               *ctx;
    ngx_rtmp_frame_t                  **header;
    uint8_t                             fmt;
    static ngx_uint_t                   sample_rates[] =
                                        { 5512, 11025, 22050, 44100 };

    if (h->type != NGX_RTMP_MSG_AUDIO && h->type != NGX_RTMP_MSG_VIDEO) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_codec_module);
    }

    //set bitrate
    if (ctx->already_set_fps_bitrate == 0) {
        ngx_rtmp_codec_set_fps_bitrate(s, h);
    }

    /* save codec */
    if (in->buf->last - in->buf->pos < 1) {
        return NGX_OK;
    }

    fmt =  in->buf->pos[0];
    if (h->type == NGX_RTMP_MSG_AUDIO) {
        ctx->audio_size += h->mlen;
        ctx->audio_codec_id = (fmt & 0xf0) >> 4;
        ctx->audio_channels = (fmt & 0x01) + 1;
        ctx->sample_size = (fmt & 0x02) ? 2 : 1;

        if (ctx->sample_rate == 0) {
            ctx->sample_rate = sample_rates[(fmt & 0x0c) >> 2];
        }
    } else {
        ctx->video_size += h->mlen;
        ctx->video_codec_id = (fmt & 0x0f);
    }

    /* save AVC/AAC header */
    if (in->buf->last - in->buf->pos < 3) {
        return NGX_OK;
    }

    /* no conf */
    if (!ngx_rtmp_is_codec_header(in)) {
        return NGX_OK;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    header = NULL;

    if (h->type == NGX_RTMP_MSG_AUDIO) {
        if (ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC) {
            header = &ctx->aac_header;
            ngx_rtmp_codec_parse_aac_header(s, in);
        }
    } else {
        if (ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
            header = &ctx->avc_header;
            ngx_rtmp_codec_parse_avc_header(s, in);
        } else if (ctx->video_codec_id == NGX_RTMP_VIDEO_H265) {
            header = &ctx->avc_header;
            ngx_rtmp_codec_parse_hevc_header(s, in);
        }
    }

    if (header == NULL) {
        return NGX_OK;
    }

    if (*header) {
        ngx_rtmp_shared_free_frame(*header);
    }

    *header = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, in, 0);

    return NGX_OK;
}


static void
ngx_rtmp_codec_parse_aac_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_uint_t              idx;
    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;

    static ngx_uint_t      aac_sample_rates[] =
        { 96000, 88200, 64000, 48000,
          44100, 32000, 24000, 22050,
          16000, 12000, 11025,  8000,
           7350,     0,     0,     0 };

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "aac", in);
#endif

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    ngx_rtmp_bit_read(&br, 16);

    ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
    if (ctx->aac_profile == 31) {
        ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
    }

    idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
    if (idx == 15) {
        ctx->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);
    } else {
        ctx->sample_rate = aac_sample_rates[idx];
    }

    ctx->aac_chan_conf = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);

    if (ctx->aac_profile == 5 || ctx->aac_profile == 29) {

        if (ctx->aac_profile == 29) {
            ctx->aac_ps = 1;
        }

        ctx->aac_sbr = 1;

        idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
        if (idx == 15) {
            ctx->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);
        } else {
            ctx->sample_rate = aac_sample_rates[idx];
        }

        ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
        if (ctx->aac_profile == 31) {
            ctx->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
        }
    }

    /* MPEG-4 Audio Specific Config

       5 bits: object type
       if (object type == 31)
         6 bits + 32: object type
       4 bits: frequency index
       if (frequency index == 15)
         24 bits: frequency
       4 bits: channel configuration

       if (object_type == 5)
           4 bits: frequency index
           if (frequency index == 15)
             24 bits: frequency
           5 bits: object type
           if (object type == 31)
             6 bits + 32: object type

       var bits: AOT Specific Config
     */

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: aac header profile=%ui, "
                   "sample_rate=%ui, chan_conf=%ui",
                   ctx->aac_profile, ctx->sample_rate, ctx->aac_chan_conf);
}

#define Extended_SAR 255


static void ngx_get_correct_fps(ngx_rtmp_session_t *s, double *fps, int sps_fps)
{
    if(sps_fps > 0 && sps_fps < 200){
        *fps = sps_fps;
    }else{
        if(*fps > 200){
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                      "codec: ngx_get_correct_fps| "
                      "fps bigger than 200 ,set zero");
            *fps = 0;
        }
        if (*fps == 0) {
            *fps = NGX_RTMP_CODEC_DEFAULE_FPS;
        }
    }
}

static ngx_int_t
ngx_rtmp_codec_get_localport(ngx_rtmp_session_t *s)
{
    struct sockaddr_in       sa;
    socklen_t                len = sizeof(sa);

    ngx_memzero(&sa, sizeof(sa));
    getsockname(s->connection->fd, (struct sockaddr*)&sa, &len);

    return ntohs(sa.sin_port);
}


/*
 * ITU-T H.265 7.3.1 General NAL unit syntax
 */
static ngx_int_t
ngx_rtmp_codec_parse_hevc_nal_to_rbsp(ngx_rtmp_session_t *s, u_char *p,
        ngx_rtmp_bit_reader_t *br, ngx_uint_t nal_unit_type,
        ngx_uint_t nal_unit_len)
{
    ngx_uint_t                  i, count, rbsp_bytes;

    /*
     * nal_unit
     *      nal_unit_header()
     *      NumBytesInRbsp = 0
     *      for (i = 2; i < NumBytesInNalUnit; i++)
     *          if (i + 2 < NumBytesInNalUnit && next_bits(24) == 0x000003) {
     *              rbsp_byte[NumBytesInRbsp++]
     *              rbsp_byte[NumBytesInRbsp++]
     *              i += 2
     *              emulation_prevention_three_byte // equal to 0x03
     *          } else
     *              rbsp_byte[NumBytesInRbsp++]
     *
     * nal_unit_header
     *      forbidden_zero_bit                      1 bit
     *      nal_unit_type                           6 bits
     *      nuh_layer_id                            6 bits
     *      nuh_temporal_id_plus1                   3 bits
     *
     * ITU-T H.265 7.4.2.1
     * emulation_prevention_three_byte is a byte equal to 0x03.
     * When an emulation_prevention_three_byte is present in the NAL unit,
     * it shall be discarded by the decoding process
     *      Within the NAL unit, the following three-byte sequences shall not
     *      occur at any byte-aligned position:
     *          0x000000
     *          0x000001
     *          0x000002
     *      Within the NAL unit, any four-byte sequence that starts with
     *      0x000003 other than the following sequences shall not occur at
     *      any byte-aligned position:
     *          0x00000300
     *          0x00000301
     *          0x00000302
     *          0x00000303
     */

    ngx_rtmp_bit_read(br, 1);
    if (ngx_rtmp_bit_read(br, 6) != nal_unit_type) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "nal_unit_type not expect %ui", nal_unit_type);
        return NGX_ERROR;
    }
    ngx_rtmp_bit_read(br, 6);
    ngx_rtmp_bit_read(br, 3);

    count = 0;
    rbsp_bytes = 0;
    for (i = 0; i < nal_unit_len; ++i) {
        if (count == 2) { /* already 0x0000 */
            if (br->pos[i] < 0x03) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "three bytes sequence error");
                return NGX_ERROR;
            }

            if (br->pos[i] == 0x03 && br->pos[i + 1] > 0x03) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "four bytes sequence error");
                return NGX_ERROR;
            }

            if (br->pos[i] == 0x03) {
                count = 0;
                continue;
            }
        }

        *p++ = br->pos[i];
        ++rbsp_bytes;
        if (br->pos[i] == 0x00) {
            ++count;
        } else {
            count = 0;
        }
    }

    return rbsp_bytes;
}

/*
 * ITU-T H.265 7.3.3 Profile, tier and level syntax
 */
static void
ngx_rtmp_codec_parse_hevc_ptl(ngx_rtmp_session_t *s, ngx_rtmp_bit_reader_t *br,
        ngx_flag_t profilePresentFlag, ngx_uint_t maxNumSubLayersMinus1)
{
    ngx_uint_t                  i, slppf[8], sllpf[8];

    if (profilePresentFlag) {
        /*
         * profile_tier_level
         *      general_profile_space                       2 bits
         *      general_tier_flag                           1 bit
         *      general_profile_idc                         5 bits
         *      for (j = 0; j < 32; j++)
         *          general_profile_compatibility_flag[j]   1 bit
         *      general_progressive_source_flag             1 bit
         *      general_interlaced_source_flag              1 bit
         *      general_non_packed_constraint_flag          1 bit
         *      general_frame_only_constraint_flag          1 bit
         *
         *      general_max_12bit_constraint_flag           1 bit
         *      general_max_10bit_constraint_flag           1 bit
         *      general_max_8bit_constraint_flag            1 bit
         *      general_max_422chroma_constraint_flag       1 bit
         *      general_max_420chroma_constraint_flag       1 bit
         *      general_max_monochrome_constraint_flag      1 bit
         *      general_intra_constraint_flag               1 bit
         *      general_one_picture_only_constraint_flag    1 bit
         *      general_lower_bit_rate_constraint_flag      1 bit
         *      general_reserved_zero_34bits                34 bits
         *
         *      general_inbld_flag                          1 bit
         */
        ngx_rtmp_bit_read(br, 88);
    }

    /*
     * profile_tier_level
     *      general_level_idc                               8 bits
     */
    ngx_rtmp_bit_read(br, 8);

    /*
     * profile_tier_level
     *      for(i = 0; i < maxNumSubLayersMinus1; i++) {
     *           sub_layer_profile_present_flag[i]          1 bit
     *           sub_layer_level_present_flag[i]            1 bit
     *      }
     *
     *      if (maxNumSubLayersMinus1 > 0)
     *           for(i = maxNumSubLayersMinus1; i < 8; i++)
     *               reserved_zero_2bits[i]                 2 bits
     */
    for (i = 0; i < maxNumSubLayersMinus1; ++i) {
        slppf[i] = ngx_rtmp_bit_read(br, 1);
        sllpf[i] = ngx_rtmp_bit_read(br, 1);
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "%d sub_layer_profile_present_flag:%d, "
                "sub_layer_level_present_flag:%d", i, slppf[i], sllpf[i]);
    }

    if (maxNumSubLayersMinus1 > 0) {
        for (i = maxNumSubLayersMinus1; i < 8; ++i) {
            ngx_uint_t t = ngx_rtmp_bit_read(br, 2);
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "zero bit %d", t);
        }
    }

    /*
     * profile_tier_level
     *      for (i = 0; i < maxNumSubLayersMinus1; i++) {
     *          if (sub_layer_profile_present_flag[i] {
     *                                                      44 bits
     *          }
     *          if (sub_layer_level_present_flag[i]) {
     *              sub_layer_level_idc[i]                  8 bits
     *          }
     *      }
     */
    for (i = 0; i < maxNumSubLayersMinus1; ++i) {
        if (slppf[i]) {
            ngx_rtmp_bit_read(br, 88);
        }

        if (sllpf[i]) {
            ngx_rtmp_bit_read(br, 8);
        }
    }
}

/*
 * ITU-T H.265 7.3.2.2 Sequence parameter set RBSP syntax
 */
static void
ngx_rtmp_codec_parse_hevc_sps(ngx_rtmp_session_t *s, ngx_rtmp_codec_ctx_t *ctx,
        ngx_rtmp_bit_reader_t *pbr, ngx_uint_t nal_unit_len)
{
    ngx_uint_t              mslm, psi, cfi, width, height,
                            subwidthC, subheightC,
                            cwlo, cwro, cwto, cwbo;
    ngx_rtmp_bit_reader_t   br;
    u_char                  buf[4096];
    ngx_int_t               rbsp_bytes;

    ngx_rtmp_bit_init_reader(&br, pbr->pos, pbr->pos + nal_unit_len);
    rbsp_bytes = ngx_rtmp_codec_parse_hevc_nal_to_rbsp(s, buf, &br, NAL_SPS,
                                                       nal_unit_len);
    if (rbsp_bytes == NGX_ERROR) {
        return;
    }

    ngx_rtmp_bit_init_reader(&br, buf, buf + rbsp_bytes);

    /*
     * seq_parameter_set_rbsp
     *      sps_video_parameter_set_id              4 bits
     *      sps_max_sub_layers_minus1               3 bits
     *      sps_temporal_id_nesting_flag            1 bit
     */
    ngx_rtmp_bit_read(&br, 4);
    mslm = ngx_rtmp_bit_read(&br, 3);
    ngx_rtmp_bit_read(&br, 1);

    /*
     * seq_parameter_set_rbsp
     *      profile_tier_level(1, sps_max_sub_layers_minus1)
     */
    ngx_rtmp_codec_parse_hevc_ptl(s, &br, 1, mslm);

    /* calc resolution */
    /*
     * seq_parameter_set_rbsp
     *      sps_seq_parameter_set_id                v
     *      chroma_format_idc                       v
     *      if (chroma_format_idc == 3)
     *          separate_colour_plane_flag          1 bit
     *      pic_width_in_luma_samples               v
     *      pic_height_in_luma_samples              v
     *      conformance_window_flag                 1 bit
     *      if (conformance_window_flag) {
     *          conf_win_left_offset                v
     *          conf_win_right_offset               v
     *          conf_win_top_offset                 v
     *          conf_win_bottom_offset              v
     *      }
     */
    psi = ngx_rtmp_bit_read_golomb(&br);
    if (psi > 16 || br.err) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "read sps_seq_parameter_set_id error: %ui", psi);
        return;
    }

    cfi = ngx_rtmp_bit_read_golomb(&br);
    if (cfi > 3 || br.err) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "read chroma_format_idc error: %ui", cfi);
        return;
    }

    if (cfi == 3) {
        ngx_rtmp_bit_read(&br, 1);
    }

    width = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
    if (br.err) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "read width error");
        return;
    }

    height = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
    if (br.err) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "read height error");
        return;
    }

    if (ngx_rtmp_bit_read(&br, 1)) {
        cwlo = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        cwro = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        cwto = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        cwbo = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

        /*
         * ITU-T H.265 Table 6-1
         */
        if (cfi == 1) { /* 4:2:0 */
            subwidthC = 2;
            subheightC = 2;
        } else if (cfi == 2) { /* 4:2:2 */
            subwidthC = 2;
            subheightC = 1;
        } else { /* Monochrome or 4:4:4 */
            subwidthC = 1;
            subheightC = 1;
        }

        /*
         * ITU-T H.265 7.4.3.2.1
         *
         * horizontal picture coordinates from
         *  SubWidthC * conf_win_left_offset to
         *  pic_width_in_luma_samples - (SubWidthC * conf_win_right_offset + 1)
         * vertical picture coordinates from
         *  SubHeightC * conf_win_top_offset to
         *  pic_height_in_luma_samples -
         *  (SubHeightC * conf_win_bottom_offset + 1)
         */
        ctx->width = width - (subwidthC * cwro + 1) - (subwidthC * cwlo);
        ctx->height = height - (subheightC * cwbo + 1) - (subheightC * cwto);
    } else {
        ctx->width = width;
        ctx->height = height;
    }

    return;
}

static void
ngx_rtmp_codec_parse_hevc_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_uint_t              i, j, num_arrays, nal_unit_type, num_nalus,
                            nal_unit_len;
    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "hevc", in);
#endif

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    /*
     * FrameType                                    4 bits
     * CodecID                                      4 bits
     * AVCPacketType                                1 byte
     * CompositionTime                              3 bytes
     * HEVCDecoderConfigurationRecord
     *      configurationVersion                    1 byte
     */
    ngx_rtmp_bit_read(&br, 48);

    /*
     * HEVCDecoderConfigurationRecord
     *      general_profile_space                   2 bits
     *      general_tier_flag                       1 bit
     *      general_profile_idc                     5 bits
     *      general_profile_compatibility_flags     4 bytes
     *      general_constraint_indicator_flags      6 bytes
     *      general_level_idc                       1 byte
     *      min_spatial_segmentation_idc            4 bits reserved + 12 bits
     *      parallelismType                         6 bits reserved + 2 bits
     *      chroma_format_idc                       6 bits reserved + 2 bits
     *      bit_depth_luma_minus8                   5 bits reserved + 3 bits
     *      bit_depth_chroma_minus8                 5 bits reserved + 3 bits
     *      avgFrameRate                            2 bytes
     */
    ngx_rtmp_bit_read(&br, 160);

    /*
     * HEVCDecoderConfigurationRecord
     *      constantFrameRate                       2 bits
     *      numTemporalLayers                       3 bits
     *      temporalIdNested                        1 bit
     *      lengthSizeMinusOne                      2 bits
     */
    ctx->avc_nal_bytes = (ngx_uint_t) ((ngx_rtmp_bit_read_8(&br) & 0x03) + 1);

    /*
     * HEVCDecoderConfigurationRecord
     *      numOfArrays                             1 byte
     */
    num_arrays = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);

    for (i = 0; i < num_arrays; ++i) {
        /*
         * array_completeness                       1 bit
         * reserved                                 1 bit
         * NAL_unit_type                            6 bits
         * numNalus                                 2 bytes
         */
        nal_unit_type = (ngx_uint_t) (ngx_rtmp_bit_read_8(&br) & 0x3f);
        num_nalus = (ngx_uint_t) ngx_rtmp_bit_read_16(&br);

        for (j = 0; j < num_nalus; ++j) {
            /*
             * nalUnitLength                        2 bytes
             */
            nal_unit_len = (ngx_uint_t) ngx_rtmp_bit_read_16(&br);

            switch (nal_unit_type) {
            case NAL_SPS:
                ngx_rtmp_codec_parse_hevc_sps(s, ctx, &br, nal_unit_len);
                ngx_rtmp_bit_read(&br, nal_unit_len * 8);
                break;
            default:
                ngx_rtmp_bit_read(&br, nal_unit_len * 8);
                break;
            }
        }
    }

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: hevc header "
                   "profile=%ui, compat=%ui, level=%ui, "
                   "nal_bytes=%ui, ref_frames=%ui, width=%ui, height=%ui",
                   ctx->avc_profile, ctx->avc_compat, ctx->avc_level,
                   ctx->avc_nal_bytes, ctx->avc_ref_frames,
                   ctx->width, ctx->height);
}


static void
ngx_rtmp_codec_parse_avc_header(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_uint_t              profile_idc, width, height, crop_left, crop_right,
                            crop_top, crop_bottom, frame_mbs_only, n, cf_idc,
                            num_ref_frames;
    ngx_rtmp_codec_ctx_t   *ctx;
    ngx_rtmp_bit_reader_t   br;
    ngx_uint_t              nal_size;
    ngx_uint_t              colour_description_present_flag,color_primaries, color_trc, colorspace;
    ngx_uint_t              aspect_ratio_idc, sar_width, sar_height, video_format, video_full_range_flag,fixed_frame_rate_flag;
    unsigned                num_units_in_tick, time_scale;

#if (NGX_DEBUG)
    ngx_rtmp_codec_dump_header(s, "avc", in);
#endif

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    ngx_rtmp_bit_read(&br, 48);

    ctx->avc_profile = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);
    ctx->avc_compat = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);
    ctx->avc_level = (ngx_uint_t) ngx_rtmp_bit_read_8(&br);

    /* nal bytes */
    ctx->avc_nal_bytes = (ngx_uint_t) ((ngx_rtmp_bit_read_8(&br) & 0x03) + 1);

    /* nnals */
    if ((ngx_rtmp_bit_read_8(&br) & 0x1f) == 0) {
        return;
    }

    /* nal size */
    nal_size = ngx_rtmp_bit_read(&br, 16);

    /* nal type */
    if (ngx_rtmp_bit_read_8(&br) != 0x67) {
        return;
    }

    /* SPS */
    ngx_get_correct_fps(s, &ctx->frame_rate,
            ngx_parse_h264_sps_fps(s, in->buf->pos + 6 + 8, nal_size - 1));
    ctx->localport = ngx_rtmp_codec_get_localport(s);

    /* profile idc */
    profile_idc = (ngx_uint_t) ngx_rtmp_bit_read(&br, 8);

    /* flags */
    ngx_rtmp_bit_read(&br, 8);

    /* level idc */
    ngx_rtmp_bit_read(&br, 8);

    /* SPS id */
    ngx_rtmp_bit_read_golomb(&br);

    if (profile_idc == 100 || profile_idc == 110 ||
        profile_idc == 122 || profile_idc == 244 || profile_idc == 44 ||
        profile_idc == 83 || profile_idc == 86 || profile_idc == 118)
    {
        /* chroma format idc */
        cf_idc = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

        if (cf_idc == 3) {

            /* separate color plane */
            ngx_rtmp_bit_read(&br, 1);
        }

        /* bit depth luma - 8 */
        ngx_rtmp_bit_read_golomb(&br);

        /* bit depth chroma - 8 */
        ngx_rtmp_bit_read_golomb(&br);

        /* qpprime y zero transform bypass */
        ngx_rtmp_bit_read(&br, 1);

        /* seq scaling matrix present */
        if (ngx_rtmp_bit_read(&br, 1)) {

            for (n = 0; n < (cf_idc != 3 ? 8u : 12u); n++) {

                /* seq scaling list present */
                if (ngx_rtmp_bit_read(&br, 1)) {

                    /* TODO: scaling_list()
                    if (n < 6) {
                    } else {
                    }
                    */
                }
            }
        }
    }

    /* log2 max frame num */
    ngx_rtmp_bit_read_golomb(&br);

    /* pic order cnt type */
    switch (ngx_rtmp_bit_read_golomb(&br)) {
    case 0:

        /* max pic order cnt */
        ngx_rtmp_bit_read_golomb(&br);
        break;

    case 1:

        /* delta pic order alwys zero */
        ngx_rtmp_bit_read(&br, 1);

        /* offset for non-ref pic */
        ngx_rtmp_bit_read_golomb(&br);

        /* offset for top to bottom field */
        ngx_rtmp_bit_read_golomb(&br);

        /* num ref frames in pic order */
        num_ref_frames = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

        for (n = 0; n < num_ref_frames; n++) {

            /* offset for ref frame */
            ngx_rtmp_bit_read_golomb(&br);
        }
    }

    /* num ref frames */
    ctx->avc_ref_frames = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* gaps in frame num allowed */
    ngx_rtmp_bit_read(&br, 1);

    /* pic width in mbs - 1 */
    width = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* pic height in map units - 1 */
    height = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    /* frame mbs only flag */
    frame_mbs_only = (ngx_uint_t) ngx_rtmp_bit_read(&br, 1);

    if (!frame_mbs_only) {

        /* mbs adaprive frame field */
        ngx_rtmp_bit_read(&br, 1);
    }

    /* direct 8x8 inference flag */
    ngx_rtmp_bit_read(&br, 1);

    /* frame cropping */
    if (ngx_rtmp_bit_read(&br, 1)) {

        crop_left = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_right = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_top = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);
        crop_bottom = (ngx_uint_t) ngx_rtmp_bit_read_golomb(&br);

    } else {

        crop_left = 0;
        crop_right = 0;
        crop_top = 0;
        crop_bottom = 0;
    }

    ctx->width = (width + 1) * 16 - (crop_left + crop_right) * 2;
    ctx->height = (2 - frame_mbs_only) * (height + 1) * 16 -
                  (crop_top + crop_bottom) * 2;


    /* vui_parameters_present_flag */
    if (ngx_rtmp_bit_read(&br, 1)) {
        /* vui_parameters */

        /* aspect_ratio_info_present_flag */
        if(ngx_rtmp_bit_read(&br, 1)){
            aspect_ratio_idc = ngx_rtmp_bit_read(&br, 8);
            if(aspect_ratio_idc == Extended_SAR){
                sar_width = ngx_rtmp_bit_read(&br, 16);
                sar_height = ngx_rtmp_bit_read(&br, 16);
                ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "sar_width = %ui, sar_height = %ui", sar_width, sar_height);
            }
        }else{
            sar_width = 0;
            sar_height = 0;
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "sar_width = %ui, sar_height = %ui", sar_width, sar_height);
        }

        /* overscan_info_present_flag */
        if(ngx_rtmp_bit_read(&br, 1)){
            ngx_rtmp_bit_read(&br, 1);  // overscan_appropriate_flag

        }

        /* video_signal_type_present_flag */
        if(ngx_rtmp_bit_read(&br, 1)){
            /* video_format */
            video_format = ngx_rtmp_bit_read(&br, 3);
            /* video_full_range_flag */
            video_full_range_flag = ngx_rtmp_bit_read(&br, 1);
            /* colour_description_present_flag  */
            colour_description_present_flag = ngx_rtmp_bit_read(&br, 1);
            if(colour_description_present_flag){
                /* color_primaries */
                color_primaries = ngx_rtmp_bit_read(&br, 8);
                /* color_trc */
                color_trc = ngx_rtmp_bit_read(&br, 8);
                /* colorspace */
                colorspace = ngx_rtmp_bit_read(&br, 8);
                ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "color_primaries = %ui, color_trc = %ui colorspace = %ui",color_primaries, color_trc, colorspace);
            }
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "video_format = %ui, video_full_range_flag = %ui",video_format, video_full_range_flag);
        }

        /* chroma_location_info_present_flag */
        if(ngx_rtmp_bit_read(&br, 1)){
            ngx_rtmp_bit_read_golomb(&br);
            ngx_rtmp_bit_read_golomb(&br);
        }

        /*timing_info_present_flag  */
        if(ngx_rtmp_bit_read(&br, 1)){
            /* num_units_in_tick time_scale */
            num_units_in_tick = ngx_rtmp_bit_read(&br, 32);
            time_scale = ngx_rtmp_bit_read(&br, 32);
            /*fixed_frame_rate_flag  */
            fixed_frame_rate_flag = ngx_rtmp_bit_read(&br, 1);
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                      "num_units_in_tick = %ui, time_scale = %ui , fixed_frame_rate_flag = %ui",num_units_in_tick, time_scale, fixed_frame_rate_flag);
        }


    }

    ngx_log_debug7(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: avc header "
                   "profile=%ui, compat=%ui, level=%ui, "
                   "nal_bytes=%ui, ref_frames=%ui, width=%ui, height=%ui",
                   ctx->avc_profile, ctx->avc_compat, ctx->avc_level,
                   ctx->avc_nal_bytes, ctx->avc_ref_frames,
                   ctx->width, ctx->height);
}


#if (NGX_DEBUG)
static void
ngx_rtmp_codec_dump_header(ngx_rtmp_session_t *s, const char *type,
    ngx_chain_t *in)
{
    u_char buf[256], *p, *pp;
    u_char hex[] = "0123456789abcdef";

    for (pp = buf, p = in->buf->pos;
         p < in->buf->last && pp < buf + sizeof(buf) - 1;
         ++p)
    {
        *pp++ = hex[*p >> 4];
        *pp++ = hex[*p & 0x0f];
    }

    *pp = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "codec: %s header %s", type, buf);
}
#endif


static ngx_int_t
ngx_rtmp_codec_copy_meta_elts(ngx_rtmp_session_t *s, ngx_array_t *meta,
        ngx_rtmp_amf_elt_t *src, ngx_uint_t nelts)
{
    ngx_rtmp_amf_elt_t             *elt, *p;
    ngx_uint_t                      i;

    for (i = 0; i < nelts; i++) {
        p = src + i;
        elt = ngx_array_push(meta);

        elt->type = p->type;
        elt->name.len = p->name.len;
        elt->name.data = ngx_pcalloc(s->connection->pool, elt->name.len);
        ngx_memcpy(elt->name.data, p->name.data, elt->name.len);

        switch(elt->type) {
            case NGX_RTMP_AMF_NUMBER:
                elt->len = 8;
                break;

            case NGX_RTMP_AMF_STRING:
                if (p->len == 0 && p->data) {
                    elt->len = (uint16_t) ngx_strlen((u_char*) p->data);
                } else {
                    elt->len = p->len;
                }
                break;

            default:
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "codec: now only support NUMBER and STRING type");
                return NGX_ERROR;
        }

        elt->data = ngx_pcalloc(s->connection->pool, elt->len);
        ngx_memcpy(elt->data, p->data, elt->len);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "codec: copy meta elts's number is %d", meta->nelts);
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_reconstruct_meta(ngx_rtmp_session_t *s)
{
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_codec_app_conf_t      *cacf;
    ngx_int_t                       rc;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id;
        double                      audio_data_rate;
        double                      audio_codec_id;
        u_char                      profile[32];
        u_char                      level[32];
    }                               v;

    static ngx_rtmp_amf_elt_t       out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("Server"),
          "NGINX RTMP (github.com/arut/nginx-rtmp-module)", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayWidth"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("displayHeight"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videocodecid"),
          &v.video_codec_id, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiocodecid"),
          &v.audio_codec_id, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },
    };

    static ngx_rtmp_amf_elt_t       out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onMetaData", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    if (ctx->meta) {
        ngx_rtmp_shared_free_frame(ctx->meta);
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ctx->meta = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, NULL, 1);

    v.width = ctx->width;
    v.height = ctx->height;
    v.duration = ctx->duration;
    v.frame_rate = ctx->frame_rate;
    v.video_data_rate = ctx->video_data_rate;
    v.video_codec_id = ctx->video_codec_id;
    v.audio_data_rate = ctx->audio_data_rate;
    v.audio_codec_id = ctx->audio_codec_id;
    ngx_memcpy(v.profile, ctx->profile, sizeof(ctx->profile));
    ngx_memcpy(v.level, ctx->level, sizeof(ctx->level));

    rc = ngx_rtmp_append_amf(s, &ctx->meta->chain, &ctx->meta->chain, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0]));
    if (rc != NGX_OK || ctx->meta == NULL) {
        return NGX_ERROR;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);
    if (cacf->meta_out != NULL && cacf->meta_out->nelts > 0) {
        if (ctx->meta_out_elts != NULL) {
            ngx_array_init(ctx->meta_out_elts, s->connection->pool, 1,
                    sizeof(ngx_rtmp_amf_elt_t));
        } else {
            ctx->meta_out_elts = ngx_array_create(s->connection->pool, 1,
                    sizeof(ngx_rtmp_amf_elt_t));
            if (ctx->meta_out_elts == NULL) {
                goto done;
            }
        }

        /* storage metadata to dynamic array */
        if (ngx_rtmp_codec_copy_meta_elts(s, ctx->meta_out_elts, out_inf,
                    sizeof(out_inf) / sizeof(out_inf[0])) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "codec: error coping out metadata");
            ctx->meta_out_elts->nelts = 0;
            goto done;
        }

        ctx->meta_timestamp = 0;
    }

done:
    return ngx_rtmp_codec_prepare_meta(s, 0);
}


static ngx_int_t
ngx_rtmp_codec_fix_input_meta(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    if (*in->buf->pos == 0x02 && *(in->buf->pos + 1) == 0x00) {
        return NGX_OK;
    }

    /*
     * 1 represent type
     * 2 represent length of string
     * 10 represent 'onMetaData'
     */
    if (in->buf->pos - in->buf->start < 1 + 2 + 10) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: metadata buffer for header is less than 13");
        return NGX_ERROR;
    }

    in->buf->pos -= 13;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_copy_meta(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_codec_ctx_t      *ctx;
    ngx_rtmp_core_srv_conf_t  *cscf;
    ngx_rtmp_codec_app_conf_t *cacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx->meta) {
        ngx_rtmp_shared_free_frame(ctx->meta);
    }

    ngx_rtmp_codec_fix_input_meta(s, in);

    ctx->meta = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, in, 0);

    if (ctx->meta == NULL) {
        return NGX_ERROR;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);
    if (cacf->meta_out != NULL && cacf->meta_out->nelts > 0) {
        if (ctx->meta_out_elts != NULL) {
            ngx_array_init(ctx->meta_out_elts, s->connection->pool, 1,
                    sizeof(ngx_rtmp_amf_elt_t));
        } else {
            ctx->meta_out_elts = ngx_array_create(s->connection->pool, 1,
                    sizeof(ngx_rtmp_amf_elt_t));
            if (ctx->meta_out_elts == NULL) {
                goto done;
            }
        }

        /* storage metadata to dynamic array */
        if (ngx_rtmp_receive_meta(s, ctx->meta_out_elts, in) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "codec: error parsing metadata");
            ctx->meta_out_elts->nelts = 0;
            goto done;
        }

        ctx->meta_timestamp = h->timestamp;
    }

done:
    return ngx_rtmp_codec_prepare_meta(s, h->timestamp);
}


static ngx_int_t
ngx_rtmp_codec_prepare_meta(ngx_rtmp_session_t *s, uint32_t timestamp)
{
    ngx_rtmp_codec_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

    ctx->meta->hdr.csid = NGX_RTMP_CSID_AMF;
    ctx->meta->hdr.msid = NGX_RTMP_MSID;
    ctx->meta->hdr.type = NGX_RTMP_MSG_AMF_META;
    ctx->meta->hdr.timestamp = timestamp;

    ctx->meta_version = ngx_rtmp_codec_get_next_version();

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_codec_meta_data(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_codec_app_conf_t      *cacf;
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_uint_t                      skip;

    static struct {
        double                      width;
        double                      height;
        double                      duration;
        double                      frame_rate;
        double                      video_data_rate;
        double                      video_codec_id_n;
        u_char                      video_codec_id_s[32];
        double                      audio_data_rate;
        double                      audio_codec_id_n;
        u_char                      audio_codec_id_s[32];
        u_char                      profile[32];
        u_char                      level[32];
        int                         hasVideo;
    }                               v;

    static ngx_rtmp_amf_elt_t       in_video_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.video_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.video_codec_id_s, sizeof(v.video_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_audio_codec_id[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.audio_codec_id_n, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.audio_codec_id_s, sizeof(v.audio_codec_id_s) },
    };

    static ngx_rtmp_amf_elt_t       in_inf[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("width"),
          &v.width, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("height"),
          &v.height, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("duration"),
          &v.duration, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("framerate"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("fps"),
          &v.frame_rate, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videodatarate"),
          &v.video_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT,
          ngx_string("videocodecid"),
          in_video_codec_id, sizeof(in_video_codec_id) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audiodatarate"),
          &v.audio_data_rate, 0 },

        { NGX_RTMP_AMF_VARIANT,
          ngx_string("audiocodecid"),
          in_audio_codec_id, sizeof(in_audio_codec_id) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("profile"),
          &v.profile, sizeof(v.profile) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_string("hasVideo"),
          &v.hasVideo, 0 },
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_codec_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_codec_module);
    }

    ngx_memzero(&v, sizeof(v));
    v.hasVideo = 1;

    /* use -1 as a sign of unchanged data;
     * 0 is a valid value for uncompressed audio */
    v.audio_codec_id_n = -1;

    /* FFmpeg sends a string in front of actal metadata; ignore it */
    skip = !(in->buf->last > in->buf->pos
            && *in->buf->pos == NGX_RTMP_AMF_STRING);
    if (ngx_rtmp_receive_amf(s, in, in_elts + skip,
                sizeof(in_elts) / sizeof(in_elts[0]) - skip))
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: error parsing data frame");
        return NGX_OK;
    }

    if (0 == (ngx_flag_t)v.hasVideo) {
         s->filter |=  NGX_RTMP_FILTER_KEEPAUDIO;
    }

    ctx->width = (ngx_uint_t) v.width;
    ctx->height = (ngx_uint_t) v.height;
    ctx->duration = (ngx_uint_t) v.duration;
    ctx->frame_rate = v.frame_rate;
    ctx->video_data_rate = (ngx_uint_t) v.video_data_rate;
    ctx->video_codec_id = (ngx_uint_t) v.video_codec_id_n;
    ctx->audio_data_rate = (ngx_uint_t) v.audio_data_rate;
    ctx->audio_codec_id = (v.audio_codec_id_n == -1
            ? 0 : v.audio_codec_id_n == 0
            ? NGX_RTMP_AUDIO_UNCOMPRESSED : (ngx_uint_t) v.audio_codec_id_n);
    ngx_memcpy(ctx->profile, v.profile, sizeof(v.profile));
    ngx_memcpy(ctx->level, v.level, sizeof(v.level));

    ngx_log_debug8(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "codec: data frame: "
            "width=%ui height=%ui duration=%ui frame_rate=%ui "
            "video=%s (%ui) audio=%s (%ui)",
            ctx->width, ctx->height, ctx->duration, ctx->frame_rate,
            ngx_rtmp_get_video_codec_name(ctx->video_codec_id),
            ctx->video_codec_id,
            ngx_rtmp_get_audio_codec_name(ctx->audio_codec_id),
            ctx->audio_codec_id);

    switch (cacf->meta) {
        case NGX_RTMP_CODEC_META_ON:
            return ngx_rtmp_codec_reconstruct_meta(s);
        case NGX_RTMP_CODEC_META_COPY:
            return ngx_rtmp_codec_copy_meta(s, h, in);
    }

    /* NGX_RTMP_CODEC_META_OFF */

    return NGX_OK;
}


static void
ngx_rtmp_codec_copy_meta_array(ngx_array_t *dst, ngx_array_t *src)
{
    ngx_uint_t                      i;
    ngx_rtmp_amf_elt_t             *elt, *p;

    p = src->elts;

    for (i = 0; i < src->nelts; i++) {
        elt = ngx_array_push(dst);

        elt->type = p[i].type;
        elt->name = p[i].name;
        elt->len = p[i].len;
        elt->data = p[i].data;
    }
}


static ngx_rtmp_amf_elt_t*
ngx_rtmp_codec_check_duplicate(ngx_array_t *dst,
        ngx_rtmp_codec_extra_meta_t *extra)
{
    ngx_uint_t                          i;
    ngx_rtmp_amf_elt_t                 *elt;

    elt = dst->elts;
    for (i = 0; i < dst->nelts; i++, elt++) {
        if (elt->name.len != extra->name.len ||
            ngx_strncmp(elt->name.data, extra->name.data, elt->name.len) != 0)
        {
            continue;
        }

        if (extra->cover == 1) {
            return elt;
        }

        return NULL;
    }

    return ngx_array_push(dst);
}


static void
ngx_rtmp_codec_add_extra_meta(ngx_rtmp_session_t *s, ngx_array_t *dst,
        ngx_array_t *src)
{
    ngx_uint_t                          i;
    ngx_rtmp_amf_elt_t                 *meta;
    ngx_rtmp_codec_extra_meta_t        *p;
    ngx_rtmp_variable_value_t          *vv;
    ngx_str_t                           str;

    p = src->elts;

    for (i = 0; i < src->nelts; i++) {
        if (p[i].var == 1) {
            vv = ngx_rtmp_get_indexed_variable(s, p[i].index);
            if (vv == NULL || vv->not_found) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "codec: add extra meta %V failed, index = %d",
                        p[i].name, p[i].index);
                continue;
            }

            str.data = vv->data;
            str.len = vv->len;
        } else {
            str = p[i].config_str;
        }

        meta = ngx_rtmp_codec_check_duplicate(dst, &p[i]);
        if (meta == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "codec: extra meta %V is duplicate", &p[i].name);
            continue;
        }

        meta->type = NGX_RTMP_AMF_STRING;
        meta->name = p[i].name;
        meta->len = str.len;
        meta->data = ngx_pcalloc(s->connection->pool, meta->len);
        ngx_memcpy(meta->data, str.data, meta->len);
    }
}


void
ngx_rtmp_codec_construct_sub_meta(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ss)
{
    ngx_rtmp_codec_app_conf_t      *cacf;
    ngx_rtmp_codec_ctx_t           *ctx;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_array_t                    *out_inf;
    ngx_int_t                       rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (ss->sub_meta_version == ctx->meta_version) {
        goto done;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_codec_module);
    if (cacf->meta_out == NULL || cacf->meta_out->nelts == 0) {
        ss->sub_meta = ctx->meta;
        goto done;
    }

    if (ctx->meta_out_elts == NULL || ctx->meta_out_elts->nelts <= 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: ctx->meta_out_elts is NULL when there are some extra "
                "out meta in conf");
        ss->sub_meta = ctx->meta;
        goto done;
    }

    out_inf = ngx_array_create(ss->connection->pool, ctx->meta_out_elts->nelts +
            cacf->meta_out->nelts, sizeof(ngx_rtmp_amf_elt_t));
    if (out_inf == NULL) {
        ss->sub_meta = ctx->meta;
        goto done;
    }

    ngx_rtmp_codec_copy_meta_array(out_inf, ctx->meta_out_elts);
    ngx_rtmp_codec_add_extra_meta(ss, out_inf, cacf->meta_out);

    ngx_rtmp_amf_elt_t           out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "onMetaData", 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf->elts, out_inf->nelts * sizeof(out_elts[0]) },
    };

    if (ss->sub_meta) {
        ngx_rtmp_shared_free_frame(ss->sub_meta);
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ss->sub_meta = ngx_rtmp_shared_alloc_frame(cscf->chunk_size, NULL, 1);

    rc = ngx_rtmp_append_amf(ss, &ss->sub_meta->chain, &ss->sub_meta->chain,
            out_elts, sizeof(out_elts) / sizeof(out_elts[0]));
    if (rc != NGX_OK || ss->sub_meta == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "codec: sub meta append amf failed");
        ss->sub_meta = ctx->meta;
        goto done;
    }

    ss->sub_meta->hdr.csid = NGX_RTMP_CSID_AMF;
    ss->sub_meta->hdr.msid = NGX_RTMP_MSID;
    ss->sub_meta->hdr.type = NGX_RTMP_MSG_AMF_META;
    ss->sub_meta->hdr.timestamp = ctx->meta_timestamp;

done:
    ss->sub_meta_version = ctx->meta_version;
}


static char *
ngx_rtmp_codec_customize_meta(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_codec_app_conf_t          *cacf = conf;
    ngx_str_t                          *value, v, n;
    ngx_uint_t                          i;
    ngx_int_t                           index = -1;
    ngx_rtmp_codec_extra_meta_t        *extra_meta;
    u_char                             *p;
    ngx_flag_t                          flag = 0;

    value = cf->args->elts;

    if (value[1].data[0] == '$') {
        value[1].len--;
        value[1].data++;

        index = ngx_rtmp_get_variable_index(cf, &value[1]);
        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        flag = 1;
    }

    if (cacf->meta_out == NGX_CONF_UNSET_PTR) {
        cacf->meta_out = ngx_array_create(cf->pool, 1,
                sizeof(ngx_rtmp_codec_extra_meta_t));
        if (cacf->meta_out == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    extra_meta = ngx_array_push(cacf->meta_out);
    extra_meta->index = index;
    extra_meta->name = value[1];
    extra_meta->cover = 0;
    extra_meta->var = flag;
    extra_meta->config_str = value[1];

    value += 2;
    for (i = 2; i < cf->args->nelts; ++i, ++value) {
        p = ngx_strlchr(value->data, value->data + value->len, '=');

        if (p == NULL) {
            return NGX_CONF_ERROR;
        } else {
            n.data = value->data;
            n.len  = p - value->data;

            v.data = p + 1;
            v.len  = value->data + value->len - p - 1;
        }

        if (n.len == sizeof("name") - 1
            && ngx_strncasecmp(n.data, (u_char *) "name", n.len) == 0)
        {
            extra_meta->name = v;
            continue;
        }

        if (n.len == sizeof("cover") -1
            && ngx_strncasecmp(n.data, (u_char *) "cover", n.len) == 0)
        {
            extra_meta->cover = ngx_atoi(v.data, v.len);
            continue;
        }

        return "unsuppored parameter";
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_codec_preconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_variable_t        *cv, *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    for (cv = ngx_rtmp_codec_variables; cv->name.len; cv++) {
        v = ngx_rtmp_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}

static void *
ngx_rtmp_codec_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_codec_app_conf_t  *cacf;

    cacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_codec_app_conf_t));
    if (cacf == NULL) {
        return NULL;
    }

    cacf->default_fps_bitrate = NGX_CONF_UNSET;
    cacf->meta = NGX_CONF_UNSET_UINT;
    cacf->meta_out = NGX_CONF_UNSET_PTR;

    return cacf;
}


static char *
ngx_rtmp_codec_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_codec_app_conf_t *prev = parent;
    ngx_rtmp_codec_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->default_fps_bitrate,
                         prev->default_fps_bitrate, 1);
    ngx_conf_merge_uint_value(conf->meta, prev->meta, NGX_RTMP_CODEC_META_ON);
    ngx_conf_merge_ptr_value(conf->meta_out, prev->meta_out, NULL);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_codec_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_codec_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    *h = ngx_rtmp_codec_disconnect;

    /* register metadata handler */
    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&ch->name, "@setDataFrame");
    ch->handler = ngx_rtmp_codec_meta_data;

    ch = ngx_array_push(&cmcf->amf);
    if (ch == NULL) {
        return NGX_ERROR;
    }
    ngx_str_set(&ch->name, "onMetaData");
    ch->handler = ngx_rtmp_codec_meta_data;


    return NGX_OK;
}
