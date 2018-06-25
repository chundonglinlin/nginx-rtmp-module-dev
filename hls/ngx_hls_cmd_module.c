#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_streams.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_mpegts_module.h"
#include "ngx_hls_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rbuf.h"

#define ngx_hls_cmd_acquire_frag(fg) fg->ref++


ngx_hls_play_pt ngx_hls_play;
static ngx_hls_play_pt next_hls_play;

ngx_hls_close_pt ngx_hls_close;
static ngx_hls_close_pt next_hls_close;

#define NGX_HTTP_HLS_TYPE_LIVE          1
#define NGX_HTTP_HLS_TYPE_EVENT         2

#define NGX_HTTP_HLS_SLICING_PLAIN      1
#define NGX_HTTP_HLS_SLICING_ALIGNED    2

ngx_conf_enum_t                         ngx_hls_type_slots[] = {
    { ngx_string("live"),               NGX_HTTP_HLS_TYPE_LIVE  },
    { ngx_string("event"),              NGX_HTTP_HLS_TYPE_EVENT },
    { ngx_null_string,                  0 }
};

static ngx_conf_enum_t                  ngx_hls_slicing_slots[] = {
    { ngx_string("plain"),              NGX_HTTP_HLS_SLICING_PLAIN },
    { ngx_string("aligned"),            NGX_HTTP_HLS_SLICING_ALIGNED  },
    { ngx_null_string,                  0 }
};

//static ngx_int_t ngx_hls_cmd_postconfiguration(ngx_conf_t *cf);
static void *
ngx_hls_cmd_create_app_conf(ngx_conf_t *cf);
static char *
ngx_hls_cmd_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_hls_cmd_postconfiguration(ngx_conf_t *cf);

static ngx_command_t ngx_hls_cmd_commands[] = {

    { ngx_string("hls2_debug_log"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, debug_log),
      NULL },

    { ngx_string("hls2_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, fraglen),
      NULL },

    { ngx_string("hls2_max_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, max_fraglen),
      NULL },

    { ngx_string("hls2_playlist_length"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, playlen),
      NULL },

    { ngx_string("hls2_minfrags"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, minfrags),
      NULL },

    { ngx_string("hls2_fragment_slicing"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, slicing),
      &ngx_hls_slicing_slots },

    { ngx_string("hls2_base_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, base_url),
      NULL },

    { ngx_string("hls2_key_url"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, key_url),
      NULL },

    { ngx_string("hls2_type"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, type),
      &ngx_hls_type_slots },

    { ngx_string("hls2_keys"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_hls_cmd_app_conf_t, keys),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_hls_cmd_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_hls_cmd_postconfiguration,              /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_hls_cmd_create_app_conf,                /* create app configuration */
    ngx_hls_cmd_merge_app_conf                  /* merge app configuration */
};


ngx_module_t  ngx_hls_cmd_module = {
    NGX_MODULE_V1,
    &ngx_hls_cmd_module_ctx,                    /* module context */
    ngx_hls_cmd_commands,                       /* module directives */
    NGX_RTMP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_hls_cmd_create_app_conf(ngx_conf_t *cf)
{
    ngx_hls_cmd_app_conf_t          *hacf;

    hacf = ngx_pcalloc(cf->pool, sizeof(ngx_hls_cmd_app_conf_t));
    hacf->fraglen = NGX_CONF_UNSET_MSEC;
    hacf->playlen = NGX_CONF_UNSET_MSEC;

    hacf->type = NGX_CONF_UNSET_UINT;
    hacf->keys = NGX_CONF_UNSET;
    hacf->minfrags = NGX_CONF_UNSET;
    hacf->max_fraglen = NGX_CONF_UNSET_MSEC;
    hacf->slicing = NGX_CONF_UNSET_UINT;
    hacf->debug_log = NGX_CONF_UNSET_UINT;

    return hacf;
}


static char *
ngx_hls_cmd_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_hls_cmd_app_conf_t    *prev = parent;
    ngx_hls_cmd_app_conf_t    *conf = child;

    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);

    ngx_conf_merge_msec_value(conf->fraglen, prev->fraglen, 2000);
    ngx_conf_merge_msec_value(conf->max_fraglen, prev->max_fraglen, 6000);
    ngx_conf_merge_msec_value(conf->playlen, prev->playlen, 8000);
    if (conf->fraglen) {
        conf->winfrags = conf->playlen / conf->fraglen;
    }

    ngx_conf_merge_uint_value(conf->type, prev->type, NGX_HTTP_HLS_TYPE_LIVE);
    ngx_conf_merge_str_value(conf->base_url, prev->base_url, "");
    ngx_conf_merge_str_value(conf->key_url, prev->key_url, "");
    ngx_conf_merge_value(conf->keys, prev->keys, 0);
    ngx_conf_merge_uint_value(conf->minfrags, prev->minfrags, 3);
    if (conf->minfrags > conf->winfrags) {
        conf->minfrags = conf->winfrags;
    }
    ngx_conf_merge_uint_value(conf->slicing, prev->slicing, NGX_HTTP_HLS_SLICING_PLAIN);
    ngx_conf_merge_value(conf->debug_log, prev->debug_log, 0);

    return NGX_CONF_OK;
}


static ngx_mpegts_frag_t *
ngx_hls_cmd_get_frag(ngx_hls_session_t *hls, ngx_int_t n)
{
    ngx_m3u8_info_t            *m3u8;

    m3u8 = hls->m3u8;

    return &m3u8->frags[(m3u8->frag + n) % (m3u8->winfrags * 2 + 1)];
}


static void
ngx_hls_cmd_next_frag(ngx_hls_session_t *hls)
{
    ngx_m3u8_info_t            *m3u8;

    m3u8 = hls->m3u8;

    if (m3u8->nfrags == m3u8->winfrags) {
        m3u8->frag++;
    } else {
        m3u8->nfrags++;
    }
}


static void
ngx_hls_cmd_save_frame(FILE *fd, ngx_mpegts_frame_t *frame)
{
    ngx_chain_t                *cl;
    ngx_int_t                   rc;
    u_char                     *p;

    cl = frame->chain;
    for (; cl; cl = cl->next) {

        p = cl->buf->pos;
        while (cl->buf->last > p) {
            rc = fwrite(p, 1, cl->buf->last - p, fd);
            if (rc <= 0) {
                return;
            }
            p += rc;
        }
    }
}


static void
ngx_hls_cmd_save_static_frag(ngx_str_t *stream, ngx_str_t *session_id, ngx_mpegts_frame_t *patpmt,
                      ngx_mpegts_frame_t *start, ngx_mpegts_frame_t *end)
{
    u_char                      name[256] = {0};
    static FILE                *fd = NULL;
    ngx_mpegts_frame_t         *f;

    ngx_snprintf(name, sizeof(name), "%V_%V.ts", stream, session_id);

    if (!fd) {
        fd = fopen((char*)name, "wb");
        if (!fd) {
            return;
        }
        ngx_hls_cmd_save_frame(fd, patpmt);
    }

    for (f = start; f != end; f = f->next) {
        ngx_hls_cmd_save_frame(fd, f);
    }

    ngx_hls_cmd_save_frame(fd, f);
}


static void
ngx_hls_cmd_save_frag(ngx_hls_session_t *hls, ngx_mpegts_frag_t *frag)
{
    ngx_str_t                  *stream, *session_id;
    ngx_mpegts_frame_t         *patpmt, *start, *end;
    u_char                      name[256] = {0};
    FILE                       *fd;
    ngx_mpegts_frame_t         *f;

    stream = &hls->name;
    session_id = &hls->session_id;

    patpmt = frag->patpmt;
    start = frag->frame_header;
    end = frag->frame_tail;

    return;

    ngx_snprintf(name, sizeof(name), "%V_%V_%ud_%ud_%ud.ts",
                                  stream, session_id, start->pts, end->pts,
                                  (end->pts - start->pts)/90);
    fd = fopen((char*)name, "wb+");
    if (!fd) {
        return;
    }

    ngx_hls_cmd_save_frame(fd, patpmt);
    for (f = start; f != end; f = f->next) {
        ngx_hls_cmd_save_frame(fd, f);
    }

    ngx_hls_cmd_save_frame(fd, f);

    fclose(fd);

    ngx_hls_cmd_save_static_frag(stream, session_id, patpmt, start, end);

}


static void
ngx_hls_cmd_print_m3u8(ngx_hls_session_t *hls)
{
    ngx_log_t                   *log;
    ngx_mpegts_frag_t           *frag;
    ngx_uint_t                   i;
    ngx_m3u8_info_t             *m3u8;


#if !(NGX_DEBUG)
    return;
#endif

    m3u8 = hls->m3u8;
    log = hls->log;

    ngx_log_error(NGX_LOG_DEBUG, log, 0,
                          "hls-cmd: print_m3u8| "
                          "*****************************************");

    for (i = 0; i < m3u8->nfrags; i++) {
        frag = ngx_hls_cmd_get_frag(hls, i);

        ngx_log_error(NGX_LOG_DEBUG, log, 0,
                          "hls-cmd: print_m3u8| "
                          "%z-%z.ts, duration = %.3f",
                          frag->frame_header->pts, frag->frame_tail->pts,
                          frag->duration);
    }
    ngx_log_error(NGX_LOG_DEBUG, log, 0,
                          "hls-cmd: print_m3u8| "
                          "=========================================");
}


static ngx_int_t
ngx_hls_cmd_close_session(ngx_hls_session_t *hls)
{

    ngx_uint_t                   i;
    ngx_m3u8_info_t             *m3u8;
    ngx_live_stream_t           *stream = NULL;

    stream = hls->live_stream;
    m3u8 = hls->m3u8;

    ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                      "hls-cmd: close_session| "
                      "close hls session");

    for (i = 0; i < 2*m3u8->winfrags + 1; ++i) {
        ngx_hls_cmd_free_frag(hls, &m3u8->frags[i]);
    }

    ngx_live_delete_hls_ctx(hls);
    ngx_destroy_pool(hls->pool);

    if (stream && stream->hls_play_ctx == NULL) {
        ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                      "hls-cmd: close_session| "
                      "All hls sessions have been deleted,"
                      "finalize rtmp fake session created by mpegts module,"
                      "rtmp-session = %p",
                      stream->hls_publish_ctx->session);
        ngx_rtmp_finalize_fake_session(stream->hls_publish_ctx->session);
    }

    return NGX_OK;
}


ngx_int_t
ngx_hls_cmd_finalize_session(ngx_hls_session_t *hls)
{
    ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                          "hls-cmd: finalize_session| clean up hls session");

    ngx_hls_close(hls);

    return NGX_OK;
}


void
ngx_hls_cmd_free_frag(ngx_hls_session_t *hls, ngx_mpegts_frag_t *frag)
{
    ngx_mpegts_frame_t         *f, *next;

    if (frag == NULL || frag->frame_header == NULL || frag->frame_tail == NULL ||
        --frag->ref != 0) {
        return;
    }

    for (f = frag->frame_header; f != frag->frame_tail;) {

        ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                  "hls-cmd: free_frag| f = %p, "
                  "frame pts = %uD, pos = %uD, ref = %uD",
                  f, f->pts/90, f->pos, f->ref);

        next = f->next;
        ngx_rtmp_shared_free_mpegts_frame(f);

        f = next;
    }

    ngx_rtmp_shared_free_mpegts_frame(f);
    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                  "hls-cmd: free_frag| f = %p, "
                  "frame pts = %uD, pos = %uD, ref = %uD",
                  f, f->pts/90, f->pos, f->ref);

    ngx_rtmp_shared_free_mpegts_frame(frag->patpmt);

    return;
}


static void
ngx_hls_cmd_print_frag(u_char *name, ngx_mpegts_frag_t *fg)
{
    FILE                       *file;
    u_char                      content[1024] = {0};
    u_char                     *p, *e;
    ngx_mpegts_frame_t         *f;
    u_char                      type[4] = {0};

    time_t                      timer;
    struct tm                  *tblock;

    file = fopen((char*)name, "ab+");

    p = &content[0];
    e = &content[1023];


    timer = time(NULL);

    tblock = localtime(&timer);

    e = ngx_slprintf(p, e, "%sfrag %s, ref=%d, id=%uL\n",
        asctime(tblock), fg->name, fg->ref, fg->frag_id);

    fwrite(p, 1, e - p, file);
    p = e;
    e = &content[1023];

    for (f = fg->frame_header; f; f = f->next) {
        switch(f->type) {
            case NGX_RTMP_MPEGTS_TYPE_VIDEO:
                if (f->key) {
                    ngx_snprintf(type, sizeof(type), "-K");
                } else {
                    ngx_snprintf(type, sizeof(type), "-P");
                }
                break;
            case NGX_RTMP_MPEGTS_TYPE_AUDIO:
                ngx_snprintf(type, sizeof(type), "-A");
                break;
            case NGX_RTMP_MPEGTS_TYPE_PATPMT:
                ngx_snprintf(type, sizeof(type), "-T");
                break;
        }
        e = ngx_slprintf(p, e, "type = %s, f=%p, next=%p, pos=%uL, ref=%d, pts=%uL\n",
            type, f, f->next, f->pos, f->ref, f->pts);

        fwrite(p, 1, e - p, file);

        if (f == fg->frame_tail) {
            break;
        }
    }

    fclose(file);
}


static void
ngx_hls_cmd_write_frame(ngx_hls_session_t *hls, ngx_mpegts_frame_t *f)
{
    ngx_mpegts_frag_t          *frag;
    ngx_m3u8_info_t            *m3u8;

    ngx_rtmp_shared_acquire_mpegts_frame(f);

    m3u8 = hls->m3u8;
    frag = ngx_hls_cmd_get_frag(hls, m3u8->nfrags);
    if (frag->frame_header == NULL) {
        frag->frame_header = f;
    }
    frag->frame_tail = f;
    frag->content_length += f->length;
}


static void
ngx_hls_cmd_close_fragment(ngx_hls_session_t *hls)
{
    ngx_hls_cmd_ctx_t          *ctx;
    ngx_mpegts_frag_t          *frag;
    u_char                      frag_log[1024] = {0};

    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    if (ctx->opened == 0) {
        return;
    }

    frag = ngx_hls_cmd_get_frag(hls, hls->m3u8->nfrags);
    *ngx_snprintf(frag->name, sizeof(frag->name), "%V-%uL-%uL.ts",
                 &hls->name, frag->frame_header->pts/90, frag->frame_tail->pts/90) = 0;
    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0, "hls-cmd: close_fragment| frag = %p, ts file %s",
                  frag, frag->name);
    ngx_hls_cmd_print_m3u8(hls);
    if (hls->m3u8->debug_log) {
        ngx_snprintf(frag_log, sizeof(frag_log), "%V_origin.log", &hls->session_id);
        ngx_hls_cmd_print_frag(frag_log, frag);
        ngx_hls_cmd_save_frag(hls, frag);
    }

    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    ctx->opened = 0;

    ngx_hls_cmd_next_frag(hls);
}


static ngx_int_t
ngx_hls_cmd_set_para(ngx_hls_session_t *hls)
{
    ngx_rtmp_codec_ctx_t       *codec_ctx;
    ngx_hls_cmd_ctx_t          *ctx;

    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    codec_ctx = ngx_rtmp_get_module_ctx(hls->live_stream->publish_ctx->session,
                                        ngx_rtmp_codec_module);

    if (ctx == NULL || codec_ctx == NULL) {
        return NGX_OK;
    }

    if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_MP3) {
        ctx->audio_type = TS_AUDIO_TYPE_MP3;
    } else if (codec_ctx->audio_codec_id == NGX_RTMP_AUDIO_AAC){
        ctx->audio_type = TS_AUDIO_TYPE_AAC;
    }
    /* pure audio support aac and mp3 */
    if (codec_ctx->aac_header
        && NULL == codec_ctx->avc_header
        && (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264
            || codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H265))
    {
        ctx->audio_only = 1;
    }

    if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264){
        ctx->video_type = TS_VIDEO_TYPE_H264;
    } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) {
        ctx->video_type = TS_VIDEO_TYPE_H265;
    }
    /* pure video support h264 h265 */
    if (codec_ctx->avc_header
        && NULL == codec_ctx->aac_header
        && (codec_ctx->audio_codec_id == 0
            || (codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC
                && codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_MP3)))
    {
        ctx->video_only = 1;
    }

    return NGX_OK;
}


static void
ngx_hls_cmd_open_fragment(ngx_hls_session_t *hls, uint64_t ts, ngx_int_t discont)
{
    ngx_hls_cmd_ctx_t          *ctx;
    ngx_mpegts_frag_t          *frag;
    ngx_m3u8_info_t            *m3u8;

    m3u8 = hls->m3u8;
    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    ctx->opened = 1;

    ngx_hls_cmd_set_para(hls);

    frag = ngx_hls_cmd_get_frag(hls, m3u8->nfrags);
    if (frag->patpmt) {
        ngx_hls_cmd_free_frag(hls, frag);
    }

    ngx_memzero(frag, sizeof(*frag));

    frag->ref = 1;
    frag->discont = discont;
    frag->patpmt = ngx_rtmp_mpegts_patpmt(hls);
    ngx_rtmp_shared_acquire_mpegts_frame(frag->patpmt);
    frag->frag_id = m3u8->frag + m3u8->nfrags;
    frag->content_length += frag->patpmt->length;
    ctx->frag_ts = ts;
}


static ngx_int_t
ngx_hls_cmd_update_fragment(ngx_hls_session_t *hls, ngx_mpegts_frame_t *f, ngx_int_t boundary)
{
    ngx_m3u8_info_t            *m3u8;
    ngx_hls_cmd_ctx_t          *ctx;
    ngx_mpegts_frag_t          *frag;
    ngx_msec_t                  ts_frag_len;
    ngx_int_t                   same_frag, force, discont;
    int64_t                     d;
    uint64_t                    ts;

    ts = f->pts;
    m3u8 = hls->m3u8;

    frag = NULL;
    force = 0;
    discont = 1;
    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);

    d = (int64_t) (ts - ctx->frag_ts);

    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                      "hls-cmd: update_fragment| fragment, boundary = %d, opened = %d, key = %d "
                      "type = %d, pos = %uL, frag_ts %uL, ts %uL, split: %.3f sec, ",
                      boundary, ctx->opened, f->key, f->type,
                      f->pos, ctx->frag_ts, ts, d / 90000.);

    if (ctx->opened) {
        frag = ngx_hls_cmd_get_frag(hls, m3u8->nfrags);
        if (d > (int64_t) m3u8->max_fraglen * 90 || d < -90000) {
            ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                          "hls-cmd: update_fragment| force fragment"
                          " frag_ts %uL, ts %uL, split: %.3f sec, ",
                          ctx->frag_ts, ts, d / 90000.);
            force = 1;
        } else {
            frag->duration = (ts - ctx->frag_ts) / 90000.;
            discont = 0;
        }
    }

    switch (m3u8->slicing) {
        case NGX_HTTP_HLS_SLICING_PLAIN:
            if (frag && frag->duration < m3u8->fraglen / 1000.) {
                boundary = 0;
            }
            break;

        case NGX_HTTP_HLS_SLICING_ALIGNED:

            ts_frag_len = m3u8->fraglen * 90;
            same_frag = ctx->frag_ts / ts_frag_len == ts / ts_frag_len;

            if (frag && same_frag) {
                boundary = 0;
            }

            if (frag == NULL && (ctx->frag_ts == 0 || same_frag)) {
                ctx->frag_ts = ts;
                boundary = 0;
            }

            break;
    }

    if (boundary || force) {
        ngx_hls_cmd_close_fragment(hls);
        ngx_hls_cmd_open_fragment(hls, ts, discont);

        return NGX_OK;
    }

    return NGX_AGAIN;
}


ngx_int_t
ngx_hls_cmd_update_frags(ngx_hls_session_t *hls)
{
    ngx_hls_cmd_ctx_t          *ctx;
    ngx_rtmp_mpegts_ctx_t      *mctx;
    ngx_live_stream_t          *live_stream;
    ngx_mpegts_frame_t         *f, *lf, *tf, *kf;
    int64_t                     delta;
    ngx_m3u8_info_t            *m3u8;
    ngx_uint_t                  frags;
    ngx_int_t                   boundary;
    ngx_uint_t                  n;
    ngx_uint_t                  pos, last;

    boundary = 0;
    m3u8 = hls->m3u8;
    live_stream = hls->live_stream;
    if (live_stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                      "hls-cmd: update_frags| live stream is null");
        return NGX_ERROR;
    }

    mctx = live_stream->hls_publish_ctx;
    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    if (mctx == NULL || ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                      "hls-cmd: update_frags| publish ctx is %p, ctx is %p",
                      mctx, ctx);
        return NGX_ERROR;
    }

    if ((time(NULL) - hls->last_update)*1000 >
         3 * m3u8->max_fraglen * m3u8->winfrags)
    {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                    "hls-cmd: update_frags| "
                    "timeout %ui, last_update %ui, current time %ui",
                    hls->timeout, hls->last_update, time(NULL));
        return NGX_ERROR;
    }
    // ctx->updated
    // val : 0, first time update
    // val : 1, nfrags < winfrags, building m3u8
    // val : 2, nfrags >= winfrags, m3u8 is enabled
    if (ctx->updated == 0) {
        ctx->cache_pos = mctx->cache_pos;
    }

    f = mctx->cache[ctx->cache_pos];
    last = ngx_rtmp_mpegts_prev(mctx, mctx->cache_last);
    lf = mctx->cache[last];

    if (mctx->cache_pos == mctx->cache_last ||
        ctx->cache_pos == mctx->cache_last ||
        f == NULL || lf == NULL)
    {
        ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                      "hls-cmd: update_frags| "
                      "mpegts buffer is empty,"
                      "ctx pos %ui, mctx pos %ui, mctx last %ui, curr frame %p",
                      ctx->cache_pos, mctx->cache_pos, mctx->cache_last,
                      mctx->cache[mctx->cache_pos]);
        return NGX_AGAIN;
    }

    m3u8 = hls->m3u8;
    delta = (int64_t)(lf->pts - f->pts);
/*
    if (delta > -90000 && delta < (int64_t)m3u8->fraglen*90) {
        ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                      "hls-cmd: update_frags| "
                      "There is no enough data for a ts file,"
                      "first pts = %ui, last pts = %ui, fraglen %ui",
                      f->pts/90, lf->pts/90, m3u8->fraglen);
        return NGX_AGAIN;
    }
*/
    // too many mpegts-frames, drop frames and skip to key frame
    while ((ctx->updated == 0 || m3u8->nfrags == m3u8->winfrags) &&
           delta > (int64_t)(m3u8->minfrags*m3u8->fraglen*90))
    {
        ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                      "hls-cmd: update_frags| "
                      "pos = %uD, too many mpegts-frames, drop frames and skip to key frame",
                      f->pos);

        for (tf = f; tf && !tf->key; tf = tf->next);
        if (tf == NULL) {
            break;
        }

        if (ctx->updated == 0) {
            n = m3u8->minfrags;
        } else {
            n = 1;
        }

        kf = NULL;
        delta = (int64_t)(lf->pts - tf->pts);
        while((tf->key_next != NULL) && (delta >= (int64_t)(n*m3u8->fraglen*90))) {
            kf = tf;
            tf = tf->key_next;
            delta = (int64_t)(lf->pts - tf->pts);
        }

        if (kf) {
            f = kf;
            ctx->cache_pos = f->pos;
        }

        break;
    }

    if (ctx->updated == 0) {
        ctx->updated = 1;
    }

    m3u8 = hls->m3u8;
    frags = 0;

    pos = ctx->cache_pos;
    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                  "hls-cmd: update_frags| f = %p, pos = %ui", f, pos);
    while (((ctx->updated < 2 && m3u8->nfrags < m3u8->minfrags) ||
            (ctx->updated == 2 && frags < m3u8->winfrags)) &&
           pos != mctx->cache_last)
    {
        boundary = 0;
        f = mctx->cache[pos];
        if ((f->key && (!ctx->opened || mctx->last_audio)) ||
            (f->type == NGX_RTMP_MPEGTS_TYPE_AUDIO && mctx->last_video == NULL))
        {
            boundary = 1;
        }

        frags = m3u8->frag + m3u8->nfrags;
        ngx_hls_cmd_update_fragment(hls, f, boundary);
        frags = m3u8->frag + m3u8->nfrags - frags;

        ngx_hls_cmd_write_frame(hls, f);

        pos = ngx_rtmp_mpegts_next(mctx, pos);
    }

    ctx->cache_pos = pos;

    if (ctx->updated < 2 && m3u8->nfrags >= m3u8->minfrags) {
        // first time enough frags
        ngx_hls_play(hls);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_hls_cmd_m3u8_init(ngx_hls_session_t *hls)
{
    ngx_hls_cmd_app_conf_t     *hacf;
    ngx_rtmp_mpegts_app_conf_t *macf;
    u_char                     *p;

    hacf = ngx_rtmp_get_module_app_conf(hls, ngx_hls_cmd_module);
    macf = ngx_rtmp_get_module_app_conf(hls, ngx_rtmp_mpegts_module);

    p = ngx_pcalloc(hls->pool, sizeof(ngx_m3u8_info_t)+
                sizeof(ngx_mpegts_frag_t)*(hacf->winfrags*2+1));
    if (p == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                          "hls-cmd: m3u8_init| "
                          "memory error, alloc m3u8 failed");
        return NGX_ERROR;
    }

    hls->m3u8 = (ngx_m3u8_info_t*)p;
    hls->m3u8->winfrags = hacf->winfrags;
    hls->m3u8->fraglen  = hacf->fraglen;
    hls->m3u8->minfrags = hacf->minfrags;
    hls->m3u8->max_fraglen = hacf->max_fraglen;
    hls->m3u8->slicing = hacf->slicing;
    hls->m3u8->type = hacf->type;
    hls->m3u8->debug_log = hacf->debug_log;

    hls->out_queue = macf->out_queue;

    p += sizeof(ngx_m3u8_info_t);

    return NGX_OK;
}


static u_char *
ngx_hls_cmd_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_hls_session_t          *hls;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    hls = log->data;

    p = ngx_snprintf(buf, len, ", *live-stream %p*", hls->live_stream);
    len -= p - buf;
    buf = p;

    p = ngx_snprintf(buf, len, ", hls-session: %V", &hls->session_id);
    len -= p - buf;
    buf = p;

    p = ngx_snprintf(buf, len, ", stream: %V", &hls->stream);
    len -= p - buf;
    buf = p;

    if (hls->live_server == NULL) {
        return p;
    }
    p = ngx_snprintf(buf, len, ", server: %s", hls->live_server->serverid);
    len -= p - buf;
    buf = p;

    return p;
}


ngx_hls_session_t*
ngx_hls_cmd_init_session(ngx_mpegts_play_t *v, ngx_str_t *session_id)
{
    ngx_rtmp_addr_conf_t       *addr_conf = v->addr_conf;
    ngx_int_t                   rc;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_hls_session_t          *hls = NULL;
    ngx_hls_cmd_app_conf_t     *hacf;
    void                      **app_conf = NULL;
    ngx_log_t                  *log;
    ngx_uint_t                  n;
    ngx_str_t                  *stream;
    ngx_live_stream_t          *live_stream;
    ngx_live_server_t          *live_server;
    ngx_str_t                  *serverid;

    stream = &v->stream;
    serverid = &v->serverid;

    log = v->log;

    cscf = addr_conf->default_server->ctx->
            srv_conf[ngx_rtmp_core_module.ctx_index];

    live_server = ngx_live_create_server(serverid);
    if (live_server == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                          "hls-cmd: init_session| "
                          "create server failed, svr=%V, stream=%V",
                          serverid, stream);
        return NULL;
    }

    live_stream = ngx_live_create_stream(serverid, stream);
    if (live_stream == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "hls-cmd: init_session| "
                      "create stream failed, svr=%V, stream=%V",
                      serverid, stream);
        return NULL;
    }

    if (live_stream->hls_publish_ctx == NULL) {
        rc = ngx_rtmp_mpegts_start(v);
        if (rc == NGX_ERROR) { // memory leak, maybe lose live_stream memory
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "hls-cmd: init_session| "
                          "start mpegts stream failed, svr=%V, stream=%V",
                          serverid, stream);
            return NULL;
        }
    }

    cacfp = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == v->app.len &&
            ngx_strncmp((*cacfp)->name.data, v->app.data, v->app.len) == 0)
        {
            /* found app! */
            app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (NULL == app_conf) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "hls-cmd: init_session| "
                      "unknown application, svr=%V, stream=%V",
                      serverid, stream);
        return NULL;
    }

    hacf = app_conf[ngx_hls_cmd_module.ctx_index];

    hls = ngx_pcalloc(hacf->pool, sizeof(ngx_hls_session_t));

    hls->main_conf = addr_conf->default_server->ctx->main_conf;
    hls->srv_conf  = addr_conf->default_server->ctx->srv_conf;
    hls->app_conf  = app_conf;

    hls->live_server = live_server;
    hls->live_stream = live_stream;

    hls->pool = ngx_create_pool(1024, ngx_cycle->log);
    if (NULL == hls->pool) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "hls-cmd: init_session| "
                      "create pool failed, svr=%V, stream=%V",
                      serverid, stream);
        goto failed;
    }

    log = ngx_pcalloc(hls->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto failed;
    }

    *log = *v->log;
    hls->log = log;
    log->connection = 0;
    log->action = NULL;
    log->data = hls;
    log->handler = ngx_hls_cmd_log_error;

    hls->timeout = cscf->timeout;

#define NGX_HLS_CMD_SESSION_COPY(to, from)             \
    hls->to.data = ngx_pcalloc(hls->pool, from.len);   \
    if (hls->to.data == NULL) { return NULL; }         \
    hls->to.len = from.len;                            \
    ngx_memcpy(hls->to.data, from.data, from.len);

    NGX_HLS_CMD_SESSION_COPY(session_id, (*session_id));
    NGX_HLS_CMD_SESSION_COPY(name, v->name);
    NGX_HLS_CMD_SESSION_COPY(stream, v->stream);

	hls->ctx = ngx_pcalloc(hls->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (ngx_live_create_hls_ctx(hls) != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "hls-cmd: init_session| "
                      "create hls ctx failed");
        goto failed;
    }

    ngx_rtmp_set_ctx(hls, live_stream->hls_publish_ctx, ngx_rtmp_mpegts_module);

    ngx_log_error(NGX_LOG_INFO, log, 0,
                      "hls-cmd: init_session| "
                      "create hls session success %p", hls);

    //init hls->m3u8
    if (ngx_hls_cmd_m3u8_init(hls)!=NGX_OK) {
        goto failed;
    }

    return hls;

failed:
    ngx_hls_cmd_finalize_session(hls);
    return NULL;
}


ngx_hls_session_t*
ngx_hls_cmd_find_session(ngx_str_t *server_id,
                         ngx_str_t *stream,
                         ngx_str_t *session_id)
{
    ngx_live_stream_t               *live_stream;
    ngx_hls_cmd_ctx_t               *ctx;
    ngx_hls_session_t               *hls;

    hls = NULL;

    live_stream = ngx_live_create_stream(server_id, stream);
    if (live_stream == NULL) {
        return NULL;
    }

    for (ctx = live_stream->hls_play_ctx; ctx; ctx = ctx->next) {
        hls = ctx->session;
        if (hls->session_id.len == session_id->len &&
           !ngx_strncmp(hls->session_id.data, session_id->data, session_id->len))
        {
            return hls;
        }
    }

    return NULL;
}


ngx_int_t
ngx_hls_cmd_create_m3u8_string(ngx_hls_session_t *hls, ngx_buf_t *buf)
{
    u_char                         *p, *end;
    ngx_mpegts_frag_t              *frag;
    ngx_uint_t                      i, max_frag;
    ngx_m3u8_info_t                *m3u8;
    ngx_str_t                       mstring;
    ngx_hls_cmd_app_conf_t         *hacf;

    hacf = ngx_rtmp_get_module_app_conf(hls, ngx_hls_cmd_module);

    m3u8 = hls->m3u8;

    hls->last_update = time(NULL);

    if(m3u8->nfrags < m3u8->minfrags) {
        ngx_log_error(NGX_LOG_INFO, hls->log, 0,
                "hls-cmd: m3u8_string| "
                "nfrags < minfrags (%uD < %uD)", m3u8->nfrags, m3u8->minfrags);
        return NGX_AGAIN;
    }

    max_frag = m3u8->fraglen / 1000;

    for (i = 0; i < m3u8->nfrags; i++) {
        frag = ngx_hls_cmd_get_frag(hls, i);
        if (frag->duration > max_frag) {
            max_frag = (ngx_uint_t) (frag->duration + .5);
        }
    }

    p = buf->pos;
    end = buf->end;

    p = ngx_slprintf(p, end,
                     "#EXTM3U\n"
                     "#EXT-X-VERSION:3\n"
                     "#EXT-X-MEDIA-SEQUENCE:%uL\n"
                     "#EXT-X-TARGETDURATION:%ui\n",
                     m3u8->frag, max_frag);

    if (m3u8->type == NGX_HTTP_HLS_TYPE_EVENT) {
        p = ngx_slprintf(p, end, "#EXT-X-PLAYLIST-TYPE: EVENT\n");
    }

    for (i = 0; i < m3u8->nfrags; i++) {
        frag = ngx_hls_cmd_get_frag(hls, i);

        if (frag->discont) {
            p = ngx_slprintf(p, end, "#EXT-X-DISCONTINUITY\n");
        }

        p = ngx_slprintf(p, end,
                          "#EXTINF:%.3f,\n"
                          "%V%s?session=%V&name=%V\n",
                          frag->duration,
                         &hacf->base_url,
                          frag->name,
                         &hls->session_id,
                         &hls->name);
    }

    buf->last = p;

    mstring.data = buf->pos;
    mstring.len = buf->last - buf->pos;

    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                     "hls-cmd: m3u8_string| \n"
                     "%V", &mstring);

    return NGX_OK;
}


ngx_chain_t*
ngx_hls_cmd_append_chain(ngx_chain_t *chain, ngx_mpegts_frame_t *f)
{
    ngx_chain_t                        *cl, *tl, *hl, *ll;

    hl = NULL;
    tl = NULL;
    ll = NULL;
    for (cl = f->chain; cl; cl = cl->next) {
        tl = ngx_get_chainbuf(0, 0);
        if (hl == NULL) {
            hl = tl;
        }
        *(tl->buf) = *(cl->buf);
        if (ll) {
            ll->next = tl;
        }

        ll = tl;
    }

    if (chain) {
        chain->next = hl;
    } else {
        return hl;
    }

    return tl;
}


static void
ngx_hls_cmd_save_chain(char *file, ngx_chain_t *cl)
{
    FILE                                *fd;
    ngx_buf_t                           *buf;

    return;
    fd = fopen(file, "ab+");
    for (; cl; cl = cl->next) {
        buf = cl->buf;
        fwrite(buf->pos, 1, buf->last - buf->pos, fd);
    }

    fclose(fd);
}


ngx_chain_t*
ngx_hls_cmd_prepare_chain(ngx_hls_session_t *hls, ngx_mpegts_frag_t *frag)
{
    ngx_chain_t                         *hl, *tl;
    ngx_mpegts_frame_t                  *f;
    u_char                               frag_log[1024] = {0};
    u_char                               file[1024] = {0};

    hl = ngx_hls_cmd_append_chain(NULL, frag->patpmt);
    ngx_rtmp_shared_acquire_mpegts_frame(frag->patpmt);

    for (tl = hl; tl->next; tl = tl->next);

    for (f = frag->frame_header; f != frag->frame_tail; f = f->next) {
        tl = ngx_hls_cmd_append_chain(tl, f);
        ngx_rtmp_shared_acquire_mpegts_frame(f);
    }

    tl = ngx_hls_cmd_append_chain(tl, f);
    ngx_rtmp_shared_acquire_mpegts_frame(f);
    tl->buf->last_in_chain = 1;
    tl->buf->last_buf = 1;
    ngx_hls_cmd_acquire_frag(frag);

    if (hls->m3u8->debug_log) {
        ngx_snprintf(frag_log, sizeof(frag_log), "%V_prepare.log", &hls->session_id);
        ngx_snprintf(file, sizeof(file), "%V_prepare.ts", &hls->session_id);
        ngx_hls_cmd_print_frag(frag_log, frag);
        ngx_hls_cmd_save_chain((char*)file, hl);
    }

    return hl;
}


ngx_mpegts_frag_t *
ngx_hls_cmd_find_frag(ngx_hls_session_t *hls, ngx_str_t *name)
{
    ngx_mpegts_frag_t                  *frag;
    ngx_uint_t                          i;
    ngx_m3u8_info_t                    *m3u8;

    m3u8 = hls->m3u8;

    ngx_log_error(NGX_LOG_DEBUG, hls->log, 0,
                      "hls-cmd: find_frag| finding frag %V", name);

    for (i = 0; i < m3u8->nfrags; i++) {
        frag = ngx_hls_cmd_get_frag(hls, i);
        if (name->len == ngx_strlen(frag->name) &&
            ngx_strncmp(frag->name, name->data, name->len) == 0)
        {
            return frag;
        }
    }

    ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                      "hls-cmd: find_frag| cannot find frag %V", name);

    return NULL;
}


static ngx_int_t
ngx_hls_cmd_mpegts_av(ngx_rtmp_session_t *s,
                      ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_hls_cmd_ctx_t                  *ctx, *pctx;
    ngx_int_t                           rc;

    for (ctx = s->live_stream->hls_play_ctx; ctx;) {
        pctx = ctx->next;
        rc = ngx_hls_cmd_update_frags(ctx->session);
        if (rc == NGX_ERROR) {
            ngx_hls_cmd_finalize_session(ctx->session);
        }
        ctx = pctx;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_hls_cmd_close_stream(ngx_rtmp_session_t *s,
                         ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_hls_cmd_ctx_t                  *ctx, *pctx;
    ngx_hls_session_t                  *hls;

    if (s->live_type != NGX_HLS_LIVE) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "hls-cmd: close_stream| "
                          "mpegts stream has been closed ,so close hls sessions");

    ctx = s->live_stream->hls_play_ctx;
    while (ctx) {
        pctx = ctx->next;

        hls = ctx->session;
        ngx_hls_cmd_finalize_session(hls);

        ctx = pctx;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_hls_cmd_hls_play_init(ngx_hls_session_t *hls)
{
    ngx_hls_cmd_ctx_t                  *ctx;

    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    ctx->updated = 2;

    return NGX_OK;
}


static ngx_int_t
ngx_hls_cmd_hls_close_init(ngx_hls_session_t *hls)
{
    ngx_hls_cmd_close_session(hls);
    return NGX_OK;
}



static ngx_int_t
ngx_hls_cmd_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MPEGTS_AV]);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_hls_cmd_mpegts_av;


    h = ngx_array_push(&cmcf->events[NGX_RTMP_MPEGTS_CLOSE_STREAM]);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_hls_cmd_close_stream;

    next_hls_play = ngx_hls_play;
    ngx_hls_play = ngx_hls_cmd_hls_play_init;

    next_hls_close = ngx_hls_close;
    ngx_hls_close = ngx_hls_cmd_hls_close_init;

    return NGX_OK;
}


