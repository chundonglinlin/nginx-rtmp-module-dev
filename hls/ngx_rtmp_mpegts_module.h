#ifndef _NGX_RTMP_MPEGTS_MODULE_H
#define _NGX_RTMP_MPEGTS_MODULE_H

#define NGX_MPEGTS_BUF_SIZE   1316
#define NGX_RTMP_MPEG_BUFSIZE 1024*1024

#define TS_AUDIO_TYPE_AAC    0
#define TS_AUDIO_TYPE_MP3    1

#define TS_VIDEO_TYPE_H264   0
#define TS_VIDEO_TYPE_H265   1


typedef struct ngx_mpegts_play_s ngx_mpegts_play_t;

struct ngx_mpegts_play_s {
    ngx_str_t               name;
    /* connection parameters */
    ngx_rtmp_addr_conf_t   *addr_conf;
    ngx_str_t               app;
    ngx_str_t               stream;
    ngx_str_t               args;
    ngx_str_t               flashver;
    ngx_str_t               swf_url;
    ngx_str_t               tc_url;
    uint32_t                acodecs;
    uint32_t                vcodecs;
    ngx_str_t               page_url;
    ngx_str_t               domain;
    ngx_str_t               serverid;
    ngx_log_t              *log;
};

typedef struct ngx_rtmp_mpegts_app_conf_s {
    ngx_msec_t              cache_time;
    ngx_pool_t             *pool;
    ngx_hls_session_t      *free_session;
    size_t                  audio_buffer_size;
    ngx_msec_t              sync;
    ngx_msec_t              audio_delay;
    size_t                  out_queue;
    u_char                  packet_buffer[NGX_RTMP_MPEG_BUFSIZE];
} ngx_rtmp_mpegts_app_conf_t;

#define ngx_rtmp_mpegts_next(s, pos) ((pos + 1) % s->out_queue)
#define ngx_rtmp_mpegts_prev(s, pos) (pos == 0 ? s->out_queue - 1 : pos - 1)

ngx_int_t
ngx_rtmp_mpegts_start(ngx_mpegts_play_t *v);
ngx_mpegts_frame_t *
ngx_rtmp_mpegts_patpmt(ngx_hls_session_t *hls);

#endif
