#ifndef _NGX_HLS_CMD_MODULE_H
#define _NGX_HLS_CMD_MODULE_H

#include "ngx_rtmp_mpegts_module.h"
#define NGX_HLS_MAX_SESSION 128

typedef struct ngx_hls_cmd_app_conf_s ngx_hls_cmd_app_conf_t;
typedef struct ngx_hls_heartbeat_s ngx_hls_heartbeat_t;


struct ngx_hls_heartbeat_s {
    ngx_hls_session_t     *hls;
    u_char                 sid[NGX_HLS_MAX_SESSION];
    ngx_hls_heartbeat_t   *next;
};


struct ngx_hls_cmd_app_conf_s {
    ngx_pool_t              *pool;
    ngx_msec_t               max_fraglen;
    ngx_msec_t               fraglen;          // ts length msec
    ngx_msec_t               playlen;          // m3u8 length msec
    ngx_uint_t               winfrags;         // hls_cmd_playlen/hls_cmd_fraglen
    ngx_uint_t               minfrags;
    ngx_uint_t               slicing;

    ngx_uint_t               type;
    ngx_str_t                base_url;
    ngx_str_t                key_url;
    ngx_flag_t               keys;
    ngx_flag_t               debug_log;
};

typedef ngx_int_t (*ngx_hls_play_pt)(ngx_hls_session_t *hls);
extern ngx_hls_play_pt ngx_hls_play;
typedef ngx_int_t (*ngx_hls_close_pt)(ngx_hls_session_t *hls);
extern ngx_hls_close_pt ngx_hls_close;

ngx_hls_session_t*
ngx_hls_cmd_init_session(ngx_mpegts_play_t *v, ngx_str_t *session_id);

ngx_hls_session_t*
ngx_hls_cmd_find_session(ngx_str_t *sever_id,
                     ngx_str_t *stream, ngx_str_t *session_id);

ngx_int_t
ngx_hls_cmd_update_frags(ngx_hls_session_t *hs);

ngx_int_t
ngx_hls_cmd_finalize_session(ngx_hls_session_t *hs);

ngx_int_t
ngx_hls_cmd_create_m3u8_string(ngx_hls_session_t *hs, ngx_buf_t *buf);

ngx_chain_t *
ngx_hls_cmd_prepare_chain(ngx_hls_session_t *hls, ngx_mpegts_frag_t *frag);
ngx_mpegts_frag_t *
ngx_hls_cmd_find_frag(ngx_hls_session_t *hls, ngx_str_t *name);
void
ngx_hls_cmd_free_frag(ngx_hls_session_t *hls, ngx_mpegts_frag_t *frag);

#endif

