#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rtmp.h>

#ifndef _NGX_HTTP_HLS_LIVE_MODULE_H_
#define _NGX_HTTP_HLS_LIVE_MODULE_H_

typedef struct {
    ngx_str_t                           suffix;
    ngx_array_t                         args;
} ngx_http_hls_live_variant_t;

typedef struct {
	ngx_str_t                   app;
    ngx_str_t                   flashver;
    ngx_str_t                   swf_url;
    ngx_str_t                   tc_url;
    ngx_str_t                   page_url;
	size_t                      out_queue;
	ngx_msec_t                  timeout;
    ngx_listening_t            *ls;
	ngx_str_t                   hls_live_base_url;
	ngx_flag_t                  hls_live_nested;
} ngx_http_hls_live_loc_conf_t;

typedef struct {
    ngx_array_t                *hls_live_variant;
} ngx_http_hls_live_loc_dconf_t;


#define ngx_strrchr(s1, c)     strrchr((const char *) s1, (int) c)
#define ngx_strcat(s1, s2)     strcat((char *)s1, (const char *)s2)
#define ngx_slstring(str)      { ngx_strlen(str), (u_char *) str }

#define NGX_MPEGTS_MSG_PAT              1
#define NGX_MPEGTS_MSG_PMT              2
#define NGX_MPEGTS_MSG_TS               3

typedef struct {
    ngx_str_t                   app;
    ngx_str_t                   name;
    ngx_str_t                   stream;
    ngx_str_t                   serverid;
    ngx_str_t                   sid;
    ngx_hls_session_t          *hls;
    ngx_msec_t                  timeout;

    ngx_buf_t                  *mbuf;

    ngx_mpegts_frame_t         *out_frame;
    ngx_chain_t                *out_chain;
    ngx_mpegts_frag_t          *frag;

    ngx_uint_t                  out_pos;
    ngx_uint_t                  out_last;
	ngx_uint_t                  out_queue;
    ngx_mpegts_frame_t         *out[0];
} ngx_http_hls_live_ctx_t;


typedef struct {
    ngx_http_hls_live_variant_t  variant[512];
    ngx_uint_t                   size;
	ngx_int_t                    flag;
}hls_bite_rate;



extern ngx_module_t  ngx_http_hls_live_module;


#endif

