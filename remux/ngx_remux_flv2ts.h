#ifndef _NGX_REMUX_FLV2TS_H_
#define _NGX_REMUX_FLV2TS_H_

typedef struct ngx_remux_file_s {
    ngx_int_t                           content_length;
    ngx_chain_t                        *content;
    ngx_chain_t                        *tail;
    void                               *remuxer;
    ngx_log_t                          *log;
} ngx_remux_file_t;

ngx_int_t
ngx_remux_flv2ts(ngx_fd_t fd, off_t pos, off_t last, ngx_remux_file_t *of);

void ngx_remux_flv2ts_destory(ngx_remux_file_t *file);
#endif