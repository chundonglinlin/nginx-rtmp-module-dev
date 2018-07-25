#ifndef _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#define _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#include "ngx_map.h"
#include "ngx_rtmp.h"

#define NGX_HTTP_DEFAULT                   0
#define NGX_HTTP_QQFLV_NORMAL              1
#define NGX_HTTP_QQFLV_PLAYBACK            2
#define NGX_HTTP_QQFLV_SOURCE              3
#define NGX_HTTP_QQFLV_BLOCK               4
#define NGX_HTTP_QQFLV_PIECE               5
#define NGX_HTTP_QQFLV_IDLE                6

typedef struct ngx_http_qqflv_loc_conf_s ngx_http_qqflv_loc_conf_t;

typedef struct {
    ngx_str_t                       path;
    ngx_pool_t                     *pool;
    ngx_map_t                       channel_map;
    ngx_queue_t                     channel_queue;
    ngx_queue_t                     idle_block_index;
} ngx_http_qqflv_main_conf_t;

typedef struct {
    ngx_chain_t                     *head;
    unsigned                        buname:1;
    unsigned                        xHttpTrunk:1;
    unsigned                        block_sent:1;
    unsigned                        type:3;
    ngx_int_t                       backsec;    
    ngx_int_t                       blockid;
    ngx_int_t                       piecesize;
    ngx_str_t                       channel_name;
    time_t                          timestamp;
    ngx_file_t                      file;
    ngx_chain_t                    *out_chain;
    ngx_qq_flv_index_t             *qq_flv_index;
    ngx_qq_flv_block_index_t       *qq_flv_block_index;
}ngx_http_qqflv_ctx_t;

typedef ngx_int_t (*ngx_http_qqflv_request_handler_pt)(ngx_http_request_t *r);

typedef struct {

    ngx_int_t                                type;
    ngx_str_t                                name;
    ngx_http_qqflv_request_handler_pt        handler;

} ngx_http_qqflv_request_cmd_t;

struct ngx_http_qqflv_loc_conf_s {
    ngx_http_qqflv_loc_conf_t      *parent;
};

ngx_int_t ngx_http_qqflv_insert_block_index(ngx_str_t channel_name, time_t timestamp,
                                ngx_qq_flv_header_t qqflvhdr, off_t file_offset,
                                ngx_qq_flv_index_t *qq_flv_index, unsigned curflag);

ngx_int_t ngx_http_qqflv_write_index_file(ngx_file_t *index_file, ngx_qq_flv_header_t *qqflvhdr,
                            off_t index_offset);

ngx_int_t ngx_http_qqflv_open_index_file(ngx_str_t *path, ngx_file_t *index_file, 
                                    ngx_log_t *log, ngx_str_t *id, ngx_flag_t *lock_file, 
                                    u_char *channel_name);

ngx_int_t ngx_http_relay_parse_qq_flv(ngx_rtmp_session_t *s, ngx_buf_t *b);

ngx_chain_t * ngx_http_qqflv_live_prepare_out_chain(ngx_http_request_t *r, ngx_rtmp_session_t *s, 
                                                ngx_rtmp_frame_t *frame, unsigned sourceflag);

#endif