#ifndef _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#define _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#include "ngx_map.h"
#include "ngx_rtmp.h"

typedef struct ngx_http_qqflv_loc_conf_s ngx_http_qqflv_loc_conf_t;

typedef struct {
    ngx_str_t                       path;
    ngx_pool_t                     *pool;
    ngx_map_t                       channel_map;
    ngx_queue_t                     channel_queue;
    ngx_queue_t                     idle_block_index;
} ngx_http_qqflv_main_conf_t;

typedef struct {

    ngx_int_t       type;

    ngx_flag_t      variant_playback;

    ngx_int_t       start_time;
    ngx_int_t       end_time;

    ngx_str_t       auth;
    ngx_str_t       contentid;
    ngx_str_t       session_id;
    ngx_str_t       channel_name;


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
                                ngx_qq_flv_index_t *qq_flv_index);

ngx_int_t ngx_http_qqflv_write_index_file(ngx_file_t *index_file, ngx_qq_flv_header_t *qqflvhdr,
                            off_t index_offset);

ngx_int_t ngx_http_qqflv_open_index_file(ngx_str_t *path, ngx_file_t *index_file, 
                                    ngx_log_t *log, ngx_str_t *id, ngx_flag_t *lock_file, 
                                    u_char *channel_name);

#endif