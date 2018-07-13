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

struct ngx_http_qqflv_loc_conf_s {
    ngx_http_qqflv_loc_conf_t      *parent;
};

ngx_int_t ngx_http_qqflv_insert_block_index(ngx_str_t channel_name, time_t timestamp,
                                ngx_qq_flv_header_t qqflvhdr, off_t file_offset,
                                ngx_qq_flv_index_t *qq_flv_index);

#endif