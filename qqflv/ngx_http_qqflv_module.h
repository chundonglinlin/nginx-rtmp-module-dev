#ifndef _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#define _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#include "ngx_map.h"
#include "ngx_rtmp.h"

typedef struct ngx_http_qqflv_loc_conf_s ngx_http_qqflv_loc_conf_t;

typedef struct {
	ngx_map_t                        map;
} ngx_http_qqflv_sh_t;

typedef struct {
    ngx_http_qqflv_sh_t        *sh;
    ngx_slab_pool_t                 *shpool;
    ngx_shm_zone_t                  *shm_zone;
    ngx_http_complex_value_t        key;
} ngx_http_qqflv_zone_t;

typedef struct {
    ngx_array_t                     zones;
} ngx_http_qqflv_main_conf_t;

struct ngx_http_qqflv_loc_conf_s {
    ngx_array_t                     req_zones;
    ngx_http_qqflv_loc_conf_t *parent;
};

#endif