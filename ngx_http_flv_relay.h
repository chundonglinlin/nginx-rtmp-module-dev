/*
 *  * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 *   */


#ifndef _NGX_HTTP_FLV_RELAY_H_INCLUDE_
#define _NGX_HTTP_FLV_RELAY_H_INCLUDE_


#include "ngx_rtmp.h"
#include "ngx_rtmp_relay_module.h"


ngx_rtmp_relay_ctx_t *ngx_http_relay_create_connection(ngx_rtmp_session_t *s,
        ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target);


#endif
