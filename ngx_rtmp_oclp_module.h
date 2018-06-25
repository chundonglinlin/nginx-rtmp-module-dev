/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 *
 */


#ifndef _NGX_RTMP_OCLP_MODULE_H_INCLUDED_
#define _NGX_RTMP_OCLP_MODULE_H_INCLUDED_


#include "ngx_rtmp.h"
#include "ngx_netcall.h"


void ngx_rtmp_oclp_pnotify_done(ngx_rtmp_session_t *s);
void ngx_rtmp_oclp_pnotify_start(ngx_rtmp_session_t *s, ngx_uint_t type);
void ngx_rtmp_oclp_stream_start(ngx_rtmp_session_t *s);
void ngx_rtmp_oclp_stream_done(ngx_rtmp_session_t *s);


#endif
