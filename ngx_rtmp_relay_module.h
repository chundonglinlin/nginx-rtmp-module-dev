
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_RELAY_H_INCLUDED_
#define _NGX_RTMP_RELAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"

enum {
    NGX_RTMP_RELAY_RTMP,
    NGX_RTMP_RELAY_HDL,
    NGX_RTMP_RELAY_MAX
};

typedef struct {
    ngx_url_t                   url;
    ngx_str_t                   schema;
    ngx_str_t                   app;
    ngx_str_t                   name;
    ngx_str_t                   tc_url;
    ngx_str_t                   page_url;
    ngx_str_t                   swf_url;
    ngx_str_t                   flash_ver;
    ngx_str_t                   push_object;
    ngx_str_t                   play_path;
    ngx_int_t                   live;
    ngx_int_t                   start;
    ngx_int_t                   stop;

    ngx_str_t                   groupid;

    void                       *tag;
    ngx_uint_t                  idx;
    unsigned                    publishing:1;

    ngx_uint_t                  counter; /* mutable connection counter */
} ngx_rtmp_relay_target_t;


extern ngx_module_t  ngx_rtmp_relay_module;


ngx_int_t ngx_rtmp_relay_status_error(ngx_rtmp_session_t *s, char *type,
                                      char *code, char *level, char *desc);

ngx_rtmp_relay_ctx_t *ngx_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
                      ngx_rtmp_relay_target_t *target);
ngx_rtmp_relay_ctx_t *ngx_relay_push(ngx_rtmp_session_t *s, ngx_str_t *name,
                      ngx_rtmp_relay_target_t *target);

ngx_int_t ngx_rtmp_relay_publish_local(ngx_rtmp_session_t *s);


#endif /* _NGX_RTMP_RELAY_H_INCLUDED_ */
