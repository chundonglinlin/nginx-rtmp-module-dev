/*
 * Copyright (C) Roman Arutyunyan
 */

#include <math.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"
#include "ngx_rtmp_record_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_dynamic_resolver.h"
#include "ngx_rtmp_variables.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_dynamic_conf.h"
#include "ngx_rtmp_dynamic.h"

#define NGX_RTMP_DOMAIN_MAX 512
#define NGX_RTMP_ARGS_MAX   1024

static ngx_rtmp_connect_pt                      next_connect;
static ngx_rtmp_disconnect_pt                   next_disconnect;
static ngx_rtmp_publish_pt                      next_publish;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_close_stream_pt                 next_close_stream;
static ngx_rtmp_record_done_pt                  next_record_done;

typedef struct ngx_rtmp_notify_multi_url_s ngx_rtmp_notify_multi_url_t;
typedef struct ngx_rtmp_notify_act_s ngx_rtmp_notify_act_t;

static ngx_int_t
ngx_rtmp_notify_preconfiguration(ngx_conf_t *cf);
static ngx_int_t
ngx_rtmp_notify_init_process(ngx_cycle_t *cycle);
static void
ngx_rtmp_notify_exit_process(ngx_cycle_t *cycle);
static char *
ngx_rtmp_notify_on_main_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_url_t *
ngx_rtmp_notify_set_ns_urls(ngx_rtmp_notify_session_t *ns, ngx_url_t *origin_u);
static char *
ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_rtmp_notify_reconnect_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *
ngx_rtmp_notify_parse_pargs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf);
static void *
ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf);
static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);
static void *
ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf);
static char *
ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void *
ngx_rtmp_notify_create_main_conf(ngx_conf_t *cf);
static char *
ngx_rtmp_notify_init_main_conf(ngx_conf_t *cf, void *conf);

static void
ngx_rtmp_notify_reconnect(ngx_rtmp_notify_act_t *act);
static void
ngx_rtmp_notify_session_netcall(ngx_rtmp_session_t *s, void *data,
                                ngx_uint_t datalen, ngx_uint_t notify_flag,
                                ngx_uint_t act_flag, ngx_uint_t opt_flag);
static ngx_chain_t *
ngx_rtmp_notify_http_format(ngx_rtmp_session_t *s,
                            ngx_rtmp_notify_multi_url_t *mu, ngx_pool_t *pool);
static ngx_int_t
ngx_rtmp_notify_netcall(ngx_rtmp_notify_act_t *act);

ngx_str_t   ngx_rtmp_notify_urlencoded =
    ngx_string("application/x-www-form-urlencoded");


enum {
    NGX_RTMP_NOTIFY_ON_INIT_PROC,
    NGX_RTMP_NOTIFY_ON_EXIT_PROC,
    NGX_RTMP_NOTIFY_MAIN_MAX
};


enum {
    NGX_RTMP_NOTIFY_CONNECT,
    NGX_RTMP_NOTIFY_DISCONNECT,
    NGX_RTMP_NOTIFY_SRV_MAX
};


enum {
    NGX_RTMP_NOTIFY_PLAY,
    NGX_RTMP_NOTIFY_PUBLISH,
    NGX_RTMP_NOTIFY_STREAM,
    NGX_RTMP_NOTIFY_RECORD,
    NGX_RTMP_NOTIFY_APP_MAX
};

static const char *ngx_rtmp_notify_call_str[] = {
    "play",
    "publish",
    "stream",
    "record"
};

enum {
    NGX_RTMP_NOTIFY_PUBLISHING = 0x01,
    NGX_RTMP_NOTIFY_PLAYING = 0x02,
    NGX_RTMP_NOTIFY_STREAMING = 0x04,
    NGX_RTMP_NOTIFY_RECORDING = 0x08
};

static const ngx_uint_t ngx_rtmp_notify_flags[] = {
    NGX_RTMP_NOTIFY_PLAYING,
    NGX_RTMP_NOTIFY_PUBLISHING,
    NGX_RTMP_NOTIFY_STREAMING,
    NGX_RTMP_NOTIFY_RECORDING
};

/* notify's act start */
enum {
    NGX_RTMP_NOTIFY_ACT_START,
    NGX_RTMP_NOTIFY_ACT_UPDATE,
    NGX_RTMP_NOTIFY_ACT_DONE,
    NGX_RTMP_NOTIFY_ACT_MAX
};

static const char *ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_MAX] = {
    "start",
    "update",
    "done"
};
struct ngx_rtmp_notify_act_s {
    ngx_rtmp_notify_session_t     *ns;
    ngx_event_t                    ev;
    ngx_flag_t                     not_reconnect;
    ngx_uint_t                     flag;
    ngx_msec_t                     reconnect_timer;
    ngx_rtmp_netcall_init_t        ci;
    void                          *data;
    ngx_url_t                      url;
    ngx_str_t                      uri;
    ngx_rtmp_notify_act_t         *next;
};
/* notify's act end */

/* notify's option start */
enum {
    NGX_RTMP_NOTIFY_OPT_NOTIFY = 0x01,
    NGX_RTMP_NOTIFY_OPT_RELAY = 0x02,
    NGX_RTMP_NOTIFY_OPT_TRANSCODE = 0x04,
    NGX_RTMP_NOTIFY_OPT_GLOBAL = 0x08,
    NGX_RTMP_NOTIFY_OPT_ALL = 0xffffffff
};

static ngx_int_t ngx_rtmp_notify_opt_integer[] = {
    NGX_RTMP_NOTIFY_OPT_NOTIFY,
    NGX_RTMP_NOTIFY_OPT_RELAY,
    NGX_RTMP_NOTIFY_OPT_TRANSCODE,
    NGX_RTMP_NOTIFY_OPT_GLOBAL
};

#define ngx_rtmp_notify_opt_index(__opt)  ((ngx_int_t)(log(__opt)/log(2)))

static const char *ngx_rtmp_notify_opt_str[] = {
    "notify",
    "relay",
    "transcode",
    "global"
};

static ngx_uint_t ngx_rtmp_notify_opt_mask[] = {
    // on_play
    NGX_RTMP_NOTIFY_OPT_NOTIFY | NGX_RTMP_NOTIFY_OPT_GLOBAL |
    NGX_RTMP_NOTIFY_OPT_RELAY | NGX_RTMP_NOTIFY_OPT_TRANSCODE,
    // on_publish
    NGX_RTMP_NOTIFY_OPT_NOTIFY | NGX_RTMP_NOTIFY_OPT_GLOBAL |
    NGX_RTMP_NOTIFY_OPT_RELAY | NGX_RTMP_NOTIFY_OPT_TRANSCODE,
    // on_stream
    NGX_RTMP_NOTIFY_OPT_NOTIFY | NGX_RTMP_NOTIFY_OPT_GLOBAL,
    // on_record
    NGX_RTMP_NOTIFY_OPT_NOTIFY | NGX_RTMP_NOTIFY_OPT_GLOBAL
};

#define NGX_RTMP_NOTIFY_DETACHED_MASK (NGX_RTMP_NOTIFY_OPT_RELAY |            \
                                       NGX_RTMP_NOTIFY_OPT_TRANSCODE |        \
                                       NGX_RTMP_NOTIFY_OPT_GLOBAL)
/* notify's option end */

struct ngx_rtmp_notify_multi_url_s {
    ngx_array_t                    urls;
    ngx_uint_t                     notify;
    ngx_uint_t                     act[NGX_RTMP_NOTIFY_ACT_MAX];
    ngx_str_t                      args;
    ngx_str_t                      groupid;
    ngx_uint_t                     opt;
    ngx_flag_t                     detached;
    ngx_flag_t                     response;
};


struct ngx_rtmp_notify_session_s {
    ngx_rtmp_session_t            *s;
    ngx_int_t                      notify;
    ngx_pool_t                    *pool;
    ngx_uint_t                     url_index;
    ngx_flag_t                     static_url;
    ngx_rtmp_notify_multi_url_t   *mu;
    //copy mu->urls
    ngx_array_t                    urls;
    ngx_rtmp_notify_act_t         *act[NGX_RTMP_NOTIFY_ACT_MAX];
    ngx_msec_t                     reconnect_min_timer;
    ngx_msec_t                     reconnect_max_timer;
    ngx_event_t                    update_evt;
    ngx_msec_t                     update_timer;
    ngx_uint_t                     method;
    ngx_flag_t                     active;
    ngx_flag_t                     closed;
    ngx_flag_t                     reach_last_urls;
    ngx_log_t                     *log;
    ngx_chain_t                   *args;
    ngx_live_stream_t             *live_stream;
    ngx_msec_t                     connect_timeout;
    size_t                         bufsize;
    ngx_str_t                      serverid;
    ngx_str_t                      stream;
    ngx_rtmp_notify_session_t     *next;
};

typedef struct {
    uintptr_t                       index;
    ngx_str_t                       name;
} ngx_rtmp_notify_variable_t;


typedef struct {
    ngx_url_t                      *url[NGX_RTMP_NOTIFY_MAIN_MAX];
    ngx_str_t                      *args[NGX_RTMP_NOTIFY_MAIN_MAX];
    ngx_uint_t                      method;
} ngx_rtmp_notify_main_conf_t;


typedef struct {
    ngx_url_t                      *url[NGX_RTMP_NOTIFY_APP_MAX];
    ngx_array_t                    *multi_url[NGX_RTMP_NOTIFY_APP_MAX];
    ngx_flag_t                      active;
    ngx_uint_t                      method;
    ngx_msec_t                      update_timer;
    ngx_msec_t                      reconnect_min_timer;
    ngx_msec_t                      reconnect_max_timer;
    ngx_msec_t                      connect_timeout;
    size_t                          bufsize;
    ngx_pool_t                     *pool;
    ngx_str_t                       npargs;
    ngx_flag_t                      shield_relay;
} ngx_rtmp_notify_app_conf_t;


typedef struct {
    ngx_url_t                      *url[NGX_RTMP_NOTIFY_SRV_MAX];
    ngx_array_t                    *multi_url[NGX_RTMP_NOTIFY_SRV_MAX];
    ngx_uint_t                      method;
} ngx_rtmp_notify_srv_conf_t;


typedef struct {
    ngx_uint_t                      opt_flags;
    u_char                          name[NGX_RTMP_MAX_NAME];
    u_char                          args[NGX_RTMP_MAX_ARGS];
    time_t                          start;
    void                           *data;
    ngx_uint_t                      datalen;
    ngx_rtmp_notify_session_t      *nl[NGX_RTMP_NOTIFY_APP_MAX];
    ngx_flag_t                      on_publish_meta;
    ngx_flag_t                      publish_opt_trans;
    unsigned                        publishing:1;
} ngx_rtmp_notify_ctx_t;


static ngx_command_t  ngx_rtmp_notify_commands[] = {

    { ngx_string("on_init_proc"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_rtmp_notify_on_main_event,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_exit_proc"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_rtmp_notify_on_main_event,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_connect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_disconnect"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_publish"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_play"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("on_stream"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_notify_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_method"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_method,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_update_timer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, update_timer),
      NULL },

    { ngx_string("notify_reconnect_timer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE2,
      ngx_rtmp_notify_reconnect_timer,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_connect_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, connect_timeout),
      NULL },

    { ngx_string("notify_buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, bufsize),
      NULL },

    { ngx_string("relay_pargs"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_notify_parse_pargs,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("notify_shield_relay"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_notify_app_conf_t, shield_relay),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_notify_module_ctx = {
    ngx_rtmp_notify_preconfiguration,       /* preconfiguration */
    ngx_rtmp_notify_postconfiguration,      /* postconfiguration */
    ngx_rtmp_notify_create_main_conf,       /* create main configuration */
    ngx_rtmp_notify_init_main_conf,         /* init main configuration */
    ngx_rtmp_notify_create_srv_conf,        /* create server configuration */
    ngx_rtmp_notify_merge_srv_conf,         /* merge server configuration */
    ngx_rtmp_notify_create_app_conf,        /* create app configuration */
    ngx_rtmp_notify_merge_app_conf          /* merge app configuration */
};


ngx_module_t  ngx_rtmp_notify_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_notify_module_ctx,            /* module context */
    ngx_rtmp_notify_commands,               /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_notify_init_process,           /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    ngx_rtmp_notify_exit_process,           /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_notify_preconfiguration(ngx_conf_t *cf)
{
    return NGX_OK;
}


static void *
ngx_rtmp_notify_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_uint_t                      n;

    nacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_app_conf_t));
    if (nacf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        nacf->url[n] = NGX_CONF_UNSET_PTR;
        nacf->multi_url[n] =
        ngx_array_create(cf->pool, 1024, sizeof(ngx_rtmp_notify_multi_url_t));
        if (nacf->multi_url[n] == NULL) {
            return NULL;
        }
    }

    nacf->method = NGX_CONF_UNSET_UINT;
    nacf->update_timer = NGX_CONF_UNSET_MSEC;
    nacf->reconnect_max_timer = NGX_CONF_UNSET_MSEC;
    nacf->reconnect_min_timer = NGX_CONF_UNSET_MSEC;
    nacf->connect_timeout = NGX_CONF_UNSET_MSEC;
    nacf->bufsize = NGX_CONF_UNSET_SIZE;
    nacf->shield_relay = NGX_CONF_UNSET;

    nacf->pool = ngx_create_pool(4096, cf->log);
    if (nacf->pool == NULL) {
        return NULL;
    }

    return nacf;
}


static char *
ngx_rtmp_notify_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_app_conf_t *prev = parent;
    ngx_rtmp_notify_app_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
        if (conf->url[n]) {
            conf->active = 1;
        }
    }

    if (conf->active) {
        prev->active = 1;
    }

    ngx_conf_merge_uint_value(conf->method,
                              prev->method, NGX_RTMP_NETCALL_HTTP_GET);
    ngx_conf_merge_msec_value(conf->update_timer,
                              prev->update_timer, 30000);
    ngx_conf_merge_msec_value(conf->reconnect_max_timer,
                              prev->reconnect_max_timer, 5000);
    ngx_conf_merge_msec_value(conf->reconnect_min_timer,
                              prev->reconnect_min_timer, 50);
    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 5000);
    ngx_conf_merge_size_value(conf->bufsize, prev->bufsize, 1024);

    ngx_conf_merge_value(conf->shield_relay, prev->shield_relay, 1);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_notify_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_uint_t                      n;

    nscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_srv_conf_t));
    if (nscf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        nscf->url[n] = NGX_CONF_UNSET_PTR;
        nscf->multi_url[n] = ngx_array_create(cf->pool, 1024, sizeof(ngx_url_t*));
        if (nscf->multi_url[n] == NULL) {
            return NULL;
        }
    }

    nscf->method = NGX_CONF_UNSET_UINT;

    return nscf;
}


static char *
ngx_rtmp_notify_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_notify_srv_conf_t *prev = parent;
    ngx_rtmp_notify_srv_conf_t *conf = child;
    ngx_uint_t                  n;

    for (n = 0; n < NGX_RTMP_NOTIFY_SRV_MAX; ++n) {
        ngx_conf_merge_ptr_value(conf->url[n], prev->url[n], NULL);
    }

    ngx_conf_merge_uint_value(conf->method, prev->method,
                              NGX_RTMP_NETCALL_HTTP_POST);

    return NGX_CONF_OK;
}


static void *
ngx_rtmp_notify_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_notify_main_conf_t     *nmcf;
    ngx_uint_t                       n;

    nmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_notify_main_conf_t));
    if (nmcf == NULL) {
        return NULL;
    }
    for (n = 0; n < NGX_RTMP_NOTIFY_MAIN_MAX; ++n) {
        nmcf->url[n] = NGX_CONF_UNSET_PTR;
        nmcf->args[n] = NGX_CONF_UNSET_PTR;
    }
    nmcf->method = NGX_CONF_UNSET_UINT;
    return nmcf;
}


static char *
ngx_rtmp_notify_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_rtmp_notify_main_conf_t     *nmcf = conf;
    ngx_uint_t                       n;

    for (n = 0; n < NGX_RTMP_NOTIFY_MAIN_MAX; ++n) {
        if (nmcf->url[n] == NGX_CONF_UNSET_PTR) {
            nmcf->url[n] = NULL;
            nmcf->args[n] = NULL;
        }
    }
    ngx_conf_init_uint_value(nmcf->method, NGX_RTMP_NETCALL_HTTP_GET);

    return NGX_CONF_OK;
}


static u_char *
ngx_rtmp_notify_strlechr(u_char *p, u_char *last)
{
    while (p != last) {
        if ((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            *p == '_')
        {
            p++;
            continue;
        }

        return p;
    }

    return NULL;
}


static ngx_int_t
ngx_rtmp_notify_variable_index(ngx_conf_t *cf,
                               ngx_str_t *origin, ngx_str_t *target)
{
    u_char                   *p, *e, *t;
    u_char                   *wp, *we;
    ngx_str_t                 str, var;
    ngx_buf_t                *buf;
    ngx_int_t                 index;

    p = origin->data;
    e = origin->data + origin->len;

    buf = ngx_create_temp_buf(cf->pool, 2 * origin->len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    wp = buf->start;
    we = buf->end;

    while (p < e) {
        t = ngx_strlchr(p, e, '$');
        if (t == NULL) {
            t = e;
        }
        str.data = p;
        str.len = t - p;
        wp = ngx_slprintf(wp, we, "%V", &str);

        if (t == e) {
            break;
        }

        var.data = ++t;
        t = ngx_rtmp_notify_strlechr(t, e);
        if (t == NULL) {
            t = e;
        }
        var.len = t - var.data;

        index = ngx_rtmp_get_variable_index(cf, &var);
        if (index == NGX_ERROR) {
            return NGX_ERROR;
        }

        wp = ngx_slprintf(wp, we, "$%d", index);
        p = t;
    }

    target->data = buf->start;
    target->len = wp - buf->start;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_notify_fetch_variable(ngx_rtmp_session_t *s, ngx_pool_t *pool,
                          ngx_str_t *origin, ngx_str_t *target)
{
    ngx_rtmp_variable_value_t         *vv;
    u_char                            *p, *e, *t;
    u_char                            *wp, *we;
    ngx_chain_t                       *ch, *cl, *ct;
    u_char                            *pt;
    ngx_uint_t                         length;
    ngx_int_t                          index;
    ngx_str_t                          var;

    length = 0;
    p = origin->data;
    e = p + origin->len;

    #define NGX_RTMP_NOTIFY_BUF(__start__, __end__)                            \
    ct = cl;                                                                   \
    pt = ngx_pcalloc(pool, sizeof(ngx_chain_t) +                               \
                     sizeof(ngx_buf_t) + __end__ - __start__);                 \
    cl = (ngx_chain_t*)pt;                                                     \
    cl->buf = (ngx_buf_t*)(pt + sizeof(ngx_chain_t));                          \
    cl->buf->start =                                                           \
    cl->buf->pos =                                                             \
    cl->buf->last = pt + sizeof(ngx_chain_t) + sizeof(ngx_buf_t);              \
    if (ch == NULL) {                                                          \
        ch = cl;                                                               \
    } else {                                                                   \
        ct->next = cl;                                                         \
    }                                                                          \
    cl->buf->last = ngx_cpymem(cl->buf->pos, __start__, __end__ - __start__);  \
    length += __end__ - __start__

    ch = cl = ct = NULL;

    while(p < e) {
        t = ngx_strlchr(p, e, '$');
        if (t == NULL) {
            t = e;
        }
        NGX_RTMP_NOTIFY_BUF(p, t);
        if (t == e) {
            break;
        }

        var.data = ++t;
        t = ngx_rtmp_notify_strlechr(t, e);
        if (t == NULL) {
            t = e;
        }
        var.len = t - var.data;
        index = ngx_atoi(var.data, var.len);
        vv = ngx_rtmp_get_indexed_variable(s, index);
        if (vv == NULL) {
            p = t;
            continue;
        }
        wp = vv->data;
        we = vv->data + vv->len;

        NGX_RTMP_NOTIFY_BUF(wp, we);
        p = t;
    }

    #undef NGX_RTMP_NOTIFY_BUF

    wp = ngx_pcalloc(pool, length);
    we = wp;

    for (ct = ch; ct;) {
        we = ngx_cpymem(we, ct->buf->pos, ct->buf->last - ct->buf->pos);
        cl = ct->next;
        ngx_pfree(pool, ct);
        ct = cl;
    }
    target->data = wp;
    target->len = we - wp;
    if (target->len != length) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
        "notify: fetch_variable| target len = %d, content length = %d",
         target->len, length);
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_rtmp_notify_detached(ngx_rtmp_session_t *s,
                               ngx_rtmp_notify_session_t *ns)
{
    ngx_live_stream_t             *live_stream;

    live_stream = s->live_stream;
    ns->next = live_stream->nns[ns->notify];
    live_stream->nns[ns->notify] = ns;

    if (ns->notify == NGX_RTMP_NOTIFY_PLAY &&
        live_stream->idle_transcodes == 0)
    {
        live_stream->idle_transcodes = ns->mu->opt & NGX_RTMP_NOTIFY_OPT_TRANSCODE;
    }
}


ngx_rtmp_notify_session_t *
ngx_rtmp_notify_fetch_session(ngx_rtmp_session_t *s, ngx_uint_t notify_flag)
{
    ngx_live_stream_t               *st;

    if (notify_flag >= NGX_RTMP_NOTIFY_APP_MAX) {
        return NULL;
    }

    st = s->live_stream;
    if (st == NULL) {
        st = ngx_live_fetch_stream(&s->serverid, &s->stream);
    }

    if (st == NULL) {
        return NULL;
    }

    return st->nns[notify_flag];
}


static void
ngx_rtmp_notify_session_free(ngx_rtmp_notify_session_t *ns)
{
    ngx_int_t                       i;
    ngx_rtmp_notify_act_t          *act;
    ngx_uint_t                      opt_index;

    if (ns == NULL) {
        return;
    }

    if (ns->update_evt.timer_set) {
        ngx_del_timer(&ns->update_evt);
    }

    for (i = 0; i < NGX_RTMP_NOTIFY_ACT_MAX; i++) {
        if (ns->act[i] == NULL) {
            continue;
        }

        act = ns->act[i];
        if (act->ev.timer_set) {
            ngx_del_timer(&act->ev);
        }
    }

    opt_index = ngx_rtmp_notify_opt_index(ns->mu->opt);
    ngx_log_error(NGX_LOG_INFO, ns->log, 0,
      "notify: session_free| opt %s", ngx_rtmp_notify_opt_str[opt_index]);

    ngx_destroy_pool(ns->pool);
}


static void
ngx_rtmp_notify_session_close(ngx_rtmp_session_t *s, ngx_flag_t stream_done)
{
    ngx_rtmp_notify_session_t      *nl, *cl;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_int_t                       n;
    ngx_live_stream_t              *st;
    ngx_rtmp_notify_act_t          *act;
    ngx_int_t                       i;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx) {
        for (n = 0; n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
            nl = ctx->nl[n];

            while (nl) {
                cl = nl->next;
                if (nl->active) {
                    nl->closed = 1;
                    for (i = 0; i < NGX_RTMP_NOTIFY_ACT_MAX; i++) {
                        if (nl->act[i] == NULL) {
                            continue;
                        }
                        act = nl->act[i];
                        if (act->ev.timer_set) {
                            ngx_del_timer(&act->ev);
                        }
                    }
                } else {
                    ngx_rtmp_notify_session_free(nl);
                }
                nl = cl;
            }

            ctx->nl[n] = NULL;
        }
    }

    st = s->live_stream;
    if (st == NULL) {
        st = ngx_live_fetch_stream(&s->serverid, &s->stream);
    }
    for (n = 0; st && n < NGX_RTMP_NOTIFY_APP_MAX; ++n) {
        nl = st->nns[n];

        while (nl) {
            cl = nl->next;
            if (stream_done == 0) {
                if (nl->s == s) {
                    nl->s = NULL;
                }
                nl = cl;
                continue;
            }

            if (nl->active) {
                nl->closed = 1;
                for (i = 0; i < NGX_RTMP_NOTIFY_ACT_MAX; i++) {
                    if (nl->act[i] == NULL) {
                        continue;
                    }
                    act = nl->act[i];
                    if (act->ev.timer_set) {
                        ngx_del_timer(&act->ev);
                    }
                }
            } else {
                ngx_rtmp_notify_session_free(nl);
            }
            nl = cl;
        }
    }
}


static ngx_int_t
ngx_rtmp_notify_session_create(ngx_rtmp_session_t *s, ngx_uint_t notify)
{
    ngx_rtmp_notify_app_conf_t    *nacf;
    ngx_rtmp_notify_session_t     *ns;
    ngx_pool_t                    *pool;
    ngx_rtmp_notify_ctx_t         *ctx;
    ngx_uint_t                     n, i, url_index;
    ngx_array_t                   *na;
    ngx_rtmp_notify_act_t         *act;
    ngx_rtmp_notify_multi_url_t   *mu;
    ngx_live_stream_t             *live_stream;
    ngx_flag_t                     detached_done = 0;
    ngx_url_t                     **uu, *u, **uus;
    ngx_str_t                      uri;

    live_stream = s->live_stream;
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    na = nacf->multi_url[notify];
    ns = ngx_rtmp_notify_fetch_session(s, notify);
    if (ns) {
        detached_done = 1;
    }

    for (n = 0; na && n < na->nelts; n++) {
        mu = na->elts;
        mu = &mu[n];

        ctx->opt_flags |= mu->opt;
        if (notify == NGX_RTMP_NOTIFY_PUBLISH &&
            (mu->opt & NGX_RTMP_NOTIFY_OPT_TRANSCODE))
        {
            ctx->publish_opt_trans = 1;
        }

        if (mu->detached && detached_done) {
            continue;
        }

        pool = ngx_create_pool(1024, ngx_cycle->log);
        if (pool == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "notify: session_create| creating pool failed");

            return NGX_ERROR;
        }

        ns = ngx_pcalloc(pool, sizeof(ngx_rtmp_notify_session_t));
        if (ns == NULL) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "notify: session_create| creating notify session failed");

            return NGX_ERROR;
        }

        ns->log = ngx_cycle->log;
        ns->mu = mu;
        ns->s = s;
        ns->reconnect_max_timer = nacf->reconnect_max_timer;
        ns->reconnect_min_timer = nacf->reconnect_min_timer;
        ns->notify = notify;
        ns->pool = pool;
        ns->method = nacf->method;
        ns->update_timer = nacf->update_timer;
        ns->live_stream = live_stream;
        ns->stream.data = ngx_pcalloc(ns->pool, s->stream.len);
        ns->stream.len = s->stream.len;
        ngx_memcpy(ns->stream.data, s->stream.data, s->stream.len);
        ns->serverid.data = ngx_pcalloc(ns->pool, s->serverid.len);
        ns->serverid.len = s->serverid.len;
        ngx_memcpy(ns->serverid.data, s->serverid.data, s->serverid.len);
        ns->connect_timeout = nacf->connect_timeout;
        ns->bufsize = nacf->bufsize;

        if (ns->urls.nalloc == 0) {
            ngx_array_init(&ns->urls, ns->pool, 1, sizeof(ngx_url_t*));
        }
        for (url_index = 0; url_index < mu->urls.nelts; ++url_index) {
            uu = mu->urls.elts;
            u = uu[url_index];
            uus = (ngx_url_t**)ngx_array_push(&ns->urls);
            *uus = ngx_rtmp_notify_set_ns_urls(ns, u);
            ngx_rtmp_notify_fetch_variable(s, ns->pool, &((*uus)->uri), &uri);
            (*uus)->uri = uri;
        }

        for (i = 0; i < NGX_RTMP_NOTIFY_ACT_MAX; i++) {
            if (ns->mu->act[i] != 1) {
                continue;
            }

            act = ngx_pcalloc(ns->pool, sizeof(ngx_rtmp_notify_act_t));
            if (act== NULL) {
                return NGX_ERROR;
            }

            ns->act[i] = act;
            act->flag = i;
            act->ns = ns;
            act->reconnect_timer = ns->reconnect_min_timer;
        }

        if (mu->detached) {
            ngx_rtmp_notify_detached(s, ns);
        } else {
            ns->next = ctx->nl[notify];
            ctx->nl[notify] = ns;
        }
    }

    return NGX_OK;
}

static ngx_chain_t *
ngx_rtmp_notify_init_proc_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_main_conf_t    *nmcf = arg;
    ngx_str_t                      *args;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl;
    ngx_buf_t                      *b;
    ngx_uint_t                      args_len = 0;

    url = nmcf->url[NGX_RTMP_NOTIFY_ON_INIT_PROC];
    args = nmcf->args[NGX_RTMP_NOTIFY_ON_INIT_PROC];
    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    if (args != NULL && args->len){
        args_len = args->len;
    }

    b = ngx_create_temp_buf(pool,
            sizeof("call=init_process") - 1 +
            sizeof("worker_id=") - 1 +
            args_len + 1
        );

    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "worker_id=", sizeof("worker_id=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", ngx_worker);

    b->last = ngx_cpymem(b->last, (u_char*) "&call=init_process",
                         sizeof("&call=init_process") - 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, args->data, args_len);
    }

    bl = NULL;
    if (nmcf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nmcf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


ngx_int_t
ngx_rtmp_notify_process_parse_http_retcode(ngx_chain_t *in)
{
    ngx_buf_t      *b;
    ngx_int_t       n;
    u_char          c;

    /* find 10th character */

    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                switch (c) {
                    case (u_char) '2':
                        return NGX_OK;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    default:
                        return NGX_DONE;
                }
            }

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_notify_init_proc_handle(ngx_rtmp_session_t *s, void *arg,
            ngx_chain_t *in)
{
    ngx_int_t                     rc;

    rc = ngx_rtmp_notify_process_parse_http_retcode(in);
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "notify: notify_init_proc_handle|"
                "init process notify return %d", rc);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "notify: notify_init_proc_handle|"
                    "init process notify return error");
    }

    return NGX_OK;
}


static ngx_chain_t *
ngx_rtmp_notify_exit_proc_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_main_conf_t    *nmcf = arg;
    ngx_str_t                      *args;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl;
    ngx_buf_t                      *b;
    ngx_uint_t                      args_len = 0;

    url = nmcf->url[NGX_RTMP_NOTIFY_ON_EXIT_PROC];
    args = nmcf->args[NGX_RTMP_NOTIFY_ON_EXIT_PROC];
    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    if (args != NULL && args->len){
        args_len = args->len;
    }

    b = ngx_create_temp_buf(pool,
            sizeof("call=exit_process") - 1 +
            sizeof("worker_id=") - 1 +
            args_len + 1
        );

    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "worker_id=", sizeof("worker_id=") - 1);
    b->last = ngx_sprintf(b->last, "%ui", ngx_worker);

    b->last = ngx_cpymem(b->last, (u_char*) "&call=exit_process",
                         sizeof("&call=exit_process") - 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, args->data, args_len);
    }

    bl = NULL;
    if (nmcf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nmcf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}

static ngx_int_t
ngx_rtmp_notify_exit_proc_handle(ngx_rtmp_session_t *s, void *arg,
            ngx_chain_t *in)
{
    ngx_int_t                     rc;

    rc = ngx_rtmp_notify_process_parse_http_retcode(in);
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "notify: notify_exit_proc_handle|"
                "exit process notify return %d", rc);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "notify: notify_exit_proc_handle|"
                    "exit process notify return error");
    }

    return NGX_OK;
}


static ngx_chain_t *
ngx_rtmp_notify_connect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_connect_t             *v = arg;

    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl;
    ngx_buf_t                      *b;
    ngx_str_t                      *addr_text;
    size_t                          app_len, args_len, flashver_len,
                                    swf_url_len, tc_url_len, page_url_len;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    /* these values are still missing in session
     * so we have to construct the request from
     * connection struct */

    app_len = ngx_strlen(v->app);
    args_len = ngx_strlen(v->args);
    flashver_len = ngx_strlen(v->flashver);
    swf_url_len = ngx_strlen(v->swf_url);
    tc_url_len = ngx_strlen(v->tc_url);
    page_url_len = ngx_strlen(v->page_url);

    addr_text = &s->connection->addr_text;

    b = ngx_create_temp_buf(pool,
            sizeof("call=connect") - 1 +
            sizeof("&app=") - 1 + app_len * 3 +
            sizeof("&flashver=") - 1 + flashver_len * 3 +
            sizeof("&swfurl=") - 1 + swf_url_len * 3 +
            sizeof("&tcurl=") - 1 + tc_url_len * 3 +
            sizeof("&pageurl=") - 1 + page_url_len * 3 +
            sizeof("&addr=") - 1 + addr_text->len * 3 +
            sizeof("&epoch=") - 1 + NGX_INT32_LEN +
            1 + args_len
        );

    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "app=", sizeof("app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->app, app_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&flashver=",
                         sizeof("&flashver=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->flashver, flashver_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&swfurl=",
                         sizeof("&swfurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->swf_url, swf_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&tcurl=",
                         sizeof("&tcurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->tc_url, tc_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&pageurl=",
                         sizeof("&pageurl=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, v->page_url, page_url_len,
                                       NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&addr=", sizeof("&addr=") -1);
    b->last = (u_char*) ngx_escape_uri(b->last, addr_text->data,
                                       addr_text->len, NGX_ESCAPE_ARGS);

    b->last = ngx_cpymem(b->last, (u_char*) "&epoch=", sizeof("&epoch=") -1);
    b->last = ngx_sprintf(b->last, "%uD", (uint32_t) s->epoch);

    b->last = ngx_cpymem(b->last, (u_char*) "&call=connect",
                         sizeof("&call=connect") - 1);

    if (args_len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, v->args, args_len);
    }

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nscf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


static ngx_chain_t *
ngx_rtmp_notify_disconnect_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_url_t                      *url;
    ngx_chain_t                    *al, *bl, *pl;
    ngx_buf_t                      *b;

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);

    pl = ngx_alloc_chain_link(pool);
    if (pl == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool,
                            sizeof("&call=disconnect") +
                            sizeof("&app=") + s->app.len * 3 +
                            1 + s->args.len);
    if (b == NULL) {
        return NULL;
    }

    pl->buf = b;
    pl->next = NULL;

    b->last = ngx_cpymem(b->last, (u_char*) "&call=disconnect",
                         sizeof("&call=disconnect") - 1);

    b->last = ngx_cpymem(b->last, (u_char*) "&app=", sizeof("&app=") - 1);
    b->last = (u_char*) ngx_escape_uri(b->last, s->app.data, s->app.len,
                                       NGX_ESCAPE_ARGS);

    if (s->args.len) {
        *b->last++ = '&';
        b->last = (u_char *) ngx_cpymem(b->last, s->args.data, s->args.len);
    }

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];

    al = ngx_rtmp_netcall_http_format_session(s, pool);
    if (al == NULL) {
        return NULL;
    }

    al->next = pl;

    bl = NULL;

    if (nscf->method == NGX_RTMP_NETCALL_HTTP_POST) {
        bl = al;
        al = NULL;
    }

    return ngx_rtmp_netcall_http_format_request(nscf->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


ngx_int_t
ngx_rtmp_notify_parse_http_retcode(ngx_log_t *log,
        ngx_chain_t *in)
{
    ngx_buf_t      *b;
    ngx_int_t       n;
    u_char          c;

    /* find 10th character */

    n = 9;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            c = b->pos[n];
            if (c >= (u_char)'0' && c <= (u_char)'9') {
                switch (c) {
                    case (u_char) '2':
                        return NGX_OK;
                    case (u_char) '3':
                        return NGX_AGAIN;
                    default:
                        return NGX_DONE;
                }
            }

            ngx_log_error(NGX_LOG_INFO, log, 0,
                    "notify: invalid HTTP retcode: %d..", (int)c);

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
            "notify: empty or broken HTTP response");

    /*
     * not enough data;
     * it can happen in case of empty or broken reply
     */

    return NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_notify_parse_http_header(ngx_chain_t *in,
                                  ngx_str_t *name,
                                  u_char *data, size_t len)
{
    ngx_buf_t      *b;
    ngx_int_t       matched;
    u_char         *p, c;
    ngx_uint_t      n;

    enum {
        parse_name,
        parse_space,
        parse_value,
        parse_value_newline
    } state = parse_name;

    n = 0;
    matched = 0;

    while (in) {
        b = in->buf;

        for (p = b->pos; p != b->last; ++p) {
            c = *p;

            if (c == '\r') {
                continue;
            }

            switch (state) {
                case parse_value_newline:
                    if (c == ' ' || c == '\t') {
                        state = parse_space;
                        break;
                    }

                    if (matched) {
                        return n;
                    }

                    if (c == '\n') {
                        return NGX_OK;
                    }

                    n = 0;
                    state = parse_name;

                case parse_name:
                    switch (c) {
                        case ':':
                            matched = (n == name->len);
                            n = 0;
                            state = parse_space;
                            break;
                        case '\n':
                            n = 0;
                            break;
                        default:
                            if (n < name->len &&
                                ngx_tolower(c) == ngx_tolower(name->data[n]))
                            {
                                ++n;
                                break;
                            }
                            n = name->len + 1;
                    }
                    break;

                case parse_space:
                    if (c == ' ' || c == '\t') {
                        break;
                    }
                    state = parse_value;

                case parse_value:
                    if (c == '\n') {
                        state = parse_value_newline;
                        break;
                    }

                    if (matched && n + 1 < len) {
                        data[n++] = c;
                    }

                    break;
            }
        }

        in = in->next;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_notify_connect_handle(ngx_rtmp_session_t *s,
        void *arg, ngx_chain_t *in)
{
    ngx_rtmp_connect_t *v = arg;
    ngx_int_t           rc;
    u_char              app[NGX_RTMP_MAX_NAME] = {0};

    static ngx_str_t    location = ngx_string("location");

    rc = ngx_rtmp_notify_parse_http_retcode(s->connection->log, in);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "notify: connect redirect received");

        rc = ngx_rtmp_notify_parse_http_header(in, &location, app,
                                               sizeof(app) - 1);
        if (rc > 0) {
            *ngx_cpymem(v->app, app, rc) = 0;
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "notify: connect redirect to '%s'", v->app);
        }
    }

    return next_connect(s, v);
}


static void
ngx_rtmp_notify_parse_target(ngx_rtmp_session_t *s,
                             ngx_buf_t *domain, ngx_rtmp_relay_target_t *target)
{
    u_char                            *p, *lp, *e, *t;
    ngx_str_t                         *app, *str = NULL;
    ngx_str_t                         *url;
    ngx_int_t                          tcurl_len;
    ngx_buf_t                         *tcurl_buf;
    ngx_buf_t                         *name_buf;
    ngx_str_t                         *name;

    url = &target->url.url;

    p = url->data;
    e = url->data + url->len;

    // find arg
    t = ngx_strlchr(p, e, '?');
    if (t == NULL) {
        t = e;
    }

    // find app
    lp = p;
    p = ngx_strlchr(p, t, '/');
    if (p == NULL || ++p == t) {
        goto _args;
    }

    str = &target->app;
    str->data = p;
    str->len = t - p;

    // find stream name
    lp = p;
    p = ngx_strlchr(p, t, '/');
    if (p == NULL || ++p == t) {
        goto _args;
    }

    str->len = p - str->data - 1;

    str = &target->name;
    str->data = p;
    str->len = t - p;

_args:
    // find args
    if (p == NULL) {
        p = lp;
    }

    if (t == e) {
        goto _tc_url;
    }

    p = t;
    if (p == NULL || ++p == e) {
        goto _tc_url;
    }

    if (str) {
        str->len = p - str->data - 1;
    }

    str = &target->args;
    str->data = p;
    str->len = e - p;

_tc_url:

    target->domain.data = domain->pos;
    target->domain.len  = domain->last - domain->pos;

    app = &s->app;

    if (target->app.len > 0) {
        app = &target->app;
    }

    if (target->domain.len > 0) {
        tcurl_len = sizeof("rtmp://") - 1 +
                     target->domain.len + 1 +
                     app->len;

        tcurl_buf = ngx_create_temp_buf(s->connection->pool, tcurl_len);
        tcurl_buf->last = ngx_slprintf(tcurl_buf->pos, tcurl_buf->end,
                                  "rtmp://%V/%V", &target->domain, app);
        target->tc_url.data = tcurl_buf->pos;
        target->tc_url.len = tcurl_buf->last - tcurl_buf->pos;
    }

    if (target->args.len == 0) {
        return;
    }
    // name with args
    name = &s->name;

    if (target->name.len) {
        name = &target->name;
    }

    name_buf = ngx_create_temp_buf(s->connection->pool,
        name->len + target->args.len + 1);
    if (name_buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: parse_target| create temp buf failed");
        return;
    }
    name_buf->last = ngx_slprintf(name_buf->start, name_buf->end,
                                  "%V?%V", name, &target->args);
    target->name.data = name_buf->pos;
    target->name.len = name_buf->last - name_buf->pos;
}


static ngx_int_t
ngx_rtmp_notify_update_handle(ngx_int_t retcode,
                              ngx_rtmp_notify_act_t *act, ngx_chain_t *in)
{
    ngx_rtmp_notify_session_t     *ns;

    ns = act->ns;
    ngx_add_timer(&ns->update_evt, ns->update_timer);

    return NGX_OK;
}


static void
ngx_rtmp_notify_update(ngx_event_t *e)
{
    ngx_rtmp_notify_session_t      *ns;
    ngx_rtmp_notify_act_t          *act;
    ngx_int_t                       rc;

    act = e->data;
    ns = act->ns;

    ngx_log_error(NGX_LOG_INFO, ns->log, 0,
                  "notify: update| %s",
                  ns->notify == NGX_RTMP_NOTIFY_PLAY? "play":"publish");


    rc = ngx_rtmp_notify_netcall(act);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ns->log, 0,
                  "notify: update| %s, netcall failed",
                  ns->notify == NGX_RTMP_NOTIFY_PLAY? "play": "publish");
        ngx_add_timer(&ns->update_evt, ns->update_timer);
    }
}


static void
ngx_rtmp_notify_update_init(ngx_rtmp_notify_session_t *ns, ngx_uint_t flags)
{
    ngx_event_t                    *e;
    ngx_rtmp_notify_act_t          *act;

    act = ns->act[NGX_RTMP_NOTIFY_ACT_UPDATE];

    if (act == NULL) {
        return;
    }

    if (ns->update_evt.timer_set) {
        return;
    }
    act->not_reconnect = 1;

    e = &ns->update_evt;

    e->data = act;
    e->log = ns->log;
    e->handler = ngx_rtmp_notify_update;

    ngx_add_timer(e, ns->update_timer);

    ngx_log_debug1(NGX_LOG_DEBUG_RTMP, ns->log, 0,
                   "notify: schedule initial update %Mms", ns->update_timer);
}


static ngx_int_t
ngx_rtmp_notify_publish_handle(ngx_int_t retcode,
                               ngx_rtmp_notify_act_t *act, ngx_chain_t *in)
{
    ngx_rtmp_notify_session_t  *ns;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_publish_t         *v;
    ngx_int_t                   rc = -1;
    ngx_str_t                   local_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *u;
    u_char                      name[NGX_RTMP_MAX_NAME];
    ngx_buf_t                  *domain_buf;
    ngx_str_t                   push_url;
    ngx_flag_t                  reconnect;
    ngx_live_stream_t          *live_stream;
    ngx_rtmp_notify_app_conf_t *nacf;
    ngx_str_t                   npargs;
    u_char                     *p;

    static ngx_str_t            location = ngx_string("location");
    static ngx_str_t            domain = ngx_string("domain");

    ns = act->ns;
    v = act->data;
    reconnect = 0;

    if (ns->mu->opt != NGX_RTMP_NOTIFY_OPT_RELAY ||
        retcode != NGX_AGAIN || ns->mu->response == 0)
    {
        goto next;
    }

    live_stream = ngx_live_fetch_stream(&ns->serverid, &ns->stream);
    if (live_stream == NULL) {
        return NGX_ERROR;
    }
    if (live_stream->publish_ctx == NULL) {
        return NGX_ERROR;
    }
    s = live_stream->publish_ctx->session;
    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if(nacf && nacf->npargs.len != 0) {
        rc = ngx_rtmp_notify_fetch_variable(s, ns->pool, &nacf->npargs, &npargs);
    }
    if (rc == NGX_ERROR)
        npargs.len = 0;

    /* HTTP 3xx */

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: publish redirect received");
    ngx_memzero(name, NGX_RTMP_MAX_NAME);
    rc = ngx_rtmp_notify_parse_http_header(in, &location,
                                       name, sizeof(name) - 1);
    if (rc <= 0) {
        goto next;
    }

    push_url.data = name;
    push_url.len = rc;

    if (ngx_strncasecmp(name, (u_char *) "rtmp://", 7)) {
        *ngx_cpymem(v->name, name, rc) = 0;
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: publish redirect to '%s'", v->name);
        reconnect = 1;
        goto next;
    }

    /* push */

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "notify: push '%s' to '%s'", v->name, name);

    local_name.data = v->name;
    local_name.len = ngx_strlen(v->name);

    ngx_memzero(&target, sizeof(target));

    domain_buf = ngx_create_temp_buf(ns->pool, NGX_RTMP_DOMAIN_MAX);

    if ( (rc = ngx_rtmp_notify_parse_http_header(in, &domain,
                      domain_buf->pos, NGX_RTMP_DOMAIN_MAX)) > 0)
    {
        domain_buf->last = domain_buf->pos + rc;
    }

    u = &target.url;
    u->url.data = ngx_pcalloc(ns->pool, push_url.len - 7 + 1 + npargs.len * 3);
    p = u->url.data;
    p = (u_char*) ngx_escape_uri(p, push_url.data + 7,
                                      push_url.len - 7, NGX_ESCAPE_URI);
    if(npargs.len != 0){
        if (ngx_strlchr(push_url.data + 7,  push_url.data +
            push_url.len - 7, '?'))
        {
            p = (u_char*) ngx_escape_uri(p, (u_char*) "&",
                                      sizeof("&") - 1, NGX_ESCAPE_URI);
        } else{
            p = ngx_cpymem(p, (u_char*) "?", sizeof("?") - 1);
        }
        p = (u_char*) ngx_escape_uri(p, npargs.data,
                                       npargs.len, NGX_ESCAPE_URI);
    }
    u->url.len = p - u->url.data;
    u->default_port = 1935;
    u->uri_part = 1;
    u->no_resolve = 1; /* want ip here */

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: push failed '%V'", &local_name);
        reconnect = 1;
        goto next;
    }

    if (domain_buf->pos == domain_buf->last) {
        domain_buf->last = ngx_slprintf(domain_buf->pos, domain_buf->end, "%V", &u->host);
    }

    ngx_rtmp_notify_parse_target(s, domain_buf, &target);
    if (target.name.len > 0) {
        local_name = target.name;
    }

    target.tag = &ngx_rtmp_notify_module;
    target.data = ns;
    ngx_rtmp_relay_push(s, &local_name, &target);

next:
    if (reconnect) {
        ngx_rtmp_notify_reconnect(act);
        return NGX_OK;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_notify_play_handle(ngx_int_t retcode,
                            ngx_rtmp_notify_act_t *act, ngx_chain_t *in)
{
    ngx_rtmp_notify_session_t  *ns;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_play_t            *v;
    ngx_int_t                   rc;
    ngx_str_t                   local_name;
    ngx_rtmp_relay_target_t     target;
    ngx_url_t                  *u;
    u_char                      name[NGX_RTMP_MAX_NAME] = {0};
    ngx_buf_t                  *domain_buf;
    ngx_int_t                   method;
    ngx_str_t                   pull_url;
    ngx_flag_t                  reconnect;
    ngx_live_stream_t          *live_stream;
    ngx_flag_t                  s_in_ns = 1;
    ngx_rtmp_relay_app_conf_t  *racf;

    static ngx_str_t            location = ngx_string("location");
    static ngx_str_t            domain = ngx_string("domain");
    static ngx_str_t            bandwidth = ngx_string("DN-bandwidth");

    ns = act->ns;
    v = act->data;
    s = ns->s;
    reconnect = 0;
    live_stream = NULL;

    if (s && ngx_rtmp_notify_parse_http_header(in, &bandwidth, name,
                                              sizeof(name) - 1) > 0)
    {
        if (ngx_strncasecmp(name, (u_char*)"backsource",
                            ngx_strlen("backsource")) == 0)
        {
            s->back_source = 1;
        }
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                     "notify: play_handle| DN-bandwidth: %s", name);
    }

    if (ns->mu->opt != NGX_RTMP_NOTIFY_OPT_RELAY) {
        return NGX_OK;
    }

    live_stream = ngx_live_fetch_stream(&ns->serverid, &ns->stream);
    if (live_stream == NULL) {
        return NGX_ERROR;
    }
    if (s == NULL){
        s_in_ns = 0;
        if (live_stream->play_ctx == NULL) {
            return NGX_ERROR;
        }
        s = live_stream->play_ctx->session;
    }

    if (s && s_in_ns == 1) {
        racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
        if (racf && racf->pulls.nelts != 0 && ns->reach_last_urls) {
            live_stream->relay_pull_tag = NULL;
            goto next;
        }
    }

    if (retcode == NGX_OK && live_stream->relay_pull_tag != NULL) {
        live_stream->relay_pull_tag = NULL;
        goto next;
    }

    /* HTTP 3xx */
    if (retcode != NGX_AGAIN) {
        reconnect = 1;
        goto next;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "notify: play_handle| redirect received");

    rc = ngx_rtmp_notify_parse_http_header(in, &location, name,
                                           sizeof(name) - 1);
    if (rc <= 0) {
        reconnect = 1;
        goto next;
    }
    pull_url.data = name;
    pull_url.len = rc;

    if (ngx_strncasecmp(name, (u_char *) "rtmp://", 7) == 0) {
        method = NGX_RTMP_RELAY_RTMP;
    } else if (ngx_strncasecmp(name, (u_char *) "http://", 7) == 0) {
        method = NGX_RTMP_RELAY_HDL;
    } else {
        *ngx_cpymem(v->name, name, rc) = 0;
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: play_handle| redirect to '%s'", v->name);
        reconnect = 1;
        goto next;
    }

    /* pull */

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "notify: pull '%s' from '%*s'", v->name, rc, name);

    local_name.data = v->name;
    local_name.len = ngx_strlen(v->name);

    ngx_memzero(&target, sizeof(target));

    target.method = method;

    domain_buf = ngx_create_temp_buf(ns->pool, NGX_RTMP_DOMAIN_MAX);

    rc = ngx_rtmp_notify_parse_http_header(in, &domain,
                                          domain_buf->pos, NGX_RTMP_DOMAIN_MAX);
    if (rc > 0) {
        domain_buf->last = domain_buf->pos + rc;
    }

    u = &target.url;
    u->url.data = ngx_pcalloc(ns->pool, pull_url.len - 7);
    ngx_memcpy(u->url.data, pull_url.data + 7, pull_url.len - 7);
    u->url.len = pull_url.len;
    u->url.len  -= 7;

    if (method == NGX_RTMP_RELAY_RTMP) {
        target.schema.data = name;
        target.schema.len = 4;
        u->default_port = 1935;
    } else if (method == NGX_RTMP_RELAY_HDL) {
        target.schema.data = name;
        target.schema.len = 4;
        u->default_port = 80;
    }
    u->uri_part = 1;
    u->no_resolve = 1; /* want ip here */

    if (ngx_parse_url(ns->pool, u) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "notify: pull failed '%V'", &local_name);
        reconnect = 1;
        goto next;
    }
    if (domain_buf->pos == domain_buf->last) {
        domain_buf->last = ngx_slprintf(domain_buf->pos, domain_buf->end, "%V", &u->host);
    }

    ngx_rtmp_notify_parse_target(s, domain_buf, &target);

    target.tag = &ngx_rtmp_notify_module;
    target.data = ns;
    live_stream->relay_pull_tag = NULL;
    ngx_rtmp_relay_pull(s, &local_name, &target);

next:
    if (reconnect) {
        ngx_rtmp_notify_reconnect(act);
        return NGX_OK;
    }

    ns->s = NULL;
    if (s_in_ns) {
        return next_play(s, v);
    }
    return NGX_OK;
}


static void
ngx_rtmp_notify_init_process_event_handle(ngx_event_t *ev)
{
    ngx_rtmp_notify_main_conf_t    *nmcf;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_conf_ctx_t            *ctx;
    ngx_rtmp_netcall_init_t        ci;
    ngx_url_t                      *url;

    ctx = (ngx_rtmp_conf_ctx_t *)
                ngx_get_conf(ngx_cycle->conf_ctx, ngx_rtmp_module);
    nmcf = (ngx_rtmp_notify_main_conf_t *)
                ctx->main_conf[ngx_rtmp_notify_module.ctx_index];
    nacf = (ngx_rtmp_notify_app_conf_t *)
                ctx->app_conf[ngx_rtmp_notify_module.ctx_index];

    if (nmcf == NULL || nacf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "notify: init proc| notify main conf is null or"
                    "notify app conf is null");
        return;
    }

    url = nmcf->url[NGX_RTMP_NOTIFY_ON_INIT_PROC];
    if (url == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "notify: init proc | url is null");
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "notify: process| init");

    ngx_memzero(&ci, sizeof(ngx_rtmp_netcall_init_t));
    ci.url = url;
    ci.log = ngx_cycle->log;
    ci.connect_timeout = (nacf->connect_timeout == NGX_CONF_UNSET_MSEC)
                                            ?5000:nacf->connect_timeout;
    ci.bufsize = (nacf->bufsize == NGX_CONF_UNSET_SIZE)?1024:nacf->bufsize;
    ci.create = ngx_rtmp_notify_init_proc_create;
    ci.handle = ngx_rtmp_notify_init_proc_handle;
    ci.arg = nmcf;
    ci.argsize = sizeof(*nmcf);

    if (ngx_rtmp_netcall_create(NULL, &ci) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                "notify: notify failed when initial process");
    }
    return;
}


static ngx_int_t
ngx_rtmp_notify_init_process(ngx_cycle_t *cycle)
{
    ngx_event_t                  *event;

    event = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_event_t));
    if (event == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "notify: init_process| calloc event failed");
        return NGX_ERROR;
    }
    event->data = NULL;
    event->log = &cycle->new_log;
    event->handler = ngx_rtmp_notify_init_process_event_handle;
    ngx_post_event(event, &ngx_rtmp_init_queue);

    return NGX_OK;
}


static void
ngx_rtmp_notify_exit_process(ngx_cycle_t *cycle)
{
    ngx_rtmp_notify_main_conf_t    *nmcf;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_conf_ctx_t            *ctx;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    ctx = (ngx_rtmp_conf_ctx_t *)
                ngx_get_conf(cycle->conf_ctx, ngx_rtmp_module);
    nmcf = (ngx_rtmp_notify_main_conf_t *)
                ctx->main_conf[ngx_rtmp_notify_module.ctx_index];
    nacf = (ngx_rtmp_notify_app_conf_t *)
                ctx->app_conf[ngx_rtmp_notify_module.ctx_index];

    if (nmcf == NULL || nacf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "notify: exit proc| notify main conf is null or"
                    "notify app conf is null");
        return;
    }

    url = nmcf->url[NGX_RTMP_NOTIFY_ON_EXIT_PROC];
    if (url == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "notify: exit proc | url is null");
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "notify: process| exit");

    ngx_memzero(&ci, sizeof(ngx_rtmp_netcall_init_t));
    ci.url = url;
    ci.log = ngx_cycle->log;
    ci.connect_timeout = (nacf->connect_timeout == NGX_CONF_UNSET_MSEC)
                                            ?5000:nacf->connect_timeout;
    ci.bufsize = (nacf->bufsize == NGX_CONF_UNSET_SIZE)?1024:nacf->bufsize;
    ci.create = ngx_rtmp_notify_exit_proc_create;
    ci.handle = ngx_rtmp_notify_exit_proc_handle;
    ci.arg = nmcf;
    ci.argsize = sizeof(*nmcf);

    if (ngx_rtmp_netcall_create(NULL, &ci) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                "notify: notify failed when initial process");
    }
    return;
}


static ngx_int_t
ngx_rtmp_notify_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    if (s->interprocess || s->auto_pulled)
    {
        goto next;
    }

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);
    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_CONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "notify: connect| '%V'", &url->url);

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.connect_timeout = nacf->connect_timeout;
    ci.bufsize = nacf->bufsize;
    ci.create = ngx_rtmp_notify_connect_create;
    ci.handle = ngx_rtmp_notify_connect_handle;
    ci.arg = v;
    ci.argsize = sizeof(*v);

    return ngx_rtmp_netcall_create(s, &ci);

next:
    return next_connect(s, v);
}


static ngx_int_t
ngx_rtmp_notify_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_netcall_init_t         ci;
    ngx_url_t                      *url;

    if (s->interprocess || s->auto_pulled ) {
        goto next;
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "notify: disconnect| %V", &s->name);

    nscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_notify_module);
    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);

    url = nscf->url[NGX_RTMP_NOTIFY_DISCONNECT];
    if (url == NULL) {
        goto next;
    }

    ngx_memzero(&ci, sizeof(ci));

    ci.url = url;
    ci.create = ngx_rtmp_notify_disconnect_create;
    ci.connect_timeout = nacf->connect_timeout;
    ci.bufsize = nacf->bufsize;

    ngx_rtmp_netcall_create(s, &ci);

next:
    return next_disconnect(s);
}


static ngx_int_t
ngx_rtmp_notify_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_int_t                       rc;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_live_stream_t              *live_stream;

    live_stream = s->live_stream;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_notify_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "notify: publish| creating notify ctx failed");

            return NGX_ERROR;
        }
        ctx->data = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_publish_t));
        ctx->datalen = sizeof(ngx_rtmp_publish_t);
        ngx_memcpy(ctx->data, v, sizeof(ngx_rtmp_publish_t));

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_notify_module);
    }
    ctx->publishing = 1;
    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }
    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (s->interprocess || (rctx && rctx->tag == &ngx_rtmp_auto_pull_module) ||
        (s->relay && nacf->shield_relay == 0))
    {
        goto next;
    }

    if (nacf->multi_url[NGX_RTMP_NOTIFY_PUBLISH]->nelts) {

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
            "notify: publish| on_publish act %s",
            ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_START]);

        rc = ngx_rtmp_notify_session_create(s, NGX_RTMP_NOTIFY_PUBLISH);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "notify: publish| on_publish create notify session failed");
            goto next;
        }

        ngx_rtmp_notify_session_netcall(s, v, sizeof(*v),
                                        NGX_RTMP_NOTIFY_PUBLISH,
                                        NGX_RTMP_NOTIFY_ACT_START,
                                    ~NGX_RTMP_NOTIFY_OPT_TRANSCODE);
    }

    ctx->start = ngx_cached_time->sec;

    if (nacf->multi_url[NGX_RTMP_NOTIFY_STREAM]->nelts == 0 ||
        live_stream->play_ctx || live_stream->publish_ctx->next)
    {
        goto next;
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
         "notify: publish| on_stream act %s",
         ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_START]);

    rc = ngx_rtmp_notify_session_create(s, NGX_RTMP_NOTIFY_STREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "notify: publish| on_stream create notify session failed");
        goto next;
    }
    ngx_rtmp_notify_session_netcall(s, v, sizeof(*v),
                                    NGX_RTMP_NOTIFY_STREAM,
                                    NGX_RTMP_NOTIFY_ACT_START,
                                    NGX_RTMP_NOTIFY_OPT_ALL);

next:
    return next_publish(s, v);
}


static void
ngx_rtmp_notify_reconnect_handle(ngx_event_t *ev)
{
    ngx_int_t                       rc;
    ngx_rtmp_notify_act_t          *act;

    act = ev->data;

    ngx_log_error(NGX_LOG_DEBUG, act->ns->log, 0,
                        "notify: reconnect_handle| stream %V, uri %V, timer %p",
                        &act->ns->stream, &act->url.uri, &act->ev);

    rc = ngx_rtmp_notify_netcall(act);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, act->ns->log, 0,
                        "notify: reconnect_handle| "
                        "netcall failed, stream %V, uri %V, timer %p",
                        &act->ns->stream, &act->url.uri, &act->ev);
        ngx_rtmp_notify_reconnect(act);
    }

    return;
}


static void
ngx_rtmp_notify_reconnect(ngx_rtmp_notify_act_t *act)
{
    ngx_rtmp_notify_session_t      *ns;
    ngx_msec_t                      timer;

    ns = act->ns;

    timer = 0;

    if (act->not_reconnect) {
        return;
    }

    if (ns->static_url == 0) {
        ns->url_index++;
        if (ns->url_index != 0 && (ns->url_index % ns->mu->urls.nelts) == 0) {
             ns->reach_last_urls = 1;
        }
        ns->url_index %= ns->mu->urls.nelts;
    }

    if (ns->url_index == 0 || ns->static_url) {
        act->reconnect_timer += act->reconnect_timer/2;
        if (act->reconnect_timer > ns->reconnect_max_timer) {
            act->reconnect_timer = ns->reconnect_max_timer;
        }
        timer = act->reconnect_timer;
    }

    ngx_log_error(NGX_LOG_INFO, ns->log, 0,
        "notify: reconnect| "
        "%V, act %s, timeout %d, timer %p ",
        &act->url.url, ngx_rtmp_notify_act_str[act->flag], timer, &act->ev);

    act->ev.handler = ngx_rtmp_notify_reconnect_handle;
    act->ev.log = ns->log;
    act->ev.data = act;

    ngx_add_timer(&act->ev, timer);
}


static ngx_chain_t *
ngx_rtmp_notify_http_format(ngx_rtmp_session_t *s,
                            ngx_rtmp_notify_multi_url_t *mu, ngx_pool_t *pool)
{
    ngx_chain_t                   *chain;
    ngx_int_t                      rc;
    ngx_str_t                      args;
    ngx_buf_t                     *buf;

    rc = ngx_rtmp_notify_fetch_variable(s, pool, &mu->args, &args);
    if (rc == NGX_ERROR) {
        return NULL;
    }
    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                  "notify: http_format| args = %V, data = %p, len = %d",
                   &args, args.data, args.len);

    if (args.len == 0) {
        return NULL;
    }
    buf = ngx_create_temp_buf(pool, NGX_RTMP_ARGS_MAX + sizeof(ngx_chain_t));
    chain = (ngx_chain_t *)(buf->start);
    buf->start = buf->pos = buf->last = buf->start + sizeof(ngx_chain_t);
    chain->buf = buf;
    chain->next = NULL;

    chain->buf->start = chain->buf->pos = args.data;
    chain->buf->end = chain->buf->last = args.data + args.len;

    return chain;
}


static ngx_chain_t *
ngx_rtmp_notify_common_create(ngx_rtmp_session_t *s, void *arg, ngx_pool_t *pool)
{
    ngx_rtmp_notify_act_t          *act;
    ngx_rtmp_notify_session_t      *ns;
    ngx_chain_t                    *al, *bl, *cl, *tl, **ll;
    ngx_url_t                      *url;
    ngx_buf_t                      *buf;
    ngx_int_t                       opt_index;

    ngx_memcpy(&act, arg, sizeof(act));
    ns = act->ns;

    al = bl = NULL;
    url = act->ci.url;
    opt_index = ngx_rtmp_notify_opt_index(ns->mu->opt);

    ngx_log_error(NGX_LOG_INFO, ns->log, 0,
        "notify: common_create| host %V, uri %V, act %s, opt %s",
        &url->host, &url->uri, ngx_rtmp_notify_act_str[act->flag],
        ngx_rtmp_notify_opt_str[opt_index]);

    tl = ns->args;
    ll = &al;
    for (; tl; tl = tl->next) {
        buf = ngx_create_temp_buf(pool, sizeof(ngx_chain_t) +
                                        tl->buf->last - tl->buf->pos);
        *ll = (ngx_chain_t*)buf->start;
        buf->start = buf->pos = buf->last = buf->start + sizeof(ngx_chain_t);
        buf->last = ngx_cpymem(buf->pos, tl->buf->pos, tl->buf->last - tl->buf->pos);
        (*ll)->buf = buf;
        ll = &((*ll)->next);
    }

    bl = NULL;

    buf = ngx_create_temp_buf(pool, sizeof(ngx_chain_t) +
                            sizeof("&call=&act=&opt=") +
                            ngx_strlen(ngx_rtmp_notify_call_str[ns->notify]) +
                            ngx_strlen(ngx_rtmp_notify_act_str[act->flag]) +
                            ngx_strlen(ngx_rtmp_notify_opt_str[opt_index]));
    tl = (ngx_chain_t*)buf->start;
    ngx_memzero(tl, sizeof(*tl));
    buf->start = buf->pos = buf->last = buf->start + sizeof(ngx_chain_t);
    buf->last = ngx_slprintf(buf->pos, buf->end, "&call=%s&act=%s&opt=%s",
                             ngx_rtmp_notify_call_str[ns->notify],
                             ngx_rtmp_notify_act_str[act->flag],
                             ngx_rtmp_notify_opt_str[opt_index]);
    tl->buf = buf;
    if (al) {
        al->next = tl;
    } else {
        al = tl;
        buf->pos++;
    }

    if (ns->method == NGX_RTMP_NETCALL_HTTP_POST) {
        cl = al;
        al = bl;
        bl = cl;
    }

    return ngx_rtmp_netcall_http_format_request(ns->method, &url->host,
                                                &url->uri, al, bl, pool,
                                                &ngx_rtmp_notify_urlencoded);
}


ngx_int_t
ngx_rtmp_notify_common_handle(ngx_rtmp_session_t *s, void *arg, ngx_chain_t *in)
{
    ngx_rtmp_notify_act_t          *act;
    ngx_rtmp_notify_session_t      *ns;
    ngx_str_t                       content;
    ngx_int_t                       retcode;

    ngx_memcpy(&act, arg, sizeof(act));
    ns = act->ns;

    ns->active--;
    ngx_log_error(NGX_LOG_INFO, ns->log, 0,
                  "notify: common_handle| "
                  "active %d, closed %d, notify %d, act %s",
                   ns->active, ns->closed,
                   ns->notify, ngx_rtmp_notify_act_str[act->flag]);
    if (ns->active == 0 && ns->closed) {
        ngx_rtmp_notify_session_free(ns);
        return NGX_OK;
    }

    retcode = ngx_rtmp_notify_parse_http_retcode(ns->log, in);
    if (retcode == NGX_ERROR || retcode == NGX_DONE) { // content or network error or return 4xx
        if (ns->notify == NGX_RTMP_NOTIFY_PLAY &&
            act->flag == NGX_RTMP_NOTIFY_ACT_START && ns->reach_last_urls &&
            ns->mu->opt == NGX_RTMP_NOTIFY_OPT_RELAY)
        {
            if (act->ev.timer_set) {
                ngx_del_timer(&act->ev);
            }
            return ngx_rtmp_notify_play_handle(retcode, act, in);
        }
        ngx_rtmp_notify_reconnect(act);
        return NGX_OK;
    }

    if (act->ev.timer_set) {
        ngx_del_timer(&act->ev);
    }

    if (ns->static_url == 0) {
        ns->static_url = 1;
    }

    if (act->flag == NGX_RTMP_NOTIFY_ACT_START) {
        ngx_rtmp_notify_update_init(ns, ns->mu->notify);
    }

    content.data = in->buf->pos;
    content.len = in->buf->last - in->buf->pos;
    ngx_log_error(NGX_LOG_DEBUG, ns->log, 0,
                "notify: common_handle| %V", &content);

    if (ns->notify == NGX_RTMP_NOTIFY_PLAY) {
        switch (act->flag) {
            case NGX_RTMP_NOTIFY_ACT_START:
                return ngx_rtmp_notify_play_handle(retcode, act, in);
            case NGX_RTMP_NOTIFY_ACT_UPDATE:
                return ngx_rtmp_notify_update_handle(retcode, act, in);
            case NGX_RTMP_NOTIFY_ACT_DONE:
                break;
        }
    } else if (ns->notify == NGX_RTMP_NOTIFY_PUBLISH) {
        switch (act->flag) {
            case NGX_RTMP_NOTIFY_ACT_START:
                return ngx_rtmp_notify_publish_handle(retcode, act, in);
            case NGX_RTMP_NOTIFY_ACT_UPDATE:
                return ngx_rtmp_notify_update_handle(retcode, act, in);
            case NGX_RTMP_NOTIFY_ACT_DONE:
                break;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_notify_netcall(ngx_rtmp_notify_act_t *act)
{
    ngx_rtmp_notify_session_t     *ns;
    ngx_rtmp_netcall_init_t       *ci;
    ngx_rtmp_notify_multi_url_t   *mu;
    ngx_url_t                    **uu, *u;
    ngx_event_t                   *ev;
    ngx_int_t                      opt_index;
    ngx_rtmp_session_t            *s;
    ngx_live_stream_t             *live_stream;

    ns = act->ns;
    ci = &act->ci;
    mu = ns->mu;
    live_stream = ns->live_stream;
    s = NULL;

    if (mu->detached){
        if (ns->notify == NGX_RTMP_NOTIFY_PLAY && live_stream->play_ctx
            && live_stream->play_ctx->session)
        {
            s = live_stream->play_ctx->session;
        }else if (ns->notify == NGX_RTMP_NOTIFY_PUBLISH && live_stream->publish_ctx
            && live_stream->publish_ctx->session) {
            s = live_stream->publish_ctx->session;
        }else{
            if(live_stream->play_ctx && live_stream->play_ctx->session){
                s = live_stream->play_ctx->session;
            }else if(live_stream->publish_ctx && live_stream->publish_ctx->session){
                s = live_stream->publish_ctx->session;
            }else{
                s = NULL;
            }
        }
    }else{
        s = ns->s;
    }

    if(s){
        ns->args = ngx_rtmp_notify_http_format(s, mu, ns->pool);
    }else{
        ngx_log_error(NGX_LOG_ERR, ns->log, 0,
                          "notify: netcall| rtmp session is null");
        /* Prevent the push-pull flow ends have
        been disconnected lead has been reconnected */
        return NGX_OK;
    }

    ci = &act->ci;
    ci->create = ngx_rtmp_notify_common_create;
    ci->handle = ngx_rtmp_notify_common_handle;
    ci->arg = &act;
    ci->argsize = sizeof(act);
    ci->connect_timeout = ns->connect_timeout;
    ci->bufsize = ns->bufsize;

    uu = ns->urls.elts;
    u = uu[ns->url_index];

    act->url = *u;
    ci->url = &act->url;

    //juege act=start and opt=relay  set relay_pull_tag
    if (ns->notify == NGX_RTMP_NOTIFY_PLAY &&
        (ns->mu->opt & NGX_RTMP_NOTIFY_OPT_RELAY))
    {
        live_stream->relay_pull_tag = &ngx_rtmp_notify_module;
    }

    if (act->flag == NGX_RTMP_NOTIFY_ACT_DONE &&
        ns->act[NGX_RTMP_NOTIFY_ACT_UPDATE])
    {
        ev = &ns->update_evt;
        if (ev->timer_set) {
            ngx_del_timer(ev);
        }
    }

    opt_index = ngx_rtmp_notify_opt_index(ns->mu->opt);

    ns->active++;
    ngx_log_error(NGX_LOG_DEBUG, ns->log, 0,
                          "notify: netcall| %s %s %s, active %d",
                          ngx_rtmp_notify_call_str[mu->notify],
                          ngx_rtmp_notify_act_str[act->flag],
                          ngx_rtmp_notify_opt_str[opt_index], ns->active);
    return ngx_rtmp_netcall_create(NULL, ci);
}


static void
ngx_rtmp_notify_session_netcall(ngx_rtmp_session_t *s,
              void *data, ngx_uint_t datalen,
              ngx_uint_t notify_flag, ngx_uint_t act_flag, ngx_uint_t opt_flag)
{
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_notify_session_t      *ns, *tns, *detached_ns, *ttns;
    ngx_rtmp_notify_act_t          *act;
    ngx_int_t                       rc;
    ngx_flag_t                      detached;

    detached_ns = NULL;
    ns = NULL;
    detached = opt_flag & NGX_RTMP_NOTIFY_DETACHED_MASK;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx) {
        ns = ctx->nl[notify_flag];
    }

    if (detached) {
        detached_ns = ngx_rtmp_notify_fetch_session(s, notify_flag);
    }

    if (detached_ns) {
        ttns = ns;
        tns = detached_ns;
    } else {
        ttns = detached_ns;
        tns = ns;
    }

    while (tns) {
        act = tns->act[act_flag];
        if (act == NULL || !(tns->mu->opt & opt_flag) || act->ev.timer_set) {
            tns = tns->next;
            if (tns == NULL && ttns) {
                tns = ttns;
                ttns = NULL;
            }
            continue;
        }

        if (act->flag == NGX_RTMP_NOTIFY_ACT_START) {
            tns->static_url = 0;
            tns->url_index = 0;
        }

        if (data && datalen) {
            if (act->data == NULL) {
                act->data = ngx_pcalloc(tns->pool, datalen);
            } else {
                ngx_pfree(tns->pool, act->data);
                act->data = ngx_pcalloc(tns->pool, datalen);
            }
            ngx_memcpy(act->data, data, datalen);
        }

        tns->s = s;
        rc = ngx_rtmp_notify_netcall(act);
        if (rc != NGX_OK) {
            ngx_rtmp_notify_reconnect(act);
        }
        tns = tns->next;
        if (tns == NULL && ttns) {
            tns = ttns;
            ttns = NULL;
        }
    }

    return;
}


static ngx_int_t
ngx_rtmp_notify_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_int_t                       rc;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_live_stream_t              *live_stream;
    ngx_flag_t                      relay = 0;

    ctx = NULL;
    live_stream = s->live_stream;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_notify_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "notify: play| creating notify ctx failed");

            return NGX_ERROR;
        }
        ctx->data = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_play_t));
        ctx->datalen = sizeof(ngx_rtmp_play_t);
        ngx_memcpy(ctx->data, v, sizeof(ngx_rtmp_play_t));

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_notify_module);
    }
    ctx->publishing = 0;
    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (s->interprocess || (rctx && rctx->tag == &ngx_rtmp_auto_pull_module) ||
            s->relay)
    {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                "notify: play| interprocess %d, relay %d,",
                s->interprocess, s->relay);
        goto next;
    }

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        goto next;
    }

    if (nacf->multi_url[NGX_RTMP_NOTIFY_PLAY]->nelts) {

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                    "notify: play| on_play act %s",
                    ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_START]);

        rc = ngx_rtmp_notify_session_create(s, NGX_RTMP_NOTIFY_PLAY);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "notify: play| on_play create notify session failed");
            goto next;
        }

        ngx_rtmp_notify_session_netcall(s, v, sizeof(*v), NGX_RTMP_NOTIFY_PLAY,
                                           NGX_RTMP_NOTIFY_ACT_START,
                                           NGX_RTMP_NOTIFY_OPT_NOTIFY);

        if (live_stream->play_ctx->next == NULL) {
            ngx_rtmp_notify_session_netcall(s, v, sizeof(*v),
                                               NGX_RTMP_NOTIFY_PLAY,
                                               NGX_RTMP_NOTIFY_ACT_START,
                    NGX_RTMP_NOTIFY_OPT_TRANSCODE | NGX_RTMP_NOTIFY_OPT_GLOBAL);

            if (live_stream->relay_pull_tag == NULL &&
                live_stream->publish_ctx == NULL)
            {
                relay = 1;
                ngx_rtmp_notify_session_netcall(s, v, sizeof(*v),
                                                   NGX_RTMP_NOTIFY_PLAY,
                                                   NGX_RTMP_NOTIFY_ACT_START,
                                                   NGX_RTMP_NOTIFY_OPT_RELAY);
            }
        }
    }

    ctx->start = ngx_cached_time->sec;

    if (nacf->multi_url[NGX_RTMP_NOTIFY_STREAM]->nelts == 0 ||
        live_stream->play_ctx->next || live_stream->publish_ctx)
    {
        goto next;
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                "notify: play| on_stream act %s",
                ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_START]);

    rc = ngx_rtmp_notify_session_create(s, NGX_RTMP_NOTIFY_STREAM);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "notify: play| on_stream create notify session failed");
        goto next;
    }
    ngx_rtmp_notify_session_netcall(s, v, sizeof(*v),
                    NGX_RTMP_NOTIFY_STREAM, NGX_RTMP_NOTIFY_ACT_START,
                    NGX_RTMP_NOTIFY_OPT_ALL);

next:
    if (relay && (ctx->opt_flags & NGX_RTMP_NOTIFY_OPT_RELAY)) {
        return NGX_OK;
    }

    return next_play(s, v);
}


static void
ngx_rtmp_notify_create_reconnect(ngx_live_stream_t *st,
                               ngx_rtmp_notify_session_t *ns,
                               ngx_flag_t publishing)
{
    ngx_uint_t                      notify_flag;
    ngx_rtmp_notify_act_t          *act;

    notify_flag = NGX_RTMP_NOTIFY_PUBLISH;
    if (publishing) {
        notify_flag = NGX_RTMP_NOTIFY_PLAY;
    }

    if (ns == NULL)  {
        ns = st->nns[notify_flag];
    }

    if (ns == NULL) {
        return;
    }

    act = ns->act[NGX_RTMP_NOTIFY_ACT_START];
    if (act == NULL) {
        return;
    }

    ns->static_url = 0;
    ns->s = NULL;

    if (publishing) {
        st->relay_pull_tag = &ngx_rtmp_notify_module;
    }
    ngx_rtmp_notify_reconnect(act);
}


static ngx_int_t
ngx_rtmp_notify_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_live_stream_t              *st;
    ngx_flag_t                      stream_done;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_rtmp_notify_session_t      *ns;
    ngx_rtmp_notify_ctx_t          *ctx;

    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    stream_done = 0;

    if (s->interprocess || (rctx && rctx->tag == &ngx_rtmp_auto_pull_module)
        || s->closed)
    {
        goto next;
    }

    st = ngx_live_fetch_stream(&s->serverid, &s->stream);
    if (st == NULL) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        goto reconnect;
    }

    // publish done
    if (ctx->publishing) {
        ngx_rtmp_notify_session_netcall(s, NULL, 0, NGX_RTMP_NOTIFY_PUBLISH,
                        NGX_RTMP_NOTIFY_ACT_DONE, NGX_RTMP_NOTIFY_OPT_ALL);
        if (st->play_ctx == NULL &&
            st->publish_ctx->next == NULL)
        {
            stream_done = 1;
        }
    } else { // play done
        ngx_rtmp_notify_session_netcall(s, NULL, 0, NGX_RTMP_NOTIFY_PLAY,
                    NGX_RTMP_NOTIFY_ACT_DONE, NGX_RTMP_NOTIFY_OPT_NOTIFY);
        if (st->play_ctx && st->play_ctx->next == NULL) {
            ngx_rtmp_notify_session_netcall(s, NULL, 0, NGX_RTMP_NOTIFY_PLAY,
                        NGX_RTMP_NOTIFY_ACT_DONE, ~NGX_RTMP_NOTIFY_OPT_NOTIFY); 
        }
        if (st->play_ctx->next == NULL && st->publish_ctx == NULL) {
            stream_done = 1;
        }
    }

    // stream done
    if (stream_done) {
        ngx_rtmp_notify_session_netcall(s, NULL, 0,
                NGX_RTMP_NOTIFY_STREAM, NGX_RTMP_NOTIFY_ACT_DONE,
                NGX_RTMP_NOTIFY_OPT_ALL);
    }

    ngx_rtmp_notify_session_close(s, stream_done);

    if (stream_done) {
        goto next;
    }
reconnect:
    if (rctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "notify: close_stream| relay ctx is null");
        goto next;
    }

    if (rctx->publishing) { /* pull session */
        if (st->relay_pull_tag != &ngx_rtmp_notify_module) {
            /* relay pull not create by notify module */
            goto next;
        }
    } else { /* push session */
        if (s->relay == 0 || rctx->tag != &ngx_rtmp_notify_module) {
            /* relay not create by rtmp notify module */
            goto next;
        }
    }

    if (rctx->publishing) { /* relay pull session close */
        if (st->publish_ctx && (st->publish_ctx->session != s
                            || st->publish_ctx->next))
        {
            goto next;
        }

        if (st->play_ctx != NULL) {
            ns = st->relay_pull_data;
            if (ns) { /* pure push */
                ngx_rtmp_notify_create_reconnect(st, ns, 1);
            }
        }
    } else { /* relay push session close */
        if (st->publish_ctx != NULL) {
            ns = rctx->data;
            ngx_rtmp_notify_create_reconnect(st, ns, 0);
        }
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_notify_record_done(ngx_rtmp_session_t *s, ngx_rtmp_record_done_t *v)
{
    return next_record_done(s, v);
}


static ngx_url_t *
ngx_rtmp_notify_parse_url(ngx_conf_t *cf, ngx_str_t *url)
{
    ngx_url_t                         *u;
    size_t                             add;
    ngx_str_t                          t_url;

    add = 0;

    u = ngx_pcalloc(cf->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    if (ngx_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
    }

    ngx_rtmp_notify_variable_index(cf, url, &t_url);

    u->url.len = t_url.len - add;
    u->url.data = t_url.data + add;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }
    ngx_dynamic_resolver_add_domain(&u->host, cf->cycle);

    return u;
}

static ngx_url_t *
ngx_rtmp_notify_set_ns_urls(ngx_rtmp_notify_session_t *ns, ngx_url_t *origin_u)
{
    ngx_str_t                         *url;
    ngx_url_t                         *u;
    ngx_str_t                          t_url;

    url = &(origin_u->url);

    u = ngx_pcalloc(ns->pool, sizeof(ngx_url_t));
    if (u == NULL) {
        return NULL;
    }

    t_url.len = url->len;
    t_url.data = ngx_pcalloc(ns->pool, t_url.len);
    ngx_memcpy(t_url.data, url->data, t_url.len);

    u->url.len = t_url.len;
    u->url.data = t_url.data;
    u->default_port = 80;
    u->uri_part = 1;

    if (ngx_parse_url(ns->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_ERR, ns->log, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NULL;
    }
    u->host = origin_u->host;

    return u;
}

static char *
ngx_rtmp_notify_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_srv_conf_t     *nscf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_connect") - 1:
            n = NGX_RTMP_NOTIFY_CONNECT;
            break;

        case sizeof("on_disconnect") - 1:
            n = NGX_RTMP_NOTIFY_DISCONNECT;
            break;
    }

    nscf->url[n] = u;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_on_main_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_main_conf_t     *nmcf = conf;

    ngx_str_t                       *name, *value;
    ngx_url_t                       *u;
    ngx_uint_t                       n, i;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {
        case sizeof("on_init_proc") - 1:
            if (name->data[3] == 'i') {
                n = NGX_RTMP_NOTIFY_ON_INIT_PROC;
            } else if (name->data[3] == 'e') {
                n = NGX_RTMP_NOTIFY_ON_EXIT_PROC;
            }
            break;
        default:

            return NGX_CONF_ERROR;
    }

    nmcf->url[n] = u;

    for (i = 1; i < cf->args->nelts; ++i) {
         if (ngx_strncmp(value[i].data, "args=", 5) == 0) {
            nmcf->args[n] = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
            nmcf->args[n]->data = value[i].data + 5;
            nmcf->args[n]->len = value[i].len - 5;
         }
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_parse_act(ngx_rtmp_notify_multi_url_t *mu, ngx_str_t *act)
{
    u_char                        *p, *pos;
    ngx_str_t                      a;
    ngx_uint_t                     n;

    p = act->data;
    pos = p;
    while (p <= act->data + act->len) {
        if ((*p != ',') && (p < act->data + act->len)) {
            p++;
            continue;
        }

        a.data = pos;
        a.len = p - pos;

        switch (a.len) {
            case sizeof("done") - 1:

                n = NGX_RTMP_NOTIFY_ACT_DONE;

                break;

            case sizeof("start") - 1:

                n = NGX_RTMP_NOTIFY_ACT_START;

                break;

            case sizeof("update") - 1:

                n = NGX_RTMP_NOTIFY_ACT_UPDATE;

                break;
            default:
                return NGX_CONF_ERROR;
        }

        mu->act[n] = 1;

        p++;
        pos = p;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_parse_option(ngx_rtmp_notify_multi_url_t *mu, ngx_str_t *opt)
{
    ngx_uint_t                     i;
    ngx_uint_t                     mask;

    for (i = 0; i < sizeof(ngx_rtmp_notify_opt_str)/sizeof(void*); ++i) {
        if (opt->len != ngx_strlen(ngx_rtmp_notify_opt_str[i]) ||
            ngx_strncmp(ngx_rtmp_notify_opt_str[i], opt->data, opt->len))
        {
            continue;
        }

        mu->opt = ngx_rtmp_notify_opt_integer[i];
        mu->detached = mu->opt & NGX_RTMP_NOTIFY_DETACHED_MASK;

        mu->response =
        mu->opt & NGX_RTMP_NOTIFY_OPT_RELAY;

        break;
    }

    if (mu->opt == 0) {
        return "The notify-opt is not known";
    }

    mask = ngx_rtmp_notify_opt_mask[mu->notify];
    if (!(mask & mu->opt)) {
        return "The notify-opt is not supported";
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_parse_multi_url(ngx_conf_t *cf,
                                ngx_rtmp_notify_app_conf_t *nacf,
                                ngx_uint_t n)
{
    ngx_rtmp_notify_multi_url_t   *mu;
    ngx_str_t                     *value;
    ngx_uint_t                     i;
    ngx_url_t                    **uu;
    ngx_str_t                      act, args, opt;
    char                          *rc;

    mu = (ngx_rtmp_notify_multi_url_t*)ngx_array_push(nacf->multi_url[n]);

    ngx_array_init(&mu->urls, cf->pool, 1, sizeof(ngx_url_t*));

    mu->notify = n;
    mu->opt = NGX_RTMP_NOTIFY_OPT_NOTIFY;

    value = cf->args->elts;
    for (i = 1; i < cf->args->nelts; ++i) {

        if (value[i].len < 7) {
            return NGX_CONF_ERROR;
        }

        if (ngx_strncmp(value[i].data, "act=", 4) == 0) {
            act.data = value[i].data + 4;
            act.len = value[i].len - 4;
            rc = ngx_rtmp_notify_parse_act(mu, &act);
            if (rc != NGX_CONF_OK) {
                return rc;
            }

        } else if (ngx_strncmp(value[i].data, "args=", 5) == 0) {
            args.data = value[i].data + 5;
            args.len = value[i].len - 5;
            if (ngx_rtmp_notify_variable_index(cf, &args, &mu->args)
                != NGX_OK)
            {
                return "invalid args";
            }

        } else if (ngx_strncmp(value[i].data, "groupid=", 8) == 0) {
            mu->groupid.data = value[i].data + 8;
            mu->groupid.len = value[i].len - 8;

        } else if (ngx_strncmp(value[i].data, "http://", 7)== 0) {
            uu = (ngx_url_t**)ngx_array_push(&mu->urls);
           *uu = ngx_rtmp_notify_parse_url(cf, &value[i]);

        } else if (ngx_strncmp(value[i].data, "opt=", 4) == 0) {
            opt.data = value[i].data + 4;
            opt.len = value[i].len - 4;
            rc = ngx_rtmp_notify_parse_option(mu, &opt);
            if (rc != NGX_CONF_OK) {
                return rc;
            }

        } else {
            return "unknown param";
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_str_t                      *name, *value;
    ngx_url_t                      *u;
    ngx_uint_t                      n;

    value = cf->args->elts;

    u = ngx_rtmp_notify_parse_url(cf, &value[1]);
    if (u == NULL) {
        return NGX_CONF_ERROR;
    }

    name = &value[0];

    n = 0;

    switch (name->len) {

        case sizeof("on_play") - 1:
            n = NGX_RTMP_NOTIFY_PLAY;

            break;

        case sizeof("on_stream") - 1:
            if (name->data[3] == 'r') {
                n = NGX_RTMP_NOTIFY_RECORD;
            } else if (name->data[3] == 's') {
                n = NGX_RTMP_NOTIFY_STREAM;
            }

            break;

        case sizeof("on_publish") - 1:
            n = NGX_RTMP_NOTIFY_PUBLISH;
            break;

        default:

            return NGX_CONF_ERROR;

    }

    nacf->url[n] = u;

    return ngx_rtmp_notify_parse_multi_url(cf, nacf, n);
}


static char *
ngx_rtmp_notify_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;

    ngx_rtmp_notify_srv_conf_t     *nscf;
    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    if (value->len == sizeof("get") - 1 &&
        ngx_strncasecmp(value->data, (u_char *) "get", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_GET;

    } else if (value->len == sizeof("post") - 1 &&
               ngx_strncasecmp(value->data, (u_char *) "post", value->len) == 0)
    {
        nacf->method = NGX_RTMP_NETCALL_HTTP_POST;

    } else {
        return "got unexpected method";
    }

    nscf = ngx_rtmp_conf_get_module_srv_conf(cf, ngx_rtmp_notify_module);
    nscf->method = nacf->method;

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_notify_reconnect_timer(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;
    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    nacf->reconnect_min_timer = ngx_parse_time(&value[0], 0);
    nacf->reconnect_max_timer = ngx_parse_time(&value[1], 0);

    if (!nacf->reconnect_min_timer || !nacf->reconnect_max_timer ||
        nacf->reconnect_min_timer == (ngx_msec_t) NGX_ERROR ||
        nacf->reconnect_max_timer == (ngx_msec_t) NGX_ERROR ||
        nacf->reconnect_min_timer >= nacf->reconnect_max_timer)
    {
        return "max timer must be larger than min timer, and must not be zero";
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_notify_parse_pargs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_notify_app_conf_t     *nacf = conf;
    ngx_str_t                      *value;

    value = cf->args->elts;
    value++;

    if (value == NULL || ngx_rtmp_notify_variable_index(cf, value, &nacf->npargs)
                != NGX_OK)
    {
        return "parse pargs invalid args";
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_notify_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_notify_app_conf_t     *nacf;
    ngx_rtmp_notify_ctx_t          *ctx;
    ngx_rtmp_codec_ctx_t           *cctx;
    ngx_rtmp_relay_ctx_t           *rctx;

    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    nacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_notify_module);
    if (nacf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "notify: notify_av| nacf is null");
        return NGX_ERROR;
    }


    if (s->interprocess || (rctx && rctx->tag == &ngx_rtmp_auto_pull_module) ||
        (s->relay && nacf->shield_relay == 0))
    {
        return NGX_OK;
    }

    cctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    if (cctx == NULL || cctx->meta == NULL || cctx->height == 0 ||
            cctx->width == 0 || cctx->frame_rate == 0 ||
                cctx->video_data_rate == 0 || cctx->audio_data_rate == 0)
    {
        ngx_log_error(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "notify: notify_av| meta data is not received");
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_notify_module);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "notify: notify_av| notify ctx is null");
    }
    if (ctx->publish_opt_trans == 0) {
        ngx_log_error(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "notify: notify_av| opt transcode of publish is null");
        return NGX_OK;
    }

    if (ctx->on_publish_meta == 1) {
        ngx_log_error(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "notify: notify_av| trancode publish is already send");
        return NGX_OK;
    }

    if (nacf->multi_url[NGX_RTMP_NOTIFY_PUBLISH]->nelts == 0) {
        ngx_log_error(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                "notify: notify_av| notify publish mu nelts is zero");
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
        "notify: notify_av| on_publish act %s",
         ngx_rtmp_notify_act_str[NGX_RTMP_NOTIFY_ACT_START]);

    ngx_rtmp_notify_session_netcall(s, NULL, 0,
                                    NGX_RTMP_NOTIFY_PUBLISH,
                                    NGX_RTMP_NOTIFY_ACT_START,
                                    NGX_RTMP_NOTIFY_OPT_TRANSCODE);

    ctx->on_publish_meta = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_notify_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_notify_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_notify_av;

    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_notify_connect;

    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_notify_disconnect;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_notify_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_notify_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_notify_close_stream;

    next_record_done = ngx_rtmp_record_done;
    ngx_rtmp_record_done = ngx_rtmp_notify_record_done;

    return NGX_OK;
}
