/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 *
 * Open Capability Live Platform
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_dynamic_resolver.h"
#include "ngx_toolkit_misc.h"
#include "ngx_netcall.h"


static ngx_rtmp_publish_pt          next_publish;
static ngx_rtmp_play_pt             next_play;
static ngx_rtmp_push_pt             next_push;
static ngx_rtmp_pull_pt             next_pull;
static ngx_rtmp_close_stream_pt     next_close_stream;


static ngx_int_t ngx_rtmp_oclp_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_rtmp_oclp_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_oclp_create_main_conf(ngx_conf_t *cf);
static char *ngx_rtmp_oclp_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_rtmp_oclp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_rtmp_oclp_merge_srv_conf(ngx_conf_t *cf, void *parent,
       void *child);
static void *ngx_rtmp_oclp_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_oclp_merge_app_conf(ngx_conf_t *cf, void *parent,
       void *child);

static char *ngx_rtmp_oclp_on_main_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_oclp_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char *ngx_rtmp_oclp_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);

#define NGX_RTMP_OCLP_START     0x01
#define NGX_RTMP_OCLP_UPDATE    0x02
#define NGX_RTMP_OCLP_DONE      0x04


enum {
    NGX_RTMP_OCLP_PROC,         /* only notify */
    NGX_RTMP_OCLP_MAIN_MAX
};

enum {
    NGX_RTMP_OCLP_CONNECT,      /* only notify */
    NGX_RTMP_OCLP_SRV_MAX
};

enum {
    NGX_RTMP_OCLP_PLAY,         /* only notify */
    NGX_RTMP_OCLP_PUBLISH,      /* only notify */
    NGX_RTMP_OCLP_PULL,         /* relay pull */
    NGX_RTMP_OCLP_PUSH,         /* relay push */
    NGX_RTMP_OCLP_STREAM,       /* only notify */
    NGX_RTMP_OCLP_META,         /* for transcode */
    NGX_RTMP_OCLP_RECORD,       /* for record */
    NGX_RTMP_OCLP_APP_MAX
};

static char *ngx_rtmp_oclp_stage[] = {
    "",
    "start",
    "update",
    "",
    "done",
};

static char *ngx_rtmp_oclp_app_type[] = {
    "play",
    "publish",
    "pull",
    "push",
    "stream",
    "meta",
    "record",
};

typedef struct {
    ngx_uint_t                  status;
    char                       *code;
    char                       *level;
    char                       *desc;
} ngx_rtmp_oclp_relay_error_t;

static ngx_rtmp_oclp_relay_error_t ngx_rtmp_oclp_relay_errors[] = {
    { 404, "NetStream.Play.StreamNotFound", "error", "No such stream" },
    { 400, "NetStream.Publish.BadName",     "error", "Already publishing" },
    { 0, NULL, NULL, NULL },
};


typedef struct {
    ngx_netcall_ctx_t          *pctx;   /* play or publish ctx */
    ngx_netcall_ctx_t          *mctx;   /* meta ctx */
} ngx_rtmp_oclp_ctx_t;


#define NGX_RTMP_OCLP_META_VIDEO    0
#define NGX_RTMP_OCLP_META_AUDIO    1
#define NGX_RTMP_OCLP_META_BOTH     2

static ngx_conf_enum_t ngx_rtmp_oclp_meta_type[] = {
    { ngx_string("video"),  NGX_RTMP_OCLP_META_VIDEO },
    { ngx_string("audio"),  NGX_RTMP_OCLP_META_AUDIO },
    { ngx_string("both"),   NGX_RTMP_OCLP_META_BOTH  },
    { ngx_null_string,      0 }
};

typedef struct {
    ngx_str_t                   url;
    ngx_str_t                   args;
    ngx_str_t                   groupid;
    ngx_uint_t                  stage;
    ngx_msec_t                  timeout;
    ngx_int_t                   retries;
    ngx_msec_t                  update;
} ngx_rtmp_oclp_event_t;

typedef struct {
    ngx_rtmp_oclp_event_t       events[NGX_RTMP_OCLP_MAIN_MAX];
} ngx_rtmp_oclp_main_conf_t;

typedef struct {
    ngx_rtmp_oclp_event_t       events[NGX_RTMP_OCLP_SRV_MAX];
} ngx_rtmp_oclp_srv_conf_t;

typedef struct {
    ngx_flag_t                  meta_once;
    ngx_uint_t                  meta_type;
    ngx_array_t                 events[NGX_RTMP_OCLP_APP_MAX];
} ngx_rtmp_oclp_app_conf_t;


static ngx_command_t ngx_rtmp_oclp_commands[] = {

    { ngx_string("oclp_proc"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_main_event,
      NGX_RTMP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_connect"),
      NGX_RTMP_SRV_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_srv_event,
      NGX_RTMP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_play"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_publish"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_pull"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_push"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_stream"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_meta"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_record"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_oclp_on_app_event,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oclp_meta_once"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_oclp_app_conf_t, meta_once),
      NULL },

    { ngx_string("oclp_meta_type"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_conf_set_enum_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_oclp_app_conf_t, meta_type),
      &ngx_rtmp_oclp_meta_type },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_oclp_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_oclp_postconfiguration,        /* postconfiguration */
    ngx_rtmp_oclp_create_main_conf,         /* create main configuration */
    ngx_rtmp_oclp_init_main_conf,           /* init main configuration */
    ngx_rtmp_oclp_create_srv_conf,          /* create server configuration */
    ngx_rtmp_oclp_merge_srv_conf,           /* merge server configuration */
    ngx_rtmp_oclp_create_app_conf,          /* create app configuration */
    ngx_rtmp_oclp_merge_app_conf            /* merge app configuration */
};


ngx_module_t  ngx_rtmp_oclp_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_oclp_module_ctx,              /* module context */
    ngx_rtmp_oclp_commands,                 /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_oclp_init_process,             /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_oclp_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_oclp_main_conf_t  *omcf;

    omcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_oclp_main_conf_t));
    if (omcf == NULL) {
        return NULL;
    }

    return omcf;
}

static char *
ngx_rtmp_oclp_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static void *
ngx_rtmp_oclp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_rtmp_oclp_srv_conf_t   *oscf;

    oscf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_oclp_srv_conf_t));
    if (oscf == NULL) {
        return NULL;
    }

    return oscf;
}

static char *
ngx_rtmp_oclp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

static void *
ngx_rtmp_oclp_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_uint_t                  n;

    oacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_oclp_app_conf_t));
    if (oacf == NULL) {
        return NULL;
    }

    for (n = 0; n < NGX_RTMP_OCLP_APP_MAX; ++n) {
        if (ngx_array_init(&oacf->events[n], cf->pool, NGX_RTMP_MAX_OCLP,
            sizeof(ngx_rtmp_oclp_event_t)) == NGX_ERROR)
        {
            return NULL;
        }
    }

    oacf->meta_once = NGX_CONF_UNSET;
    oacf->meta_type = NGX_CONF_UNSET_UINT;

    return oacf;
}

static char *
ngx_rtmp_oclp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_oclp_app_conf_t   *prev = parent;
    ngx_rtmp_oclp_app_conf_t   *conf = child;

    ngx_conf_merge_value(conf->meta_once, prev->meta_once, 1);
    ngx_conf_merge_uint_value(conf->meta_type, prev->meta_type,
                              NGX_RTMP_OCLP_META_VIDEO);

    return NGX_CONF_OK;
}

static u_char *
ngx_rtmp_oclp_strlechr(u_char *p, u_char *last)
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
ngx_rtmp_oclp_variable_index(ngx_conf_t *cf,
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
        t = ngx_rtmp_oclp_strlechr(t, e);
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
ngx_rtmp_oclp_fetch_variable(ngx_rtmp_session_t *s, ngx_pool_t *pool,
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

    #define NGX_RTMP_OCLP_BUF(__start__, __end__)                            \
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
        NGX_RTMP_OCLP_BUF(p, t);
        if (t == e) {
            break;
        }

        var.data = ++t;
        t = ngx_rtmp_oclp_strlechr(t, e);
        if (t == NULL) {
            t = e;
        }
        var.len = t - var.data;
        index = ngx_atoi(var.data, var.len);
        vv = ngx_rtmp_get_indexed_variable(s, index);
        if (vv == NULL || vv->not_found) {
            p = t;
            continue;
        }
        wp = vv->data;
        we = vv->data + vv->len;

        NGX_RTMP_OCLP_BUF(wp, we);
        p = t;
    }

    #undef NGX_RTMP_OCLP_BUF

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
        "rtmp oclp: fetch_variable| target len = %d, content length = %d",
         target->len, length);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_oclp_create_event(ngx_conf_t *cf, ngx_rtmp_oclp_event_t *event,
    ngx_str_t *values, ngx_uint_t n)
{
    ngx_request_url_t           ru;
    ngx_str_t                   tmp;
    ngx_uint_t                  i;
    u_char                     *p, *last;
    ngx_str_t                   tmp_args;

    for (i = 0; i < n; ++i) {
        if (ngx_strncmp(values[i].data, "args=", 5) == 0) {
            tmp_args.len = values[i].len - 5;
            tmp_args.data = values[i].data + 5;
            ngx_rtmp_oclp_variable_index(cf, &tmp_args, &event->args);
            continue;
        }

        if (ngx_strncmp(values[i].data, "groupid=", 8) == 0) {
            event->groupid.len = values[i].len - 8;
            event->groupid.data = values[i].data + 8;
            continue;
        }

        if (ngx_strncmp(values[i].data, "stage=", 6) == 0) {
            p = values[i].data + 6;
            last = values[i].data + values[i].len;

            while (1) {
                tmp.data = p;
                p = ngx_strlchr(p, last, ',');
                if (p == NULL) {
                    tmp.len = last - tmp.data;
                } else {
                    tmp.len = p - tmp.data;
                }

                switch (tmp.len) {
                case 4:
                    if (ngx_strncmp(tmp.data, "done", 4) == 0) {
                        event->stage |= NGX_RTMP_OCLP_DONE;
                    } else {
                        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                "unknown stage \"%V\"", &tmp);
                        return NGX_ERROR;
                    }
                    break;
                case 5:
                    if (ngx_strncmp(tmp.data, "start", 5) == 0) {
                        event->stage |= NGX_RTMP_OCLP_START;
                    } else {
                        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                "unknown stage \"%V\"", &tmp);
                        return NGX_ERROR;
                    }
                    break;
                case 6:
                    if (ngx_strncmp(tmp.data, "update", 6) == 0) {
                        event->stage |= NGX_RTMP_OCLP_UPDATE;
                    } else {
                        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                "unknown stage \"%V\"", &tmp);
                        return NGX_ERROR;
                    }
                    break;
                default:
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                            "unknown stage \"%V\"", &tmp);
                    return NGX_ERROR;
                }

                if (p == last || p == NULL) {
                    break;
                }

                ++p;
            }

            continue;
        }

        if (ngx_strncmp(values[i].data, "timeout=", 8) == 0) {
            tmp.len = values[i].len - 8;
            tmp.data = values[i].data + 8;

            event->timeout = ngx_parse_time(&tmp, 0);
            if (event->timeout == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "unknown timeout timer format \"%V\"", &tmp);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(values[i].data, "retries=", 8) == 0) {
            tmp.len = values[i].len - 8;
            tmp.data = values[i].data + 8;

            event->retries = ngx_atoi(tmp.data, tmp.len);
            if (event->retries == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "unknown retries format \"%V\"", &tmp);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(values[i].data, "update=", 7) == 0) {
            tmp.len = values[i].len - 7;
            tmp.data = values[i].data + 7;

            event->update = ngx_parse_time(&tmp, 0);
            if (event->update == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "unknown cont timer format \"%V\"", &tmp);
                return NGX_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(values[i].data, "http://", 7) != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "must be http url");
            return NGX_ERROR;
        }

        if (event->url.len != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate url");
            return NGX_ERROR;
        }

        event->url.len = values[i].len;
        event->url.data = values[i].data;

        if (ngx_parse_request_url(&ru, &event->url) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "request url format error");
            return NGX_ERROR;
        }

        ngx_dynamic_resolver_add_domain(&ru.host, cf->cycle);
    }

    if (event->url.len == 0) {
        return NGX_ERROR;
    } else {
        if (event->timeout == 0) {
            event->timeout = 3000;
        }

        if (event->update == 0) {
            event->update = 60000;
        }

        event->stage |= NGX_RTMP_OCLP_START;

        return NGX_OK;
    }
}

static char *
ngx_rtmp_oclp_on_main_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_oclp_main_conf_t  *omcf;
    ngx_str_t                  *name, *value;
    ngx_uint_t                  n;

    omcf = conf;

    value = cf->args->elts;

    name = &value[0];

    n = 0;

    switch (name->len) {
    case sizeof("oclp_proc") - 1:
        n = NGX_RTMP_OCLP_PROC;
        break;
    }

    if (ngx_rtmp_oclp_create_event(cf, &omcf->events[n], &value[1],
            cf->args->nelts - 1) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_oclp_on_srv_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_oclp_srv_conf_t   *oscf;
    ngx_str_t                  *name, *value;
    ngx_uint_t                  n;

    oscf = conf;

    value = cf->args->elts;

    name = &value[0];

    n = 0;

    switch (name->len) {
    case sizeof("oclp_connect") - 1:
        n = NGX_RTMP_OCLP_CONNECT;
        break;
    }

    if (ngx_rtmp_oclp_create_event(cf, &oscf->events[n], &value[1],
            cf->args->nelts - 1) == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_rtmp_oclp_on_app_event(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_str_t                  *name, *value;
    ngx_uint_t                  n;

    oacf = conf;

    value = cf->args->elts;

    name = &value[0];

    n = 0;

    switch (name->len) {
    case sizeof("oclp_play") - 1:
        if (name->data[8] == 'y') { /* oclp_play */
            n = NGX_RTMP_OCLP_PLAY;
            if (oacf->events[n].nelts != 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate %V", name);
                return NGX_CONF_ERROR;
            }
        } else if (name->data[8] == 'l') { /* oclp_pull */
            n = NGX_RTMP_OCLP_PULL;
            if (oacf->events[n].nelts != 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate %V", name);
                return NGX_CONF_ERROR;
            }
        } else if (name->data[8] == 'h') { /* oclp_push */
            n = NGX_RTMP_OCLP_PUSH;
        } else if (name->data[8] == 'a') { /* oclp_meta */
            n = NGX_RTMP_OCLP_META;
            if (oacf->events[n].nelts != 0) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate %V", name);
                return NGX_CONF_ERROR;
            }
        }
        break;
    case sizeof("oclp_publish") - 1:
        n = NGX_RTMP_OCLP_PUBLISH;
        if (oacf->events[n].nelts != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate %V", name);
            return NGX_CONF_ERROR;
        }
        break;
    case sizeof("oclp_stream") - 1:
        if (name->data[5] == 's') { /* oclp_stream */
            n = NGX_RTMP_OCLP_STREAM;
        } else if (name->data[5] == 'r') { /* oclp_record */
            n = NGX_RTMP_OCLP_RECORD;
        }

        if (oacf->events[n].nelts != 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "duplicate %V", name);
            return NGX_CONF_ERROR;
        }
        break;
    }

    if (oacf->events[n].nelts >= NGX_RTMP_MAX_OCLP) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "too much %V events", name);
        return NGX_CONF_ERROR;
    }

    event = ngx_array_push(&oacf->events[n]);
    ngx_memzero(event, sizeof(ngx_rtmp_oclp_event_t));
    if (ngx_rtmp_oclp_create_event(cf, event, &value[1], cf->args->nelts - 1)
            == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_rtmp_oclp_init_process_url(ngx_str_t *url, ngx_pool_t *pool,
    ngx_rtmp_oclp_event_t *event)
{
    size_t                      len;
    u_char                     *p;

    len = event->url.len + sizeof("?call=init_process&worker_id=") - 1
        + sizeof("256") - 1;

    url->data = ngx_pcalloc(pool, len);
    if (url->data == NULL) {
        return;
    }

    p = url->data;
    p = ngx_snprintf(p, len, "%V?call=init_process&worker_id=%ui",
            &event->url, ngx_worker);
    url->len = p - url->data;
}

static void
ngx_rtmp_oclp_init_process_handle(ngx_netcall_ctx_t *nctx, ngx_int_t code)
{
    if (code != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp init process notify error: %i", code);
    }

    return;
}

static void
ngx_rtmp_oclp_init_process_create(ngx_event_t *ev)
{
    ngx_netcall_ctx_t          *nctx;

    nctx = ev->data;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "oclp init process create");

    ngx_netcall_create(nctx, ngx_cycle->log);
}

static ngx_int_t
ngx_rtmp_oclp_init_process(ngx_cycle_t *cycle)
{
    ngx_rtmp_oclp_main_conf_t  *omcf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_rtmp_conf_ctx_t        *ctx;
    ngx_netcall_ctx_t          *nctx;
    ngx_event_t                *ev;

    if (ngx_process != NGX_PROCESS_WORKER &&
        ngx_process != NGX_PROCESS_SINGLE)
    {
        return NGX_OK;
    }

    ctx = (ngx_rtmp_conf_ctx_t *) ngx_get_conf(cycle->conf_ctx,
                                               ngx_rtmp_module);
    omcf = (ngx_rtmp_oclp_main_conf_t *)
            ctx->main_conf[ngx_rtmp_oclp_module.ctx_index];

    if (omcf->events[NGX_RTMP_OCLP_PROC].url.len == 0) {
        return NGX_OK;
    }

    event = &omcf->events[NGX_RTMP_OCLP_PROC];

    nctx = ngx_netcall_create_ctx(NGX_RTMP_OCLP_PROC, &event->groupid,
            event->stage, event->timeout, event->retries, event->update, 0);
    if (nctx == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_oclp_init_process_url(&nctx->url, nctx->pool, event);
    nctx->handler = ngx_rtmp_oclp_init_process_handle;
    nctx->data = nctx;

    ev = &nctx->ev;
    ev->handler = ngx_rtmp_oclp_init_process_create;

    ngx_post_event(ev, &ngx_rtmp_init_queue);

    return NGX_OK;
}

static void
ngx_rtmp_oclp_common_url(ngx_str_t *url, ngx_rtmp_session_t *s,
    ngx_rtmp_oclp_event_t *event, ngx_netcall_ctx_t *nctx, ngx_uint_t stage)
{
    size_t                      len;
    u_char                     *p;
    ngx_str_t                   oclp_args = ngx_null_string;

    len = event->url.len + sizeof("?call=&act=&domain=&app=&name=") - 1
        + ngx_strlen(ngx_rtmp_oclp_app_type[nctx->type])
        + ngx_strlen(ngx_rtmp_oclp_stage[stage])
        + s->domain.len + s->app.len + s->name.len;

    if (event->args.len) {
        ngx_rtmp_oclp_fetch_variable(s, nctx->pool, &event->args, &oclp_args);
        len += oclp_args.len + 1;
    }

    url->data = ngx_pcalloc(nctx->pool, len);
    if (url->data == NULL) {
        return;
    }

    p = url->data;
    p = ngx_snprintf(p, len, "%V?call=%s&act=%s&domain=%V&app=%V&name=%V",
            &event->url, ngx_rtmp_oclp_app_type[nctx->type],
            ngx_rtmp_oclp_stage[stage], &s->domain, &s->app, &s->name);

    if (event->args.len) {
        p = ngx_snprintf(p, len, "%s&%V", p, &oclp_args);
    }

    url->len = p - url->data;
}

static void
ngx_rtmp_oclp_common_timer(ngx_event_t *ev)
{
    ngx_netcall_ctx_t          *nctx;

    nctx = ev->data;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "oclp %s update create %V",
            ngx_rtmp_oclp_app_type[nctx->type], &nctx->url);

    ngx_netcall_create(nctx, ngx_cycle->log);
}

static void
ngx_rtmp_oclp_common_update_handle(ngx_netcall_ctx_t *nctx, ngx_int_t code)
{
    ngx_event_t                *ev;

    if (code != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp %s update notify error: %i",
                ngx_rtmp_oclp_app_type[nctx->type], code);
    }

    ev = &nctx->ev;
    ev->handler = ngx_rtmp_oclp_common_timer;

    ngx_add_timer(ev, nctx->update);
}

static void
ngx_rtmp_oclp_common_update_create(ngx_rtmp_session_t *s,
    ngx_netcall_ctx_t *nctx)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_event_t                *ev;

    if (nctx == NULL) {
        return;
    }

    if ((nctx->stage & NGX_RTMP_OCLP_UPDATE) == NGX_RTMP_OCLP_UPDATE) {
        oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);

        event = oacf->events[nctx->type].elts;
        event += nctx->idx;

        ngx_rtmp_oclp_common_url(&nctx->url, s, event, nctx,
                                 NGX_RTMP_OCLP_UPDATE);
        nctx->handler = ngx_rtmp_oclp_common_update_handle;

        ev = &nctx->ev;
        ev->log = ngx_cycle->log;
        ev->data = nctx;
        ev->handler = ngx_rtmp_oclp_common_timer;

        ngx_add_timer(ev, nctx->update);
    }
}

static void
ngx_rtmp_oclp_common_done(ngx_rtmp_session_t *s, ngx_netcall_ctx_t *nctx)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;

    if (nctx == NULL) {
        return;
    }

    if ((nctx->stage & NGX_RTMP_OCLP_DONE) == NGX_RTMP_OCLP_DONE) {
        oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);
        event = oacf->events[nctx->type].elts;

        ngx_rtmp_oclp_common_url(&nctx->url, s, event, nctx,
                                 NGX_RTMP_OCLP_DONE);

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "oclp %s done create %V %p",
                ngx_rtmp_oclp_app_type[nctx->type], &nctx->url, nctx);

        if (nctx->ev.timer_set) {
            ngx_del_timer(&nctx->ev);
        }

        ngx_netcall_create(nctx, s->connection->log);
    } else {
        ngx_post_event(&nctx->ev, &ngx_posted_events);
    }

    ngx_netcall_detach(nctx);
}

static void
ngx_rtmp_oclp_pnotify_start_handle(ngx_netcall_ctx_t *nctx, ngx_int_t code)
{
    ngx_rtmp_session_t         *s;

    s = nctx->data;

    if (code != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp %s start notify error: %i",
               ngx_rtmp_oclp_app_type[nctx->type], code);

        if (code != -1) {
            if (nctx->type == NGX_RTMP_OCLP_PUBLISH) {
                ngx_rtmp_send_status(s, "NetStream.Publish.Forbidden", "status",
                        "Publish stream Forbidden");
            } else {
                s->status = 403;
                ngx_rtmp_send_status(s, "NetStream.Play.Forbidden", "status",
                        "Play stream Forbidden");
            }
            ngx_rtmp_finalize_session(s);
        }

        return;
    }

    ngx_rtmp_oclp_common_update_create(s, nctx);
}

void
ngx_rtmp_oclp_pnotify_start(ngx_rtmp_session_t *s, ngx_uint_t type)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_rtmp_oclp_ctx_t        *ctx;
    ngx_netcall_ctx_t          *nctx;

    if (s->relay || s->interprocess) {
        return;
    }

    oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);

    if (oacf->events[type].nelts == 0) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_oclp_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_oclp_ctx_t));
        if (ctx == NULL) {
            return;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_oclp_module);
    }

    if ((type == NGX_RTMP_OCLP_PUBLISH_NOTIFY
         || type == NGX_RTMP_OCLP_PLAY_NOTIFY)
        && ctx->pctx)
    {
        return;    /* publish or play notify has been sent */
    }

    event = oacf->events[type].elts;

    if (oacf->events[type].nelts &&
        (event->stage & NGX_RTMP_OCLP_START) == NGX_RTMP_OCLP_START)
    {
        nctx = ngx_netcall_create_ctx(type, &event->groupid,
                event->stage, event->timeout, event->retries, event->update, 0);

        ngx_rtmp_oclp_common_url(&nctx->url, s, event, nctx,
                                 NGX_RTMP_OCLP_START);
        nctx->handler = ngx_rtmp_oclp_pnotify_start_handle;
        nctx->data = s;

        if (type == NGX_RTMP_OCLP_META_NOTIFY) {
            if (ctx->mctx != NULL) {
                ngx_netcall_detach(ctx->mctx);
            }
            ctx->mctx = nctx;
        } else {
            ctx->pctx = nctx;
        }

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "oclp %s start create %V",
                ngx_rtmp_oclp_app_type[nctx->type], &nctx->url);

        ngx_netcall_create(nctx, s->connection->log);
    }
}

void
ngx_rtmp_oclp_pnotify_done(ngx_rtmp_session_t *s)
{
    ngx_rtmp_oclp_ctx_t        *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_oclp_module);
    if (ctx == NULL) {
        return;
    }

    ngx_rtmp_oclp_common_done(s, ctx->mctx);
    ngx_rtmp_oclp_common_done(s, ctx->pctx);
}

static void
ngx_rtmp_oclp_relay_error(ngx_rtmp_session_t *s, ngx_uint_t status)
{
    ngx_rtmp_core_ctx_t        *cctx;
    size_t                      i;

    for (i = 0; ngx_rtmp_oclp_relay_errors[i].status; ++i) {
        if (status != ngx_rtmp_oclp_relay_errors[i].status) {
            continue;
        }

        if (s->publishing) {
            cctx = s->live_stream->publish_ctx;
        } else {
            cctx = s->live_stream->play_ctx;
        }

        for (; cctx; cctx = cctx->next) {
			if(cctx->session->static_pull_fake) {
				continue;
			}
            cctx->session->status = status;
            ngx_rtmp_finalize_session(cctx->session);
        }
    }
}

static void
ngx_rtmp_oclp_relay_start_handle(ngx_netcall_ctx_t *nctx, ngx_int_t code)
{
    ngx_rtmp_relay_target_t     target;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_request_url_t           ru;
    ngx_url_t                  *u;
    ngx_str_t                  *local_name;
    ngx_str_t                  *local_domain;
    ngx_live_stream_t          *st;
    ngx_rtmp_session_t         *s;
    u_char                     *p, *e, *last;
    size_t                      len;

    static ngx_str_t            location = ngx_string("location");
    static ngx_str_t            domain = ngx_string("domain");

    st = nctx->data;
    if (nctx->type == NGX_RTMP_OCLP_PULL) {
        if (st->play_ctx == NULL) {
            return;
        }

        s = st->play_ctx->session;
        st->pull_relay = 0;
    } else {
        if (st->publish_ctx == NULL) {
            return;
        }

        s = st->publish_ctx->session;
        --st->push_count;
    }

    if (code == -1) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp relay start notify timeout");
        if (nctx->type != NGX_RTMP_OCLP_PULL) {
            st->push_nctx[nctx->idx] = NULL;
        }
        return;
    }

    if (code >= 400) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp relay start notify error: %i", code);

        if (nctx->type == NGX_RTMP_OCLP_PULL) {
            ngx_rtmp_oclp_relay_error(s, 404);
        } else {
            st->push_nctx[nctx->idx] = NULL;
            ngx_rtmp_oclp_relay_error(s, 400);
        }

        return;
    }

    if (code == NGX_HTTP_OK) {
        if (s->publishing) {
            s->live_stream->oclp_ctx[nctx->idx] = NGX_CONF_UNSET_PTR;
        } else { /* relay pull */
            ngx_live_put_relay_reconnect(s->live_stream->pull_reconnect);
        }
        return;
    }

    /* redirect */
    local_name = ngx_netcall_header(nctx, &location);
    if (local_name == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp relay start has no Location when redirect");

        if (nctx->type == NGX_RTMP_OCLP_PULL) {
            ngx_rtmp_oclp_relay_error(s, 404);
        } else {
            ngx_rtmp_oclp_relay_error(s, 400);
        }

        return;
    }

    ngx_memzero(&target, sizeof(target));
    u = &target.url;

    if (ngx_strncasecmp(local_name->data, (u_char *) "rtmp://", 7) == 0) {
        target.schema.data = local_name->data;
        target.schema.len = 4;
        u->default_port = 1935;
    } else if (ngx_strncasecmp(local_name->data, (u_char *) "http://", 7)
        == 0)
    {
        target.schema.data = local_name->data;
        target.schema.len = 4;
        u->default_port = 80;
    } else {
        goto error;
    }
    u->url.data = local_name->data + 7;
    u->url.len = local_name->len - 7;
    u->uri_part = 1;
    u->no_resolve = 1;

    if (ngx_parse_url(nctx->pool, u) != NGX_OK) {
        goto error;
    }

    ngx_memzero(&ru, sizeof(ngx_request_url_t));
    if (ngx_parse_request_url(&ru, local_name) == NGX_ERROR) {
        goto error;
    }

    if (ru.path.len == 0) {
        goto error;
    }
    p = ru.path.data;
    e = p;
    last = ru.path.data + ru.path.len;

    while (1) {
        e = ngx_strlchr(e, last, '/');
        if (e == NULL) {
            e = last;
            break;
        }

        p = e;
        ++e;
    }

    if (p == ru.path.data || p + 1 == last) { /* name not exist */
        goto error;
    }

    /* app */
    target.app.data = ru.path.data;
    target.app.len = p - ru.path.data;

    /* name */
    last = ru.uri_with_args.data + ru.uri_with_args.len;
    target.name.data = p + 1;
    target.name.len = last - target.name.data;

    /* tc_url */
    local_domain = ngx_netcall_header(nctx, &domain);
    if (local_domain) {
        len = target.schema.len + 3 + local_domain->len + 1 + target.app.len;
        target.tc_url.len = len;
        target.tc_url.data = ngx_pcalloc(nctx->pool, len);
        ngx_snprintf(target.tc_url.data, len, "%V://%V/%V", &target.schema,
                local_domain, &target.app);
    } else {
        target.tc_url.data = local_name->data;
        target.tc_url.len = p - local_name->data;
    }

    target.tag = &ngx_rtmp_oclp_module;
    target.idx = nctx->idx;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
            "oclp relay, tc_url: %V app: %V, name: %V",
            &target.tc_url, &target.app, &target.name);

    if (nctx->type == NGX_RTMP_OCLP_PULL) {
        target.publishing = 1;
        ctx = ngx_relay_pull(s, &target.name, &target);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "oclp relay pull, push failed name='%V' app='%V' "
                    "playpath='%V' url='%V'",
                    &target.name, &target.app, &target.play_path,
                    &target.url.url);
            return;
        }
    } else {
        ctx = ngx_relay_push(s, &target.name, &target);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "oclp relay push, push failed name='%V' app='%V' "
                    "playpath='%V' url='%V'",
                    &target.name, &target.app, &target.play_path,
                    &target.url.url);
            return;
        }

        if (s->live_stream->oclp_ctx[nctx->idx]) {
            ngx_rtmp_finalize_session(
                    s->live_stream->oclp_ctx[nctx->idx]->session);
        }
        s->live_stream->oclp_ctx[nctx->idx] = ctx;
    }

    return;

error:
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "oclp relay start Location format error: %V", local_name);

    if (nctx->type == NGX_RTMP_OCLP_PULL) {
        ngx_rtmp_oclp_relay_error(s, 404);
    } else {
        ngx_rtmp_oclp_relay_error(s, 400);
    }
}

static void
ngx_rtmp_oclp_relay_start(ngx_rtmp_session_t *s, ngx_uint_t idx,
    unsigned publishing, ngx_uint_t type)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_netcall_ctx_t          *nctx;

    oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);

    event = oacf->events[type].elts;
    event += idx;

    nctx = ngx_netcall_create_ctx(type, &event->groupid, event->stage,
            event->timeout, event->retries, event->update, idx);

    ngx_rtmp_oclp_common_url(&nctx->url, s, event, nctx,
            NGX_RTMP_OCLP_START);
    nctx->handler = ngx_rtmp_oclp_relay_start_handle;
    nctx->data = s->live_stream;

    if (publishing) {
        s->live_stream->push_nctx[idx] = nctx;
    } else {
        s->live_stream->pull_nctx = nctx;
        s->live_stream->pull_relay = 1;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "oclp %s start create %V",
            ngx_rtmp_oclp_app_type[nctx->type], &nctx->url);

    ngx_netcall_create(nctx, s->connection->log);
}

static void
ngx_rtmp_oclp_relay_done(ngx_rtmp_session_t *s)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_netcall_ctx_t          *nctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    if (s->publishing) { /* relay pull */
        nctx = s->live_stream->pull_nctx;
        ngx_rtmp_oclp_common_done(s, nctx);
        s->live_stream->pull_nctx = NULL;
    } else { /* relay push */
        nctx = s->live_stream->push_nctx[ctx->idx];
        ngx_rtmp_oclp_common_done(s, nctx);
        s->live_stream->push_nctx[ctx->idx] = NULL;
    }
}

static void
ngx_rtmp_oclp_stream_start_handle(ngx_netcall_ctx_t *nctx, ngx_int_t code)
{
    ngx_live_stream_t          *st;
    ngx_rtmp_session_t         *s;

    st = nctx->data;

    if (code != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "oclp stream start notify error: %i", code);

        return;
    }

    if (st->play_ctx) {
        s = st->play_ctx->session;
    } else if (st->publish_ctx) {
        s = st->publish_ctx->session;
    } else {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "oclp stream start handle but all stream session close");
        return;
    }

    ngx_rtmp_oclp_common_update_create(s, nctx);
}

void
ngx_rtmp_oclp_stream_start(ngx_rtmp_session_t *s)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_oclp_event_t      *event;
    ngx_netcall_ctx_t          *nctx;

    oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);

    if (oacf->events[NGX_RTMP_OCLP_STREAM].nelts == 0) {
        return;
    }

    nctx = s->live_stream->stream_nctx;
    if (nctx) { /* stream start has been sent */
        return;
    }

    event = oacf->events[NGX_RTMP_OCLP_STREAM].elts;

    if ((event->stage & NGX_RTMP_OCLP_START) == NGX_RTMP_OCLP_START) {
        nctx = ngx_netcall_create_ctx(NGX_RTMP_OCLP_STREAM, &event->groupid,
                event->stage, event->timeout, event->retries, event->update, 0);

        ngx_rtmp_oclp_common_url(&nctx->url, s, event, nctx,
                                 NGX_RTMP_OCLP_START);
        nctx->handler = ngx_rtmp_oclp_stream_start_handle;
        nctx->data = s->live_stream;

        s->live_stream->stream_nctx = nctx;

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "oclp stream start create %V", &nctx->url);

        ngx_netcall_create(nctx, s->connection->log);
    }
}

void
ngx_rtmp_oclp_stream_done(ngx_rtmp_session_t *s)
{
    ngx_netcall_ctx_t          *nctx;

    nctx = s->live_stream->stream_nctx;
    ngx_rtmp_oclp_common_done(s, nctx);
    s->live_stream->stream_nctx = NULL;
}

static ngx_int_t
ngx_rtmp_oclp_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_netcall_ctx_t          *nctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || s->relay) {
        goto next;
    }

    if (ctx->tag != &ngx_rtmp_oclp_module) {
        goto next;
    }

    nctx = s->live_stream->pull_nctx;
    ngx_rtmp_oclp_common_update_create(s, nctx);

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_oclp_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_netcall_ctx_t          *nctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || s->relay) {
        goto next;
    }

    if (ctx->tag != &ngx_rtmp_oclp_module) {
        goto next;
    }

    nctx = s->live_stream->push_nctx[ctx->idx];
    ngx_rtmp_oclp_common_update_create(s, nctx);

next:
    return next_play(s, v);
}

static ngx_int_t
ngx_rtmp_oclp_push(ngx_rtmp_session_t *s)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_netcall_ctx_t          *nctx;
    ngx_uint_t                  i;
    ngx_uint_t                  type;

    type = NGX_RTMP_OCLP_PUSH;
    oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);
    if (oacf->events[type].nelts == 0 || (s->relay && !s->static_pull_fake)) {
        return next_push(s);
    }

    for (i = 0; i < oacf->events[type].nelts; ++i) {
        ctx = s->live_stream->oclp_ctx[i];
        if (ctx == NGX_CONF_UNSET_PTR) {
            continue;
        }

        if (ctx && ctx->relay_completion) { /* oclp push already complete */
            continue;
        }

        nctx = s->live_stream->push_nctx[i];
        if (nctx) {
            ngx_netcall_detach(nctx);
            if (ctx == NULL) { /* relay not create */
                --s->live_stream->push_count;
            }
        }

        ++s->live_stream->push_count;
        ngx_rtmp_oclp_relay_start(s, i, 1, type);
    }

    return next_push(s);
}

static ngx_int_t
ngx_rtmp_oclp_pull(ngx_rtmp_session_t *s)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
    ngx_netcall_ctx_t          *nctx;

    oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);
    if (oacf->events[NGX_RTMP_OCLP_PULL].nelts == 0 || s->relay) {
        return next_pull(s);
    }

    nctx = s->live_stream->pull_nctx;
    if (nctx) {
        ngx_netcall_detach(nctx);
    }

    ngx_rtmp_oclp_relay_start(s, 0, 0, NGX_RTMP_OCLP_PULL);

    return NGX_AGAIN;
}

static ngx_int_t
ngx_rtmp_oclp_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h, ngx_chain_t *in)
{
    ngx_rtmp_oclp_app_conf_t   *oacf;
#ifdef NGX_DEBUG
    const char                 *type_s;
#endif

    if (ngx_rtmp_is_codec_header(in)) {
#ifdef NGX_DEBUG
        type_s = (h->type == NGX_RTMP_MSG_VIDEO? "video": "audio");
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "recv %s header", type_s);
#endif

        oacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_oclp_module);

        if (oacf->meta_once && s->live_stream->oclp_meta) {
            return NGX_OK;
        }

        switch (oacf->meta_type) {
        case NGX_RTMP_OCLP_META_VIDEO:
            if (h->type == NGX_RTMP_MSG_AUDIO) {
                return NGX_OK;
            }
            break;
        case NGX_RTMP_OCLP_META_AUDIO:
            if (h->type == NGX_RTMP_MSG_VIDEO) {
                return NGX_OK;
            }
            break;
        default:
            break;
        }

        s->live_stream->oclp_meta = 1;

        ngx_rtmp_oclp_pnotify_start(s, NGX_RTMP_OCLP_META_NOTIFY);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_oclp_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        goto next;
    }

    ngx_rtmp_oclp_relay_done(s);

    if (ctx->tag != &ngx_rtmp_oclp_module || s->publishing) {
        goto next;
    }

    if (ctx == s->live_stream->oclp_ctx[ctx->idx]) {
        s->live_stream->oclp_ctx[ctx->idx] = NULL;
    }

    if (!ctx->relay_completion) {
        --s->live_stream->push_count;
    }

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_oclp_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_rtmp_handler_pt        *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_oclp_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_oclp_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_oclp_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_oclp_play;

    next_push = ngx_rtmp_push;
    ngx_rtmp_push = ngx_rtmp_oclp_push;

    next_pull = ngx_rtmp_pull;
    ngx_rtmp_pull = ngx_rtmp_oclp_pull;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_oclp_close_stream;

    return NGX_OK;
}
