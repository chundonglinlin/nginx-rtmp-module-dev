/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_eval.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_netcall_module.h"


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;


static void ngx_rtmp_auth_request_location(void *ctx, ngx_rtmp_eval_t *e,
        ngx_str_t *ret);
static void ngx_rtmp_auth_request_session_str(void *ctx, ngx_rtmp_eval_t *e,
        ngx_str_t *ret);
static void ngx_rtmp_auth_request_refer(void *ctx, ngx_rtmp_eval_t *e,
        ngx_str_t *ret);
static void ngx_rtmp_auth_request_ipport(void *ctx, ngx_rtmp_eval_t *e,
        ngx_str_t *ret);
static void *ngx_rtmp_auth_request_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_auth_request_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_auth_request_postconfiguration(ngx_conf_t *cf);


ngx_str_t   ngx_rtmp_urlencoded =
            ngx_string("application/x-www-form-urlencoded");


typedef struct {
    ngx_str_t                           auth_uri;
    ngx_msec_t                          auth_timeout;
    size_t                              auth_bufsize;
} ngx_rtmp_auth_request_app_conf_t;

typedef struct {
    ngx_url_t                          *url;
    ngx_rtmp_play_t                    *play_v;
    ngx_rtmp_publish_t                 *publish_v;

    unsigned                            publishing;
} ngx_rtmp_auth_request_ctx_t;


static ngx_rtmp_eval_t ngx_rtmp_auth_request_specific_eval[] = {

    { ngx_string("pargs"),
      ngx_rtmp_auth_request_session_str,
      offsetof(ngx_rtmp_session_t, pargs) },

    { ngx_string("domain"),
      ngx_rtmp_auth_request_session_str,
      offsetof(ngx_rtmp_session_t, domain) },

    { ngx_string("name"),
      ngx_rtmp_auth_request_session_str,
      offsetof(ngx_rtmp_session_t, name) },

    { ngx_string("location"),
      ngx_rtmp_auth_request_location,
      offsetof(ngx_rtmp_core_app_conf_t, name) },

    { ngx_string("referer"),
      ngx_rtmp_auth_request_refer, 0 },

    { ngx_string("ipport"),
      ngx_rtmp_auth_request_ipport, 0 },

    ngx_rtmp_null_eval
};


static ngx_rtmp_eval_t *ngx_rtmp_auth_request_eval[] = {
    ngx_rtmp_eval_session,
    ngx_rtmp_auth_request_specific_eval,
    NULL
};


static ngx_command_t  ngx_rtmp_auth_request_commands[] = {

    { ngx_string("auth_uri"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_auth_request_app_conf_t, auth_uri),
      NULL },

    { ngx_string("auth_buf"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_auth_request_app_conf_t, auth_bufsize),
      NULL },

    { ngx_string("auth_timeout"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_auth_request_app_conf_t, auth_timeout),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_auth_request_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_rtmp_auth_request_postconfiguration,    /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_rtmp_auth_request_create_app_conf,      /* create app configuration */
    ngx_rtmp_auth_request_merge_app_conf        /* merge app configuration */
};


ngx_module_t  ngx_rtmp_auth_request_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_auth_request_module_ctx,          /* module context */
    ngx_rtmp_auth_request_commands,             /* module directives */
    NGX_RTMP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static void
ngx_rtmp_auth_request_session_str(void *ctx, ngx_rtmp_eval_t *e,
        ngx_str_t *ret)
{
    *ret = *(ngx_str_t *) ((u_char *) ctx + e->offset);
}


static void
ngx_rtmp_auth_request_location(void *ctx, ngx_rtmp_eval_t *e,
         ngx_str_t *ret)
{
    ngx_rtmp_session_t         *s = ctx;
    ngx_rtmp_core_app_conf_t   *cacf;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    *ret = *(ngx_str_t *) ((u_char *) cacf + e->offset);
}


static void
ngx_rtmp_auth_request_refer(void *ctx, ngx_rtmp_eval_t *e,
         ngx_str_t *ret)
{
    ngx_rtmp_session_t         *s = ctx;
    ngx_str_t                   str;
    u_char                     *args;
    u_char                     *pageurl;

    if (s->page_url.len == 0 || s->page_url.data == NULL) {
        args = s->pargs.data;

        pageurl = ngx_strstrn(args, (char *)"pageUrl", 7 - 1);
        if (pageurl == NULL) {
            str.len = 0;
            str.data =NULL;
        } else {
            str.data = pageurl + sizeof("pageUrl") -1;
            str.len = s->pargs.len - (str.data - args);
        }
        *ret = str;
    } else {
        *ret = s->page_url;
    }
}


static void
ngx_rtmp_auth_request_ipport(void *ctx, ngx_rtmp_eval_t *e,
         ngx_str_t *ret)
{
    ngx_rtmp_session_t         *s = ctx;
    ngx_str_t                   str;

    ngx_rtmp_get_remoteaddr(s->connection, &str);
    *ret = str;
}


static void *
ngx_rtmp_auth_request_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_auth_request_app_conf_t   *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_auth_request_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->auth_timeout = NGX_CONF_UNSET_MSEC;
    conf->auth_bufsize = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *
ngx_rtmp_auth_request_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_auth_request_app_conf_t   *prev = parent;
    ngx_rtmp_auth_request_app_conf_t   *conf = child;

    ngx_conf_merge_str_value(conf->auth_uri, prev->auth_uri, "");
    ngx_conf_merge_msec_value(conf->auth_timeout, prev->auth_timeout, 5000);
    ngx_conf_merge_size_value(conf->auth_bufsize, prev->auth_bufsize, 1024);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_auth_request_http_parse_retcode(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_buf_t                          *b;
    ngx_int_t                           n;
    u_char                             *p;
    ngx_uint_t                          retcode = 0;

    /* find 10th character */

    n = sizeof("HTTP/1.1 ") - 1;
    while (in) {
        b = in->buf;
        if (b->last - b->pos > n) {
            p = b->pos + n; /* skip 'HTTP/1.1 ' */
            /* start parse retcode */
            while (*p >= (u_char)'0' && *p <= (u_char)'9' && p < b->last) {
                retcode = retcode * 10 + (int)(*p - '0');
                ++p;
            }

            if (retcode >= 100 && retcode < 600) {
                return retcode;
            }

            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "netcall: invalid HTTP retcode: %d", retcode);

            return NGX_ERROR;
        }
        n -= (b->last - b->pos);
        in = in->next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "netcall: empty or broken HTTP response");

    /*
     * not enough data;
     * it can happen in case of empty or broken reply
     */

    return NGX_ERROR;
}

static ngx_chain_t *
ngx_rtmp_auth_request_create(ngx_rtmp_session_t *s, void *arg,
        ngx_pool_t *pool)
{
    ngx_rtmp_auth_request_ctx_t        *ctx;
    ngx_url_t                          *u;
    ngx_buf_t                          *b;
    ngx_str_t                           uri_str;
    u_char                             *host, *last, *uri, *args, *p, *q;
    size_t                              uri_len, args_len;
    ngx_chain_t                        *al;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_request_module);

    u = ctx->url;

    host = u->url.data;
    last = u->url.len + host;

    uri = ngx_strlchr(host, last, '/');
    args = ngx_strlchr(host, last, '?') + 1;

    uri_len = args - uri - 1;
    args_len = last - args;

    p = ngx_pnalloc(pool, uri_len * 3);
    if (p == NULL) {
        return NULL;
    }

    q = p;
    p = (u_char *) ngx_escape_uri(p, uri, uri_len,
            NGX_ESCAPE_URI);

    uri_str.data = q;
    uri_str.len = p - q;

    al = ngx_alloc_chain_link(pool);
    if (al == NULL) {
        return NULL;
    }

    b = ngx_create_temp_buf(pool, args_len * 3);
    if (b == NULL) {
        return NULL;
    }

    al->buf = b;
    al->next = NULL;

    b->last = (u_char *) ngx_escape_uri(b->last, args, args_len,
            NGX_ESCAPE_URI);

    return ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET,
            &u->host, &uri_str, al, NULL, pool, &ngx_rtmp_urlencoded);
}

static ngx_int_t
ngx_rtmp_auth_request_handle(ngx_rtmp_session_t *s, void *arg,
        ngx_chain_t *in)
{
    ngx_rtmp_auth_request_ctx_t        *ctx;
    ngx_int_t                           rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_request_module);

    rc = ngx_rtmp_auth_request_http_parse_retcode(s, in);
    if (rc != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "rtmp auth request, auth retcode %d, forbiden", rc);
        ngx_rtmp_finalize_session(s);
        return NGX_OK;
    }

    if (ctx->publishing) {
        return next_publish(s, ctx->publish_v);
    } else {
        return next_play(s, ctx->play_v);
    }
}

static ngx_int_t
ngx_rtmp_auth_request_send(ngx_rtmp_session_t *s)
{
    ngx_rtmp_auth_request_app_conf_t   *aacf;
    ngx_rtmp_auth_request_ctx_t        *ctx;
    ngx_rtmp_eval_t                   **eval;
    ngx_str_t                           url;
    ngx_int_t                           rc;
    ngx_url_t                          *u;
    ngx_rtmp_netcall_init_t             ci;

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auth_request_module);
    if (ngx_strncasecmp(aacf->auth_uri.data, (u_char *) "http://",
            sizeof("http://") - 1))
    {
        return NGX_ERROR;
    }

    /* get URL */
    eval = ngx_rtmp_auth_request_eval;
    rc = ngx_rtmp_eval(s, &aacf->auth_uri, eval, &url, s->connection->log);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp auth request, eval for uri failed");
        return NGX_ERROR;
    }

    /* parse URL */
    u = ngx_pcalloc(s->connection->pool, sizeof(ngx_url_t));
    u->url.len = url.len - 7; /* 7: sizeof("http://") - 1 */
    u->url.data = url.data + 7;
    u->default_port = 80;
    u->uri_part = 1;
    u->no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "rtmp auth request, %s in url \"%V\"", u->err, &u->url);
        }
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_request_module);
    ctx->url = u;

    /* create ci */
    ngx_memzero(&ci, sizeof(ci));
    ci.url = u;
    ci.create = ngx_rtmp_auth_request_create;
    ci.handle = ngx_rtmp_auth_request_handle;
    ci.arg = NULL;
    ci.argsize = 0;
    ci.connect_timeout = aacf->auth_timeout;
    ci.bufsize = aacf->auth_bufsize;

    return ngx_rtmp_netcall_create(s, &ci);
}

static ngx_int_t
ngx_rtmp_auth_request_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_auth_request_app_conf_t   *aacf;
    ngx_rtmp_auth_request_ctx_t        *ctx;

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auth_request_module);
    if (aacf->auth_uri.len == 0) {
        goto next;
    }

    if (s->relay || s->live_type != NGX_RTMP_LIVE) {
        goto next;
    }

    if (s->connection->sockaddr->sa_family == AF_UNIX) { /* inter processes */
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_request_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool,
                sizeof(ngx_rtmp_auth_request_ctx_t));
        if (ctx == NULL) {
            goto next;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_auth_request_module);
        ctx->publishing = 1;
    }

    ctx->publish_v = v;

    if (ngx_rtmp_auth_request_send(s) == NGX_ERROR) {
        goto next;
    }

    return NGX_OK;

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_auth_request_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_auth_request_app_conf_t   *aacf;
    ngx_rtmp_auth_request_ctx_t        *ctx;

    aacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_auth_request_module);
    if (aacf->auth_uri.len == 0) {
        goto next;
    }

    if (s->relay || s->live_type != NGX_RTMP_LIVE) {
        goto next;
    }

    if (s->connection->sockaddr->sa_family == AF_UNIX) { /* inter processes */
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_auth_request_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool,
                sizeof(ngx_rtmp_auth_request_ctx_t));
        if (ctx == NULL) {
            goto next;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_auth_request_module);
    }

    ctx->play_v = v;

    if (ngx_rtmp_auth_request_send(s) == NGX_ERROR) {
        goto next;
    }

    return NGX_OK;

next:
    return next_play(s, v);
}

static ngx_int_t
ngx_rtmp_auth_request_postconfiguration(ngx_conf_t *cf)
{
    /* chain handlers */

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_auth_request_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_auth_request_play;

    return NGX_OK;
}
