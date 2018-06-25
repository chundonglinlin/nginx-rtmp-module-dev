#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_rtmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ngx_rtmp_cmd_module.h>
#include "../http/ngx_http_set_header.h"
#include "ngx_rtmp_mpegts_module.h"
#include "ngx_hls_cmd_module.h"
#include "ngx_rbuf.h"
#include "ngx_rtmp_dynamic.h"

#ifndef NGX_HTTP_GONE
#define NGX_HTTP_GONE 410
#endif

static ngx_hls_play_pt next_hls_play;
static ngx_hls_close_pt next_hls_close;

static ngx_keyval_t ngx_302_headers[] = {
    { ngx_string("Location"),  ngx_null_string },
    { ngx_null_string, ngx_null_string }
};

static ngx_keyval_t ngx_m3u8_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("application/vnd.apple.mpegurl") },
    { ngx_null_string, ngx_null_string }
};

static ngx_keyval_t ngx_ts_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("video/mp2t") },
    { ngx_null_string, ngx_null_string }
};


typedef struct {
    ngx_str_t                   app;
    ngx_str_t                   name;
    ngx_str_t                   stream;
    ngx_str_t                   serverid;
    ngx_str_t                   sid;
    ngx_hls_session_t          *hls;
    ngx_msec_t                  timeout;


    ngx_mpegts_frame_t         *out_frame;
    ngx_chain_t                *out_chain;
    ngx_mpegts_frag_t          *frag;
} ngx_hls_live_ctx_t;


typedef struct {
	ngx_str_t                   app;
    ngx_str_t                   flashver;
    ngx_str_t                   swf_url;
    ngx_str_t                   tc_url;
    ngx_str_t                   page_url;
	size_t                      out_queue;
	ngx_msec_t                  timeout;
    ngx_listening_t            *ls;
    ngx_array_t                *hls;
    size_t                      hls_queue;
} ngx_hls_live_loc_conf_t;

static u_char  NGX_HLS_LIVE_ARG_SESSION[] = "session";

static ngx_int_t NGX_HLS_LIVE_ARG_SESSION_LENGTH = 7;

static void * ngx_hls_live_create_loc_conf(ngx_conf_t *cf);
static char * ngx_hls_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char * ngx_hls_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static char * ngx_hls_live_variant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_hls_live_postconfiguration(ngx_conf_t *cf);

static ngx_command_t  ngx_hls_live_commands[] = {

    { ngx_string("hls2_live"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_hls_live,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_hls_live_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_hls_live_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_hls_live_create_loc_conf,  /* create location configuration */
    ngx_hls_live_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_hls_live_module = {
    NGX_MODULE_V1,
    &ngx_hls_live_module_ctx,      /* module context */
    ngx_hls_live_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_hls_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_hls_live_loc_conf_t       *hlcf;

    hlcf = ngx_pcalloc(cf->pool, sizeof(ngx_hls_live_loc_conf_t));
    if (hlcf == NULL) {
        return NULL;
    }

    return hlcf;
}

static char *
ngx_hls_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_hls_live_loc_conf_t       *prev = parent;
    ngx_hls_live_loc_conf_t       *conf = child;

	ngx_conf_merge_str_value(conf->app, prev->app, "");
    ngx_conf_merge_str_value(conf->flashver, prev->flashver, "");
    ngx_conf_merge_str_value(conf->swf_url, prev->swf_url, "");
    ngx_conf_merge_str_value(conf->tc_url, prev->tc_url, "");
    ngx_conf_merge_str_value(conf->page_url, prev->page_url, "");

    return NGX_CONF_OK;
}


static void
ngx_hls_live_ctx_init(ngx_http_request_t *r)
{
    u_char                             *p, *e;
    ngx_buf_t                          *buf;
    ngx_rtmp_core_srv_dconf_t          *rcsdf;
    ngx_hls_live_loc_conf_t            *hlcf;
    ngx_rtmp_session_t                  s;
    ngx_hls_live_ctx_t                 *ctx;
    ngx_str_t                          *app, *name, *stream, *domain, *serverid;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hls_live_module);
    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);

    app = &ctx->app;
    name = &ctx->name;
    stream = &ctx->stream;
    serverid = &ctx->serverid;
    domain = &r->headers_in.server;

    p = r->uri.data;
    e = r->uri.data + r->uri.len;

    p++;
    app->data = p;
    p = ngx_strlchr(p, e, '/');
    if (p == NULL) {
        app->data = NULL;
        app->len = 0;
        return;
    }
    app->len = p - app->data;

    if (hlcf->app.len > 0 && hlcf->app.data) {
        *app = hlcf->app;
    }

    p++;
    name->data = p;
    if (ngx_strncmp(&e[-5], ".m3u8", 5) == 0) {
        p = ngx_strlchr(p, e, '.');
    } else if (ngx_strncmp(&e[-3], ".ts", 3) == 0) {
        p = ngx_strlchr(p, e, '-');
    } else {
        p = NULL;
    }

    if (p == NULL) {
        name->data = NULL;
        name->len = 0;
        return;
    }
    name->len = p - name->data;

    ngx_memzero(&s, sizeof(s));
    s.domain = *domain;
    rcsdf = ngx_rtmp_get_module_srv_dconf(&s, &ngx_rtmp_core_module);
    if (rcsdf && rcsdf->serverid.len) {
        serverid->data = ngx_pcalloc(r->connection->pool, rcsdf->serverid.len);
        if (rcsdf->serverid.data == NULL) {
            return;
        }
        serverid->len = rcsdf->serverid.len;
        ngx_memcpy(serverid->data, rcsdf->serverid.data, serverid->len);
    } else {
        *serverid = *domain;
    }

    buf = ngx_create_temp_buf(r->connection->pool,
                              serverid->len + 1 + app->len + name->len + 1);
    buf->last = ngx_slprintf(buf->start, buf->end, "%V/%V/%V", serverid, app, name);

    stream->data = buf->pos;
    stream->len = buf->last - buf->pos;
}


static ngx_int_t
ngx_hls_live_parse(ngx_http_request_t *r, ngx_mpegts_play_t *v)
{
    ngx_hls_live_loc_conf_t            *hlcf;
    size_t                              tcurl_len;
    ngx_hls_live_ctx_t                 *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hls_live_module);

    if (ctx->app.len == 0 || ctx->stream.len == 0 || ctx->stream.len > NGX_RTMP_MAX_NAME) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: hls_live_parse| url error: %V", &r->uri);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_arg(r, (u_char *) "flashver", 8, &v->flashver) != NGX_OK) {
        v->flashver = hlcf->flashver;
    }

    tcurl_len = sizeof("rtmp://") + r->headers_in.server.len + ctx->app.len;
    v->tc_url.len = tcurl_len;
    v->tc_url.data = ngx_pcalloc(r->connection->pool, tcurl_len);
    if (v->tc_url.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(v->tc_url.data, v->tc_url.len, "rtmp://%V/%V",
                 &r->headers_in.server, &ctx->app);

    if (ngx_http_arg(r, (u_char *) "swf_url", 7, &v->swf_url) != NGX_OK) {
        v->swf_url = hlcf->swf_url;
    }
    if (ngx_http_arg(r, (u_char *) "page_url", 7, &v->page_url) != NGX_OK) {
        v->page_url = hlcf->page_url;
    }
	
    if (r->headers_in.referer) {
        v->page_url = r->headers_in.referer->value;
    } else {
        v->page_url = hlcf->page_url;
    }

    v->serverid = ctx->serverid;
    v->domain = r->headers_in.server;
    v->stream = ctx->stream;
	v->name = ctx->name;
 	v->app = ctx->app;
	v->args = r->args;
    v->log = r->connection->log;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "hls-live: hls_live_parse| app=\"%V\" flashver=\"%V\" swf_url=\"%V\" "
            "tc_url=\"%V\" page_url=\"\%V\" name=\"%V\" args=\"%V\"",
            &v->app, &v->flashver, &v->swf_url, &v->tc_url, &v->page_url,
            &v->name, &v->args);

    return NGX_OK;
}


static ngx_int_t
ngx_hls_live_send_header(ngx_http_request_t *r, ngx_uint_t status, ngx_keyval_t *h)
{
    ngx_int_t                           rc;

    r->headers_out.status = status;
    r->keepalive = 0; /* set Connection to closed */

    while (h && h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
}


static ngx_int_t
ngx_hls_live_redirect_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_int_t                            rc;
    ngx_str_t                            loc;
    ngx_str_t                            host;
    u_char                               sstr[NGX_HLS_MAX_SESSION] = {0};
    static ngx_uint_t                    sindex = 0;
    ngx_str_t                            location = ngx_string("");
    ngx_str_t                            uri;
    ngx_str_t                            uri_tail;

    host = r->headers_in.host->value;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    *ngx_snprintf(sstr, sizeof(sstr) - 1, "%uDt-%uDi-%dp-%uDc",
             time(NULL), sindex++, ngx_process_slot, r->connection->number) = 0;

    ngx_http_arg(r, (u_char*)"location", 8, &location);
    if (location.len == 0) {
        uri = r->uri;
    } else {
        uri_tail.data =
        ngx_strlchr(r->uri.data + 1, r->uri.data + r->uri.len - 1, '/');
        if (uri_tail.data == NULL) {
            uri_tail = r->uri;
        } else {
            uri_tail.len = r->uri.data+r->uri.len - uri_tail.data;
        }

        uri.len = location.len + uri_tail.len;
        uri.data = ngx_pcalloc(r->pool, uri.len);
        if (uri.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "hls-live: redirect_handler| pcalloc uri buffer failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_snprintf(uri.data, uri.len, "%V%V", &location, &uri_tail);
    }

    loc.len = ngx_strlen("http://") +
               host.len +
               uri.len +
               NGX_HLS_LIVE_ARG_SESSION_LENGTH + 2 +
               ngx_strlen(sstr);

    loc.data = ngx_pcalloc(r->connection->pool, loc.len);

    ngx_snprintf(loc.data, loc.len, "http://%V%V?%s=%s",
                   &host, &uri, NGX_HLS_LIVE_ARG_SESSION, sstr);

    ngx_http_set_header_out(r, &ngx_302_headers[0].key, &loc);

    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    rc = ngx_hls_live_send_header(r, NGX_HTTP_MOVED_TEMPORARILY, ngx_m3u8_headers);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: redirect_handler| "
            "send header failed, redirect url: %V, rc=%d", &loc, rc);
    } else {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "hls-live: redirect_handler| redirect url %V", &loc);
    }

    return rc;
}


static ngx_hls_live_ctx_t *
ngx_hls_live_create_ctx(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_hls_live_ctx_t                     *ctx;
    ngx_rtmp_core_srv_conf_t               *cscf;
    u_char                                 *p;
    ngx_hls_live_loc_conf_t                *hlcf;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hls_live_module);

    cscf = addr_conf->default_server->ctx->
            srv_conf[ngx_rtmp_core_module.ctx_index];

    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);
    if (ctx == NULL) {
        p = ngx_pcalloc(r->connection->pool,
                        sizeof(ngx_hls_live_ctx_t) +
                        sizeof(ngx_mpegts_frame_t)*hlcf->out_queue);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: create_ctx| alloc hls live ctx failed");
            return NULL;
        }

        ctx = (ngx_hls_live_ctx_t *)p;

        ngx_http_set_ctx(r, ctx, ngx_hls_live_module);
    }

    ctx->timeout = cscf->timeout;

    ngx_hls_live_ctx_init(r);

    if (ctx->app.len == 0 || ctx->name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: create_ctx| parse app or name failed, uri %V", &r->uri);
        return NULL;
    }

    ngx_http_arg(r, NGX_HLS_LIVE_ARG_SESSION, NGX_HLS_LIVE_ARG_SESSION_LENGTH, &ctx->sid);

    return ctx;
}


static ngx_int_t
ngx_hls_live_m3u8_ack(ngx_http_request_t *r, ngx_hls_session_t *s)
{
    ngx_hls_live_ctx_t                 *ctx;
    ngx_int_t                           rc;
    ngx_chain_t                        *out;
    ngx_buf_t                          *buf;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);

    buf = ngx_create_temp_buf(r->connection->pool, 1024*512);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hls-live: m3u8_ack| "
                    "hls session %V, create temp buf failed", &ctx->sid);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    out = (ngx_chain_t*)buf->start;
    out->buf = buf;
    out->next = NULL;

    buf->pos = buf->last = buf->start + sizeof(ngx_chain_t);
    buf->memory = 1;
    buf->flush = 1;
    buf->last_in_chain = 1;
    buf->last_buf = 1;

    rc = ngx_hls_cmd_create_m3u8_string(ctx->hls, buf);
    if (rc != NGX_OK) {
        return NGX_AGAIN;
    }

    r->headers_out.content_length_n = buf->last - buf->pos;

    rc = ngx_hls_live_send_header(r, NGX_HTTP_OK, ngx_m3u8_headers);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: m3u8_ack| send http header failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_output_filter(r, out);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: m3u8_ack| send http content failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_HTTP_OK;
}


static void
ngx_hls_live_cleanup_handler(void *data)
{
    ngx_http_request_t                     *r;
    ngx_hls_live_ctx_t                     *ctx;
    ngx_chain_t                            *cl, *nl;

    r = data;
    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);

    ctx->hls->data = NULL;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "hls-live: cleanup_handler| http cleanup");

    for (cl = ctx->out_chain; cl;) {
        nl = cl->next;
        ngx_put_chainbuf(cl);
        cl = nl;
    }

    if (ctx->frag) {
        ngx_hls_cmd_free_frag(ctx->hls, ctx->frag);
        ctx->frag = NULL;
    }
}


static ngx_int_t
ngx_hls_live_m3u8_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_hls_live_ctx_t                     *ctx;
    ngx_mpegts_play_t                       v;
    ngx_int_t                               rc;
    ngx_hls_session_t                      *hls;
    ngx_http_cleanup_t                     *cln;

    ctx = ngx_hls_live_create_ctx(r, addr_conf);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: m3u8_handler| create ctx failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hls = ngx_hls_cmd_find_session(&ctx->serverid, &ctx->stream, &ctx->sid);
    if (hls == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hls-live: m3u8_handler| hls session %V not found", &ctx->sid);
        rc = ngx_hls_live_parse(r, &v);
        if (rc != NGX_OK) {
            return NGX_HTTP_CLOSE;
        }

        v.addr_conf = addr_conf;

        hls = ngx_hls_cmd_init_session(&v, &ctx->sid);
        if (hls == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    hls->data = r;
    ctx->hls = hls;

    rc = ngx_hls_live_m3u8_ack(r, hls);
    if (rc != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: m3u8_handler| hls session %V m3u8 ack failed", &ctx->sid);
    }

    if (rc != NGX_AGAIN) {
        return rc;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_hls_live_cleanup_handler;
    cln->data = r;

    hls->data = r;

    r->read_event_handler = ngx_http_test_reading;

    r->count++;

    return NGX_DONE;
}


static u_char*
ngx_hls_live_strrchr(ngx_str_t *str, u_char c)
{

    u_char                             *s, *e;

    s = str->data;
    e = str->data + str->len;

    e--;
    while(e != s) {
        if (*e == c) {
            break;
        }
        e--;
    }

    if (e == s) {
        return NULL;
    }

    return e;
}


static ngx_int_t
ngx_hls_live_parse_frag(ngx_http_request_t *r, ngx_str_t *name)
{
    u_char                             *s, *e;

    e = ngx_hls_live_strrchr(&r->uri, '?');
    if (e == NULL) {
        e = r->uri.data + r->uri.len;
    }

    s = ngx_hls_live_strrchr(&r->uri, '/');
    if (s == NULL) {
        s = r->uri.data;
    } else {
        s++;
    }

    name->data = s;
    name->len = e - s;

    return NGX_OK;
}


static ngx_int_t
ngx_hls_live_ts_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_hls_live_ctx_t                 *ctx;
    ngx_hls_session_t                  *hls;
    ngx_mpegts_frag_t                  *fg;
    ngx_int_t                           rc;
    ngx_http_cleanup_t                 *cln;
    ngx_str_t                           name;

    ctx = ngx_hls_live_create_ctx(r, addr_conf);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: ts_handler| create ctx failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hls = ngx_hls_cmd_find_session(&ctx->serverid, &ctx->stream, &ctx->sid);
    if (hls == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: ts_handler| hls session %V not found", &ctx->sid);
        return NGX_DECLINED;
    }

    ctx->hls = hls;

    rc = ngx_hls_live_parse_frag(r, &name);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: ts_handler| parse frag args failed %V", &r->uri);
        return NGX_HTTP_NOT_ALLOWED;
    }

    fg = ngx_hls_cmd_find_frag(hls, &name);
    if (fg == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: ts_handler| ts not found, %V", &r->uri);
        return NGX_HTTP_NOT_FOUND;
    }

    ctx->frag = fg;

    r->headers_out.content_length_n = fg->content_length;
    rc = ngx_hls_live_send_header(r, NGX_HTTP_OK, ngx_ts_headers);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: ts_handler| send http header failed, %V", &r->uri);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_hls_live_cleanup_handler;
    cln->data = r;

    r->read_event_handler = ngx_http_test_reading;

    ctx->out_chain = ngx_hls_cmd_prepare_chain(hls, fg);

    return ngx_http_output_filter(r, ctx->out_chain);
}



static ngx_int_t
ngx_hls_live_handler(ngx_http_request_t *r)
{
    ngx_hls_live_loc_conf_t            *hlcf;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_addr_conf_t               *addr_conf;
    ngx_str_t                           sstr;
    ngx_int_t                           rc;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_hls_live_module);

    addr_conf = ngx_rtmp_get_addr_conf_by_listening(hlcf->ls, r->connection);
    if (addr_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: live_handler| found addr conf failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    /* find ngx_rtmp_core_srv_conf_t */
    cscf = addr_conf->default_server->ctx->
            srv_conf[ngx_rtmp_core_module.ctx_index];
    if (cscf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: live_handler| found core conf failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: live_handler| donnot support the method");
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.len < 4) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: live_handler| donnot support the file type");
        return NGX_DECLINED;
    }

    if(!ngx_strncmp(r->uri.data + r->uri.len - 5, ".m3u8", 5)) {

        rc = ngx_http_arg(r, NGX_HLS_LIVE_ARG_SESSION,
                         NGX_HLS_LIVE_ARG_SESSION_LENGTH, &sstr);

        if (rc != NGX_OK || sstr.len == 0) {
            return ngx_hls_live_redirect_handler(r, addr_conf);
        } else {
            return ngx_hls_live_m3u8_handler(r, addr_conf);
        }

    } else if (!ngx_strncmp(r->uri.data + r->uri.len - 3, ".ts", 3)) {

        return ngx_hls_live_ts_handler(r, addr_conf);

    } else {
        return NGX_DECLINED;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_hls_live_play(ngx_hls_session_t *hls)
{
    ngx_http_request_t                 *r;
    ngx_int_t                           rc;
    ngx_hls_live_ctx_t                 *ctx;

    if (hls->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                "hls-live: play| hls session's http request is null");
        goto next;
    }

    r = hls->data;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_live_module);
    if ( ctx == NULL) {
       ngx_log_error(NGX_LOG_ERR, hls->log, 0,
               "hls-live: play| hls live ctx is null");
       goto next;
    }

    rc = ngx_hls_live_m3u8_ack(r, hls);
    if (rc != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: play| m3u8 ack failed");
    }

    ngx_http_finalize_request(r, rc);

next:

    return next_hls_play(hls);
}


static ngx_int_t
ngx_hls_live_close(ngx_hls_session_t *hls)
{
    ngx_http_request_t                 *r;
    if (hls->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                "hls-live: close| hls session's http request is null");
        goto next;
    }

    r = hls->data;

    ngx_http_finalize_request(r, NGX_HTTP_GONE);

next:
    return next_hls_close(hls);
}


static char *
ngx_hls_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t           *clcf;
    ngx_hls_live_loc_conf_t            *hlcf;
    ngx_str_t                          *value;
    ngx_uint_t                          n;
	
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_hls_live_handler;

    hlcf = conf;

    value = cf->args->elts;

    hlcf->ls = ngx_rtmp_find_relation_port(cf->cycle, &value[1]);
    if (hlcf->ls == NULL) {
        return NGX_CONF_ERROR;
    }

    for (n = 2; n < cf->args->nelts; ++n) {
#define PARSE_CONF_ARGS(conf, arg)                              \
        {                                                       \
        size_t len = sizeof(#arg"=") - 1;                       \
        if (ngx_memcmp(value[n].data, #arg"=", len) == 0) {     \
            conf->arg.data = value[n].data + len;               \
            conf->arg.len = value[n].len - len;                 \
            continue;                                           \
        }                                                       \
        }

        PARSE_CONF_ARGS(hlcf, app);
        PARSE_CONF_ARGS(hlcf, flashver);
        PARSE_CONF_ARGS(hlcf, swf_url);
        PARSE_CONF_ARGS(hlcf, tc_url);
        PARSE_CONF_ARGS(hlcf, page_url);
#undef PARSE_CONF_ARGS

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" para not support", &value[n]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
            "\napp: %V\nflashver: %V\nswf_url: %V\ntc_url: %V\npage_url: %V",
            &hlcf->app, &hlcf->flashver, &hlcf->swf_url, &hlcf->tc_url,
            &hlcf->page_url);
	
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_hls_live_postconfiguration(ngx_conf_t *cf)
{
    next_hls_play = ngx_hls_play;
    ngx_hls_play = ngx_hls_live_play;

    next_hls_close = ngx_hls_close;
    ngx_hls_close = ngx_hls_live_close;

    return NGX_OK;
}

