#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ngx_rtmp_cmd_module.h>
#include "../http/ngx_http_set_header.h"
#include "ngx_hls_cmd_module.h"
#include "ngx_rbuf.h"
#include "ngx_http_hls_live_module.h"
#include "ngx_rtmp_dynamic.h"
#include "ngx_dynamic_conf.h"
#include "ngx_http_dynamic.h"
#include "ngx_stream_zone_module.h"
#include "ngx_multiport.h"

#define HTTP_HLS_TS_TYPE           1
#define HTTP_HLS_M3U8_TYPE         2
#define HTTP_HLS_ERR_TYPE          3

#define HTTP       "http://"

static u_char  SESSION[] = "session";

static ngx_int_t SESSION_LEN = 7;

static ngx_hls_play_pt next_hls_play;

static ngx_keyval_t ngx_http_hls_302_headers[] = {
    { ngx_string("Location"),  ngx_null_string },
    { ngx_null_string, ngx_null_string }
};


static ngx_keyval_t ngx_http_hls_live_m3u8_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("application/vnd.apple.mpegurl") },
    { ngx_null_string, ngx_null_string }
};

static ngx_keyval_t ngx_http_hls_live_ts_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("video/mp2t") },
    { ngx_null_string, ngx_null_string }
};


static void * ngx_http_hls_live_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_hls_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void * ngx_http_hls_live_create_loc_dconf(ngx_conf_t *cf);

static char *ngx_http_hls_live_init_loc_dconf(ngx_conf_t *cf, void *conf);

static char * ngx_http_hls_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char * ngx_http_hls_live_variant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_http_hls_live_postconfiguration(ngx_conf_t *cf);


static ngx_command_t  ngx_http_hls_live_commands[] = {

    { ngx_string("hls_live"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_hls_live,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_hls_live_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_http_hls_live_postconfiguration,  /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_hls_live_create_loc_conf,    /* create location configuration */
    ngx_http_hls_live_merge_loc_conf      /* merge location configuration */
};

static ngx_command_t  ngx_http_hls_live_dcommands[] = {

    { ngx_string("hls_live_variant"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_hls_live_variant,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_dynamic_module_t  ngx_http_hls_live_module_dctx = {
    NULL,                                    /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* init server configuration */

    ngx_http_hls_live_create_loc_dconf,      /* create location configuration */
    ngx_http_hls_live_init_loc_dconf         /* init location configuration */
};



ngx_module_t  ngx_http_hls_live_module = {
    NGX_MODULE_V1,
    &ngx_http_hls_live_module_ctx,      /* module context */
    ngx_http_hls_live_commands,         /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    (uintptr_t) &ngx_http_hls_live_module_dctx, /* module dynamic context */
    (uintptr_t) ngx_http_hls_live_dcommands, /* module dynamic directives */
    NGX_MODULE_V1_DYNAMIC_PADDING
};

static void *
ngx_http_hls_live_create_loc_dconf(ngx_conf_t *cf)
{
    ngx_http_hls_live_loc_dconf_t       *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hls_live_loc_dconf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_hls_live_init_loc_dconf(ngx_conf_t *cf, void *conf)
{
    ngx_http_hls_live_loc_dconf_t       *hlldcf;

    hlldcf = conf;

    ngx_conf_init_ptr_value(hlldcf->hls_live_variant, NULL);

    return NGX_CONF_OK;
}


static char *
ngx_http_hls_live_variant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hls_live_loc_dconf_t  *hhlcf = conf;

    ngx_str_t                      *value, *arg;
    ngx_uint_t                      n;
    ngx_http_hls_live_variant_t    *var;

    value = cf->args->elts;

    if (hhlcf->hls_live_variant == NULL) {
        hhlcf->hls_live_variant = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_http_hls_live_variant_t));
        if (hhlcf->hls_live_variant == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    var = ngx_array_push(hhlcf->hls_live_variant);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(var, sizeof(ngx_http_hls_live_variant_t));

    var->suffix = value[1];

    if (cf->args->nelts == 2) {
        return NGX_CONF_OK;
    }

    if (ngx_array_init(&var->args, cf->pool, cf->args->nelts - 2,
                       sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    arg = ngx_array_push_n(&var->args, cf->args->nelts - 2);
    if (arg == NULL) {
        return NGX_CONF_ERROR;
    }

    for (n = 2; n < cf->args->nelts; n++) {
        *arg++ = value[n];
    }

    return NGX_CONF_OK;
}



static void *
ngx_http_hls_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hls_live_loc_conf_t       *hhlcf;

    hhlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hls_live_loc_conf_t));
    if (hhlcf == NULL) {
        return NULL;
    }

	hhlcf->out_queue = 40960;

    return hhlcf;
}

static char *
ngx_http_hls_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hls_live_loc_conf_t       *prev = parent;
    ngx_http_hls_live_loc_conf_t       *conf = child;

	ngx_conf_merge_str_value(conf->app, prev->app, "");
    ngx_conf_merge_str_value(conf->flashver, prev->flashver, "");
    ngx_conf_merge_str_value(conf->swf_url, prev->swf_url, "");
    ngx_conf_merge_str_value(conf->tc_url, prev->tc_url, "");
    ngx_conf_merge_str_value(conf->page_url, prev->page_url, "");

    return NGX_CONF_OK;
}

static void
ngx_http_hls_live_cleanup(void *data)
{
    ngx_http_request_t                     *r;
    ngx_http_hls_live_ctx_t                     *ctx;
    ngx_chain_t                            *cl, *nl;

    r = data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);

    ctx->hls->data = NULL;

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

static void
ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http-hls-live: ngx_http_close_request| http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http-hls-live: ngx_http_close_request| http request count is zero");
    }

    r->count--;

    if (r->count || r->blocked) {
        return;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        ngx_http_v2_close_stream(r->stream, rc);
        return;
    }
#endif

    ngx_http_free_request(r, rc);
    ngx_http_close_connection(c);
}


void
ngx_http_hls_test_reading(ngx_http_request_t *r)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = r->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http-hls-live: ngx_http_hls_test_reading| hls ts reading");

#if (NGX_HTTP_V2)

    if (r->stream) {
        if (c->error) {
            err = 0;
            goto closed;
        }

        return;
    }

#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;
        err = rev->kq_errno;

        goto closed;
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT) && ngx_use_epoll_rdhup) {
        socklen_t  len;

        if (!rev->pending_eof) {
            return;
        }

        rev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(ngx_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        goto closed;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EAGAIN) {
            rev->eof = 1;
            c->error = 1;

            goto closed;
        }
    }

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {

        if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }
    }

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "http-hls-live: ngx_http_hls_test_reading| client prematurely closed connection");

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}


static ngx_str_t *
ngx_http_hls_live_get_rand_str(ngx_http_request_t *r,ngx_int_t begin, ngx_int_t end){
    ngx_int_t          code;
    ngx_str_t         *rand_str;
    time_t             t;
    ngx_int_t          dis,pos;

    rand_str = ngx_pcalloc(r->connection->pool, sizeof(ngx_str_t));
    rand_str->data = ngx_pcalloc(r->connection->pool, 64);

    time(&t);
    srand((unsigned)t);

    if(begin == end){
        code = begin;
    }else if(begin>end){
        pos = end;
        dis = begin-end+1;
        code = rand()%dis+pos;
    }else{
        pos = begin;
        dis = end-begin+1;
        code = rand()%dis+pos;
    }
    ngx_sprintf(rand_str->data,"%d",code);
    rand_str->len = ngx_strlen(rand_str->data);
    return rand_str;

};

static ngx_str_t*
ngx_http_hls_live_get_sessionid(ngx_http_request_t *r)
{
    ngx_connection_t    *c;
    ngx_str_t            addr_text;
    time_t               now;
    ngx_tm_t             tm;
    ngx_str_t           *sessionid;
    u_char                 buf[128] = {0};
    char                 time_buf[64]={0};
    ngx_str_t           *rand_str;

    rand_str = ngx_http_hls_live_get_rand_str(r,10,99);
    c= r->connection;
    if(c == NULL)
        return NULL;
    addr_text = c->addr_text;
	
    now = ngx_time();
    ngx_localtime(now, &tm);
    strftime(time_buf, 64, "%Y%m%d%H%M%S", &tm);

    *ngx_snprintf(buf, sizeof(buf) - 1, "%V-%s-%V-%dp-%uDc",
                       &addr_text, time_buf, rand_str, ngx_process_slot, r->connection->number) = 0;

    sessionid = ngx_pcalloc(r->connection->pool, sizeof(ngx_str_t));
    sessionid->len = ngx_strlen(buf);
    sessionid->data = ngx_pcalloc(r->connection->pool, sessionid->len);
    ngx_memcpy(sessionid->data, buf, sessionid->len);
    return sessionid;
};


static ngx_int_t
ngx_http_hls_live_send_header(ngx_http_request_t *r, ngx_uint_t status, ngx_keyval_t *h)
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
ngx_http_hls_live_redirect_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_str_t                          *session_id;
    ngx_str_t                           loc;
    ngx_str_t                           host;
    ngx_int_t                           rc;
    ngx_str_t                           uri;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    session_id = ngx_http_hls_live_get_sessionid(r);
    if(session_id == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "http-hls-live: hls_live_redirect_handler| session_id init failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }			

    uri.len = r->uri_end - r->uri_start;
    uri.data = ngx_pcalloc(r->connection->pool, uri.len);
    ngx_memcpy(uri.data, r->uri_start, uri.len);
    host = r->headers_in.host->value;
    loc.len = ngx_strlen("http://") +
               host.len +
               uri.len + 1 +
               SESSION_LEN + 1 +
               session_id->len;

    loc.data = ngx_pcalloc(r->connection->pool, loc.len);

    if(r->args.len > 0){
        ngx_snprintf(loc.data, loc.len, "http://%V%V&%s=%V",
                   &host, &uri, SESSION, session_id);
    }else{
        ngx_snprintf(loc.data, loc.len, "http://%V%V?%s=%V",
                   &host, &uri, SESSION, session_id);
    }

    ngx_http_set_header_out(r, &ngx_http_hls_302_headers[0].key, &loc);

    //r->headers_out.content_length_n = 0;
    //r->header_only = 1;
    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t response = ngx_string("Hello World");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = response.len;
    r->headers_out.content_type = type;

    rc = ngx_http_hls_live_send_header(r, NGX_HTTP_MOVED_TEMPORARILY, ngx_http_hls_live_m3u8_headers);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: hls_live_redirect_handler| send header failed, redirect url: %V, rc=%d", &loc, rc);
        return rc;
    } else {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "hls-live: hls_live_redirect_handler| redirect url %V", &loc);
    }

    ngx_buf_t *b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    b->start = (u_char*)ngx_pcalloc(r->pool, response.len);
    if(b == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + response.len;
    b->temporary = 1;
    ngx_memcpy(b->pos, response.data, response.len);
    b->last = b->pos + response.len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
    //return rc;
};


static ngx_int_t
ngx_http_hls_live_m3u8_send_header(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_keyval_t                       *h;

    r->headers_out.status = NGX_HTTP_OK;
    r->keepalive = 0; /* set Connection to closed */

    //set modified time
    time_t timep;
    time(&timep);
    r->headers_out.last_modified_time = timep;
    //set eTag
    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_http_hls_live_m3u8_headers;
    while (h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
};

static void
ngx_http_hls_live_ctx_init(ngx_http_request_t *r)
{
    u_char                             *p, *e;
    ngx_buf_t                          *buf;
    ngx_rtmp_core_srv_dconf_t          *rcsdf;
    ngx_http_hls_live_loc_conf_t       *hlcf;
    ngx_rtmp_session_t                  s;
    ngx_http_hls_live_ctx_t            *ctx;
    ngx_str_t                          *app, *name, *stream, *domain, *serverid;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);

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
ngx_http_hls_live_parse(ngx_http_request_t *r, ngx_mpegts_play_t *v)
{
    ngx_http_hls_live_loc_conf_t            *hlcf;
    ngx_http_hls_live_ctx_t                 *ctx;
    size_t                                   tcurl_len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);

    if (ctx->app.len == 0 || ctx->stream.len == 0 || ctx->stream.len > NGX_RTMP_MAX_NAME) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: hls_live_parse| url error: %V", &r->uri);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_arg(r, (u_char *) "flashver", 8, &v->flashver) != NGX_OK) {
        v->flashver = hlcf->flashver;
    }

    tcurl_len = sizeof("rtmp://") + r->headers_in.server.len + ctx->app.len + 2;
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


static ngx_http_hls_live_ctx_t *
ngx_http_hls_live_create_ctx(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_http_hls_live_ctx_t                *ctx;
    ngx_rtmp_core_srv_conf_t               *cscf;
    ngx_http_hls_live_loc_conf_t           *hlcf;
    u_char                                 *p;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);

    cscf = addr_conf->default_server->
            ctx->srv_conf[ngx_rtmp_core_module.ctx_index];

    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);
    if (ctx == NULL) {
        p = ngx_pcalloc(r->connection->pool,
                        sizeof(ngx_http_hls_live_ctx_t) +
                        sizeof(ngx_mpegts_frame_t)*hlcf->out_queue);
        if (p == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: create_ctx| alloc hls live ctx failed");
            return NULL;
        }

        ctx = (ngx_http_hls_live_ctx_t *)p;

        ngx_http_set_ctx(r, ctx, ngx_http_hls_live_module);
    }

    ctx->timeout = cscf->timeout;

    ngx_http_hls_live_ctx_init(r);

    if (ctx->app.len == 0 || ctx->name.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: create_ctx| parse app or name failed, uri %V", &r->uri);
        return NULL;
    }

    ngx_http_arg(r, SESSION, SESSION_LEN, &ctx->sid);

    return ctx;
}
static ngx_int_t
ngx_http_hls_live_m3u8_ack(ngx_http_request_t *r, ngx_hls_session_t *s)
{
    ngx_http_hls_live_ctx_t            *ctx;
    ngx_int_t                           rc;
    ngx_chain_t                         out;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);

    ctx->mbuf = ngx_create_temp_buf(r->connection->pool, 1024*512);
    if (ctx->mbuf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hls-live: m3u8_ack| "
                    "hls session %V, create temp buf failed", &ctx->sid);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_hls_cmd_create_m3u8_string(ctx->hls, ctx->mbuf);
    if (rc != NGX_OK) {
        return NGX_AGAIN;
    }

    out.buf = ctx->mbuf;
    out.buf->memory = 1;
    out.buf->flush = 1;
    out.buf->last_in_chain = 1;
    out.buf->last_buf = 1;
    out.next = NULL;

    r->headers_out.content_length_n = out.buf->last - out.buf->pos;

    rc = ngx_http_hls_live_send_header(r, NGX_HTTP_OK, ngx_http_hls_live_m3u8_headers);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: m3u8_ack| send http header failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_output_filter(r, &out);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: m3u8_ack| send http content failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_HTTP_OK;
}

static ngx_int_t
ngx_http_hls_send_m3u8_playlist_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_http_hls_live_ctx_t            *ctx;
    ngx_hls_session_t                  *hs;
    ngx_http_cleanup_t                 *cln;
    ngx_mpegts_play_t                   v;
    ngx_int_t                           rc;

    ctx = ngx_http_hls_live_create_ctx(r, addr_conf);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: send_m3u8_playlist_handler| create ctx failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    hs = ngx_hls_cmd_find_session(&ctx->serverid, &ctx->stream, &ctx->sid);

    if (hs == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hls-live: send_m3u8_playlist_handler| hls session %V not found", &ctx->sid);
        rc = ngx_http_hls_live_parse(r, &v);
        if (rc != NGX_OK) {
            return NGX_HTTP_CLOSE;
        }

        v.addr_conf = addr_conf;
        v.acodecs = 0x0DF7;
        v.vcodecs = 0xFC;

        hs = ngx_hls_cmd_init_session(&v, &ctx->sid);
        if (hs == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

    }

    hs->data = r;
    ctx->hls = hs;

    rc = ngx_http_hls_live_m3u8_ack(r, hs);
    if (rc != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: send_m3u8_playlist_handler| hls session %V m3u8 ack failed", &ctx->sid);
    }

    if (rc != NGX_AGAIN) {
        return rc;
    }

    /* cleanup handler use in ngx_http_free_request */
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_http_hls_live_cleanup;
    cln->data = r;

    hs->data = r;
    r->read_event_handler = ngx_http_test_reading;
    ++r->count;

    return NGX_DONE;
};


static ngx_int_t ngx_http_hls_live_alloc_frame(ngx_http_request_t *r, ngx_hls_session_t *hs, ngx_mpegts_frag_t *frags)
{
    ngx_mpegts_frame_t                 *head;
    ngx_http_hls_live_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    head = frags->frame_header;

    ctx->out[ctx->out_last++] = frags->patpmt;
    ngx_rtmp_shared_acquire_frame(frags->patpmt);
    ctx->out_last %= ctx->out_queue;

    while(head != frags->frame_tail && head != NULL){
        ctx->out[ctx->out_last++] = head;
        ngx_rtmp_shared_acquire_frame(head);
        ctx->out_last %= ctx->out_queue;
        head = head->next;
    }

    ctx->out[ctx->out_last++] = head;
    ngx_rtmp_shared_acquire_frame(head);
    ctx->out_last %= ctx->out_queue;

    return NGX_OK;

}

static ngx_int_t
ngx_http_hls_live_ts_send_header(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_keyval_t                       *h;

    r->headers_out.status = NGX_HTTP_OK;
    r->keepalive = 0; /* set Connection to closed */

    h = ngx_http_hls_live_ts_headers;
    while (h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
};

static ngx_chain_t *
ngx_http_hls_live_prepare_out_chain(ngx_http_request_t *r,
        ngx_hls_session_t *hs)
{
    ngx_mpegts_frag_t                  *fg;
    ngx_mpegts_frame_t                 *frame;
    ngx_chain_t                        *head, **ll, *cl;
    size_t                              datasize = 0;
    ngx_int_t                           rc;
    ngx_http_hls_live_ctx_t            *ctx;

    frame = NULL;
    head = NULL;
    datasize = 0;


    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);
    if(ctx == NULL){
        return NULL;
    }

    frame = ctx->out[ctx->out_pos];
    if (frame == NULL) {
        return NULL;
    }

    fg = ctx->frag;
    /* no frame to send */
    if (fg == NULL) {
        return NULL;
    }

    for (ll = &head; *ll; ll = &(*ll)->next);

    for (cl = frame->chain; cl; cl = cl->next) {
        datasize += (cl->buf->last - cl->buf->pos);
    }
    ngx_log_error(NGX_LOG_DEBUG, hs->log, 0,
                "hs(%p) http-hls-live: hls_live_prepare_out_chain| "
                "frame pts = %d type = %d datasize = %d",
                hs, frame->pts,frame->type, datasize);

    /* first send */
    if (!r->header_sent) {
        r->headers_out.content_length_n = fg->content_length;
        rc = ngx_http_hls_live_ts_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return NULL;
        }
		
    }

    /* ts payload */
    for (cl = frame->chain; cl; cl = cl->next) {
        (*ll) = ngx_get_chainbuf(0, 0);
        if (*ll == NULL) {
            goto falied;
        }
        (*ll)->buf->pos = cl->buf->pos;
        (*ll)->buf->last = cl->buf->last;
        (*ll)->buf->memory = 1;
        (*ll)->buf->flush = 1;
        ll = &(*ll)->next;
    }

    return head;

falied:
    for (cl = head; cl; cl = cl->next) {
        head = cl->next;
        ngx_put_chainbuf(cl);
        cl = head;
    }

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
    return NULL;
};

static void
ngx_http_hls_live_write_handler(ngx_http_request_t *r)
{
    ngx_http_hls_live_ctx_t            *ctx;
    ngx_hls_session_t                  *s;
    ngx_event_t                        *wev;
    size_t                              present, sent;
    ngx_int_t                           rc;
    ngx_chain_t                        *cl;

    wev = r->connection->write;           //wev->handler = ngx_http_request_handler;

    if (r->connection->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                "http_hls_live: http_hls_live_write_handler| client timed out");
        r->connection->timedout = 1;
        if (r->header_sent) {
            ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        } else {
            ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        }
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_hls_live_module);
    s = ctx->hls;

    if (ctx->out_chain == NULL) {
        ctx->out_chain = ngx_http_hls_live_prepare_out_chain(r, s);
    }

    rc = NGX_OK;

    ngx_int_t sent_datasize = 0;
    while (ctx->out_chain) {
        present = r->connection->sent;

        if (r->connection->buffered) {
            rc = ngx_http_output_filter(r, NULL);
        } else {
            //计算发送字节
            ngx_chain_t *head = ctx->out_chain;
            for(; head!=NULL;head=head->next){
                sent_datasize += head->buf->last-head->buf->pos;
            }
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                        "http_hls_live: http_hls_live_write_handler| r->headers_out.content_length_n=%l "
                        "sent_datasize = %d", r->headers_out.content_length_n, sent_datasize);

            rc = ngx_http_output_filter(r, ctx->out_chain);
        }

        sent = r->connection->sent - present;

        ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, sent);

        if (rc == NGX_AGAIN) {
            ngx_add_timer(wev, s->timeout);
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http_hls_live: http_hls_live_write_handler| handle write event failed");
                ngx_http_finalize_request(r, NGX_ERROR);
            }
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "http_hls_live: http_hls_live_write_handler| send error");
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        /* NGX_OK */
        cl = ctx->out_chain;
        while (cl) {
            ctx->out_chain = cl->next;
            ngx_put_chainbuf(cl);
            cl = ctx->out_chain;
        }
        ngx_rtmp_shared_free_mpegts_frame(ctx->out[ctx->out_pos]);
        ++ctx->out_pos;
        ctx->out_pos %= ctx->out_queue;
        if (ctx->out_pos == ctx->out_last) {
            break;
        }

        ctx->out_chain = ngx_http_hls_live_prepare_out_chain(r, s);
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "http_hls_live: http_hls_live_write_handler| send secceed");
        ngx_http_finalize_request(r, rc);
    }
}


static void
ngx_http_hls_live_ts_send(ngx_hls_session_t *hs)
{
    ngx_connection_t                   *c;
    ngx_http_request_t                 *r;
    r = hs->data;
    c = r->connection;

    ngx_http_hls_live_write_handler(r);

    ngx_http_run_posted_requests(c);

    return;
}

static u_char*
ngx_http_hls_live_strrchr(ngx_str_t *str, u_char c)
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
ngx_http_hls_live_parse_frag(ngx_http_request_t *r, ngx_str_t *name)
{
    u_char                             *s, *e;

    e = ngx_http_hls_live_strrchr(&r->uri, '?');
    if (e == NULL) {
        e = r->uri.data + r->uri.len;
    }

    s = ngx_http_hls_live_strrchr(&r->uri, '/');
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
ngx_http_hls_send_ts_handler(ngx_http_request_t *r, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_http_hls_live_loc_conf_t       *hhlcf;
    ngx_http_hls_live_ctx_t            *ctx;
    ngx_hls_session_t                  *hs;
    ngx_mpegts_frag_t                  *fg;
    ngx_int_t                           rc;
    ngx_http_cleanup_t                 *cln;
    ngx_str_t                           name;

    hhlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);

    ctx = ngx_http_hls_live_create_ctx(r, addr_conf);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: send_ts_handler| create ctx failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    hs = ngx_hls_cmd_find_session(&ctx->serverid, &ctx->stream, &ctx->sid);
    if(hs == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "hs(%p) http-hls-live: send_ts_handler| "
            "hs is not found serverid=%V ts_stream=%V sessionid_value=%V",hs, &ctx->serverid, &ctx->stream, &ctx->sid);
        return NGX_HTTP_NOT_FOUND;
    }
    hs->data = r;
    ctx->hls = hs;

    rc = ngx_http_hls_live_parse_frag(r, &name);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: send_ts_handler| parse frag args failed %V", &r->uri);
        return NGX_HTTP_NOT_ALLOWED;
    }

    fg = ngx_hls_cmd_find_frag(hs, &name);
    if (fg == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: send_ts_handler| ts not found, %V", &r->uri);
        return NGX_HTTP_NOT_FOUND;
    }

    ctx->frag = fg;
    ctx->out_queue = hhlcf->out_queue;
    ctx->out_pos = ctx->out_last = 0;

    ngx_http_hls_live_alloc_frame(r, hs, fg);

    /* cleanup handler use in ngx_http_free_request*/
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_http_hls_live_cleanup;
    cln->data = r;

    ngx_add_timer(r->connection->write, hs->timeout);
    r->read_event_handler = ngx_http_hls_test_reading;
    r->write_event_handler = ngx_http_hls_live_write_handler;
    ++r->count;
    ngx_http_hls_live_ts_send(hs);
    return NGX_DONE;

};

static ngx_buf_t*
ngx_http_hls_live_write_variant_playlist(ngx_http_request_t *r)
{
    ngx_http_hls_live_variant_t       *var;
    ngx_http_hls_live_loc_conf_t      *hhlcf;
    ngx_http_hls_live_loc_dconf_t      *hhldcf;
    ngx_str_t                         *arg;
    ngx_uint_t                         n, k;
    ngx_buf_t                         *buf;
    ngx_str_t                         *session_id;
    ngx_str_t                         *name;
    u_char                            *p, *last;
    u_char                            *e, *h;

    session_id = ngx_http_hls_live_get_sessionid(r);
    if(session_id == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
           "http-hls-live: send_master_m3u8_handler| session_id init failed");
        return NULL;
    }	

    buf = ngx_create_temp_buf(r->connection->pool, 1024*512);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "hls-live: write_variant_playlist| "
                    "create buf failed");
        return NULL;
    }
    buf->pos = buf->last;

    name = ngx_pcalloc(r->connection->pool, sizeof(ngx_str_t));
    e = r->uri.data;
    h = r->uri.data + r->uri.len;
    e++;
    e = ngx_strlchr(e, h, '/');
    e++;
    name->data = e;
    if (ngx_strncmp(&h[-5], ".m3u8", 5) == 0) {
        e = ngx_strlchr(e, h, '.');
    } else {
        e = NULL;
    }

    if (e == NULL) {
        name->data = NULL;
        name->len = 0;
        return NULL;
    }
    name->len = e - name->data;

    hhlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);
    hhldcf = ngx_http_get_module_loc_dconf(r, &ngx_http_hls_live_module);

#define NGX_HTTP_HLS_VAR_HEADER "#EXTM3U\n#EXT-X-VERSION:3\n"
    p = buf->pos;
    last = buf->end;
    p = ngx_slprintf(p, last, NGX_HTTP_HLS_VAR_HEADER);

    var = hhldcf->hls_live_variant->elts;
    for (n = 0; n < hhldcf->hls_live_variant->nelts; n++, var++)
    {
        p = ngx_slprintf(p, last, "#EXT-X-STREAM-INF:PROGRAM-ID=1");

        arg = var->args.elts;
        for (k = 0; k < var->args.nelts; k++, arg++) {
            p = ngx_slprintf(p, last, ",%V", arg);
        }

        if (p < last) {
            *p++ = '\n';
        }

        p = ngx_slprintf(p, last, "%V%V%V",
                         &hhlcf->hls_live_base_url, name,
                         &var->suffix);

        if (hhlcf->hls_live_nested) {
            p = ngx_slprintf(p, last, "%s", "/index");
        }


        p = ngx_slprintf(p, last, "%s", ".m3u8");

        if(r->args.len != 0){
            p = ngx_slprintf(p, last, "?%V&%s=%V\n", &r->args, SESSION, session_id);
        }else{
            p = ngx_slprintf(p, last, "?%s=%V\n", SESSION, session_id);
        }

    }

    buf->last = p;
    return buf;
}



static ngx_int_t
ngx_http_hls_send_master_m3u8_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_chain_t                     out;
    ngx_buf_t                      *master_m3u8;

    master_m3u8 = ngx_http_hls_live_write_variant_playlist(r);
    if(master_m3u8 == NULL){
         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http-hls-live: send_master_m3u8_handler| init master_m3u8_str failed");
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_length_n = master_m3u8->last - master_m3u8->pos;
    rc = ngx_http_hls_live_m3u8_send_header(r);
    if(NGX_OK != rc){
        return rc;
    }

    out.buf = master_m3u8;
    out.buf->memory = 1;
    out.buf->flush = 1;
    out.buf->temporary = 1;
    out.buf->last_in_chain = 1;
    out.buf->last_buf = 1;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);

};

static ngx_int_t
ngx_http_hls_determine_nesting(ngx_http_request_t *r){
    ngx_http_hls_live_loc_dconf_t       *hhldcf;
    ngx_http_hls_live_variant_t         *var;
    ngx_uint_t                           n;
    ngx_str_t                            name, app;
    u_char                              *p, *e;

    p = r->uri.data;
    e = r->uri.data + r->uri.len;

    p++;
    app.data = p;
    p = ngx_strlchr(p, e, '/');
    if (p == NULL) {
        app.data = NULL;
        app.len = 0;
        return NGX_ERROR;
    }
    app.len = p - app.data;

    p++;
    name.data = p;
    if (ngx_strncmp(&e[-5], ".m3u8", 5) == 0) {
        p = ngx_strlchr(p, e, '.');
    } else {
        p = NULL;
    }

    if (p == NULL) {
        name.data = NULL;
        name.len = 0;
        return NGX_ERROR;
    }
    name.len = p - name.data;

    hhldcf = ngx_http_get_module_loc_dconf(r, &ngx_http_hls_live_module);

    if(NULL == hhldcf || NULL == hhldcf->hls_live_variant){
        return NGX_ERROR;
    }

    var = hhldcf->hls_live_variant->elts;
    for (n = 0; n < hhldcf->hls_live_variant->nelts; n++, var++){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                       "transcode: judge_name| live joined var->suffix = %V", &var->suffix);
        if(name.len < var->suffix.len){
            continue;
        }
        if(ngx_strncmp(name.data + name.len - var->suffix.len ,var->suffix.data , var->suffix.len) == 0){

            return NGX_OK;
        }

    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_http_hls_live_handler(ngx_http_request_t *r)
{
    ngx_http_hls_live_loc_dconf_t      *hhldcf;
    ngx_http_hls_live_loc_conf_t       *hhlcf;
    ngx_rtmp_addr_conf_t               *addr_conf;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_str_t                           session_value = ngx_null_string;
    ngx_int_t                           session_rc;

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ngx_http_hls_live_handler %d", ngx_process_slot);

    hhlcf = ngx_http_get_module_loc_conf(r, ngx_http_hls_live_module);

    hhldcf = ngx_http_get_module_loc_dconf(r, &ngx_http_hls_live_module);

    if(hhldcf == NULL){
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "hls-live: live_handler| hhldcf conf is not validate");
    }

    addr_conf = ngx_rtmp_get_addr_conf_by_listening(hhlcf->ls, r->connection);
    if (addr_conf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    /* find ngx_rtmp_core_srv_conf_t */
    cscf = addr_conf->default_server->
            ctx->srv_conf[ngx_rtmp_core_module.ctx_index];
    if (cscf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-live: live_handler| found core conf failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

	/*file name judge*/
    if( ngx_strncmp(r->uri.data + r->uri.len - 5, ".m3u8", 5) != 0 &&
            ngx_strncmp(r->uri.data + r->uri.len - 3, ".ts", 3) !=0 ){
        return NGX_DECLINED;
    }

    session_rc = ngx_http_arg(r, (u_char*)"session", 7 , &session_value);

    if(ngx_strncmp(r->uri.data + r->uri.len - 5, ".m3u8", 5) == 0){
        if(session_rc != NGX_OK){
            if(hhldcf != NULL && hhldcf->hls_live_variant != NULL && ngx_http_hls_determine_nesting(r) == NGX_ERROR){
                return ngx_http_hls_send_master_m3u8_handler(r);
            }else{
                return ngx_http_hls_live_redirect_handler(r, addr_conf);
            }

        }else{
            return ngx_http_hls_send_m3u8_playlist_handler(r, addr_conf);
        }

    }else if(ngx_strncmp(r->uri.data + r->uri.len - 3, ".ts", 3) == 0){
        if (session_rc != NGX_OK){
            return NGX_HTTP_NOT_ALLOWED;
        }
        return ngx_http_hls_send_ts_handler(r, addr_conf);
    }else{
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http-hls-live: hls_live_handler| http hls request is not legal %V", &r->uri);
        return NGX_DECLINED;
    }

}

static ngx_int_t
ngx_http_hls_live_play(ngx_hls_session_t *hls)
{
    ngx_http_request_t                 *r;
    ngx_int_t                           rc;

    if (hls->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, hls->log, 0,
                "hls-live: play| hls session's http request is null");
        goto next;
    }

    r = hls->data;

    rc = ngx_http_hls_live_m3u8_ack(r, hls);

    if (rc != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "hls-live: play| m3u8 ack failed");
    }
    ngx_http_finalize_request(r, rc);
next:

    return next_hls_play(hls);
}


static char *
ngx_http_hls_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t           *clcf;
    ngx_http_hls_live_loc_conf_t       *hhlcf;
    ngx_str_t                          *value;
    ngx_uint_t                          n;
	
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hls_live_handler;

    hhlcf = conf;

    value = cf->args->elts;

    hhlcf->ls = ngx_rtmp_find_relation_port(cf->cycle, &value[1]);
    if (hhlcf->ls == NULL) {
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

        PARSE_CONF_ARGS(hhlcf, app);
        PARSE_CONF_ARGS(hhlcf, flashver);
        PARSE_CONF_ARGS(hhlcf, swf_url);
        PARSE_CONF_ARGS(hhlcf, tc_url);
        PARSE_CONF_ARGS(hhlcf, page_url);
#undef PARSE_CONF_ARGS

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" para not support", &value[n]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
            "\napp: %V\nflashver: %V\nswf_url: %V\ntc_url: %V\npage_url: %V",
            &hhlcf->app, &hhlcf->flashver, &hhlcf->swf_url, &hhlcf->tc_url,
            &hhlcf->page_url);
	
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_hls_live_postconfiguration(ngx_conf_t *cf)
{
    next_hls_play = ngx_hls_play;
    ngx_hls_play = ngx_http_hls_live_play;

    return NGX_OK;
}

