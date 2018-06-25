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
#include "ngx_stream_zone_module.h"
#include "ngx_multiport.h"

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

typedef struct
{
    ngx_chain_t                   *out;
    ngx_str_t                      app;
    ngx_str_t                      name;
    ngx_str_t                      stream;
    ngx_str_t                      serverid;
    ngx_str_t                      port;
    ngx_str_t                      url;
    ngx_keyval_t                  *header;
    ngx_keyval_t                   sub_header[64];
    ngx_int_t                      sub_header_counter;
} ngx_hls_subrequest_ctx_t;

typedef struct {
    ngx_str_t                      target_location;
    ngx_str_t                      app;
    ngx_str_t                      proxy_port;
} ngx_hls_subrequest_loc_conf_t;

static char *
ngx_hls_subrequest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_hls_subrequest_handler(ngx_http_request_t *r);
static void *
ngx_hls_subrequest_create_loc_conf(ngx_conf_t *cf);

static u_char  NGX_HLS_SUBREQUEST_ARG_NAME[] = "name";
static u_char  NGX_HLS_SUBREQUEST_ARG_APP[] = "app";

static ngx_command_t  ngx_hls_subrequest_commands[] =
{
    { ngx_string("hls_subrequest"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_hls_subrequest,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_hls_subrequest_module_ctx =
{
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_hls_subrequest_create_loc_conf,       /* create location configuration */
    NULL                                      /* merge location configuration */
};

ngx_module_t  ngx_hls_subrequest_module =
{
    NGX_MODULE_V1,
    &ngx_hls_subrequest_module_ctx,           /* module context */
    ngx_hls_subrequest_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_hls_subrequest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_hls_subrequest_loc_conf_t       *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_hls_subrequest_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static u_char*
ngx_hls_subrequest_strrchr(ngx_str_t *str, u_char c)
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


static void
ngx_hls_subrequest_parse_name(ngx_http_request_t *r, ngx_str_t *name)
{
    u_char                             *s, *e;

    e = ngx_hls_subrequest_strrchr(&r->uri, '.');
    if (e == NULL) {
        e = r->uri.data + r->uri.len;
    }

    s = ngx_hls_subrequest_strrchr(&r->uri, '/');
    if (s == NULL) {
        s = r->uri.data;
    } else {
        s++;
    }

    name->data = s;
    name->len = e - s;
}


static ngx_int_t
ngx_hls_subrequest_parse_stream(ngx_http_request_t *r)
{
    ngx_str_t                            serverid = ngx_null_string;
    ngx_str_t                            app = ngx_null_string;
    ngx_str_t                            name = ngx_null_string;
    ngx_rtmp_session_t                   s;
    ngx_rtmp_core_srv_dconf_t           *rcsdf;
    ngx_hls_subrequest_loc_conf_t       *hplf;
    ngx_hls_subrequest_ctx_t            *ctx;
    ngx_str_t                           *stream;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_subrequest_module);

    hplf = ngx_http_get_module_loc_conf(r, ngx_hls_subrequest_module);

    ngx_http_arg(r, NGX_HLS_SUBREQUEST_ARG_APP,
                        ngx_strlen(NGX_HLS_SUBREQUEST_ARG_APP), &app);
    ngx_http_arg(r, NGX_HLS_SUBREQUEST_ARG_NAME,
                        ngx_strlen(NGX_HLS_SUBREQUEST_ARG_NAME), &name);

    ngx_memzero(&s, sizeof(s));
    s.domain = r->headers_in.server;
    rcsdf = ngx_rtmp_get_module_srv_dconf(&s, &ngx_rtmp_core_module);
    serverid = rcsdf->serverid;

    if (serverid.len == 0 || serverid.data == NULL) {
        serverid = r->headers_in.server;
    }

    if (app.len == 0 || app.data == NULL) {
        app = hplf->app;
    }

    if (name.len == 0 || name.data == NULL) {
        ngx_hls_subrequest_parse_name(r, &name);
    }

    stream = &ctx->stream;
    stream->len = serverid.len + app.len + name.len + 2;
    stream->data = ngx_pcalloc(r->connection->pool, stream->len);
    ngx_snprintf(stream->data, stream->len, "%V/%V/%V", &serverid, &app, &name);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "hls-subrequest: parse_stream| stream %V", stream);
    ctx->serverid = serverid;
    ctx->app = app;
    ctx->name = name;

    return NGX_OK;
}


static ngx_int_t
ngx_hls_subrequest_send_header(ngx_http_request_t *r, ngx_keyval_t *h)
{
    ngx_int_t                           rc;
    ngx_int_t                           i;
    ngx_hls_subrequest_ctx_t           *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_subrequest_module);

    r->keepalive = 0; /* set Connection to closed */

    while (h && h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    for (i = 0; i < ctx->sub_header_counter; i++) {
        rc = ngx_http_set_header_out(r,
             &ctx->sub_header[i].key, &ctx->sub_header[i].value);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return ngx_http_send_header(r);
}


static void
ngx_hls_subrequest_ack_handler(ngx_http_request_t * r)
{
    ngx_hls_subrequest_ctx_t   *ctx;
    ngx_buf_t                  *b;
    ngx_int_t                   rc;

    ctx = ngx_http_get_module_ctx(r, ngx_hls_subrequest_module);
    r->headers_out.content_length_n = 0;
    r->header_only = 1;

    if (ctx->out) {
        b = ctx->out->buf;
        b->last_buf = 1;
        b->flush = 1;
        b->last_in_chain = 1;
        r->headers_out.content_length_n = b->last - b->pos;
        r->header_only = 0;
        r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    }
    rc = ngx_hls_subrequest_send_header(r, ctx->header);
    if (ctx) {
        rc = ngx_http_output_filter(r, ctx->out);
    }

    ngx_http_finalize_request(r, rc);
}


static ngx_int_t ngx_hls_subrequest_post_handler(ngx_http_request_t *r,
                                                void *data, ngx_int_t rc)
{
    ngx_http_request_t          *pr;
    ngx_hls_subrequest_ctx_t    *ctx;
    ngx_buf_t                   *b, *buf;
    ngx_table_elt_t             *header;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    ngx_str_t                    k, v;

    pr = r->parent;
    ctx = ngx_http_get_module_ctx(pr, ngx_hls_subrequest_module);
    ctx->sub_header_counter = 0;

    pr->headers_out.status = r->headers_out.status;
    b = &r->upstream->buffer;
    if (b->last - b->pos > 0)
    {
        buf = ngx_create_temp_buf(pr->pool,
                                  sizeof(ngx_chain_t) + b->last - b->pos);
        ctx->out = (ngx_chain_t*) buf->start;
        buf->pos = buf->last = buf->start + sizeof(ngx_chain_t);
        ctx->out->buf = buf;
        ctx->out->next = NULL;

        buf->last = ngx_cpymem(buf->pos, b->pos, b->last - b->pos);
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        k.len = header[i].key.len;
        k.data = ngx_pcalloc(pr->pool, k.len);
        ngx_memcpy(k.data, header[i].key.data, k.len);

        v.len = header[i].value.len;
        v.data = ngx_pcalloc(pr->pool, v.len);
        ngx_memcpy(v.data, header[i].value.data, v.len);

        ctx->sub_header[ctx->sub_header_counter].key = k;
        ctx->sub_header[ctx->sub_header_counter].value = v;
        ctx->sub_header_counter++;
    }

    pr->write_event_handler = ngx_hls_subrequest_ack_handler;

    return NGX_OK;
}


static char *
ngx_hls_subrequest(ngx_conf_t * cf, ngx_command_t * cmd, void * conf)
{
    ngx_http_core_loc_conf_t           *clcf;
    ngx_str_t                          *value;
    ngx_uint_t                          n;
    ngx_hls_subrequest_loc_conf_t      *hlcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_hls_subrequest_handler;

    hlcf = conf;

    value = cf->args->elts;
    for (n = 1; n < cf->args->nelts; ++n) {
#define PARSE_CONF_ARGS(conf, arg)                              \
        {                                                       \
        size_t len = sizeof(#arg"=") - 1;                       \
        if (ngx_memcmp(value[n].data, #arg"=", len) == 0) {     \
            conf->arg.data = value[n].data + len;               \
            conf->arg.len = value[n].len - len;                 \
            continue;                                           \
        }                                                       \
        }

        PARSE_CONF_ARGS(hlcf, target_location);
        PARSE_CONF_ARGS(hlcf, app);
        PARSE_CONF_ARGS(hlcf, proxy_port);
#undef PARSE_CONF_ARGS

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" para not support", &value[n]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_hls_subrequest_handler(ngx_http_request_t * r)
{
    ngx_http_request_t                  *sr;
    ngx_http_post_subrequest_t          *psr;
    ngx_hls_subrequest_ctx_t            *ctx;
    ngx_str_t                            sub_location;
    ngx_int_t                            rc;
    ngx_int_t                            pslot;
    ngx_hls_subrequest_loc_conf_t       *hlcf;
    ngx_str_t                            uri_part = ngx_string("");
    ngx_str_t                            args = ngx_string("");
    ngx_str_t                            session = ngx_string("");
    u_char                              *p;
    ngx_http_core_loc_conf_t            *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    hlcf = ngx_http_get_module_loc_conf(r, ngx_hls_subrequest_module);
    ctx = ngx_http_get_module_ctx(r, ngx_hls_subrequest_module);
    if (ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_hls_subrequest_ctx_t));
        if (ctx == NULL)
        {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_hls_subrequest_module);
    }

    if (r->uri.len < 5) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-subrequest: subrequest_handler| donnot support the file type");
        return NGX_DECLINED;
    }
    if (ngx_strncmp(r->uri.data + r->uri.len - 5, ".m3u8", 5) == 0) {
        ctx->header = &ngx_m3u8_headers[0];
    } else if (ngx_strncmp(r->uri.data + r->uri.len - 3, ".ts", 3) == 0) {
        ctx->header = &ngx_ts_headers[0];
    } else {
        return NGX_DECLINED;
    }

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_hls_subrequest_post_handler;
    psr->data = ctx;

    rc = ngx_hls_subrequest_parse_stream(r);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    pslot = ngx_stream_zone_insert_stream(&ctx->stream);
    if (pslot == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-subrequest: subrequest_handler| pslot is -1, error");
        return NGX_DECLINED;
    }

    if (ngx_multiport_get_port(r->connection->pool, &ctx->port,
            &hlcf->proxy_port, pslot) == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "hls-subrequest: subrequest_handler| get port failed");
        return NGX_DECLINED;
    }

    uri_part.data = ngx_strlchr(r->uri.data + 1, r->uri.data + r->uri.len, '/');
    if (uri_part.data) {
        uri_part.len = r->uri.data + r->uri.len - uri_part.data;
    }
    sub_location.len = ctx->port.len + 1 + hlcf->target_location.len + uri_part.len;
    sub_location.data = ngx_palloc(r->pool, sub_location.len);
    ngx_snprintf(sub_location.data, sub_location.len,
                 "%V%V/%V", &hlcf->target_location, &uri_part, &ctx->port);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "hls-subrequest: subrequest_handler|  %V, stream %V",
             &sub_location, &ctx->stream);

    rc = ngx_http_arg(r, (u_char*)"session", 7, &session);
    if (rc != NGX_OK) {
        args.len = ngx_strlen("location=") +
                   clcf->name.len +
                   (r->args.len? 1 : 0) +
                   r->args.len;
        args.data = ngx_pcalloc(r->pool, args.len);
        p = args.data;
        p = ngx_snprintf(p, args.len, "location=%V", &clcf->name);
        if (r->args.len) {
            ngx_snprintf(p, r->args.len + 1, "&%V", &r->args);
        }
    } else {
        args = r->args;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "hls-subrequest: subrequest_handler| args %V, len = %d",
                   &args, args.len);

    rc = ngx_http_subrequest(r, &sub_location, &args,
                            &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_DONE;
}

