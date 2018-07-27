/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rbuf.h"
#include "ngx_http_set_header.h"
#include "ngx_rtmp_monitor_module.h"


static char *ngx_http_flv_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_flv_add_variables(ngx_conf_t *cf);
static void *ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf, void *parent,
       void *child);

static ngx_int_t ngx_http_flv_request_location(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_flv_request_stream(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data);

static u_char  ngx_flv_live_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";
static u_char  ngx_flv_live_audio_header[] = "FLV\x1\x4\0\0\0\x9\0\0\0\0";

static ngx_keyval_t ngx_http_flv_live_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("video/x-flv") },
    { ngx_null_string, ngx_null_string }
};

#define NGX_FLV_TAG_SIZE        11
#define NGX_FLV_PTS_SIZE        4

typedef struct {
    ngx_rtmp_session_t         *session;
} ngx_http_flv_live_ctx_t;

typedef struct {
    ngx_str_t                   app;
    ngx_str_t                   flashver;
    ngx_str_t                   swf_url;
    ngx_str_t                   tc_url;
    ngx_str_t                   page_url;
    ngx_flag_t                  media_filter;

    ngx_listening_t            *ls;
} ngx_http_flv_live_loc_conf_t;


static ngx_command_t  ngx_http_flv_live_commands[] = {

    { ngx_string("flv_live"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_flv_live,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("media_filter"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_live_loc_conf_t, media_filter),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flv_live_module_ctx = {
    ngx_http_flv_add_variables,         /* preconfiguration */
    NULL,                               /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_flv_live_create_loc_conf,  /* create location configuration */
    ngx_http_flv_live_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_flv_live_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_live_module_ctx,      /* module context */
    ngx_http_flv_live_commands,         /* module directives */
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


static ngx_http_variable_t  ngx_http_flv_vars[] = {

    { ngx_string("flv_location"), NULL,
      ngx_http_flv_request_location, 0, 0, 0 },

    { ngx_string("stream_name"), NULL,
      ngx_http_flv_request_stream, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_flv_request_location(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char               *pos, *last, *p;

    pos = r->uri.data;
    last = r->uri.len + pos;

    for (p = last -1; p > pos; --p) {
        if (*p == '/') {
            break;
        }

        if (p == pos) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - (pos + 1);
    v->data = pos + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_request_stream(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char               *pos, *last, *p;

    pos = r->uri.data;
    last = r->uri.len + pos;

    for (p = last -1; p > pos; --p) {
        if (*p == '/') {
            break;
        }

        if (p == pos) {
            v->not_found = 1;
            return NGX_OK;
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = last - 1 - p;
    v->data = p + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_flv_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_live_send_header(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_keyval_t                       *h;

    r->headers_out.status = NGX_HTTP_OK;
    r->keepalive = 0; /* set Connection to closed */

    h = ngx_http_flv_live_headers;
    while (h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
}

static ngx_chain_t *
ngx_http_flv_live_prepare_out_chain(ngx_http_request_t *r,
        ngx_rtmp_session_t *s)
{
    ngx_rtmp_frame_t                   *frame;
    ngx_chain_t                        *head, **ll, *cl;
    u_char                             *p;
    size_t                              datasize, prev_tag_size;
    ngx_int_t                           rc;
    uint32_t                            timestamp;

    frame = NULL;
    head = NULL;
    datasize = 0;

    while (s->out_pos != s->out_last) {
        frame = s->out[s->out_pos];
        if ((frame->hdr.type != NGX_RTMP_MSG_VIDEO
                && frame->hdr.type != NGX_RTMP_MSG_AUDIO
                && frame->hdr.type != NGX_RTMP_MSG_AMF_META
                && frame->hdr.type != NGX_RTMP_MSG_AMF3_META) ||
            (frame->hdr.type == NGX_RTMP_MSG_VIDEO
                && s->filter == NGX_RTMP_FILTER_KEEPAUDIO))
        {
            ngx_rtmp_shared_free_frame(frame);
            ++s->out_pos;
            s->out_pos %= s->out_queue;
            frame = NULL;

            continue;
        }
        break;
    }

    /* no frame to send */
    if (frame == NULL) {
        return NULL;
    }

    /* fix timestamp */
    timestamp = frame->hdr.timestamp;
    timestamp = ngx_rtmp_timestamp_fix(s, timestamp, 0);

    /* first send */
    if (!r->header_sent) {
        rc = ngx_http_flv_live_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return NULL;
        }

        /* flv header */
        head = ngx_get_chainbuf(0, 0);
        if (head == NULL) {
            return NULL;
        }
        if (s->filter == NGX_RTMP_FILTER_KEEPAUDIO) {
            head->buf->pos = ngx_flv_live_audio_header;
            head->buf->last = ngx_flv_live_audio_header
                                  + sizeof(ngx_flv_live_audio_header) - 1;
        } else {
            head->buf->pos = ngx_flv_live_header;
            head->buf->last = ngx_flv_live_header
                                  + sizeof(ngx_flv_live_header) - 1;
        }
    }

    for (ll = &head; *ll; ll = &(*ll)->next);

    for (cl = frame->chain; cl; cl = cl->next) {
        datasize += (cl->buf->last - cl->buf->pos);
    }
    prev_tag_size = datasize + NGX_FLV_TAG_SIZE;

    /* flv tag header */
    *ll = ngx_get_chainbuf(NGX_FLV_TAG_SIZE, 1);
    if (*ll == NULL) {
        goto falied;
    }
    p = (*ll)->buf->pos;

    /* TagType 1 byte */
    *p++ = frame->hdr.type;

    /* DataSize 3 bytes */
    *p++ = ((u_char *) &datasize)[2];
    *p++ = ((u_char *) &datasize)[1];
    *p++ = ((u_char *) &datasize)[0];

    /* Timestamp 4 bytes */
    *p++ = ((u_char *) &timestamp)[2];
    *p++ = ((u_char *) &timestamp)[1];
    *p++ = ((u_char *) &timestamp)[0];
    *p++ = ((u_char *) &timestamp)[3];

    /* StreamID 4 bytes, always set to 0 */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    (*ll)->buf->last = p;
    ll = &(*ll)->next;

    /* flv payload */
    for (cl = frame->chain; cl; cl = cl->next) {
        (*ll) = ngx_get_chainbuf(0, 0);
        if (*ll == NULL) {
            goto falied;
        }
        (*ll)->buf->pos = cl->buf->pos;
        (*ll)->buf->last = cl->buf->last;
        ll = &(*ll)->next;
    }

    /* flv previous tag size */
    *ll = ngx_get_chainbuf(NGX_FLV_PTS_SIZE, 1);
    if (*ll == NULL) {
        goto falied;
    }
    p = (*ll)->buf->pos;

    *p++ = ((u_char *) &prev_tag_size)[3];
    *p++ = ((u_char *) &prev_tag_size)[2];
    *p++ = ((u_char *) &prev_tag_size)[1];
    *p++ = ((u_char *) &prev_tag_size)[0];

    (*ll)->buf->last = p;
    (*ll)->buf->flush = 1;

    ngx_rtmp_monitor_frame(s, &frame->hdr, NULL, frame->av_header, 0);

    return head;

falied:
    for (cl = head; cl; cl = cl->next) {
        head = cl->next;
        ngx_put_chainbuf(cl);
        cl = head;
    }

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);

    return NULL;
}

static void
ngx_http_flv_live_write_handler(ngx_http_request_t *r)
{
    ngx_http_flv_live_ctx_t            *ctx;
    ngx_rtmp_session_t                 *s;
    ngx_event_t                        *wev;
    size_t                              present, sent;
    ngx_int_t                           rc;
    ngx_chain_t                        *cl;

    wev = r->connection->write;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);
    if (ctx == NULL) {
        return;
    }

    s = ctx->session;

    if (r->connection->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                "http flv live, client timed out");
        r->connection->timedout = 1;
        if (r->header_sent) {
            ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
            ngx_http_run_posted_requests(r->connection);
        } else {
            r->error_page = 1;
            ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        }

        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (s->out_chain == NULL) {
        s->out_chain = ngx_http_flv_live_prepare_out_chain(r, s);
    }

    while (s->out_chain) {
        present = r->connection->sent;

        if (r->connection->buffered) {
            rc = ngx_http_output_filter(r, NULL);
        } else {
            rc = ngx_http_output_filter(r, s->out_chain);
        }

        sent = r->connection->sent - present;

        ngx_rtmp_update_bandwidth(&s->bw_out, sent);
        ngx_rtmp_update_bandwidth(s->out[s->out_pos]->hdr.type
                                  == NGX_RTMP_MSG_VIDEO ?
                                  &s->bw_video: &s->bw_audio, sent);
        ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, sent);

        if (rc == NGX_AGAIN) {
            ngx_add_timer(wev, s->timeout);
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http flv live, handle write event failed");
                ngx_http_finalize_request(r, NGX_ERROR);
            }
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "http flv live, send error");
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        /* NGX_OK */
        cl = s->out_chain;
        while (cl) {
            s->out_chain = cl->next;
            ngx_put_chainbuf(cl);
            cl = s->out_chain;
        }

        if (s->out[s->out_pos]->hdr.type == NGX_RTMP_MSG_VIDEO) {
            ngx_rtmp_update_frames(&s->framestat, 1);
        }

        ngx_rtmp_shared_free_frame(s->out[s->out_pos]);
        ++s->out_pos;
        s->out_pos %= s->out_queue;
        if (s->out_pos == s->out_last) {
            break;
        }

        s->out_chain = ngx_http_flv_live_prepare_out_chain(r, s);
    }

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }
}

static void
ngx_http_flv_live_send(ngx_event_t *wev)
{
    ngx_connection_t                   *c;
    ngx_http_request_t                 *r;
    ngx_http_flv_live_ctx_t            *ctx;

    c = wev->data;
    r = c->data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    if (ctx->session == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "http flv live module : ngx_http_flv_live_send | http request has been terminate");
        return;
    }

    ngx_http_flv_live_write_handler(r);

    ngx_http_run_posted_requests(c);
}

static void
ngx_http_flv_live_parse_url(ngx_http_request_t *r, ngx_str_t *app,
        ngx_str_t *name)
{
    u_char                             *p, *end;

    p = r->uri.data + 1; /* skip '/' */
    end = r->uri.data + r->uri.len;
    app->data = p;

    p = (u_char *) ngx_strnstr(p, "/", end - p);
    while (p) {
        name->data = p;
        p = (u_char *) ngx_strnstr(p + 1, "/", end - (p + 1));
    }

    if (name->data == NULL) {
        return;
    }

    app->len = name->data - app->data;

    ++name->data;
    name->len = end - name->data;
}

static ngx_int_t
ngx_http_flv_live_parse(ngx_http_request_t *r, ngx_rtmp_session_t *s,
        ngx_rtmp_play_t *v)
{
    ngx_http_flv_live_loc_conf_t       *hflcf;
    ngx_str_t                           app, stream, internal;
    size_t                              tcurl_len;
    u_char                             *p;

    hflcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_live_module);

    ngx_memzero(&app, sizeof(ngx_str_t));
    ngx_memzero(&stream, sizeof(ngx_str_t));

    ngx_http_flv_live_parse_url(r, &app, &stream);

    if (app.len == 0 ||
        stream.len == 0 ||
        app.len > NGX_RTMP_MAX_NAME - 1 ||
        stream.len > NGX_RTMP_MAX_NAME - 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http flv live, url error: %V", &r->uri);
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_arg(r, (u_char *) "dnzb_internal", sizeof("dnzb_internal") - 1,
                     &internal) == NGX_OK)
    {
        if (internal.len == sizeof("1") - 1 ||
            ngx_strncmp(internal.data, (u_char *)"1", internal.len) == 0)
        {
            s->back_source = 1;
        }
    }

    s->app = app;

    if (ngx_http_arg(r, (u_char *) "flashver", 8, &s->flashver) != NGX_OK) {
        s->flashver = hflcf->flashver;
    }

    /* tc_url */
#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        tcurl_len = sizeof("https://") - 1;
    } else
#endif
    {
        tcurl_len = sizeof("http://") - 1;
    }
    tcurl_len += r->headers_in.server.len + 1 + app.len;

    s->tc_url.len = tcurl_len;
    s->tc_url.data = ngx_pcalloc(r->pool, tcurl_len);
    if (s->tc_url.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = s->tc_url.data;

#if (NGX_HTTP_SSL)
    if (r->connection->ssl) {
        p = ngx_cpymem(p, "https://", sizeof("https://") - 1);
    } else
#endif
    {
        p = ngx_cpymem(p, "http://", sizeof("http://") - 1);
    }

    p = ngx_cpymem(p, r->headers_in.server.data, r->headers_in.server.len);
    *p++ = '/';
    p = ngx_cpymem(p, app.data, app.len);

    /* page_url */
    if (r->headers_in.referer) {
        s->page_url = r->headers_in.referer->value;
    } else {
        s->page_url = hflcf->page_url;
    }

    if (s->tc_url.len > NGX_RTMP_MAX_URL - 1 ||
        s->page_url.len > NGX_RTMP_MAX_URL - 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http flv live, bad session info");
        return NGX_HTTP_BAD_REQUEST;
    }

    s->acodecs = 0x0DF7;
    s->vcodecs = 0xFC;

    ngx_memcpy(v->name, stream.data, stream.len);

    if (r->args.len > NGX_RTMP_MAX_ARGS - 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http flv live, bad args info");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (r->args.len) {
        ngx_memcpy(v->args, r->args.data,
                ngx_min(r->args.len, NGX_RTMP_MAX_ARGS));
    }

    ngx_rtmp_cmd_middleware_init(s);

    return NGX_OK;
}

static void
ngx_http_flv_live_cleanup(void *data)
{
    ngx_http_request_t                 *r;
    ngx_http_flv_live_ctx_t            *ctx;

    r = data;

    ctx = ngx_http_get_module_ctx(r, ngx_http_flv_live_module);

    if (ctx == NULL) {
        return;
    }

    if (ctx->session) {
        if (ctx->session->close.posted) {
            ngx_delete_posted_event(&ctx->session->close);
        }
        ngx_rtmp_finalize_fake_session(ctx->session);
        ctx->session = NULL;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "http flv live, cleanup");
}


static void
ngx_http_flv_filter_init(ngx_rtmp_session_t *s, ngx_str_t *args,
        ngx_http_flv_live_loc_conf_t *hflcf)
{
    if (hflcf->media_filter == 0 || NULL == args) {
        return;
    }

    if (ngx_strnstr(args->data, "only-audio=1", args->len) != NULL) {
        s->filter |=  NGX_RTMP_FILTER_KEEPAUDIO;
    } 
}


static ngx_int_t
ngx_http_flv_live_handler(ngx_http_request_t *r)
{
    ngx_http_flv_live_loc_conf_t       *hflcf;
    ngx_http_flv_live_ctx_t            *ctx;
    ngx_rtmp_session_t                 *s;
    ngx_rtmp_play_t                     v;
    ngx_int_t                           rc;
    ngx_uint_t                          n;
    ngx_rtmp_addr_conf_t               *addr_conf;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_core_app_conf_t          **cacfp;
    ngx_http_cleanup_t                 *cln;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_flv_live_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_flv_live_module);

    /* cleanup handler */
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_http_flv_live_cleanup;
    cln->data = r;

    hflcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_live_module);

    addr_conf = ngx_rtmp_get_addr_conf_by_listening(hflcf->ls, r->connection);
    if (addr_conf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* create fake session */
    s = ngx_rtmp_init_fake_session(r->connection, addr_conf);
    if (s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_flv_filter_init(s, &r->args, hflcf);

    ctx->session = s;

    /* get host, app, stream name */
    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));
    rc = ngx_http_flv_live_parse(r, s, &v);
    if (rc != NGX_OK) {
        return rc;
    }

    if (hflcf->app.data && hflcf->app.len) {
        s->app = hflcf->app;
    }

    if (ngx_rtmp_set_virtual_server(s, &s->domain)) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->live_type = NGX_HTTP_FLV_LIVE;
    s->live_server = ngx_live_create_server(&s->serverid);
    s->handler = ngx_http_flv_live_send;
    s->request = r;

    v.silent = 1;

    cacfp = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == s->app.len &&
            ngx_strncmp((*cacfp)->name.data, s->app.data, s->app.len) == 0)
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {

        if (cscf->default_app == NULL || cscf->default_app->app_conf == NULL) {
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "http flv live, application not found '%V'", &s->app);
            return NGX_HTTP_NOT_FOUND;
        }

        s->app_conf = cscf->default_app->app_conf;
    }

    if (ngx_rtmp_play_filter(s, &v) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_add_timer(r->connection->write, s->timeout);

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_flv_live_write_handler;

    ++r->count;

    return NGX_DONE;
}


static void *
ngx_http_flv_live_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_flv_live_loc_conf_t       *hflcf;

    hflcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_live_loc_conf_t));
    if (hflcf == NULL) {
        return NULL;
    }

    hflcf->media_filter = NGX_CONF_UNSET;

    return hflcf;
}

static char *
ngx_http_flv_live_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_live_loc_conf_t       *prev = parent;
    ngx_http_flv_live_loc_conf_t       *conf = child;

    ngx_conf_merge_str_value(conf->app, prev->app, "");
    ngx_conf_merge_str_value(conf->flashver, prev->flashver, "");
    ngx_conf_merge_str_value(conf->swf_url, prev->swf_url, "");
    ngx_conf_merge_str_value(conf->tc_url, prev->tc_url, "");
    ngx_conf_merge_str_value(conf->page_url, prev->page_url, "");
    ngx_conf_merge_value(conf->media_filter, prev->media_filter, 1);

    return NGX_CONF_OK;
}

static char *
ngx_http_flv_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t           *clcf;
    ngx_http_flv_live_loc_conf_t       *hflcf;
    ngx_str_t                          *value;
    ngx_uint_t                          n;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_live_handler;

    hflcf = conf;

    value = cf->args->elts;

    hflcf->ls = ngx_rtmp_find_relation_port(cf->cycle, &value[1]);
    if (hflcf->ls == NULL) {
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

        PARSE_CONF_ARGS(hflcf, app);
        PARSE_CONF_ARGS(hflcf, flashver);
        PARSE_CONF_ARGS(hflcf, swf_url);
        PARSE_CONF_ARGS(hflcf, tc_url);
        PARSE_CONF_ARGS(hflcf, page_url);
#undef PARSE_CONF_ARGS

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"%V\" para not support", &value[n]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
