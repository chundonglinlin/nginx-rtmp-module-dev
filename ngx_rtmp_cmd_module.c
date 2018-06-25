
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_oclp_module.h"
#include "ngx_rtmp_streams.h"
#include "ngx_stream_zone_module.h"
#include "ngx_dynamic_conf.h"
#include "ngx_toolkit_misc.h"
#include "ngx_rtmp_dynamic.h"


#define NGX_RTMP_FMS_VERSION        "FMS/3,0,1,123"
#define NGX_RTMP_CAPABILITIES       31


static ngx_int_t ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s,
       ngx_rtmp_connect_t *v);
static ngx_int_t ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_create_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_close_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_close_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_delete_stream(ngx_rtmp_session_t *s,
       ngx_rtmp_delete_stream_t *v);
static ngx_int_t ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s,
       ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_cmd_play(ngx_rtmp_session_t *s,
       ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_cmd_seek(ngx_rtmp_session_t *s,
       ngx_rtmp_seek_t *v);
static ngx_int_t ngx_rtmp_cmd_pause(ngx_rtmp_session_t *s,
       ngx_rtmp_pause_t *v);


static ngx_int_t ngx_rtmp_cmd_stream_begin(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_begin_t *v);
static ngx_int_t ngx_rtmp_cmd_stream_eof(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_eof_t *v);
static ngx_int_t ngx_rtmp_cmd_stream_dry(ngx_rtmp_session_t *s,
       ngx_rtmp_stream_dry_t *v);
static ngx_int_t ngx_rtmp_cmd_recorded(ngx_rtmp_session_t *s,
       ngx_rtmp_recorded_t *v);
static ngx_int_t ngx_rtmp_cmd_set_buflen(ngx_rtmp_session_t *s,
       ngx_rtmp_set_buflen_t *v);


ngx_rtmp_connect_pt         ngx_rtmp_connect;
ngx_rtmp_disconnect_pt      ngx_rtmp_disconnect;
ngx_rtmp_create_stream_pt   ngx_rtmp_create_stream;
ngx_rtmp_close_stream_pt    ngx_rtmp_close_stream;
ngx_rtmp_delete_stream_pt   ngx_rtmp_delete_stream;
ngx_rtmp_publish_pt         ngx_rtmp_publish;
ngx_rtmp_play_pt            ngx_rtmp_play;
ngx_rtmp_seek_pt            ngx_rtmp_seek;
ngx_rtmp_pause_pt           ngx_rtmp_pause;


ngx_rtmp_stream_begin_pt    ngx_rtmp_stream_begin;
ngx_rtmp_stream_eof_pt      ngx_rtmp_stream_eof;
ngx_rtmp_stream_dry_pt      ngx_rtmp_stream_dry;
ngx_rtmp_recorded_pt        ngx_rtmp_recorded;
ngx_rtmp_set_buflen_pt      ngx_rtmp_set_buflen;


ngx_rtmp_pull_pt            ngx_rtmp_pull;
ngx_rtmp_push_pt            ngx_rtmp_push;


static ngx_int_t ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf);


static ngx_rtmp_module_t  ngx_rtmp_cmd_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_cmd_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    NULL,                                   /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_cmd_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_cmd_module_ctx,               /* module context */
    NULL,                                   /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


void
ngx_rtmp_cmd_fill_args(u_char name[NGX_RTMP_MAX_NAME],
        u_char args[NGX_RTMP_MAX_ARGS])
{
    u_char      *p;

    p = (u_char *)ngx_strchr(name, '?');
    if (p == NULL) {
        return;
    }

    *p++ = 0;
    ngx_cpystrn(args, p, NGX_RTMP_MAX_ARGS);
}

void
ngx_rtmp_cmd_reset_vhost(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_request_url_t           ru;
    ngx_str_t                   tcurl;
    char                       *p;

    tcurl.data = v->tc_url;
    tcurl.len = ngx_strlen(v->tc_url);

    if (ngx_parse_request_url(&ru, &tcurl) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "tcurl error, %s", v->tc_url);
        return;
    }

    if (ngx_inet_addr(ru.host.data, ru.host.len) == INADDR_NONE) {
        /* domain is not ip */
        return;
    }

    p = ngx_strstr(v->app, "/");
    if (p == NULL) { /* app only has one level */
        return;
    }

    /* use first level of app as domain, the rest as app */
    *ngx_snprintf(v->tc_url, NGX_RTMP_MAX_URL, "rtmp://%s", v->app) = 0;
    *ngx_snprintf(v->app, NGX_RTMP_MAX_NAME, "%s", p + 1) = 0;
}

void
ngx_rtmp_cmd_middleware_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_dconf_t  *rcsdf;
    ngx_request_url_t           rurl;

    if (ngx_parse_request_url(&rurl, &s->tc_url) == NGX_ERROR) {
        return;
    }

    s->scheme = rurl.scheme;
    s->domain = rurl.host;

    rcsdf = ngx_rtmp_get_module_srv_dconf(s, &ngx_rtmp_core_module);
    if (rcsdf && rcsdf->serverid.len) {
        s->serverid.data = ngx_pcalloc(s->connection->pool,
                                       rcsdf->serverid.len);
        if (s->serverid.data == NULL) {
            return;
        }
        s->serverid.len = rcsdf->serverid.len;
        ngx_memcpy(s->serverid.data, rcsdf->serverid.data, s->serverid.len);
    } else {
        s->serverid = s->domain;
    }
}

ngx_int_t
ngx_rtmp_cmd_stream_init(ngx_rtmp_session_t *s, u_char *name, u_char *args,
        unsigned publishing)
{
    u_char                     *p;
    ngx_str_t                   str;
    ngx_int_t                   rc;

    if (s->name.len == 0) {
        s->name.len = ngx_strlen(name);
        s->name.data = ngx_palloc(s->connection->pool, s->name.len);
        ngx_memcpy(s->name.data, name, s->name.len);
    }

    if (s->pargs.len == 0) {
        s->pargs.len = ngx_strlen(args);
        s->pargs.data = ngx_palloc(s->connection->pool, s->pargs.len);
        ngx_memcpy(s->pargs.data, args, s->pargs.len);
    }

    if (s->stream.len == 0) {
        /* serverid/app/name */
        s->stream.len = s->serverid.len + 1 + s->app.len + 1 + s->name.len;
        s->stream.data = ngx_palloc(s->connection->pool, s->stream.len);
        p = s->stream.data;

        p = ngx_copy(p, s->serverid.data, s->serverid.len);
        *p++ = '/';
        p = ngx_copy(p, s->app.data, s->app.len);
        *p++ = '/';
        p = ngx_copy(p, s->name.data, s->name.len);
    }

    if(publishing && ngx_rtmp_arg(s, (u_char *) "genid", sizeof("genid") - 1,
                         &str) == NGX_OK)
    {
        s->priority = ngx_atoi(str.data, str.len);
    }

    rc = ngx_live_handle_priority_stream(s, publishing, s->priority);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {
        s->live_stream = ngx_live_create_stream(&s->serverid, &s->stream);
        ngx_live_create_ctx(s, publishing);
    }

    s->publishing = publishing;

    ngx_rtmp_oclp_stream_start(s);

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_publish_filter(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_relay_reconnect_t      *rc;
    ngx_rtmp_relay_ctx_t       *ctx;

    if (s->published) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "session has been published");
        return NGX_OK;
    }

    s->published = 1;

    if (s->relay) { /* relay pull */
        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
        ctx->relay_completion = 1;

        rc = s->live_stream->pull_reconnect;
        ngx_live_put_relay_reconnect(rc);
        s->live_stream->pull_reconnect = NULL;
    } else {
        if (ngx_rtmp_cmd_stream_init(s, v->name, v->args, 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "publish: name='%V' pargs='%V' app='%V' args='%V' flashver='%V' "
            "swf_url='%V' tc_url='%V' page_url='%V' acodecs=%uD vcodecs=%uD "
            "scheme='%V' domain='%V' serverid='%V' stream='%V'",
            &s->name, &s->pargs, &s->app, &s->args, &s->flashver,
            &s->swf_url, &s->tc_url, &s->page_url, s->acodecs, s->vcodecs,
            &s->scheme, &s->domain, &s->serverid, &s->stream);

    ngx_rtmp_oclp_pnotify_start(s, NGX_RTMP_OCLP_PUBLISH_NOTIFY);

    return ngx_rtmp_publish(s, v);
}

ngx_int_t
ngx_rtmp_play_filter(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;

    if (s->played) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "session has been played");
        return NGX_OK;
    }

    s->played = 1;

    if (s->relay) { /* relay push */
        ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
        ctx->relay_completion = 1;

        --s->live_stream->push_count;
    } else {
        ngx_rtmp_cmd_stream_init(s, v->name, v->args, 0);
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "play: name='%V' pargs='%V' app='%V' args='%V' flashver='%V' "
            "swf_url='%V' tc_url='%V' page_url='%V' acodecs=%uD vcodecs=%uD "
            "scheme='%V' domain='%V' serverid='%V' stream='%V'",
            &s->name, &s->pargs, &s->app, &s->args, &s->flashver,
            &s->swf_url, &s->tc_url, &s->page_url, s->acodecs, s->vcodecs,
            &s->scheme, &s->domain, &s->serverid, &s->stream);

    ngx_rtmp_oclp_pnotify_start(s, NGX_RTMP_OCLP_PLAY_NOTIFY);

    return ngx_rtmp_play(s, v);
}

ngx_int_t
ngx_rtmp_close_stream_filter(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v)
{
    if (s->closed) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "session has been closed");
        return NGX_OK;
    }

    s->closed = 1;

    ngx_rtmp_oclp_pnotify_done(s);

    return ngx_rtmp_close_stream(s, v);
}

static void
ngx_rtmp_pull_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_session_t         *s;
    ngx_live_stream_t          *st;
    ngx_relay_reconnect_t      *rc;

    rc = ev->data;
    st = rc->live_stream;
    ngx_live_put_relay_reconnect(rc);
    st->pull_reconnect = NULL;
    st->pull_relay = 0;

    if (st->publish_ctx) {
        ngx_rtmp_finalize_session(st->publish_ctx->session);
        st->publish_ctx = NULL;
        st->pslot = -1;
    }

    if (st->play_ctx == NULL) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "pull reconnect, all players closed");
        return;
    }

    s = st->play_ctx->session;
    ngx_rtmp_pull_filter(s);
}

static void
ngx_rtmp_push_reconnect(ngx_event_t *ev)
{
    ngx_rtmp_session_t         *s;
    ngx_live_stream_t          *st;
    ngx_relay_reconnect_t      *rc;

    rc = ev->data;
    st = rc->live_stream;
    ngx_live_put_relay_reconnect(rc);
    st->push_reconnect = NULL;

    if (st->publish_ctx == NULL) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                "push reconnect, all publishers closed");
        return;
    }

    s = st->publish_ctx->session;
    ngx_rtmp_push_filter(s);
}

ngx_int_t
ngx_rtmp_push_filter(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_live_stream_t          *st;
    ngx_relay_reconnect_t      *reconnect;
    ngx_int_t                   rc;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "rtmp push filter");

    rc = ngx_rtmp_push(s);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    st = s->live_stream;

    if (st->push_count) {
        cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

        reconnect = st->push_reconnect;
        if (reconnect) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "relay push reconnect exist %p", reconnect);
            ngx_live_put_relay_reconnect(reconnect);
        }

        reconnect = ngx_live_get_relay_reconnect();
        st->push_reconnect = reconnect;

        reconnect->live_stream = st;
        reconnect->reconnect.data = reconnect;
        reconnect->reconnect.log = ngx_cycle->log;
        reconnect->reconnect.handler = ngx_rtmp_push_reconnect;

        ngx_add_timer(&reconnect->reconnect, cacf->push_reconnect);

        return NGX_AGAIN;
    }

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_pull_filter(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_live_stream_t          *st;
    ngx_relay_reconnect_t      *reconnect;
    ngx_int_t                   rc;

    if (s->live_stream->publish_ctx || s->live_stream->pull_relay) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, "rtmp pull filter");

    rc = ngx_rtmp_pull(s);

    if (rc == NGX_AGAIN) {
        cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

        st = s->live_stream;
        reconnect = st->pull_reconnect;
        if (reconnect) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "relay pull reconnect exist %p", reconnect);
            ngx_live_put_relay_reconnect(reconnect);
        }

        reconnect = ngx_live_get_relay_reconnect();
        st->pull_reconnect = reconnect;

        reconnect->live_stream = st;
        reconnect->reconnect.data = reconnect;
        reconnect->reconnect.log = ngx_cycle->log;
        reconnect->reconnect.handler = ngx_rtmp_pull_reconnect;

        ngx_add_timer(&reconnect->reconnect, cacf->pull_reconnect);
    }

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                "ngx rtmp pull failed");
    }

    return rc;
}

static ngx_int_t
ngx_rtmp_cmd_connect_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    size_t                      len;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_core_app_conf_t  **cacfp;
    ngx_uint_t                  n;
    u_char                     *p;

    static ngx_rtmp_connect_t   v;

    static ngx_rtmp_amf_elt_t  in_cmd[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("app"),
          v.app, sizeof(v.app) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("flashVer"),
          v.flashver, sizeof(v.flashver) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          v.swf_url, sizeof(v.swf_url) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          v.tc_url, sizeof(v.tc_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          &v.acodecs, sizeof(v.acodecs) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          &v.vcodecs, sizeof(v.vcodecs) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          v.page_url, sizeof(v.page_url) },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &v.object_encoding, 0},
    };

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_cmd, sizeof(in_cmd) },
    };

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    len = ngx_strlen(v.app);
    if (len > 10 && !ngx_memcmp(v.app + len - 10, "/_definst_", 10)) {
        v.app[len - 10] = 0;
    } else if (len && v.app[len - 1] == '/') {
        v.app[len - 1] = 0;
    }

    ngx_rtmp_cmd_fill_args(v.app, v.args);
    ngx_rtmp_cmd_reset_vhost(s, &v);

    ngx_log_error(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "connect: app='%s' args='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
            "object_encoding=%ui",
            v.app, v.args, v.flashver, v.swf_url, v.tc_url, v.page_url,
            (uint32_t)v.acodecs, (uint32_t)v.vcodecs,
            (ngx_int_t)v.object_encoding);

#define NGX_RTMP_SET_STRPAR(name)                                             \
    s->name.len = ngx_strlen(v.name);                                        \
    s->name.data = ngx_palloc(s->connection->pool, s->name.len);              \
    ngx_memcpy(s->name.data, v.name, s->name.len)

    NGX_RTMP_SET_STRPAR(app);
    NGX_RTMP_SET_STRPAR(args);
    NGX_RTMP_SET_STRPAR(flashver);
    NGX_RTMP_SET_STRPAR(swf_url);
    NGX_RTMP_SET_STRPAR(tc_url);
    NGX_RTMP_SET_STRPAR(page_url);

#undef NGX_RTMP_SET_STRPAR

    p = ngx_strlchr(s->app.data, s->app.data + s->app.len, '?');
    if (p) {
        s->app.len = (p - s->app.data);
    }

    s->acodecs = (uint32_t) v.acodecs;
    s->vcodecs = (uint32_t) v.vcodecs;

    ngx_rtmp_cmd_middleware_init(s);

    if (ngx_rtmp_set_virtual_server(s, &s->domain)) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp connect, set vhost for \"%V\" failed", &s->domain);
        return NGX_ERROR;
    }
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    /* find application & set app_conf */
    cacfp = cscf->applications.elts;
    for(n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == s->app.len &&
            ngx_strncmp((*cacfp)->name.data, s->app.data, s->app.len) == 0)
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {

        if (cscf->org_app != NULL &&
            cscf->org_app->app_conf != NULL &&
            ngx_strncasecmp(s->app.data + s->app.len - sizeof("_org") + 1,
                            (u_char *)"_org", sizeof("_org") - 1) == 0)
        {
            s->app_conf = cscf->org_app->app_conf;
        }
    }

    if (s->app_conf == NULL) {

        if (cscf->default_app == NULL || cscf->default_app->app_conf == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "connect: application not found: '%V'", &s->app);
            return NGX_ERROR;
        }

        s->app_conf = cscf->default_app->app_conf;
    }

    s->live_server = ngx_live_create_server(&s->serverid);

    return ngx_rtmp_connect(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t           h;

    static double               trans;
    static double               capabilities = NGX_RTMP_CAPABILITIES;
    static double               object_encoding = 0;

    static ngx_rtmp_amf_elt_t  out_obj[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("fmsVer"),
          NGX_RTMP_FMS_VERSION, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("capabilities"),
          &capabilities, 0 },
    };

    static ngx_rtmp_amf_elt_t  out_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          "status", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          "NetConnection.Connect.Success", 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          "Connection succeeded.", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("objectEncoding"),
          &object_encoding, 0 }
    };

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_obj, sizeof(out_obj) },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_inf, sizeof(out_inf) },
    };

    if (s->connected) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "connect: duplicate connection");
        return NGX_ERROR;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    trans = v->trans;

    /* fill session parameters */
    s->connected = 1;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    object_encoding = v->object_encoding;

    return ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK ||
           ngx_rtmp_send_bandwidth(s, cscf->ack_window,
                                   NGX_RTMP_LIMIT_DYNAMIC) != NGX_OK ||
           ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK ||
           ngx_rtmp_send_amf(s, &h, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0]))
           != NGX_OK ? NGX_ERROR : NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_create_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                                ngx_chain_t *in)
{
    static ngx_rtmp_create_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, sizeof(v.trans) },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "createStream");

    return ngx_rtmp_create_stream(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_create_stream(ngx_rtmp_session_t *s, ngx_rtmp_create_stream_t *v)
{
    /* support one message stream per connection */
    static double               stream;
    static double               trans;
    ngx_rtmp_header_t           h;

    static ngx_rtmp_amf_elt_t  out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "_result", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &stream, sizeof(stream) },
    };

    trans = v->trans;
    stream = NGX_RTMP_MSID;

    ngx_memzero(&h, sizeof(h));

    h.csid = NGX_RTMP_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
                             sizeof(out_elts) / sizeof(out_elts[0])) == NGX_OK ?
           NGX_DONE : NGX_ERROR;
}


static ngx_int_t
ngx_rtmp_cmd_close_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                               ngx_chain_t *in)
{
    static ngx_rtmp_close_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_close_stream_filter(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_core_ctx_t                *ctx;
    ngx_live_stream_t                  *st;
    ngx_relay_reconnect_t              *reconnect;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "closeStream");

    if (s->live_stream == NULL) { /* stream before publish or play status */
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_core_module);

    /* reconnect */
    st = ngx_live_fetch_stream(&s->serverid, &s->stream);
    if (st == NULL) {
        goto next;
    }

    /* push and pull reconnect */
    if (ctx->publishing) { /* relay pull */
        if (st->publish_ctx && (st->publish_ctx->session != s
                            || st->publish_ctx->next))
        {
            goto next;
        }

        if (st->play_ctx == NULL) {
            goto next;
        }

        /* set reconnect pull */
        st = s->live_stream;
        reconnect = st->pull_reconnect;
        if (reconnect) {
            goto next;
        }

        reconnect = ngx_live_get_relay_reconnect();
        st->pull_reconnect = reconnect;
        st->pslot = -1;

        reconnect->live_stream = st;
        reconnect->reconnect.data = reconnect;
        reconnect->reconnect.log = ngx_cycle->log;
        reconnect->reconnect.handler = ngx_rtmp_pull_reconnect;

        ngx_post_event(&reconnect->reconnect, &ngx_posted_events);
    } else { /* relay push */
        if (s->relay == 0) { /* not relay pull session */
            goto next;
        }

        if (st->publish_ctx == NULL) {
            goto next;
        }

        /* set reconnect push */
        st = s->live_stream;
        reconnect = st->push_reconnect;
        if (reconnect) {
            goto next;
        }

        reconnect = ngx_live_get_relay_reconnect();
        st->push_reconnect = reconnect;

        reconnect->live_stream = st;
        reconnect->reconnect.data = reconnect;
        reconnect->reconnect.log = ngx_cycle->log;
        reconnect->reconnect.handler = ngx_rtmp_push_reconnect;

        ngx_post_event(&reconnect->reconnect, &ngx_posted_events);
    }

next:
    ngx_live_delete_ctx(s);
    if (s->live_stream && s->live_stream->play_ctx == NULL
            && s->live_stream->publish_ctx == NULL)
    {
        if (s->live_stream->pslot == ngx_process_slot) {
            ngx_stream_zone_delete_stream(&s->stream);
        }
        ngx_rtmp_oclp_stream_done(s);
        ngx_live_delete_stream(&s->serverid, &s->stream);
    }

    if (s->live_stream->play_ctx == NULL) {
        /* all players close, close relay publish */
        for (ctx = s->live_stream->publish_ctx; ctx; ctx = ctx->next) {
            if (ctx->session->relay) {
                ngx_rtmp_finalize_session(ctx->session);
            }
        }
    }

    if (s->live_stream->publish_ctx == NULL) {
        /* all publishers close, close relay play */
        for (ctx = s->live_stream->play_ctx; ctx; ctx = ctx->next) {
            if (ctx->session->relay) {
                ngx_rtmp_finalize_session(ctx->session);
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                                ngx_chain_t *in)
{
    static ngx_rtmp_delete_stream_t     v;

    static ngx_rtmp_amf_elt_t  in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.stream, 0 },
    };

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    return ngx_rtmp_delete_stream(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_delete_stream(ngx_rtmp_session_t *s, ngx_rtmp_delete_stream_t *v)
{
    ngx_rtmp_close_stream_t         cv;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0, "deleteStream");

    cv.stream = 0;

    return ngx_rtmp_close_stream_filter(s, &cv);
}


static ngx_int_t
ngx_rtmp_cmd_publish_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_publish_t       v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.type, sizeof(v.type) },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "publish: name='%s' args='%s' type=%s silent=%d",
                   v.name, v.args, v.type, v.silent);

    return ngx_rtmp_publish_filter(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    return NGX_OK;
}


static void
ngx_rtmp_cmd_filter_init(ngx_rtmp_session_t *s,const u_char *args)
{
    ngx_rtmp_core_app_conf_t   *cacf;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    if (cacf->media_filter == 0 || args == NULL) {
        return;
    }

    if(s->connection && s->connection->sockaddr->sa_family == AF_UNIX){
        return;
    }

    if(ngx_strstr(args, (const char *)"only-audio=1") != NULL) {
        s->filter |=  NGX_RTMP_FILTER_KEEPAUDIO;
    }
}


static ngx_int_t
ngx_rtmp_cmd_play_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t          v;

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          &v.name, sizeof(v.name) },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.start, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.duration, 0 },

        { NGX_RTMP_AMF_OPTIONAL | NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.reset, 0 }
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    ngx_log_debug6(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play: name='%s' args='%s' start=%i duration=%i "
                   "reset=%i silent=%i",
                   v.name, v.args, (ngx_int_t) v.start,
                   (ngx_int_t) v.duration, (ngx_int_t) v.reset,
                   (ngx_int_t) v.silent);

    ngx_rtmp_cmd_filter_init(s, v.args);

    return ngx_rtmp_play_filter(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_play2_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_play_t          v;
    static ngx_rtmp_close_stream_t  vc;

    static ngx_rtmp_amf_elt_t       in_obj[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("start"),
          &v.start, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_string("streamName"),
          &v.name, sizeof(v.name) },
    };

    static ngx_rtmp_amf_elt_t       in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          &in_obj, sizeof(in_obj) }
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_fill_args(v.name, v.args);

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "play2: name='%s' args='%s' start=%i",
                   v.name, v.args, (ngx_int_t) v.start);

    /* continue from current timestamp */

    if (v.start < 0) {
        v.start = s->current_time;
    }

    ngx_memzero(&vc, sizeof(vc));

    /* close_stream should be synchronous */
    ngx_rtmp_close_stream_filter(s, &vc);

    return ngx_rtmp_play_filter(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_pause_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_pause_t     v;

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_BOOLEAN,
          ngx_null_string,
          &v.pause, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.position, 0 },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "pause: pause=%i position=%i",
                    (ngx_int_t) v.pause, (ngx_int_t) v.position);

    return ngx_rtmp_pause(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_pause(ngx_rtmp_session_t *s, ngx_rtmp_pause_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_disconnect_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
                        ngx_chain_t *in)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0, "disconnect");

    return ngx_rtmp_disconnect(s);
}


static ngx_int_t
ngx_rtmp_cmd_disconnect(ngx_rtmp_session_t *s)
{
    return ngx_rtmp_delete_stream(s, NULL);
}


static ngx_int_t
ngx_rtmp_cmd_seek_init(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    static ngx_rtmp_seek_t         v;

    static ngx_rtmp_amf_elt_t      in_elts[] = {

        /* transaction is always 0 */
        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.offset, sizeof(v.offset) },
    };

    ngx_memzero(&v, sizeof(v));

    if (ngx_rtmp_receive_amf(s, in, in_elts,
                             sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "seek: offset=%i", (ngx_int_t) v.offset);

    return ngx_rtmp_seek(s, &v);
}


static ngx_int_t
ngx_rtmp_cmd_seek(ngx_rtmp_session_t *s, ngx_rtmp_seek_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_stream_dry(ngx_rtmp_session_t *s, ngx_rtmp_stream_dry_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_recorded(ngx_rtmp_session_t *s,
                      ngx_rtmp_recorded_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_set_buflen(ngx_rtmp_session_t *s, ngx_rtmp_set_buflen_t *v)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_push(ngx_rtmp_session_t *s)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_cmd_pull(ngx_rtmp_session_t *s)
{
    return NGX_OK;
}


static ngx_rtmp_amf_handler_t ngx_rtmp_cmd_map[] = {
    { ngx_string("connect"),            ngx_rtmp_cmd_connect_init           },
    { ngx_string("createStream"),       ngx_rtmp_cmd_create_stream_init     },
    { ngx_string("closeStream"),        ngx_rtmp_cmd_close_stream_init      },
    { ngx_string("deleteStream"),       ngx_rtmp_cmd_delete_stream_init     },
    { ngx_string("publish"),            ngx_rtmp_cmd_publish_init           },
    { ngx_string("play"),               ngx_rtmp_cmd_play_init              },
    { ngx_string("play2"),              ngx_rtmp_cmd_play2_init             },
    { ngx_string("seek"),               ngx_rtmp_cmd_seek_init              },
    { ngx_string("pause"),              ngx_rtmp_cmd_pause_init             },
    { ngx_string("pauseraw"),           ngx_rtmp_cmd_pause_init             },
};


static ngx_int_t
ngx_rtmp_cmd_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch, *bh;
    size_t                              n, ncalls;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    /* redirect disconnects to deleteStream
     * to free client modules from registering
     * disconnect callback */

    h = ngx_array_push(&cmcf->events[NGX_RTMP_DISCONNECT]);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_rtmp_cmd_disconnect_init;

    /* register AMF callbacks */

    ncalls = sizeof(ngx_rtmp_cmd_map) / sizeof(ngx_rtmp_cmd_map[0]);

    ch = ngx_array_push_n(&cmcf->amf, ncalls);
    if (ch == NULL) {
        return NGX_ERROR;
    }

    bh = ngx_rtmp_cmd_map;

    for(n = 0; n < ncalls; ++n, ++ch, ++bh) {
        *ch = *bh;
    }

    ngx_rtmp_connect = ngx_rtmp_cmd_connect;
    ngx_rtmp_disconnect = ngx_rtmp_cmd_disconnect;
    ngx_rtmp_create_stream = ngx_rtmp_cmd_create_stream;
    ngx_rtmp_close_stream = ngx_rtmp_cmd_close_stream;
    ngx_rtmp_delete_stream = ngx_rtmp_cmd_delete_stream;
    ngx_rtmp_publish = ngx_rtmp_cmd_publish;
    ngx_rtmp_play = ngx_rtmp_cmd_play;
    ngx_rtmp_seek = ngx_rtmp_cmd_seek;
    ngx_rtmp_pause = ngx_rtmp_cmd_pause;

    ngx_rtmp_stream_begin = ngx_rtmp_cmd_stream_begin;
    ngx_rtmp_stream_eof = ngx_rtmp_cmd_stream_eof;
    ngx_rtmp_stream_dry = ngx_rtmp_cmd_stream_dry;
    ngx_rtmp_recorded = ngx_rtmp_cmd_recorded;
    ngx_rtmp_set_buflen = ngx_rtmp_cmd_set_buflen;

    ngx_rtmp_push = ngx_rtmp_cmd_push;
    ngx_rtmp_pull = ngx_rtmp_cmd_pull;

    return NGX_OK;
}
