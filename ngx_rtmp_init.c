
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_proxy_protocol.h"
#include "ngx_http_client.h"
#include "ngx_rbuf.h"


static void ngx_rtmp_close_connection(ngx_connection_t *c);
static u_char * ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len);


static ngx_str_t *
ngx_rtmp_get_rand_str(ngx_connection_t *c,ngx_int_t begin, ngx_int_t end){
    ngx_int_t          code;
    ngx_str_t         *rand_str;
    time_t             t;
    ngx_int_t          dis,pos;

    rand_str = ngx_pcalloc(c->pool, sizeof(ngx_str_t));
    rand_str->data = ngx_pcalloc(c->pool, 64);

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
ngx_rtmp_get_sessionid(ngx_connection_t *c)
{
    ngx_str_t            addr_text;
    time_t               now;
    ngx_tm_t             tm;
    ngx_str_t           *sessionid;
    u_char               buf[128];
    char                 time_buf[64];
    ngx_str_t           *rand_str;

    if(c == NULL) {
        return NULL;
    }

    ngx_memzero(buf, 128);
    ngx_memzero(time_buf, 64);

    /* generate random number in [10:99] */
    rand_str = ngx_rtmp_get_rand_str(c,10,99);

    addr_text = c->addr_text;
    
    now = ngx_time();
    ngx_localtime(now, &tm);
    strftime(time_buf, 64, "%Y%m%d%H%M%S", &tm);

    *ngx_snprintf(buf, sizeof(buf) - 1, "%V-%s-%V-%dp-%uDc",
                  &addr_text, time_buf, rand_str, ngx_process_slot, c->number) = 0;

    sessionid = ngx_pcalloc(c->pool, sizeof(ngx_str_t));
    sessionid->len = ngx_strlen(buf);
    sessionid->data = ngx_pcalloc(c->pool, sessionid->len);
    ngx_memcpy(sessionid->data, buf, sessionid->len);
    return sessionid;
};


void
ngx_rtmp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t             i;
    ngx_rtmp_port_t       *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_rtmp_in_addr_t    *addr;
    ngx_rtmp_session_t    *s;
    ngx_rtmp_addr_conf_t  *addr_conf;
    ngx_int_t              unix_socket;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_rtmp_in6_addr_t   *addr6;
#endif

    ++ngx_rtmp_naccepted;

    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;
    unix_socket = 0;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_rtmp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        case AF_UNIX:
            unix_socket = 1;

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client connected '%V'",
                  c->number, &c->addr_text);

    s = ngx_rtmp_init_session(c, addr_conf);
    if (s == NULL) {
        return;
    }

    /* only auto-pushed connections are
     * done through unix socket */

    s->interprocess = unix_socket;

    if (addr_conf->proxy_protocol) {
        ngx_rtmp_proxy_protocol(s);

    } else {
        ngx_rtmp_handshake(s);
    }
}


ngx_rtmp_session_t *
ngx_rtmp_init_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_main_conf_t      *cmcf;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
            sizeof(ngx_rtmp_frame_t *) * ((ngx_rtmp_core_srv_conf_t *)
                addr_conf->default_server->ctx-> srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    s->addr_conf = addr_conf;

    s->main_conf = addr_conf->default_server->ctx->main_conf;
    s->srv_conf = addr_conf->default_server->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    s->session_id = *ngx_rtmp_get_sessionid(c);

    ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
    if (ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_rtmp_log_error;
    c->log->data = ctx;
    c->log->action = NULL;

    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        ngx_rtmp_close_connection(c);
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->publish_epoch = s->epoch;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, NGX_RTMP_DEFAULT_CHUNK_SIZE);

    /* init s->variables */
    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    s->variables = ngx_pcalloc(s->connection->pool, cmcf->variables.nelts
            * sizeof(ngx_rtmp_variable_value_t));
    if (s->variables == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    ngx_memset(s->framestat.intl_stat, -1,
        sizeof(ngx_int_t) * NGX_RTMP_FRAMESTAT_MAX_COUNT);

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    return s;
}


static u_char *
ngx_rtmp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                     *p;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_error_log_ctx_t   *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V, session: %p", s->addr_text, s);
    len -= p - buf;
    buf = p;

    return p;
}


static void
ngx_rtmp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t                         *pool;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close connection");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    pool = c->pool;
    ngx_close_connection(c);
    ngx_destroy_pool(pool);
}


static void
ngx_rtmp_close_session_handler(ngx_event_t *e)
{
    ngx_rtmp_session_t                 *s;
    ngx_connection_t                   *c;

    s = e->data;
    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    if (s->ping_evt.timer_set) {
        ngx_del_timer(&s->ping_evt);
    }

    if (s->in_old_pool) {
        ngx_destroy_pool(s->in_old_pool);
    }

    if (s->in_pool) {
        ngx_destroy_pool(s->in_pool);
    }

    if (s->quick_play.posted) {
        ngx_delete_posted_event(&s->quick_play);
    }

    ngx_rtmp_free_handshake_buffers(s);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_shared_free_frame(s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }

    if (s->out_chain) {
        ngx_put_chainbufs(s->out_chain);
        s->out_chain = NULL;
    }

    ngx_rtmp_close_connection(c);
}


static void
ngx_rtmp_async_finalize_http_client(ngx_event_t *ev)
{
    ngx_rtmp_session_t         *s;
    ngx_http_request_t         *hcr;

    s = ev->data;
    hcr = s->request;

    if (hcr) {
        ngx_http_client_finalize_request(hcr, 1);
    }
}


static void
ngx_rtmp_async_finalize_http_request(ngx_event_t *ev)
{
    ngx_rtmp_session_t         *s;
    ngx_http_request_t         *r;

    s = ev->data;
    r = s->request;

    if (r->header_sent) {
        ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
        ngx_http_run_posted_requests(r->connection);
    } else {
        r->error_page = 1;

        if (s->status) {
            ngx_http_finalize_request(r, s->status);
        } else {
            ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        }
    }
}


void
ngx_rtmp_finalize_session(ngx_rtmp_session_t *s)
{
    ngx_event_t        *e;
    ngx_connection_t   *c;

    c = s->connection;
    if (c->destroyed) {
        return;
    }

    if (s->live_type == NGX_HLS_LIVE) {
        ngx_rtmp_finalize_fake_session(s);
        return;
    }

    if (s->live_type != NGX_RTMP_LIVE) {
        e = &s->close;
        e->data = s;
        if (s->relay) {
            e->handler = ngx_rtmp_async_finalize_http_client;
        } else {
            e->handler = ngx_rtmp_async_finalize_http_request;
        }
        e->log = c->log;

        ngx_post_event(e, &ngx_posted_events);

        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "finalize session");

    c->destroyed = 1;
    e = &s->close;
    e->data = s;
    e->handler = ngx_rtmp_close_session_handler;
    e->log = c->log;

    ngx_post_event(e, &ngx_posted_events);
}


void
ngx_rtmp_close_fake_connection(ngx_connection_t *c)
{
    c->destroyed = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "close fake connection");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    /* fake connection fd is -1, cannot delete timer
     * and recycled connection in ngx_close_connection
     */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_free_connection(c);

    /* fake connection fd is -1,
     * ngx_close_connection do nothing
     */
    //ngx_close_connection(c);
    ngx_destroy_pool(c->pool); /* it will destroy rtmp session */
}


ngx_connection_t *
ngx_rtmp_create_fake_connection(ngx_pool_t *pool, ngx_log_t *old_log)
{
    ngx_log_t               *log;
    ngx_connection_t        *c;

    c = ngx_get_connection(0, ngx_cycle->log);

    if (c == NULL) {
        return NULL;
    }

    c->fd = (ngx_socket_t) -1;

    if (pool) {
        c->pool = pool;

    } else {
        /* 128 reference to ngx_init_cycle ngx_temp_pool create */
        c->pool = ngx_create_pool(128, c->log);
        if (c->pool == NULL) {
            goto failed;
        }
    }

    log = ngx_pcalloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto failed;
    }

    *log = *old_log;
    c->log = log;
    c->log->connection = c->number;
    c->log->action = NULL;
    c->log->data = NULL;
    c->log->handler = ngx_rtmp_log_error;
//    c->log->log_level = NGX_LOG_DEBUG_ALL;
//    c->log_error = NGX_ERROR_INFO;

    c->error = 1;

    return c;

failed:
    ngx_rtmp_close_fake_connection(c);
    return NULL;
}


void
ngx_rtmp_finalize_fake_session(ngx_rtmp_session_t *s)
{
    ngx_connection_t               *c;
    ngx_rtmp_stream_t              *st;

    c = s->connection;
    if (c->destroyed) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, c->log, 0, "finalize fake session");

    ngx_rtmp_fire_event(s, NGX_RTMP_DISCONNECT, NULL, NULL);

    while (s->out_pos != s->out_last) {
        ngx_rtmp_shared_free_frame(s->out[s->out_pos++]);
        s->out_pos %= s->out_queue;
    }

    if (s->quick_play.posted) {
        ngx_delete_posted_event(&s->quick_play);
    }

    if (s->out_chain) {
        ngx_put_chainbufs(s->out_chain);
        s->out_chain = NULL;
    }

    st = &s->in_streams[0];
    if (st->in) {
        ngx_put_chainbufs(st->in);
        st->in = NULL;
    }
}

ngx_rtmp_session_t *
ngx_rtmp_init_fake_session(ngx_connection_t *c, ngx_rtmp_addr_conf_t *addr_conf)
{
    ngx_rtmp_session_t             *s;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_error_log_ctx_t       *ctx;
    ngx_rtmp_core_main_conf_t      *cmcf;

    s = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_session_t) +
            sizeof(ngx_rtmp_frame_t *) * ((ngx_rtmp_core_srv_conf_t *)
                addr_conf->default_server->ctx-> srv_conf[ngx_rtmp_core_module
                    .ctx_index])->out_queue);
    if (s == NULL) {
        return NULL;
    }

    s->addr_conf = addr_conf;

    s->main_conf = addr_conf->default_server->ctx->main_conf;
    s->srv_conf = addr_conf->default_server->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    s->connection = c;

    s->session_id = *ngx_rtmp_get_sessionid(c);

    if (s->connection->log->data == NULL) {
        ctx = ngx_palloc(c->pool, sizeof(ngx_rtmp_error_log_ctx_t));
        if (ctx == NULL) {
            ngx_rtmp_close_fake_connection(c);
            return NULL;
        }

        ctx->client = &addr_conf->addr_text;
        ctx->session = s;
        s->connection->log->data = ctx;
    }

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_rtmp_max_module);
    if (s->ctx == NULL) {
        return NULL;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    s->out_queue = cscf->out_queue;
    s->out_cork = cscf->out_cork;
    s->in_streams = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_stream_t)
            * cscf->max_streams);
    if (s->in_streams == NULL) {
        return NULL;
    }

#if (nginx_version >= 1007005)
    ngx_queue_init(&s->posted_dry_events);
#endif

    s->epoch = ngx_current_msec;
    s->publish_epoch = s->epoch;
    s->timeout = cscf->timeout;
    s->buflen = cscf->buflen;
    ngx_rtmp_set_chunk_size(s, cscf->chunk_size);

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);
    s->variables = ngx_pcalloc(s->connection->pool, cmcf->variables.nelts
        * sizeof(ngx_rtmp_variable_value_t));
    if (s->variables == NULL) {
        return NULL;
    }

    /* init s->variables */
    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    s->variables = ngx_pcalloc(s->connection->pool, cmcf->variables.nelts
            * sizeof(ngx_rtmp_variable_value_t));
    if (s->variables == NULL) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }

    ngx_memset(s->framestat.intl_stat, -1,
        sizeof(ngx_int_t) * NGX_RTMP_FRAMESTAT_MAX_COUNT);

    if (ngx_rtmp_fire_event(s, NGX_RTMP_CONNECT, NULL, NULL) != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return NULL;
    }


    return s;
}

ngx_int_t
ngx_rtmp_get_remoteaddr(ngx_connection_t *c,ngx_str_t *address)
{
    u_char             *p;
    u_char              sa[NGX_SOCKADDRLEN];
    socklen_t           len, len2;
    ngx_addr_t          addr;

    p = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    addr.socklen = c->socklen;
    len = NGX_SOCKADDR_STRLEN;

    if (c->sockaddr) {
        addr.sockaddr = c->sockaddr;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    } else {
        if (getpeername(c->fd, (struct sockaddr *)&sa, &len) == -1) {
            ngx_connection_error(c, ngx_socket_errno,
                                "getpeername() failed");
            return NGX_ERROR;
        }
        addr.sockaddr = (struct sockaddr*)&sa;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    }

    address->data = p;
    address->len = len2;

    return NGX_OK;
}

ngx_int_t
ngx_rtmp_arg(ngx_rtmp_session_t *s, u_char *name, size_t len, ngx_str_t *value)
{
    u_char  *p, *last;

    if (s->pargs.len == 0) {
        return NGX_DECLINED;
    }

    p = s->pargs.data;
    last = p + s->pargs.len;

    for ( /* void */ ; p < last; p++) {

        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == s->pargs.data || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = s->pargs.data + s->pargs.len;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}