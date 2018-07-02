
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_dynamic_resolver.h"
#include "ngx_rtmp_variables.h"
#include "ngx_http_flv_relay.h"


static ngx_rtmp_push_pt             next_push;
static ngx_rtmp_pull_pt             next_pull;
static ngx_rtmp_close_stream_pt     next_close_stream;


static ngx_int_t ngx_rtmp_relay_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_relay_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_relay_create_app_conf(ngx_conf_t *cf);
static char *ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char *ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_relay_var_pushobject(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_relay_init_process(ngx_cycle_t *cycle);


/*                _____
 * =push=        |     |---publish--->
 * ---publish--->|     |---publish--->
 *     (src)     |     |---publish--->
 *                -----  (next,relay)
 *                      need reconnect
 * =pull=         _____
 * -----play---->|     |
 * -----play---->|     |----play----->
 * -----play---->|     | (src,relay)
 *     (next)     -----
 */


typedef struct {
    uintptr_t                       index;
    ngx_str_t                       name;
} ngx_rtmp_relay_variable_t;


typedef struct {
    ngx_array_t                 pulls;         /* ngx_rtmp_relay_target_t * */
    ngx_array_t                 pushes;        /* ngx_rtmp_relay_target_t * */
    ngx_msec_t                  buflen;

	//ngx_array_t					static_pulls;  /* ngx_rtmp_relay_target_t * */
	ngx_array_t					static_events; /* ngx_event_t */

} ngx_rtmp_relay_app_conf_t;

typedef struct {
	ngx_rtmp_conf_ctx_t			cctx;
	ngx_rtmp_core_srv_conf_t	*cscf;
	ngx_rtmp_relay_target_t		*target;
}ngx_rtmp_relay_static_t;

typedef struct {
    char                       *code;
    ngx_uint_t                  status;
    ngx_flag_t                  finalize;
} ngx_rtmp_status_code_t;

static ngx_rtmp_status_code_t ngx_rtmp_relay_status_error_code[] = {
    { "NetStream.Publish.BadName",      400, 1 },
    { "NetStream.Stream.Forbidden",     403, 1 },
    { "NetStream.Play.StreamNotFound",  404, 1 },
    { "NetStream.Relay.ServerError",    500, 1 },
    { NULL, 0, 0 }
};


#define NGX_RTMP_RELAY_CONNECT_TRANS            1
#define NGX_RTMP_RELAY_CREATE_STREAM_TRANS      2


#define NGX_RTMP_RELAY_CSID_AMF_INI             3
#define NGX_RTMP_RELAY_CSID_AMF                 5
#define NGX_RTMP_RELAY_MSID                     1


/* default flashVer */
#define NGX_RTMP_RELAY_FLASHVER                 "LNX.11,1,102,55"


static ngx_rtmp_variable_t  ngx_rtmp_relay_variables[] = {

    { ngx_string("pushObject"), NULL,
      ngx_rtmp_relay_var_pushobject, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t  ngx_rtmp_relay_commands[] = {

    { ngx_string("push"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("pull"),
      NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_relay_push_pull,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("relay_buffer"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_relay_app_conf_t, buflen),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_relay_module_ctx = {
    ngx_rtmp_relay_preconfiguration,        /* preconfiguration */
    ngx_rtmp_relay_postconfiguration,       /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_relay_create_app_conf,         /* create app configuration */
    ngx_rtmp_relay_merge_app_conf           /* merge app configuration */
};


ngx_module_t  ngx_rtmp_relay_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_relay_module_ctx,             /* module context */
    ngx_rtmp_relay_commands,                /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    ngx_rtmp_relay_init_process,            /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_rtmp_relay_var_pushobject(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_relay_ctx_t     *rctx;
    u_char                   *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (rctx == NULL || rctx->push_object.len == 0) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    v->len = ngx_sprintf(p, "%V", &rctx->push_object) - p;
    v->data = p;

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_variables_add_relay_vars(ngx_conf_t *cf)
{
    ngx_rtmp_variable_t        *cv, *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    for (cv = ngx_rtmp_relay_variables; cv->name.len; cv++) {
        v = ngx_rtmp_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_preconfiguration(ngx_conf_t *cf)
{
    return ngx_rtmp_variables_add_relay_vars(cf);
}


static void *
ngx_rtmp_relay_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_relay_app_conf_t     *racf;

    racf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_app_conf_t));
    if (racf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&racf->pushes, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    if (ngx_array_init(&racf->pulls, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

	/*
    if (ngx_array_init(&racf->static_pulls, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }
	*/

    if (ngx_array_init(&racf->static_events, cf->pool, 1, sizeof(void *)) != NGX_OK) {
        return NULL;
    }

    racf->buflen = NGX_CONF_UNSET_MSEC;

    return racf;
}


static char *
ngx_rtmp_relay_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_relay_app_conf_t  *prev = parent;
    ngx_rtmp_relay_app_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->buflen, prev->buflen, 5000);

    return NGX_CONF_OK;
}

static void
ngx_rtmp_relay_static_pull_connect(ngx_event_t *ev)
{
	u_char						*p, *end;
	ngx_rtmp_play_t				v;
	ngx_connection_t			*c;
	ngx_rtmp_session_t			*s;
	ngx_rtmp_addr_conf_t		*addr_conf;
	
	struct sockaddr_in			*sin;

	ngx_rtmp_relay_static_t		*rs = ev->data;
	//ngx_rtmp_relay_target_t		*target = rs->target;

	/* get a connection */
	c = ngx_rtmp_create_fake_connection(NULL, ngx_cycle->log);
	if(c == NULL) {
		return ;
	}
	
	/* set connection sockaddr*/
	sin = ngx_pcalloc(c->pool, sizeof(struct sockaddr_in));
	sin->sin_addr.s_addr = ngx_inet_addr((u_char*)("127.0.0.1"), 9);

	c->socklen = sizeof(struct sockaddr);
	c->sockaddr = (struct sockaddr *)sin;
	c->sockaddr->sa_family = AF_INET;

	c->local_sockaddr = c->sockaddr;
	c->local_socklen = c->socklen;

	addr_conf = ngx_pcalloc(c->pool, sizeof(ngx_rtmp_addr_conf_t));
	if(addr_conf == NULL) {
		return ;
	}

	addr_conf->default_server = rs->cscf;
	ngx_str_set(&addr_conf->addr_text, "static-pull");
	
	s = ngx_rtmp_init_fake_session(c, addr_conf);
	if( s == NULL) {
		return ;
	}

	s->live_type = NGX_HTTP_FLV_LIVE;
	s->request = ngx_pcalloc(c->pool, sizeof(ngx_http_request_t));
	s->request->connection = c;
	s->static_pull_fake = 1;

	c->data = s;

	s->app_conf = rs->cctx.app_conf;

	s->app = rs->target->app;
	s->name = rs->target->name;
	s->tc_url = rs->target->tc_url;
	s->page_url = rs->target->page_url;

	end = rs->target->tc_url.data + rs->target->tc_url.len;
	p = ngx_strlchr(rs->target->tc_url.data, end, '?');
	if(p != NULL) {
		s->args.len = (end - p) - 1;
		s->args.data = p + 1;

		s->pargs.len = s->args.len;
		s->pargs.data = s->args.data;
	}

	ngx_memzero(&v, sizeof(ngx_rtmp_play_t));
	ngx_memcpy(v.name, rs->target->name.data, rs->target->name.len);

	v.silent = 1;

	/* get serverid */
	ngx_rtmp_cmd_middleware_init(s);

	/* get a live server */
	s->live_server = ngx_live_create_server(&s->serverid);

	s->stream.len = s->serverid.len + 1 + s->app.len + 1 + s->name.len;
	s->stream.data = ngx_palloc(s->connection->pool, s->stream.len);
	p = s->stream.data;

	p = ngx_copy(p, s->serverid.data, s->serverid.len);
	*p++ = '/';
	p = ngx_copy(p, s->app.data, s->app.len);
	*p++ = '/';
	p = ngx_copy(p, s->name.data, s->name.len);

	/* get a live stream */
	s->live_stream = ngx_live_create_stream(&s->serverid, &s->stream);

	ngx_rtmp_play_filter(s, &v);
	//ngx_relay_pull(s, &target->name, target);
}


static ngx_int_t
ngx_rtmp_relay_get_peer(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}


static void
ngx_rtmp_relay_free_peer(ngx_peer_connection_t *pc, void *data,
            ngx_uint_t state)
{
}


typedef ngx_rtmp_relay_ctx_t * (* ngx_rtmp_relay_create_ctx_pt)
    (ngx_rtmp_session_t *s, ngx_str_t *name, ngx_rtmp_relay_target_t *target);


static ngx_int_t
ngx_rtmp_relay_copy_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    if (src->len == 0) {
        return NGX_OK;
    }
    dst->len = src->len;
    dst->data = ngx_palloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    return NGX_OK;
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_connection(ngx_rtmp_session_t *s,
        ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_relay_ctx_t           *rctx;
    ngx_rtmp_addr_conf_t           *addr_conf;
    ngx_rtmp_conf_ctx_t            *addr_ctx;
    ngx_rtmp_session_t             *rs;
    ngx_peer_connection_t          *pc;
    ngx_connection_t               *c;
    ngx_addr_t                     *addr, daddr;
    ngx_pool_t                     *pool;
    ngx_log_t                      *log;
    ngx_int_t                       rc;
    ngx_str_t                       v, *uri;
    u_char                         *first, *last, *p, text[NGX_SOCKADDRLEN];
    struct sockaddr                 sa;
    struct sockaddr_in             *sin;

    pool = NULL;
    pool = ngx_create_pool(4096, ngx_cycle->log);
    if (pool == NULL) {
        return NULL;
    }

    log = ngx_pcalloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        goto clear;
    }
    *log = ngx_cycle->new_log;

    ngx_log_debug0(NGX_LOG_DEBUG_RTMP, log, 0, "relay: create remote context");

    pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
    if (pc == NULL) {
        goto clear;
    }
    pc->log = log;

    daddr.socklen = ngx_dynamic_resolver_gethostbyname(&target->url.host,
                                                       &sa);
    if (daddr.socklen == 0) { /* dynamic resolver sync failed */
        if (target->url.naddrs == 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0, "relay: no address");
            goto clear;
        }

        /* get address */
        addr = &target->url.addrs[target->counter % target->url.naddrs];
        target->counter++;
    } else {
        sin = (struct sockaddr_in *) &sa;
        sin->sin_port = ntohs(target->url.port);
        daddr.sockaddr = &sa;
        ngx_memzero(text, sizeof(text));
        daddr.name.len = ngx_sock_ntop(daddr.sockaddr, daddr.socklen, text,
                                       NGX_SOCKADDRLEN, 1);
        daddr.name.data = text;
        addr = &daddr;
    }

    /* copy log to keep shared log unchanged */
    pc->get = ngx_rtmp_relay_get_peer;
    pc->free = ngx_rtmp_relay_free_peer;
    pc->name = &addr->name;
    pc->socklen = addr->socklen;
    pc->sockaddr = (struct sockaddr *)ngx_palloc(pool, pc->socklen);
    if (pc->sockaddr == NULL) {
        goto clear;
    }
    ngx_memcpy(pc->sockaddr, addr->sockaddr, pc->socklen);

    rc = ngx_event_connect_peer(pc);
    if (rc != NGX_OK && rc != NGX_AGAIN ) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "relay: connection failed");
        goto clear;
    }
    c = pc->connection;
    c->pool = pool;
    if (ngx_rtmp_relay_copy_str(pool, &c->addr_text, &target->url.url)
        != NGX_OK)
    {
        goto clear;
    }

    addr_conf = ngx_pcalloc(pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto clear;
    }
    addr_ctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_ctx == NULL) {
        goto clear;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    addr_conf->default_server = cscf;
    addr_ctx->main_conf = cctx->main_conf;
    addr_ctx->srv_conf  = cctx->srv_conf;
    ngx_str_set(&addr_conf->addr_text, "ngx-relay");

    rs = ngx_rtmp_init_session(c, addr_conf);
    if (rs == NULL) {
        /* no need to destroy pool */
        return NULL;
    }
    rs->app_conf = cctx->app_conf;
    rs->relay = 1;
    rs->publishing = target->publishing;

#define NGX_RTMP_SESSION_STR_COPY(to, from)                                 \
    if (s && ngx_rtmp_relay_copy_str(pool, &rs->to, &s->from) != NGX_OK) {  \
        goto clear;                                                         \
    }

    NGX_RTMP_SESSION_STR_COPY(stream,   stream);

    NGX_RTMP_SESSION_STR_COPY(name,     name);
    NGX_RTMP_SESSION_STR_COPY(pargs,    pargs);

    NGX_RTMP_SESSION_STR_COPY(app,      app);
    NGX_RTMP_SESSION_STR_COPY(args,     args);
    NGX_RTMP_SESSION_STR_COPY(flashver, flashver);
    NGX_RTMP_SESSION_STR_COPY(swf_url,  swf_url);
    NGX_RTMP_SESSION_STR_COPY(tc_url,   tc_url);
    NGX_RTMP_SESSION_STR_COPY(page_url, page_url);

    if (s) {
        rs->acodecs = s->acodecs;
        rs->vcodecs = s->vcodecs;
    }

    NGX_RTMP_SESSION_STR_COPY(serverid, serverid);

#undef NGX_RTMP_SESSION_STR_COPY

#define NGX_RTMP_TARGET_STR_COPY(to, from)                                 \
    if (target && ngx_rtmp_relay_copy_str(pool, &rs->to, &target->from)    \
                  != NGX_OK)                                               \
    {                                                                      \
        goto clear;                                                        \
    }

    NGX_RTMP_TARGET_STR_COPY(groupid, groupid);

#undef NGX_RTMP_TARGET_STR_COPY

    ngx_rtmp_cmd_middleware_init(rs);

    /* rctx from here */
    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_relay_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    if (name && ngx_rtmp_relay_copy_str(pool, &rctx->name, name) != NGX_OK) {
        goto clear;
    }

    rctx->url = c->addr_text;

#define NGX_RTMP_RELAY_STR_COPY(to, from)                                     \
    if (ngx_rtmp_relay_copy_str(pool, &rctx->to, &target->from) != NGX_OK) {  \
        goto clear;                                                           \
    }                                                                         \

    NGX_RTMP_RELAY_STR_COPY(app,        app);
    NGX_RTMP_RELAY_STR_COPY(tc_url,     tc_url);
    NGX_RTMP_RELAY_STR_COPY(page_url,   page_url);
    NGX_RTMP_RELAY_STR_COPY(swf_url,    swf_url);
    NGX_RTMP_RELAY_STR_COPY(flash_ver,  flash_ver);
    NGX_RTMP_RELAY_STR_COPY(push_object,push_object);
    NGX_RTMP_RELAY_STR_COPY(play_path,  play_path);


    rctx->live  = target->live;
    rctx->start = target->start;
    rctx->stop  = target->stop;

#undef NGX_RTMP_RELAY_STR_COPY

/* if target not set, set rctx default */
#define NGX_RTMP_DEFAULT_STR(to, from)          \
    if (rctx->to.len == 0) {                    \
        rctx->to = rs->from;                    \
    }

    NGX_RTMP_DEFAULT_STR(pargs,     pargs);

    NGX_RTMP_DEFAULT_STR(app,       app);
    NGX_RTMP_DEFAULT_STR(args,      args);
    NGX_RTMP_DEFAULT_STR(tc_url,    tc_url);
    NGX_RTMP_DEFAULT_STR(page_url,  page_url);
    NGX_RTMP_DEFAULT_STR(swf_url,   swf_url);
    NGX_RTMP_DEFAULT_STR(flash_ver, flashver);

    if (rctx->acodecs == 0) {
        rctx->acodecs = rs->acodecs;
    }

    if (rctx->vcodecs == 0) {
        rctx->vcodecs = rs->vcodecs;
    }

#undef NGX_RTMP_DEFAULT_STR

    if (rctx->app.len == 0 || rctx->play_path.len == 0) {
        /* parse uri */
        uri = &target->url.uri;
        first = uri->data;
        last  = uri->data + uri->len;
        if (first != last && *first == '/') {
            ++first;
        }

        if (first != last) {

            /* deduce app */
            p = ngx_strlchr(first, last, '/');
            if (p == NULL) {
                p = last;
            }

            if (rctx->app.len == 0 && first != p) {
                v.data = first;
                v.len = p - first;
                if (ngx_rtmp_relay_copy_str(pool, &rctx->app, &v) != NGX_OK) {
                    goto clear;
                }
            }

            /* deduce play_path */
            if (p != last) {
                ++p;
            }

            if (rctx->play_path.len == 0 && p != last) {
                v.data = p;
                v.len = last - p;
                if (ngx_rtmp_relay_copy_str(pool, &rctx->play_path, &v)
                        != NGX_OK)
                {
                    goto clear;
                }
            }
        }
    }

    rctx->tag = target->tag;
    rctx->idx = target->idx;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_relay_module);
    ngx_str_set(&rs->flashver, "ngx-local-relay");

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    ngx_rtmp_client_handshake(rs, 1);
    return rctx;

clear:
    if (pool) {
        ngx_destroy_pool(pool);
    }
    return NULL;
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create_remote_ctx(ngx_rtmp_session_t *s, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_conf_ctx_t         cctx;

    cctx.app_conf = s->app_conf;
    cctx.srv_conf = s->srv_conf;
    cctx.main_conf = s->main_conf;

    if (target->schema.len == 0 ||
            ngx_memcmp(target->schema.data, "rtmp", 4) == 0)
    {
        return ngx_rtmp_relay_create_connection(s, &cctx, name, target);
    } else {
        return ngx_http_relay_create_connection(s, &cctx, name, target);
    }
}


static ngx_rtmp_relay_ctx_t *
ngx_rtmp_relay_create(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target,
        ngx_rtmp_relay_create_ctx_pt create_publish_ctx,
        ngx_rtmp_relay_create_ctx_pt create_play_ctx)
{
    ngx_rtmp_relay_ctx_t           *ctx;
    u_char                          pname[NGX_RTMP_MAX_NAME];
    u_char                          pargs[NGX_RTMP_MAX_ARGS];

    if (create_play_ctx != NULL) {
        ctx = create_play_ctx(s, name, target);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "relay create, play ctx is NULL");
            return NULL;
        }
        ++s->live_stream->push_count;
    } else {
        ctx = create_publish_ctx(s, name, target);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "relay create, publish ctx is NULL");
            return NULL;
        }
    }

	ctx->session->static_pull_fake = s->static_pull_fake;
	if(s->relay == 1) {
		ctx->session->second_relay = 1;
	}

    ngx_memzero(pname, sizeof(pname));
    ngx_memzero(pargs, sizeof(pargs));

    *(ngx_cpymem(pname, ctx->name.data,
                ngx_min(sizeof(pname) - 1, ctx->name.len))) = 0;
    if (ctx->pargs.len) {
        *(ngx_cpymem(pargs, ctx->pargs.data,
                    ngx_min(sizeof(pargs) - 1, ctx->pargs.len))) = 0;
    }

    ngx_rtmp_cmd_stream_init(ctx->session, pname, pargs,
                             ctx->session->publishing);

    return ctx;
}


ngx_rtmp_relay_ctx_t *
ngx_relay_pull(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "relay: create pull name='%V' app='%V' playpath='%V' url='%V'",
            name, &target->app, &target->play_path, &target->url.url);

    return ngx_rtmp_relay_create(s, name, target,
            ngx_rtmp_relay_create_remote_ctx,
            NULL);
}


ngx_rtmp_relay_ctx_t *
ngx_relay_push(ngx_rtmp_session_t *s, ngx_str_t *name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "relay: create push name='%V' app='%V' playpath='%V' url='%V' "
            "groupid='%V'",
            name, &target->app, &target->play_path, &target->url.url,
            &target->groupid);

    return ngx_rtmp_relay_create(s, name, target,
            NULL,
            ngx_rtmp_relay_create_remote_ctx);
}


static ngx_int_t
ngx_rtmp_relay_push(ngx_rtmp_session_t *s)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target, **t;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    if (s->interprocess || s->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->pushes.nelts == 0) {
        goto next;
    }

    name = s->name;

    t = racf->pushes.elts;
    for (n = 0; n < racf->pushes.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (name.len != target->name.len ||
            ngx_memcmp(name.data, target->name.data, name.len)))
        {
            continue;
        }

        ctx = s->live_stream->relay_ctx[n];
        if (ctx && ctx->relay_completion) { /* relay push already complete */
            continue;
        }

        ctx = ngx_relay_push(s, &name, target);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "relay: push failed name='%V' app='%V' "
                    "playpath='%V' url='%V'",
                    &name, &target->app, &target->play_path,
                    &target->url.url);

            continue;
        }

        if (s->live_stream->relay_ctx[n]) {
            ngx_rtmp_finalize_session(s->live_stream->relay_ctx[n]->session);
        }
        s->live_stream->relay_ctx[n] = ctx;
    }

next:
    return next_push(s);
}


static ngx_int_t
ngx_rtmp_relay_pull(ngx_rtmp_session_t *s)
{
    ngx_rtmp_relay_app_conf_t      *racf;
    ngx_rtmp_relay_target_t        *target, **t;
    ngx_str_t                       name;
    size_t                          n;
    ngx_rtmp_relay_ctx_t           *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx && s->relay) {
        goto next;
    }

    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    if (racf == NULL || racf->pulls.nelts == 0) {
        goto next;
    }

    name = s->name;

    t = racf->pulls.elts;
    for (n = 0; n < racf->pulls.nelts; ++n, ++t) {
        target = *t;

        if (target->name.len && (name.len != target->name.len ||
            ngx_memcmp(name.data, target->name.data, name.len)))
        {
            continue;
        }

        ctx = ngx_relay_pull(s, &name, target);
        if (ctx) {
            return NGX_AGAIN;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "relay: pull failed name='%V' app='%V' "
                "playpath='%V' url='%V'",
                &name, &target->app, &target->play_path,
                &target->url.url);

        return NGX_ERROR;
    }

next:
    return next_pull(s);
}


static ngx_int_t
ngx_rtmp_relay_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->tag != &ngx_rtmp_relay_module || s->publishing) {
        goto next;
    }

    if (ctx == s->live_stream->relay_ctx[ctx->idx]) {
        s->live_stream->relay_ctx[ctx->idx] = NULL;
    }

    if (!ctx->relay_completion) {
        --s->live_stream->push_count;
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_relay_play_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_play_t             v;
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));
    v.silent = 1;
    *(ngx_cpymem(v.name, ctx->name.data,
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;
    if (ctx->pargs.len) {
        *(ngx_cpymem(v.args, ctx->pargs.data,
                    ngx_min(sizeof(v.args) - 1, ctx->pargs.len))) = 0;
    }

    return ngx_rtmp_play_filter(s, &v);
}


ngx_int_t
ngx_rtmp_relay_publish_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_publish_t          v;
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_publish_t));
    v.silent = 1;
    *(ngx_cpymem(v.name, ctx->name.data,
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;
    if (ctx->pargs.len) {
        *(ngx_cpymem(v.args, ctx->pargs.data,
                    ngx_min(sizeof(v.args) - 1, ctx->pargs.len))) = 0;
    }

    return ngx_rtmp_publish_filter(s, &v);
}


static ngx_int_t
ngx_rtmp_relay_send_connect(ngx_rtmp_session_t *s)
{
    ngx_str_t                   app;
    double                      acodecs = 3575, vcodecs = 252;
    static double               trans = NGX_RTMP_RELAY_CONNECT_TRANS;

    static ngx_rtmp_amf_elt_t   out_cmd[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("app"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("tcUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("pageUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("swfUrl"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_STRING,
          ngx_string("flashVer"),
          NULL, 0 }, /* <-- fill */

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("audioCodecs"),
          NULL, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_string("videoCodecs"),
          NULL, 0 }
    };

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "connect", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          out_cmd, sizeof(out_cmd) }
    };

    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_header_t           h;
    size_t                      len, url_len;
    u_char                     *p, *url_end;


    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (cacf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    /* app */
    if (ctx->app.len) {
        if (ctx->args.len) {
            app.len = ctx->app.len + 1 + ctx->args.len;
            app.data = ngx_pcalloc(s->connection->pool, app.len);
            if (app.data == NULL) {
                return NGX_ERROR;
            }

            ngx_snprintf(app.data, app.len, "%V?%V", &ctx->app, &ctx->args);
        } else {
            app = ctx->app;
        }

        out_cmd[0].data = app.data;
        out_cmd[0].len  = app.len;
    } else {
        out_cmd[0].data = cacf->name.data;
        out_cmd[0].len  = cacf->name.len;
    }

    /* tcUrl */
    if (ctx->tc_url.len) {
        out_cmd[1].data = ctx->tc_url.data;
        out_cmd[1].len  = ctx->tc_url.len;
    } else {
        len = sizeof("rtmp://") - 1 + ctx->url.len +
            sizeof("/") - 1 + ctx->app.len;
        p = ngx_palloc(s->connection->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }
        out_cmd[1].data = p;
        p = ngx_cpymem(p, "rtmp://", sizeof("rtmp://") - 1);

        url_len = ctx->url.len;
        url_end = ngx_strlchr(ctx->url.data, ctx->url.data + ctx->url.len, '/');
        if (url_end) {
            url_len = (size_t) (url_end - ctx->url.data);
        }

        p = ngx_cpymem(p, ctx->url.data, url_len);
        *p++ = '/';
        p = ngx_cpymem(p, ctx->app.data, ctx->app.len);
        out_cmd[1].len = p - (u_char *)out_cmd[1].data;
    }

    /* pageUrl */
    out_cmd[2].data = ctx->page_url.data;
    out_cmd[2].len  = ctx->page_url.len;

    /* swfUrl */
    out_cmd[3].data = ctx->swf_url.data;
    out_cmd[3].len  = ctx->swf_url.len;

    /* flashVer */
    if (ctx->flash_ver.len) {
        out_cmd[4].data = ctx->flash_ver.data;
        out_cmd[4].len  = ctx->flash_ver.len;
    } else {
        out_cmd[4].data = NGX_RTMP_RELAY_FLASHVER;
        out_cmd[4].len  = sizeof(NGX_RTMP_RELAY_FLASHVER) - 1;
    }

    if (ctx->acodecs != 0) {
        acodecs = (double) ctx->acodecs;
    }
    out_cmd[5].data = &acodecs;

    if (ctx->vcodecs != 0) {
        vcodecs = (double) ctx->vcodecs;
    }
    out_cmd[6].data = &vcodecs;

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_chunk_size(s, cscf->chunk_size) != NGX_OK
        || ngx_rtmp_send_ack_size(s, cscf->ack_window) != NGX_OK
        || ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
        ? NGX_ERROR
        : NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_send_create_stream(ngx_rtmp_session_t *s)
{
    static double               trans = NGX_RTMP_RELAY_CREATE_STREAM_TRANS;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "createStream", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 }
    };

    ngx_rtmp_header_t           h;


    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF_INI;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_send_publish(ngx_rtmp_session_t *s)
{
    ngx_str_t                   name;
    static double               trans;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "publish", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- to fill */

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "live", 0 }
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_relay_ctx_t       *ctx;


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        if (ctx->pargs.len) {
            name.len = ctx->name.len + 1 + ctx->pargs.len;
            name.data = ngx_pcalloc(s->connection->pool, name.len);
            if (name.data == NULL) {
                return NGX_ERROR;
            }

            ngx_snprintf(name.data, name.len, "%V?%V", &ctx->name, &ctx->pargs);
        } else {
            name = ctx->name;
        }

        out_elts[3].data = name.data;
        out_elts[3].len  = name.len;
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.msid = NGX_RTMP_RELAY_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0]));
}


static ngx_int_t
ngx_rtmp_relay_send_play(ngx_rtmp_session_t *s)
{
    ngx_str_t                   name;
    static double               trans;
    static double               start, duration;

    static ngx_rtmp_amf_elt_t   out_elts[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          "play", 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_STRING,
          ngx_null_string,
          NULL, 0 }, /* <- fill */

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &start, 0 },

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &duration, 0 },
    };

    ngx_rtmp_header_t           h;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_rtmp_relay_app_conf_t  *racf;


    racf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_relay_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (racf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->play_path.len) {
        out_elts[3].data = ctx->play_path.data;
        out_elts[3].len  = ctx->play_path.len;
    } else {
        if (ctx->pargs.len) {
            name.len = ctx->name.len + 1 + ctx->pargs.len;
            name.data = ngx_pcalloc(s->connection->pool, name.len);
            if (name.data == NULL) {
                return NGX_ERROR;
            }

            ngx_snprintf(name.data, name.len, "%V?%V", &ctx->name, &ctx->pargs);
        } else {
            name = ctx->name;
        }

        out_elts[3].data = name.data;
        out_elts[3].len  = name.len;
    }

    if (ctx->live) {
        start = -1000;
        duration = -1000;
    } else {
        start    = (ctx->start ? ctx->start : -2000);
        duration = (ctx->stop  ? ctx->stop - ctx->start : -1000);
    }

    ngx_memzero(&h, sizeof(h));
    h.csid = NGX_RTMP_RELAY_CSID_AMF;
    h.msid = NGX_RTMP_RELAY_MSID;
    h.type = NGX_RTMP_MSG_AMF_CMD;

    return ngx_rtmp_send_amf(s, &h, out_elts,
            sizeof(out_elts) / sizeof(out_elts[0])) != NGX_OK
           || ngx_rtmp_send_set_buflen(s, NGX_RTMP_RELAY_MSID,
                   racf->buflen) != NGX_OK
           ? NGX_ERROR
           : NGX_OK;
}


ngx_int_t
ngx_rtmp_relay_status_error(ngx_rtmp_session_t *s, char *type, char *code,
        char *level, char *desc)
{
    ngx_rtmp_core_ctx_t        *cctx;
    size_t                      i;
    ngx_flag_t                  status = 0;

    if (ngx_strcmp(type, "onStatus") == 0) {
        status = 1;
    }

    for (i = 0; ngx_rtmp_relay_status_error_code[i].code; ++i) {

        if (ngx_strcmp(ngx_rtmp_relay_status_error_code[i].code, code)
                != 0)
        {
            continue;
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "relay transit, %s: level='%s' code='%s' description='%s'",
                type, level, code, desc);

        if (s->publishing) {
            cctx = s->live_stream->play_ctx;
        } else {
            cctx = s->live_stream->publish_ctx;
        }

        for (; cctx; cctx = cctx->next) {
            cctx->session->status = ngx_rtmp_relay_status_error_code[i].status;
            status ? ngx_rtmp_send_status(cctx->session, code, level, desc)
                   : ngx_rtmp_send_error(cctx->session, code, level, desc);

            if (ngx_rtmp_relay_status_error_code[i].finalize) {
                ngx_rtmp_finalize_session(cctx->session);
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_on_result(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "relay: _result: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    switch ((ngx_int_t)v.trans) {
        case NGX_RTMP_RELAY_CONNECT_TRANS:
            return ngx_rtmp_relay_send_create_stream(s);

        case NGX_RTMP_RELAY_CREATE_STREAM_TRANS:
            if (s->publishing == 0) {
                if (ngx_rtmp_relay_send_publish(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_relay_play_local(s);

            } else {
                if (ngx_rtmp_relay_send_play(s) != NGX_OK) {
                    return NGX_ERROR;
                }
                return ngx_rtmp_relay_publish_local(s);
            }

        default:
            return NGX_OK;
    }
}


static ngx_int_t
ngx_rtmp_relay_on_error(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0])))
    {
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "relay: _error: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    ngx_rtmp_relay_status_error(s, "_error", (char *) v.code,
            (char *) v.level, (char *) v.desc);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_on_status(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t       *ctx;
    static struct {
        double                  trans;
        u_char                  level[32];
        u_char                  code[128];
        u_char                  desc[1024];
    } v;

    static ngx_rtmp_amf_elt_t   in_inf[] = {

        { NGX_RTMP_AMF_STRING,
          ngx_string("level"),
          &v.level, sizeof(v.level) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("code"),
          &v.code, sizeof(v.code) },

        { NGX_RTMP_AMF_STRING,
          ngx_string("description"),
          &v.desc, sizeof(v.desc) },
    };

    static ngx_rtmp_amf_elt_t   in_elts[] = {

        { NGX_RTMP_AMF_NUMBER,
          ngx_null_string,
          &v.trans, 0 },

        { NGX_RTMP_AMF_NULL,
          ngx_null_string,
          NULL, 0 },

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };

    static ngx_rtmp_amf_elt_t   in_elts_meta[] = {

        { NGX_RTMP_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) },
    };


    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    ngx_memzero(&v, sizeof(v));
    if (h->type == NGX_RTMP_MSG_AMF_META) {
        ngx_rtmp_receive_amf(s, in, in_elts_meta,
                sizeof(in_elts_meta) / sizeof(in_elts_meta[0]));
    } else {
        ngx_rtmp_receive_amf(s, in, in_elts,
                sizeof(in_elts) / sizeof(in_elts[0]));
    }

    ngx_log_debug3(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "relay: onStatus: level='%s' code='%s' description='%s'",
            v.level, v.code, v.desc);

    ngx_rtmp_relay_status_error(s, "onStatus", (char *) v.code,
            (char *) v.level, (char *) v.desc);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_relay_handshake_done(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_chain_t *in)
{
    ngx_rtmp_relay_ctx_t   *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL || !s->relay) {
        return NGX_OK;
    }

    return ngx_rtmp_relay_send_connect(s);
}


static char *
ngx_rtmp_relay_push_pull(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *value, v, n;
    ngx_rtmp_relay_app_conf_t          *racf;
    ngx_rtmp_relay_target_t            *target, **t;
    ngx_url_t                          *u;
    ngx_uint_t                          i;
    ngx_int_t                           is_pull, is_static;
	ngx_event_t							**ee, *e;
	ngx_rtmp_relay_static_t				*rs;
    u_char                             *p, *last;

    value = cf->args->elts;

    racf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_relay_module);

    is_pull = (value[0].data[3] == 'l');
	is_static = 0;

    target = ngx_pcalloc(cf->pool, sizeof(*target));
    if (target == NULL) {
        return NGX_CONF_ERROR;
    }

    target->tag = &ngx_rtmp_relay_module;

    u = &target->url;
    u->default_port = 1935;
    u->uri_part = 1;
    u->url = value[1];

    if (ngx_strncasecmp(u->url.data, (u_char *) "rtmp://", 7) == 0) {
        target->schema.data = value[1].data;
        target->schema.len = 4;
        u->url.data += 7;
        u->url.len  -= 7;
    } else if (ngx_strncasecmp(u->url.data, (u_char *) "http://", 7) == 0) {
        target->schema.data = value[1].data;
        target->schema.len = 4;
        u->url.data += 7;
        u->url.len  -= 7;
        u->default_port = 80;
    }

    if (ngx_parse_url(cf->pool, u) != NGX_OK) {
        if (u->err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in url \"%V\"", u->err, &u->url);
        }
        return NGX_CONF_ERROR;
    }
    ngx_dynamic_resolver_add_domain(&u->host, cf->cycle);

    value += 2;
    for (i = 2; i < cf->args->nelts; ++i, ++value) {
        p = ngx_strlchr(value->data, value->data + value->len, '=');

        if (p == NULL) {
            n = *value;
            ngx_str_set(&v, "1");

        } else {
            n.data = value->data;
            n.len  = p - value->data;

            v.data = p + 1;
            v.len  = value->data + value->len - p - 1;
        }

#define NGX_RTMP_RELAY_STR_PAR(name, var)                                     \
        if (n.len == sizeof(name) - 1                                         \
            && ngx_strncasecmp(n.data, (u_char *) name, n.len) == 0)          \
        {                                                                     \
            target->var = v;                                                  \
            continue;                                                         \
        }

#define NGX_RTMP_RELAY_NUM_PAR(name, var)                                     \
        if (n.len == sizeof(name) - 1                                         \
            && ngx_strncasecmp(n.data, (u_char *) name, n.len) == 0)          \
        {                                                                     \
            target->var = ngx_atoi(v.data, v.len);                            \
            continue;                                                         \
        }

        NGX_RTMP_RELAY_STR_PAR("schema",      schema);
        NGX_RTMP_RELAY_STR_PAR("app",         app);
        NGX_RTMP_RELAY_STR_PAR("name",        name);
        NGX_RTMP_RELAY_STR_PAR("tcUrl",       tc_url);
        NGX_RTMP_RELAY_STR_PAR("pageUrl",     page_url);
        NGX_RTMP_RELAY_STR_PAR("swfUrl",      swf_url);
        NGX_RTMP_RELAY_STR_PAR("flashVer",    flash_ver);
        NGX_RTMP_RELAY_STR_PAR("pushObject",  push_object);
        NGX_RTMP_RELAY_STR_PAR("playPath",    play_path);
        NGX_RTMP_RELAY_NUM_PAR("live",        live);
        NGX_RTMP_RELAY_NUM_PAR("start",       start);
        NGX_RTMP_RELAY_NUM_PAR("stop",        stop);

#undef NGX_RTMP_RELAY_STR_PAR
#undef NGX_RTMP_RELAY_NUM_PAR

		if(n.len == sizeof("static") - 1 &&
			ngx_strncasecmp(n.data, (u_char*) "static", n.len) == 0 &&
			ngx_atoi(v.data, v.len))
		{
			is_static = 1;
			continue;
		}

        return "unsuppored parameter";
    }

	if (is_pull) {

		if(is_static) {

			if(target->app.len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "app missing in static pull declaration");
				return NGX_CONF_ERROR;
			}

			if(target->name.len == 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "stream name missing in static pull declaration");
				return NGX_CONF_ERROR;
			}

			ee = ngx_array_push(&racf->static_events);
			if(ee == NULL) {
				return NGX_CONF_ERROR;
			}

			e = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
			if(e == NULL) {
				return NGX_CONF_ERROR;
			}

			*ee = e;

			rs = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_relay_static_t));
			if( rs == NULL) {
				return NGX_CONF_ERROR;
			}

			if(target->tc_url.len == 0) {
				if(target->schema.len == 0) {
					target->schema.len = 7;
					target->schema.data = ngx_palloc(cf->pool, target->schema.len);
					last = ngx_cpymem(target->schema.data, "rtmp", 4);
				}

				target->tc_url.len = 7 + target->url.url.len;
				target->tc_url.data = ngx_palloc(cf->pool, target->tc_url.len);

				last = ngx_cpymem(target->tc_url.data, target->schema.data, target->schema.len);
				last = ngx_cpymem(last, "://", 3);
				last = ngx_cpymem(last, target->url.url.data, target->url.url.len);
			}

			//target->publishing = 1;
			rs->target = target;
			e->data = rs;
			e->log = &cf->cycle->new_log;
			e->handler = ngx_rtmp_relay_static_pull_connect;
		}

		target->idx = racf->pulls.nelts;
		target->publishing = 1;
		t = ngx_array_push(&racf->pulls);

    } else {

		if(is_static) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "static push is no allowed");
			return NGX_CONF_ERROR;
		}

        if (racf->pushes.nelts == NGX_RTMP_MAX_PUSH) {
            return "too many pushes";
        }

        target->idx = racf->pushes.nelts;
        t = ngx_array_push(&racf->pushes);
    }

    if (t == NULL) {
        return NGX_CONF_ERROR;
    }

    *t = target;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_relay_init_process(ngx_cycle_t *cycle)
{
	ngx_rtmp_core_main_conf_t  *cmcf = ngx_rtmp_core_main_conf;
	ngx_rtmp_core_srv_conf_t  **pcscf, *cscf;
	ngx_rtmp_core_app_conf_t  **pcacf, *cacf;
	ngx_rtmp_relay_app_conf_t  *racf;
	ngx_uint_t                  n, m, k, hash, workers;
	ngx_rtmp_relay_static_t    *rs;
	ngx_event_t               **pevent, *event;
	ngx_core_conf_t			   *ccf;

	if (cmcf == NULL) {
		return NGX_OK;
	}

	/* every worker get it's static  pulling by hash */

	ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
	workers = ccf->master ? ccf->worker_processes : 1;

	pcscf = cmcf->servers.elts;
	for (n = 0; n < cmcf->servers.nelts; ++n, ++pcscf) {

		cscf = *pcscf;
		pcacf = cscf->applications.elts;

		for (m = 0; m < cscf->applications.nelts; ++m, ++pcacf) {

			cacf = *pcacf;
			racf = cacf->app_conf[ngx_rtmp_relay_module.ctx_index];
			pevent = racf->static_events.elts;


			for (k = 0; k < racf->static_events.nelts; ++k, ++pevent) {
				event = *pevent;

				rs = event->data;

				hash = ngx_hash_key(rs->target->name.data, rs->target->name.len);
				if(hash % workers != (ngx_uint_t)ngx_process_slot) {
					continue;
				}
				
				rs->cscf = cscf;
				rs->cctx = *cscf->ctx;
				rs->cctx.app_conf = cacf->app_conf;

				ngx_post_event(event, &ngx_rtmp_init_queue);
			}
		}
	}

	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_relay_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t          *cmcf;
    ngx_rtmp_handler_pt                *h;
    ngx_rtmp_amf_handler_t             *ch;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);


    h = ngx_array_push(&cmcf->events[NGX_RTMP_HANDSHAKE_DONE]);
    *h = ngx_rtmp_relay_handshake_done;


    next_push = ngx_rtmp_push;
    ngx_rtmp_push = ngx_rtmp_relay_push;

    next_pull = ngx_rtmp_pull;
    ngx_rtmp_pull = ngx_rtmp_relay_pull;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_relay_close_stream;


    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_result");
    ch->handler = ngx_rtmp_relay_on_result;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "_error");
    ch->handler = ngx_rtmp_relay_on_error;

    ch = ngx_array_push(&cmcf->amf);
    ngx_str_set(&ch->name, "onStatus");
    ch->handler = ngx_rtmp_relay_on_status;

    return NGX_OK;
}
