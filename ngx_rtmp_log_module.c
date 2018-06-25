
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt  next_publish;
static ngx_rtmp_play_pt     next_play;
static ngx_rtmp_close_stream_pt     next_close_stream;


static ngx_int_t ngx_rtmp_log_postconfiguration(ngx_conf_t *cf);
static void *ngx_rtmp_log_create_main_conf(ngx_conf_t *cf);
static void * ngx_rtmp_log_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_log_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char * ngx_rtmp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char * ngx_rtmp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static char * ngx_rtmp_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops,
       ngx_array_t *args, ngx_uint_t s);


#define MAX_ACCESS_LOG_LINE_LEN     4096


typedef struct {
    ngx_str_t                   name;
    ngx_int_t                   index;
} ngx_rtmp_log_vars_op_t;


typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *ops; /* ngx_rtmp_log_vars_op_t */
} ngx_rtmp_log_fmt_t;


typedef struct {
    ngx_open_file_t            *file;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    ngx_msec_t                  trunc_timer;
    ngx_rtmp_log_fmt_t         *format;
    ngx_flag_t                  trunc_open;
} ngx_rtmp_log_t;


typedef struct {
    ngx_array_t                *logs; /* ngx_rtmp_log_t */
    ngx_uint_t                  off;
    ngx_flag_t                  relay_log;
} ngx_rtmp_log_app_conf_t;


typedef struct {
    ngx_array_t                 formats; /* ngx_rtmp_log_fmt_t */
    ngx_uint_t                  combined_used;
} ngx_rtmp_log_main_conf_t;


typedef struct {
    ngx_rtmp_session_t         *session;
    ngx_event_t                 event;
    ngx_rtmp_log_t             *log;
    ngx_msec_t                  log_time;
    uint64_t                    last_iobytes[6];
} ngx_rtmp_log_timer_ctx_t;

typedef struct {
    unsigned                    play:1;
    unsigned                    publish:1;
    u_char                      name[NGX_RTMP_MAX_NAME];
    u_char                      args[NGX_RTMP_MAX_ARGS];
    ngx_array_t                 timers; /* ngx_rtmp_log_timer_ctx_t */
} ngx_rtmp_log_ctx_t;


static ngx_str_t ngx_rtmp_access_log = ngx_string(NGX_HTTP_LOG_PATH);


static ngx_command_t  ngx_rtmp_log_commands[] = {

    { ngx_string("access_log"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE123,
      ngx_rtmp_log_set_log,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("log_format"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_2MORE,
      ngx_rtmp_log_set_format,
      NGX_RTMP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("relay_log"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_log_app_conf_t, relay_log),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_log_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_log_postconfiguration,         /* postconfiguration */
    ngx_rtmp_log_create_main_conf,          /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_log_create_app_conf,           /* create app configuration */
    ngx_rtmp_log_merge_app_conf             /* merge app configuration */
};


ngx_module_t  ngx_rtmp_log_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_log_module_ctx,               /* module context */
    ngx_rtmp_log_commands,                  /* module directives */
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


static ngx_str_t ngx_rtmp_combined_fmt =
    ngx_string("$connection_time \t$domain \t$local_addr \t$remote_addr \t$app \t$name \t"
               "$bandwidth_dynamic \t$in_bytes \t$out_bytes \t"
               "$scheme \t$ngx_role");


static void *
ngx_rtmp_log_create_main_conf(ngx_conf_t *cf)
{
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_log_fmt_t         *fmt;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_log_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&lmcf->formats, cf->pool, 4, sizeof(ngx_rtmp_log_fmt_t))
        != NGX_OK)
    {
        return NULL;
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NULL;
    }

    ngx_str_set(&fmt->name, "combined");

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_rtmp_log_vars_op_t));
    if (fmt->ops == NULL) {
        return NULL;
    }

    return lmcf;

}


static void *
ngx_rtmp_log_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_log_app_conf_t *lacf;

    lacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_log_app_conf_t));
    if (lacf == NULL) {
        return NULL;
    }

    lacf->relay_log = NGX_CONF_UNSET;

    return lacf;
}


static char *
ngx_rtmp_log_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_log_app_conf_t    *prev = parent;
    ngx_rtmp_log_app_conf_t    *conf = child;
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_rtmp_log_t             *log;

    ngx_conf_merge_value(conf->relay_log, prev->relay_log, 0);

    if (conf->logs || conf->off) {
        return NGX_OK;
    }

    conf->logs = prev->logs;
    conf->off = prev->off;

    if (conf->logs || conf->off) {
        return NGX_OK;
    }

    conf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_rtmp_log_t));
    if (conf->logs == NULL) {
        return NGX_CONF_ERROR;
    }

    log = ngx_array_push(conf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(log, sizeof(*log));

    log->file = ngx_conf_open_file(cf->cycle, &ngx_rtmp_access_log);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    log->disk_full_time = 0;
    log->error_log_time = 0;
    log->trunc_timer = 0;

    lmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_log_module);
    fmt = lmcf->formats.elts;

    log->format = &fmt[0];
    lmcf->combined_used = 1;

    return NGX_CONF_OK;
}


/*
 * access_log off;
 * access_log file;
 * access_log file format_name;
 * access_log file trunc=1m;
 * access_log file format_name trunc=1m;
 */
static char *
ngx_rtmp_log_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_log_app_conf_t    *lacf = conf;

    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_rtmp_log_t             *log;
    ngx_str_t                  *value, name, timer;
    ngx_uint_t                  n;
    ngx_flag_t                  format_configured;

    name.len = 0;
    format_configured = 0;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lacf->off = 1;
        return NGX_CONF_OK;
    }

    if (lacf->logs == NULL) {
        lacf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_rtmp_log_t));
        if (lacf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    log = ngx_array_push(lacf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(*log));

    lmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_log_module);

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    log->trunc_open = 1;

    for (n = 2; n < cf->args->nelts; ++n) {
        /* sizeof("trunc=") - 1 = 6 */
        if (ngx_memcmp("trunc=", value[n].data, 6) == 0) {
            if (ngx_memcmp("close", value[n].data + 6, 5) == 0) {
                log->trunc_open = 0;
            } else {
                timer.data = value[n].data + 6;
                timer.len = value[n].len - 6;
                log->trunc_timer = ngx_parse_time(&timer, 0);
            }

            if (log->trunc_timer == (ngx_msec_t) NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "unknown trunc timer format \"%V\"", &timer);
                return NGX_CONF_ERROR;
            }
        } else {
            if (format_configured) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                        "format name has been configured");
                return NGX_CONF_ERROR;
            }

            format_configured = 1;
            name = value[n];
        }
    }

    if (name.len == 0) {
        ngx_str_set(&name, "combined");
        lmcf->combined_used = 1;

    } else {
        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }
    }

    fmt = lmcf->formats.elts;
    for (n = 0; n < lmcf->formats.nelts; ++n, ++fmt) {
        if (fmt->name.len == name.len &&
            ngx_strncasecmp(fmt->name.data, name.data, name.len) == 0)
        {
            log->format = fmt;
            break;
        }
    }

    if (log->format == NULL) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "unknown log format \"%V\"",
                           &name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_log_set_format(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_log_main_conf_t   *lmcf = conf;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_str_t                  *value;
    ngx_uint_t                  i;

    value = cf->args->elts;

    if (cf->cmd_type != NGX_RTMP_MAIN_CONF) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "\"log_format\" directive can only be used on "
                           "\"rtmp\" level");
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == value[1].len &&
            ngx_strcmp(fmt[i].name.data, value[1].data) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate \"log_format\" name \"%V\"",
                               &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    fmt = ngx_array_push(&lmcf->formats);
    if (fmt == NULL) {
        return NGX_CONF_ERROR;
    }

    fmt->name = value[1];

    fmt->ops = ngx_array_create(cf->pool, 16, sizeof(ngx_rtmp_log_vars_op_t));
    if (fmt->ops == NULL) {
        return NGX_CONF_ERROR;
    }

    return ngx_rtmp_log_compile_format(cf, fmt->ops, cf->args, 2);
}


static char *
ngx_rtmp_log_compile_format(ngx_conf_t *cf, ngx_array_t *ops, ngx_array_t *args,
                            ngx_uint_t s)
{
    size_t                   i, len, len2;
    u_char                  *data, *d, c;
    ngx_uint_t               bracket;
    ngx_int_t                index;
    ngx_str_t               *value, var;
    ngx_rtmp_log_vars_op_t  *op;

    value = args->elts;

    for (; s < args->nelts; ++s) {
        i = 0;

        len = value[s].len;
        d = value[s].data;

        while (i < len) {

            data = &d[i];

            if (d[i] == '$') {
                if (++i == len) {
                    goto invalid;
                }

                if (d[i] == '{') {
                    bracket = 1;
                    if (++i == len) {
                        goto invalid;
                    }
                } else {
                    bracket = 0;
                }

                var.data = &d[i];

                for (var.len = 0; i < len; ++i, ++var.len) {
                    c = d[i];

                    if (c == '}' && bracket) {
                        ++i;
                        bracket = 0;
                        break;
                    }

                    if ((c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') ||
                        (c == '_'))
                    {
                        continue;
                    }

                    break;
                }

                if (bracket) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "missing closing bracket in \"%V\"",
                                       &var);
                    return NGX_CONF_ERROR;
                }

                if (var.len == 0) {
                    goto invalid;
                }

                index = ngx_rtmp_get_variable_index(cf, &var);
                if (index == NGX_ERROR) {
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                                       "log: can't get the index about \"%V\"",
                                       &var);
                    return NGX_CONF_ERROR;
                }

                op = ngx_array_push(ops);
                if (op == NULL) {
                    return NGX_CONF_ERROR;
                }
                ngx_memzero(op, sizeof(*op));
                op->index = index;
                op->name = var;

                continue;
            }

            ++i;

            while (i < len && d[i] != '$') {
                ++i;
            }

            len2 = &d[i] - data;

            if (len2) {
                op = ngx_array_push(ops);
                if (op == NULL) {
                    return NGX_CONF_ERROR;
                }
                ngx_memzero(op, sizeof(*op));
                op->index = -1;
                op->name.len = len2;
                op->name.data = data;
            }
        }
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%s\"", data);

    return NGX_CONF_ERROR;
}


static ngx_rtmp_log_ctx_t *
ngx_rtmp_log_set_names(ngx_rtmp_session_t *s, u_char *name, u_char *args)
{
    ngx_rtmp_log_ctx_t         *ctx;
    ngx_rtmp_log_app_conf_t    *lacf;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);

        if (lacf->logs) {
            if (ngx_array_init(&ctx->timers, s->connection->pool,
                lacf->logs->nelts, sizeof(ngx_rtmp_log_timer_ctx_t)) != NGX_OK)
            {
                return NULL;
            }
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_log_module);
    }

    ngx_memcpy(ctx->name, name, NGX_RTMP_MAX_NAME);
    ngx_memcpy(ctx->args, args, NGX_RTMP_MAX_ARGS);

    return ctx;
}


static void
ngx_rtmp_log_write(ngx_rtmp_session_t *s, ngx_rtmp_log_t *log, u_char *buf,
                   size_t len)
{
    u_char *name;
    time_t  now;
    ssize_t n;
    int     err;

    err = 0;
    name = log->file->name.data;
    n = ngx_write_fd(log->file->fd, buf, len);

    if (n == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (n == -1) {
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);
            log->error_log_time = now;
        }
    }

    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);
        log->error_log_time = now;
    }
}


static void
ngx_rtmp_log_pre_write(ngx_rtmp_log_timer_ctx_t *ltctx)
{
    ngx_rtmp_log_vars_op_t     *op;
    u_char                     *p, *q;
    ngx_uint_t                  n;
    ngx_rtmp_variable_value_t  *vv;
    ngx_str_t                   value_v;
    uint64_t                    last_bytes;
    ngx_str_t                   name;
    ngx_rtmp_session_t         *s;
    ngx_rtmp_log_t             *log;


    s = ltctx->session;
    log = ltctx->log;
    s->log_time = ltctx->log_time;

    if (ngx_time() == log->disk_full_time) {
        /* FreeBSD full disk protection;
         * nginx http logger does the same */
        return;
    }

    p = ngx_pnalloc(s->connection->pool, MAX_ACCESS_LOG_LINE_LEN);
    if (p == NULL) {
        return;
    }

    op = log->format->ops->elts;
    q = p;

    for (n = 0; n < log->format->ops->nelts; ++n, ++op) {
        if (op->index != -1) {
            vv = ngx_rtmp_get_indexed_variable(s, op->index);
            if (vv == NULL || vv->not_found) {
                ngx_log_error(NGX_LOG_EMERG, s->connection->log, 0,
                              "log: \"%V\" info is not found", &op->name);
                return;
            }

            name = op->name;
#define NGX_RTMP_LOG_BYTES_REWRITE(type, bw_loc)                               \
            if (name.len == sizeof(type) - 1                                   \
                && ngx_strncasecmp(name.data, (u_char *) type, name.len) == 0) \
            {                                                                  \
                last_bytes = ltctx->last_iobytes[bw_loc];                      \
                ltctx->last_iobytes[bw_loc] = ngx_atoi(vv->data, vv->len);     \
                vv->len = ngx_sprintf(vv->data, "%uL",                         \
                        ltctx->last_iobytes[bw_loc] - last_bytes) - vv->data;  \
            }

            NGX_RTMP_LOG_BYTES_REWRITE("in_bytes", 0);
            NGX_RTMP_LOG_BYTES_REWRITE("out_bytes", 1);
            NGX_RTMP_LOG_BYTES_REWRITE("bytes", 2);
            NGX_RTMP_LOG_BYTES_REWRITE("weighted_in_bytes", 3);
            NGX_RTMP_LOG_BYTES_REWRITE("weighted_out_bytes", 4);
            NGX_RTMP_LOG_BYTES_REWRITE("weighted_bytes", 5);

#undef NGX_RTMP_LOG_BYTES_REWRITE

            value_v.len = vv->len;
            value_v.data = vv->data;
        } else {
            value_v.len = op->name.len;
            value_v.data = op->name.data;
        }

        if (value_v.len == 0) {
            p = ngx_sprintf(p, "%s", (u_char *)"-");
        } else {
            p = ngx_sprintf(p, "%V", &value_v);
        }

        if ((p - q) >= MAX_ACCESS_LOG_LINE_LEN) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "Access line len %d greater than %d",
                    p - q, MAX_ACCESS_LOG_LINE_LEN);
            ngx_rtmp_finalize_session(s);

            return;
        }

    }

    ngx_linefeed(p);

    ltctx->log_time = ngx_current_msec;

    ngx_rtmp_log_write(s, log, q, p-q);
}

static void
ngx_rtmp_log_trunc_timer(ngx_event_t *ev)
{
    ngx_rtmp_log_timer_ctx_t   *ltctx;
    ngx_rtmp_log_t             *log;
    ngx_msec_t                  t;

    ltctx = ev->data;

    log = ltctx->log;

    ngx_rtmp_log_pre_write(ltctx);

    t = log->trunc_timer - ngx_current_msec % log->trunc_timer;
    ngx_add_timer(ev, t);
}

static void
ngx_rtmp_log_add_trunc_timer(ngx_rtmp_session_t *s, ngx_rtmp_log_ctx_t *ctx,
        ngx_rtmp_log_t *log)
{
    ngx_rtmp_log_timer_ctx_t   *ltctx;
    ngx_event_t                *e;
    ngx_msec_t                  t;

    ltctx = ngx_array_push(&ctx->timers);
    ngx_memzero(ltctx, sizeof(ngx_rtmp_log_timer_ctx_t));
    ltctx->session = s;
    ltctx->log = log;
    e = &ltctx->event;

    e->data = ltctx;
    e->log = s->connection->log;
    e->handler = ngx_rtmp_log_trunc_timer;

    if (log->trunc_open == 1 && log->trunc_timer != 0) {
        t = log->trunc_timer - ngx_current_msec % log->trunc_timer;
        ngx_add_timer(e, t);
    }
}

static ngx_int_t
ngx_rtmp_log_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_ctx_t         *ctx;
    ngx_uint_t                  i;

    if (s->interprocess) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL) {
        goto next;
    }

    if (s->relay && !lacf->relay_log) {
        goto next;
    }

    ctx = ngx_rtmp_log_set_names(s, v->name, v->args);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->publish) { /* avoid multi push */
        goto next;
    }

    ctx->publish = 1;

    if (lacf->logs == NULL) {
        goto next;
    }

    log = lacf->logs->elts;
    for (i = 0; i < lacf->logs->nelts; ++i, ++log) {
        ngx_rtmp_log_add_trunc_timer(s, ctx, log);
    }

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_log_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_t             *log;
    ngx_rtmp_log_ctx_t         *ctx;
    ngx_uint_t                  i;

    if (s->interprocess) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL) {
        goto next;
    }

    if (s->relay && !lacf->relay_log) {
        goto next;
    }

    ctx = ngx_rtmp_log_set_names(s, v->name, v->args);
    if (ctx == NULL) {
        goto next;
    }

    if (ctx->play) { /* avoid mulit pull */
        goto next;
    }

    ctx->play = 1;

    if (lacf->logs == NULL) {
        goto next;
    }

    log = lacf->logs->elts;
    for (i = 0; i < lacf->logs->nelts; ++i, ++log) {
        ngx_rtmp_log_add_trunc_timer(s, ctx, log);
    }

next:
    return next_play(s, v);
}


static ngx_int_t
ngx_rtmp_log_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_log_app_conf_t    *lacf;
    ngx_rtmp_log_ctx_t         *ctx;
    ngx_rtmp_log_timer_ctx_t   *ltctx;
    ngx_uint_t                  i;

    if (s->interprocess) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_log_module);
    if (lacf == NULL || lacf->off || lacf->logs == NULL) {
        goto next;
    }

    if (s->relay && !lacf->relay_log) {
        goto next;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_log_module);

    if (ctx == NULL) {
        goto next;
    }

    ltctx = ctx->timers.elts;
    for (i = 0; i < ctx->timers.nelts; ++i, ++ltctx) {
        ngx_rtmp_log_pre_write(ltctx);

        if (ltctx->event.timer_set) {
            ngx_del_timer(&ltctx->event);
        }
    }

next:
    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_log_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_log_main_conf_t   *lmcf;
    ngx_array_t                 a;
    ngx_rtmp_log_fmt_t         *fmt;
    ngx_str_t                  *value;

    lmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_log_module);
    if (lmcf->combined_used) {
        if (ngx_array_init(&a, cf->pool, 1, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        value = ngx_array_push(&a);
        if (value == NULL) {
            return NGX_ERROR;
        }

        *value = ngx_rtmp_combined_fmt;
        fmt = lmcf->formats.elts;

        if (ngx_rtmp_log_compile_format(cf, fmt->ops, &a, 0)
            != NGX_CONF_OK)
        {
            return NGX_ERROR;
        }
    }

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_log_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_log_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_log_close_stream;

    return NGX_OK;
}
