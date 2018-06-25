
#include <ngx_config.h>
#include <ngx_core.h>
#include <math.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_dynamic_conf.h"
#include "ngx_rtmp_dynamic.h"


typedef uint32_t (* ngx_rtmp_timestamp_fix_pt)(ngx_rtmp_session_t *s,
        uint32_t current_time, ngx_flag_t if_in);


static void * ngx_rtmp_timestamp_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_timestamp_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static char * ngx_rtmp_timestamp_fix_parse(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);

static uint32_t ngx_rtmp_timestamp_fix_jitter(ngx_rtmp_session_t *s,
        uint32_t current_time, ngx_flag_t if_in);
static uint32_t ngx_rtmp_timestamp_zero_play(ngx_rtmp_session_t *s,
        uint32_t current_time, ngx_flag_t if_in);


#define ABS(x)  ((uint32_t)abs(x))


static ngx_rtmp_timestamp_fix_pt ngx_rtmp_timestamp_fix_in_l[] =
{
    ngx_rtmp_timestamp_fix_jitter
};
static ngx_rtmp_timestamp_fix_pt ngx_rtmp_timestamp_fix_out_l[] =
{
    ngx_rtmp_timestamp_fix_jitter,
    ngx_rtmp_timestamp_zero_play
};


typedef struct {
    uint32_t                    last_time;
    uint32_t                    last_change;
    uint32_t                    zero_delay;
    ngx_flag_t                  first_play;
} ngx_rtmp_timestamp_ctx_t;

typedef struct {
    ngx_msec_t                  timestamp_interval;
    ngx_flag_t                  in_jitter;
    ngx_flag_t                  out_jitter;
    ngx_flag_t                  zero_play;
} ngx_rtmp_timestamp_app_conf_t;


static ngx_command_t  ngx_rtmp_timestamp_commands[] = {

    { ngx_string("timestamp_fix_in"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_timestamp_fix_parse,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("timestamp_fix_out"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_1MORE,
      ngx_rtmp_timestamp_fix_parse,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("timestamp_interval"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_timestamp_app_conf_t, timestamp_interval),
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_timestamp_module_ctx = {
    NULL,                                   /* preconfiguration */
    NULL,                                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_timestamp_create_app_conf,     /* create app configuration */
    ngx_rtmp_timestamp_merge_app_conf       /* merge app configuration */
};


ngx_module_t  ngx_rtmp_timestamp_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_timestamp_module_ctx,         /* module context */
    ngx_rtmp_timestamp_commands,            /* module directives */
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


static void *
ngx_rtmp_timestamp_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_timestamp_app_conf_t    *tacf;

    tacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_timestamp_app_conf_t));
    if (tacf == NULL) {
        return NULL;
    }

    tacf->timestamp_interval = NGX_CONF_UNSET_MSEC;
    tacf->in_jitter = NGX_CONF_UNSET;
    tacf->out_jitter = NGX_CONF_UNSET;
    tacf->zero_play = NGX_CONF_UNSET;

    return tacf;
}


static char *
ngx_rtmp_timestamp_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_timestamp_app_conf_t   *prev = parent;
    ngx_rtmp_timestamp_app_conf_t   *conf = child;

    ngx_conf_merge_msec_value(conf->timestamp_interval,
            prev->timestamp_interval, 20);
    ngx_conf_merge_value(conf->in_jitter, prev->in_jitter, 0);
    ngx_conf_merge_value(conf->out_jitter, prev->out_jitter, 0);
    ngx_conf_merge_value(conf->zero_play, prev->zero_play, 0);

    return NGX_CONF_OK;
}


static char *
ngx_rtmp_timestamp_fix_parse(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value, n;
    ngx_rtmp_timestamp_app_conf_t   *tacf;
    ngx_int_t                        if_in;
    ngx_uint_t                       i;

    value = cf->args->elts;

    tacf = ngx_rtmp_conf_get_module_app_conf(cf, ngx_rtmp_timestamp_module);

    if_in = (value[0].data[14] == 'i');

    for (i = 1; i < cf->args->nelts; ++i) {
        n.data = value[i].data;
        n.len = value[i].len;

#define NGX_RTMP_TIMESTAMP_STR_PAR(name, var)                                  \
        if (n.len == sizeof(name) - 1                                           \
            && ngx_strncasecmp(n.data, (u_char *) name, n.len) == 0)           \
        {                                                                      \
            if (tacf->var != NGX_CONF_UNSET) {                                 \
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,                       \
                        "%s in %V is duplicate", name, &value[0]);             \
                return NGX_CONF_ERROR;                                         \
            }                                                                  \
            tacf->var = 1;                                                     \
            continue;                                                          \
        }

        if (if_in) {
            NGX_RTMP_TIMESTAMP_STR_PAR("jitter",        in_jitter);
        } else {
            NGX_RTMP_TIMESTAMP_STR_PAR("jitter",        out_jitter);
            NGX_RTMP_TIMESTAMP_STR_PAR("zero_play",     zero_play);
        }

#undef NGX_RTMP_TIMESTAMP_STR_PAR

        return "unsupported parameter";
    }

    return NGX_CONF_OK;
}


static uint32_t
ngx_rtmp_timestamp_fix_jitter(ngx_rtmp_session_t *s, uint32_t current_time,
        ngx_flag_t if_in)
{
    ngx_rtmp_timestamp_app_conf_t   *tacf;
    ngx_rtmp_live_app_dconf_t       *ldcf;
    ngx_rtmp_timestamp_ctx_t        *ctx;
#if (NGX_DEBUG)
    uint32_t                         original_time;
#endif

    tacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_timestamp_module);
    if ((if_in && !tacf->in_jitter) ||
        (!if_in && !tacf->out_jitter) ||
        s->interprocess)
    {
        return current_time;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_timestamp_module);
    if (ctx == NULL) {
        return current_time;
    }

    if (ctx->last_time == 0) {
        goto done;
    }

    ldcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    if (ABS(current_time - ctx->last_time) < ldcf->sync) {
        goto done;
    }

#if (NGX_DEBUG)
    original_time = current_time;
#endif
    if (ABS(current_time - ctx->last_time - ctx->last_change) > ldcf->sync)
    {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "timestamp: jitter %d is bigger than %d, "
                "the timestamp is fixed from %d(%d) to %d, "
                "the last time is %d, last change is %d",
                ABS(current_time - ctx->last_time - ctx->last_change),
                ldcf->sync, current_time, current_time - ctx->last_change,
                ctx->last_time + tacf->timestamp_interval,
                ctx->last_time, ctx->last_change);

        ctx->last_change = current_time - ctx->last_time;
        current_time = ctx->last_time + tacf->timestamp_interval;
    } else {
        current_time -= ctx->last_change;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "timestamp: because jitter is too big, "
            "the timestamp is fixed from %d to %d, "
            "the last_time = %d, last_change = %d",
            original_time, current_time, ctx->last_time, ctx->last_change);

done:
    ctx->last_time = current_time;
    return current_time;
}


static uint32_t
ngx_rtmp_timestamp_zero_play(ngx_rtmp_session_t *s, uint32_t current_time,
        ngx_flag_t if_in)
{
    ngx_rtmp_timestamp_app_conf_t   *tacf;
    ngx_rtmp_timestamp_ctx_t        *ctx;

    tacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_timestamp_module);
    if (if_in || (!if_in && !tacf->zero_play) || s->interprocess) {
        return current_time;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_timestamp_module);
    if (ctx == NULL) {
        return current_time;
    }

    if (ctx->first_play && current_time != 0) {
        ctx->first_play = 0;
        ctx->zero_delay = current_time;
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "timestamp: session will play from tiemstamp zero, "
                "the diff is %d", ctx->zero_delay);
    }

    if (current_time < ctx->zero_delay) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "timestamp: current timestamp %d is less than zero_delay %d",
                current_time, ctx->zero_delay);
        current_time = 0;
    } else {
        current_time -= ctx->zero_delay;
    }

    return current_time;
}


uint32_t
ngx_rtmp_timestamp_fix(ngx_rtmp_session_t *s, uint32_t current_time,
        ngx_flag_t if_in)
{
    ngx_rtmp_timestamp_app_conf_t   *tacf;
    ngx_rtmp_timestamp_ctx_t        *ctx;
    ngx_rtmp_timestamp_fix_pt       *fix_list;
    ngx_uint_t                       i, array_size;

    tacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_timestamp_module);
    if (tacf == NULL) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "timestamp: timestamp app conf is NULL");
        return current_time;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_timestamp_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool,
            sizeof(ngx_rtmp_timestamp_ctx_t));
        if (ctx == NULL) {
            return current_time;
        }
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_timestamp_module);
        ctx->first_play = 1;
    }

    if (if_in) {
        fix_list = ngx_rtmp_timestamp_fix_in_l;
        array_size = sizeof(ngx_rtmp_timestamp_fix_in_l) /
                sizeof(ngx_rtmp_timestamp_fix_in_l[0]);
    } else {
        fix_list = ngx_rtmp_timestamp_fix_out_l;
        array_size = sizeof(ngx_rtmp_timestamp_fix_out_l) /
                sizeof(ngx_rtmp_timestamp_fix_out_l[0]);
    }

    for (i = 0; i < array_size; i++) {
        current_time = fix_list[i](s, current_time, if_in);
    }

    return current_time;
}
