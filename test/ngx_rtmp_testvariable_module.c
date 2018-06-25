/* for test rtmp variables */

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"


static ngx_rtmp_publish_pt                  next_publish;


static void *ngx_rtmp_testvariable_create_app_conf(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_testvariable_init(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_testvariable_add_variable(ngx_conf_t *cf);

static char *ngx_rtmp_testvariable_echo(ngx_conf_t *cf, ngx_command_t *cmd,
       void *conf);
static ngx_int_t ngx_rtmp_testvariable_echo_string(ngx_rtmp_session_t *s,
       ngx_rtmp_variable_value_t *v, uintptr_t data);


typedef struct {
    int             variable_index;
    ngx_str_t       variable;
} ngx_rtmp_testvariable_app_conf_t;


static ngx_rtmp_variable_t  ngx_rtmp_testvariable = {
    ngx_string("test_variable"), NULL,
    ngx_rtmp_testvariable_echo_string, 0, 0, 0
};


static ngx_command_t  ngx_rtmp_testvariable_commands[] = {

    { ngx_string("test_variable_echo"),
      NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_rtmp_testvariable_echo,
      NGX_RTMP_APP_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_testvariable_module_ctx = {
    ngx_rtmp_testvariable_add_variable,     /* preconfiguration */
    ngx_rtmp_testvariable_init,             /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_testvariable_create_app_conf,  /* create app configuration */
    NULL                                    /* merge app configuration */
};


ngx_module_t  ngx_rtmp_testvariable_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_testvariable_module_ctx,      /* module context */
    ngx_rtmp_testvariable_commands,         /* module directives */
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
ngx_rtmp_testvariable_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_testvariable_app_conf_t    *tacf;

    tacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_testvariable_app_conf_t));
    if (tacf == NULL) {
        return NULL;
    }

    tacf->variable_index = -1;

    return tacf;
}


static ngx_int_t
ngx_rtmp_testvariable_add_variable(ngx_conf_t *cf)
{
    ngx_rtmp_variable_t                 *v;

    v= ngx_rtmp_add_variable(cf, &ngx_rtmp_testvariable.name,
            ngx_rtmp_testvariable.flags);
    if (v == NULL) {
        return NGX_ERROR;
    }

    *v = ngx_rtmp_testvariable;

    return NGX_OK;
}


static char *
ngx_rtmp_testvariable_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_rtmp_testvariable_app_conf_t    *tacf = conf;
    ngx_str_t                           *value;

    value = cf->args->elts;

    if (cf->args->nelts != 2) {
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] != '$') {
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    tacf->variable_index = ngx_rtmp_get_variable_index(cf, &value[1]);
    if (tacf->variable_index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    tacf->variable = value[1];

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_rtmp_testvariable_echo_string(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, sizeof("Hello, world~") + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "Hello, world~") - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}



static ngx_int_t
ngx_rtmp_testvariable_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_testvariable_app_conf_t    *tacf;
    ngx_rtmp_variable_value_t           *vv;
    ngx_str_t                            v_value;

    tacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_testvariable_module);
    if (tacf == NULL) {
        goto next;
    }

    if (tacf->variable_index == -1) {
        goto next;
    }

    vv = ngx_rtmp_get_indexed_variable(s, tacf->variable_index);
    if (vv == NULL || vv->not_found) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "testvariable: not found variable %V", &tacf->variable);
        goto next;
    }

    v_value.len = vv->len;
    v_value.data = vv->data;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "testvariable: the variable '%V''s value is '%V'",
            &tacf->variable, &v_value);

next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_testvariable_init(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_testvariable_publish;

    return NGX_OK;
}
