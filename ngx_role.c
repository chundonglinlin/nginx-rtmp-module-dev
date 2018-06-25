/*
 * Copyright (C) Huang Xinjie huangxinjie@dnion.com
 */


#include "ngx_role.h"


static char *ngx_role_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_str_t  ngx_role;


static ngx_command_t  ngx_role_commands[] = {

    { ngx_string("ngx_role"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_role_block,
      0,
      0,
      NULL },

      ngx_null_command
};


ngx_core_module_t  ngx_role_module_ctx = {
    ngx_string("ngx_role"),
    NULL,
    NULL
};


ngx_module_t  ngx_role_module = {
    NGX_MODULE_V1,
    &ngx_role_module_ctx,                   /* module context */
    ngx_role_commands,                      /* module directives */
    NGX_CORE_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_role_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t      *role;

    role = cf->args->elts;

    ngx_role = role[1];

    return NGX_CONF_OK;
}
