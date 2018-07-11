#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_qqflv_module.h"
#include "../http/ngx_http_set_header.h"


static ngx_int_t ngx_http_qqflv_init_process(ngx_cycle_t *cycle);

/*static ngx_command_t ngx_http_qqflv_commands[] = {

	{ ngx_string("qqflv_playback"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_qqflv_loc_conf_t, enable),
		NULL },

	{ ngx_string("qqflv_path"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_qqflv_main_conf_t, path),
		NULL },

	{ ngx_string("qqflv_channel_map"),
		NGX_HTTP_MAIN_CONF| NGX_CONF_2MORE,
		ngx_http_qqflv_channel_map,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};*/

static ngx_http_module_t  ngx_http_qqflv_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,         	   /* postconfiguration */

	NULL,    /* create main configuration */
	NULL,      /* init main configuration */

	NULL,                              /* create server configuration */
	NULL,                              /* merge server configuration */

	NULL,     /* create location configuration */
	NULL	   /* merge location configuration */
};

ngx_module_t  ngx_http_qqflv_module = {
	NGX_MODULE_V1,
	&ngx_http_qqflv_module_ctx,         /* module context */
	NULL,            /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_qqflv_init_process,            /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


/*static ngx_int_t
ngx_http_qqflv_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_qqflv_handler;

	return NGX_OK;
}*/

static ngx_int_t ngx_http_qqflv_init_process(ngx_cycle_t *cycle)
{
	/*if( cntv_main_conf == NULL || cntv_main_conf->path.len == 0) {
		return NGX_OK;
	}*/
	

	return NGX_OK;
}
