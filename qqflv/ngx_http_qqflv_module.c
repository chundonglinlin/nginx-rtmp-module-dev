#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_qqflv_module.h"
#include "../http/ngx_http_set_header.h"


static ngx_int_t ngx_http_qqflv_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_qqflv_commands[] = {

    { ngx_string("qqflv_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE3,
      ngx_http_qqflv_zone,
      0,
      0,
      NULL
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_qqflv_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_qqflv_init,         	   /* postconfiguration */

	ngx_http_qqflv_create_main_conf,    /* create main configuration */
	ngx_http_qqflv_init_main_conf,      /* init main configuration */

	NULL,                              /* create server configuration */
	NULL,                              /* merge server configuration */

	ngx_http_qqflv_create_loc_conf,     /* create location configuration */
	ngx_http_qqflv_merge_loc_conf	   /* merge location configuration */
};

ngx_module_t  ngx_http_qqflv_module = {
	NGX_MODULE_V1,
	&ngx_http_qqflv_module_ctx,         /* module context */
	ngx_http_qqflv_commands,            /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,            /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static void *
ngx_http_req_status_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_qqflv_main_conf_t   *qmcf;

    qmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_qqflv_main_conf_t));
    if (qmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&qmcf->zones, cf->pool, 4,
                sizeof(ngx_http_qqflv_main_conf_t *)) != NGX_OK)
    {
        return NULL;
    }

	//main_conf = NULL;

    return rmcf;
}

static char *
ngx_http_qqflv_init_main_conf(ngx_conf_t *cf, void *conf)
{
  //  ngx_http_req_status_main_conf_t *qmcf = conf;

 //   ngx_conf_init_msec_value(rmcf->interval, 3000);
  //  ngx_conf_init_value(rmcf->lock_time, 10);

    return NGX_CONF_OK;
}

static void *
ngx_http_qqflv_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_qqflv_loc_conf_t *qlcf;

    qlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_qqflv_loc_conf_t));
    if (qlcf == NULL) {
        return NULL;
    }

    qlcf->parent = NGX_CONF_UNSET_PTR;

    return qlcf;
}

static char *
ngx_http_qqflv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_qqflv_loc_conf_t *prev = parent;
    ngx_http_qqflv_loc_conf_t *conf = child;
    ngx_http_qqflv_loc_conf_t *rlcf;

    if (conf->parent == NGX_CONF_UNSET_PTR){
        rlcf = prev;

        if (rlcf->parent == NGX_CONF_UNSET_PTR) {
            rlcf->parent = NULL;
        } else {
            while (rlcf->parent && rlcf->req_zones.nelts == 0) {
                rlcf = rlcf->parent;
            }
        }

        conf->parent = rlcf->req_zones.nelts ? rlcf : NULL;
    }

    return NGX_CONF_OK;
}
static void ngx_qq_backdelay_timeout_handler(ngx_event_t *event)
{
	uint32_t								 *timestamp;
	ngx_str_t                   			 *channel_name, *path;
	ngx_map_node_t							 *node;
	ngx_qq_flv_index_t                       *qq_flv_index;
	ngx_qq_flv_block_index_t                 *qq_flv_block_index;
	ngx_queue_t								 *tq;

	channel_name = (ngx_str_t *) event->data;
	timestamp = (uint32_t *) event->data + sizeof(ngx_str_t);
	path = (ngx_str_t *) event->data + sizeof(ngx_str_t) + sizeof(uint32_t);

	ngx_delete_file(path->data);

	node = ngx_map_find(&ngx_qq_flv_channnel_map, (intptr_t) &channel_name);
    if (node == NULL) {
        return ;
    }
    qq_flv_index = (ngx_qq_flv_index_t *)
            ((char *) node - offsetof(ngx_qq_flv_index_t, node));
    if (qq_flv_index == NULL) {
        return ;
    }

    for (tq = ngx_queue_head(&qq_flv_index->index_queue); tq != ngx_queue_sentinel(&qq_flv_index->index_queue);
    		tq = ngx_queue_next(tq))
    {
		qq_flv_block_index = ngx_queue_data(tq, ngx_qq_flv_block_index_t, q);
		if (qq_flv_block_index->timestamp > timestamp) {
			break;
		}
		
    }


}


static ngx_int_t
ngx_http_qqflv_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                      len;
    ngx_http_qqflv_zone_t *ctx = shm_zone->data;
    ngx_http_qqflv_zone_t *octx = data;

    if (octx){
        if (ngx_strcmp(&octx->key.value, &ctx->key.value) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                    "qqflv \"%V\" uses the \"%V\" variable "
                    "while previously it used the \"%V\" variable",
                    &shm_zone->shm.name, &ctx->key.value, &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

    if (shm_zone->shm.exists){
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_qqflv_sh_t));
    if (ctx->sh == NULL){
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh; ngx_cmp_str);

    ngx_map_init(&ctx->sh->map, ngx_map_hash_str, ngx_cmp_str);

    //ngx_queue_init(&ctx->sh->queue);

    //ctx->sh->expire_lock = 0;

    len = sizeof("in qqflv zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in req_status zone \"%V\"%Z",
            &shm_zone->shm.name);

    return NGX_OK;
}

static char *ngx_http_qqflv_zone(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
{
    ssize_t                             size;
    ngx_str_t                          *value;
    ngx_http_qqflv_zone_t         *ctx, **pctx;
    ngx_http_qqflv_conf_t         *rmcf;
    ngx_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    size = ngx_parse_size(&value[3]);

    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "invalid size of %V \"%V\"", &cmd->name, &value[3]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%V \"%V\" is too small", &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_qqflv_zone_t));
    if (ctx == NULL){
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ctx->shm_zone = ngx_shared_memory_add(cf, &value[1], size,
            &ngx_http_qqflv_module);
    if (ctx->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ctx->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "%V \"%V\" is already bound",
                &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    ctx->shm_zone->init = ngx_http_qqflv_init_zone;
    ctx->shm_zone->data = ctx;

    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_qqflv_module);

    pctx = ngx_array_push(&rmcf->zones);

    if (pctx == NULL){
        return NGX_CONF_ERROR;
    }

    *pctx = ctx;

    return NGX_CONF_OK;
}

ngx_map_t                            ngx_qq_flv_channnel_map;
ngx_event_t							 ngx_qq_flv_channnel_event;
static ngx_int_t ngx_http_qqflv_init(ngx_conf_t *cf)
{
	//ngx_map_init(&ngx_qq_flv_channnel_map, ngx_map_hash_str, ngx_cmp_str);
	//ngx_qq_flv_channnel_event.handler = ngx_qq_backdelay_timeout_handler;
	//ngx_add_timer(ngx_qq_backdelay_timeout_handler);
	/*if( cntv_main_conf == NULL || cntv_main_conf->path.len == 0) {
		return NGX_OK;
	}*/
	

	return NGX_OK;
}
