#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_qqflv_module.h"
#include "../http/ngx_http_set_header.h"


static ngx_int_t ngx_http_qqflv_init(ngx_conf_t *cf);
static void * ngx_http_qqflv_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_qqflv_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_http_qqflv_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_qqflv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_qqflv_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_qqflv_read_index_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_qqflv_read_index(ngx_http_qqflv_main_conf_t *qmcf);

static ngx_command_t ngx_http_qqflv_commands[] = {

    { ngx_string("qqflv_index_path"),
      NGX_RTMP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_qqflv_main_conf_t, path),
      NULL 
    },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_qqflv_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,         	                       /* postconfiguration */

	ngx_http_qqflv_create_main_conf,       /* create main configuration */
	ngx_http_qqflv_init_main_conf,         /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	ngx_http_qqflv_create_loc_conf,        /* create location configuration */
	ngx_http_qqflv_merge_loc_conf	       /* merge location configuration */
};

ngx_module_t  ngx_http_qqflv_module = {
	NGX_MODULE_V1,
	&ngx_http_qqflv_module_ctx,            /* module context */
	ngx_http_qqflv_commands,               /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_qqflv_init_process,           /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static void *
ngx_http_qqflv_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_qqflv_main_conf_t   *qmcf;

    qmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_qqflv_main_conf_t));
    if (qmcf == NULL) {
        return NULL;
    }    

	//main_conf = NULL;

    return qmcf;
}

static char *
ngx_http_qqflv_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_qqflv_main_conf_t *qmcf = conf;

    qmcf->pool = ngx_create_pool(100 * 1024 * 1024, cf->log);

    if(qmcf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    if (qmcf->path.len > 0 && qmcf->path.data[qmcf->path.len - 1] == '/') {
	    qmcf->path.len -= 1;
	}

    ngx_map_init(&qmcf->channel_map, ngx_map_hash_str, ngx_cmp_str);
    ngx_queue_init(&qmcf->idle_block_index);

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
		if (qq_flv_block_index->timestamp > *timestamp) {
			break;
		}		
    }
}

static ngx_map_node_t *
ngx_http_qqflv_create_channel(ngx_str_t channel_name, uint32_t backdelay, 
							unsigned buname, ngx_map_t *channel_map, ngx_pool_t *pool)
{
    ngx_qq_flv_index_t                       *qq_flv_index;
    qq_flv_index = ngx_palloc(pool, sizeof(ngx_qq_flv_index_t));
    qq_flv_index->buname = buname ? 1 : 0;
    if (qq_flv_index->buname) {
        qq_flv_index->backdelay = (backdelay == 0) ? 15 : backdelay;
    }
    else {
        qq_flv_index->backdelay = (backdelay == 0) ? 45 : backdelay;
    }
    qq_flv_index->channel_name = channel_name;
    ngx_queue_init(&qq_flv_index->index_queue);
    qq_flv_index->node.raw_key = (intptr_t) &qq_flv_index->channel_name;
    ngx_map_insert(channel_map, &qq_flv_index->node, 0);
    return NGX_OK;
}

static ngx_int_t
ngx_http_qqflv_read_index_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
	u_char                                   *left, *last, *p;
    ngx_str_t                                 channel_name, timestamp, flv_path;
    ngx_qq_flv_index_t                       *qq_flv_index;
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_file_t                                file;
    u_char                                    buf[NGX_QQ_FLV_INDEX_SIZE];
    off_t                                     file_size;
    ngx_map_node_t                           *node;
    ngx_map_t                                *channel_map;
    ngx_uint_t                                i;
    ngx_http_qqflv_main_conf_t               *qmcf;
    ngx_queue_t                              *tq;

    qmcf = ctx->data;

    p = path->data;
    left = path->data;
    last = path->data + path->len;
    for (; p != last; p++) {
        if (*p == '/') {
            left = p;
        }
        if (*p == '-' && *left == '/') {
            channel_name.data = left + 1;
            channel_name.len = p - left - 1;
            left = p;
        }
        if (*p == '.') {
            if (*left == '-') {
                timestamp.data = left + 1;
                timestamp.len = p - left - 1;
            }
            left = p;
        }
    }
    if (channel_name.len == 0 || timestamp.len == 0) {
        return NGX_OK;
    }

    printf("%s-%s\n", channel_name.data, timestamp.data);

    if (ngx_memcmp(left, ".index", last - left) != 0) {
        return NGX_OK;
    }

    flv_path.data = path->data;
    flv_path.len = path->len - 5;

    channel_map = &qmcf->channel_map;

    node = ngx_map_find(channel_map, (intptr_t) &channel_name);
    if (node == NULL) {
        printf("create\n");
        ngx_http_qqflv_create_channel(channel_name, 0, 1, channel_map, qmcf->pool);
    	node = ngx_map_find(channel_map, (intptr_t) &channel_name);
        //ngx_delete_file(path->data);
    	//ngx_delete_file(flv_path.data);   
        //return NGX_OK;
	}

	qq_flv_index = (ngx_qq_flv_index_t *)
        ((char *) node - offsetof(ngx_qq_flv_index_t, node));

    if (qq_flv_index == NULL) {
    	return NGX_OK;
	}

	if (ngx_cached_time->sec - ngx_atoi(timestamp.data, timestamp.len) > qq_flv_index->backdelay) {
    	ngx_delete_file(path->data);
    	ngx_delete_file(flv_path.data);        	
    	return NGX_OK;
	}

	file.fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN,
                                    NGX_FILE_DEFAULT_ACCESS);

	file_size = 0;

#if (NGX_WIN32)
    {
        LONG  lo, hi;

        lo = 0;
        hi = 0;
        lo = SetFilePointer(file.fd, lo, &hi, FILE_END);
        file_size = (lo == INVALID_SET_FILE_POINTER ?
                     (off_t) -1 : (off_t) hi << 32 | (off_t) lo);
    }
#else
    file_size = lseek(file.fd, 0, SEEK_END);
#endif

    file.offset = 0;

    while (file.offset < file_size) {
        if (file_size - file.offset < NGX_QQ_FLV_INDEX_SIZE) {
            break;
        }
        if (ngx_read_file(&file, buf, NGX_QQ_FLV_INDEX_SIZE, file.offset) != NGX_QQ_FLV_INDEX_SIZE) {
            break;
        }
        if (buf[NGX_QQ_FLV_INDEX_SIZE - 1] == 1) {
        	if (ngx_queue_empty(&qmcf->idle_block_index)) {
        		qq_flv_block_index = ngx_palloc(qmcf->pool, sizeof(ngx_qq_flv_block_index_t));
        	}
        	else {
        		tq = ngx_queue_head(&qmcf->idle_block_index);
        		ngx_queue_remove(tq);
        		qq_flv_block_index = ngx_queue_data(tq, ngx_qq_flv_block_index_t, q);
        	}

        	p = buf;
        	#define READ_QQ_FLV_HEADER_FROM_BUFFER(var)                         \
        		ngx_cpymem(&var, p, sizeof(var));                               \
        		p += sizeof(var);
            
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.usize);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.huheadersize);
            if (qq_flv_block_index->qqflvhdr.huheadersize != NGX_QQ_FLV_HEADER_SIZE) {
                return NGX_OK;
            }
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.huversion);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.uctype);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.uckeyframe);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.usec);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.useq);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.usegid);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->qqflvhdr.ucheck);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qq_flv_block_index->file_offset);

            #undef READ_QQ_FLV_HEADER_FROM_BUFFER	  

            qq_flv_block_index->timestamp = (time_t)ngx_atoi(timestamp.data, timestamp.len);

            printf("uszie: %u\n", qq_flv_block_index->qqflvhdr.usize);
            printf("huheadersize: %u\n", qq_flv_block_index->qqflvhdr.huheadersize);
            printf("huversion: %u\n", qq_flv_block_index->qqflvhdr.huversion);
            printf("uctype: %u\n", qq_flv_block_index->qqflvhdr.uctype);
            printf("uckeyframe: %u\n", qq_flv_block_index->qqflvhdr.uckeyframe);
            printf("usec: %u\n", qq_flv_block_index->qqflvhdr.usec);
            printf("useq: %u\n", qq_flv_block_index->qqflvhdr.useq);
            printf("usegid: %u\n", qq_flv_block_index->qqflvhdr.usegid);
            printf("ucheck: %u\n", qq_flv_block_index->qqflvhdr.ucheck);
            printf("file_offset: %u\n", qq_flv_block_index->file_offset);
           	printf("timestamp: %u\n", qq_flv_block_index->timestamp);

            ngx_queue_insert_tail(&qq_flv_index->index_queue, &qq_flv_block_index->q);
        }else {
            break;
        }
    }

    return NGX_OK;    
}

static ngx_int_t
ngx_http_qqflv_read_index(ngx_http_qqflv_main_conf_t *qmcf)
{	
	printf("%s-%d", qmcf->path.data, qmcf->path.len);
    ngx_tree_ctx_t                           tree;
    tree.init_handler = NULL;
    tree.file_handler = ngx_http_qqflv_read_index_file;
    tree.data = qmcf;
    tree.alloc = 0;
    ngx_walk_tree(&tree, &qmcf->path);

}

static ngx_int_t ngx_http_qqflv_init_process(ngx_cycle_t *cycle)
{
	ngx_http_qqflv_main_conf_t         *qmcf;
	qmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_qqflv_module);    

	if (qmcf->path.len > 0) {
		ngx_http_qqflv_read_index(qmcf);
	}
    return NGX_OK;
}
