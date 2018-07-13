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
static ngx_int_t ngx_http_qqflv_keyframe_cmd(const ngx_queue_t *one, const ngx_queue_t *two);
static ngx_int_t ngx_http_qqflv_block_cmd(const ngx_queue_t *one, const ngx_queue_t *two);

static ngx_http_qqflv_main_conf_t   *qqflv_main_conf = NULL;

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
    ngx_queue_init(&qmcf->channel_queue);
    ngx_queue_init(&qmcf->idle_block_index);

    qqflv_main_conf = conf;

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
    //ngx_http_qqflv_loc_conf_t *prev = parent;
    //ngx_http_qqflv_loc_conf_t *conf = child;

    return NGX_CONF_OK;
}

static void ngx_qq_backdelay_timeout_handler(ngx_event_t *event)
{
	/*uint32_t								 *timestamp;
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
    }*/
}

static ngx_map_node_t *
ngx_http_qqflv_create_channel(ngx_str_t channel_name, uint32_t backdelay, 
							unsigned buname)
{
    ngx_qq_flv_index_t                       *qq_flv_index;
    qq_flv_index = ngx_palloc(qqflv_main_conf->pool, sizeof(ngx_qq_flv_index_t));
    qq_flv_index->buname = buname ? 1 : 0;
    if (qq_flv_index->buname) {
        qq_flv_index->backdelay = (backdelay == 0) ? 15 : backdelay;
    }
    else {
        qq_flv_index->backdelay = (backdelay == 0) ? 45 : backdelay;
    }
    qq_flv_index->channel_name = channel_name;
    ngx_queue_init(&qq_flv_index->index_queue);
    ngx_queue_init(&qq_flv_index->keyframe_queue);
    ngx_map_init(&qq_flv_index->block_map, ngx_map_hash_str, ngx_cmp_str);
    qq_flv_index->node.raw_key = (intptr_t) &qq_flv_index->channel_name;
    ngx_map_insert(&qqflv_main_conf->channel_map, &qq_flv_index->node, 0);
    ngx_queue_insert_tail(&qqflv_main_conf->channel_queue, &qq_flv_index->q);
    return &qq_flv_index->node;
}

ngx_int_t
ngx_http_qqflv_insert_block_index(ngx_str_t channel_name, time_t timestamp,
                                ngx_qq_flv_header_t qqflvhdr, off_t file_offset,
                                ngx_qq_flv_index_t *qq_flv_index)
{
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_queue_t                              *tq;
    ngx_map_node_t                           *node;
    ngx_str_t                                 block_key;

    if (qq_flv_index == NULL) {
        node = ngx_map_find(&qqflv_main_conf->channel_map, (intptr_t) &channel_name);
        if (node == NULL) {
            printf("node not found!\n");
            return NGX_OK;
        }
        qq_flv_index = (ngx_qq_flv_index_t *)
            ((char *) node - offsetof(ngx_qq_flv_index_t, node));
        if (qq_flv_index == NULL) {
            printf("qq_flv_index not found!\n");
            return NGX_OK;
        }
    }

    if (ngx_queue_empty(&qqflv_main_conf->idle_block_index)) {
        qq_flv_block_index = ngx_palloc(qqflv_main_conf->pool, sizeof(ngx_qq_flv_block_index_t));
    }
    else {
        tq = ngx_queue_head(&qqflv_main_conf->idle_block_index);
        ngx_queue_remove(tq);
        qq_flv_block_index = ngx_queue_data(tq, ngx_qq_flv_block_index_t, q);
    }
    
    qq_flv_block_index->file_offset = file_offset;
    qq_flv_block_index->qqflvhdr = qqflvhdr;
    qq_flv_block_index->timestamp = timestamp;

   /* printf("uszie: %u\n", qq_flv_block_index->qqflvhdr.usize);
    printf("huheadersize: %u\n", qq_flv_block_index->qqflvhdr.huheadersize);
    printf("huversion: %u\n", qq_flv_block_index->qqflvhdr.huversion);
    printf("uctype: %u\n", qq_flv_block_index->qqflvhdr.uctype);
    printf("uckeyframe: %u\n", qq_flv_block_index->qqflvhdr.uckeyframe);
    printf("usec: %u\n", qq_flv_block_index->qqflvhdr.usec);
    printf("useq: %u\n", qq_flv_block_index->qqflvhdr.useq);
    printf("usegid: %u\n", qq_flv_block_index->qqflvhdr.usegid);
    printf("ucheck: %u\n", qq_flv_block_index->qqflvhdr.ucheck);
    printf("file_offset: %u\n", qq_flv_block_index->file_offset);
    printf("timestamp: %u\n", qq_flv_block_index->timestamp);*/

    ngx_queue_insert_tail(&qq_flv_index->index_queue, &qq_flv_block_index->q);
    block_key.data = &qq_flv_block_index->qqflvhdr.useq;
    block_key.len = sizeof(uint32_t);
    qq_flv_block_index->node.raw_key = (intptr_t) &block_key;
    ngx_map_insert(&qq_flv_index->block_map, &qq_flv_block_index->node, 0);
    if (qq_flv_block_index->qqflvhdr.uckeyframe == 2) {
        ngx_queue_insert_tail(&qq_flv_index->keyframe_queue, &qq_flv_block_index->kq);
    }
    return NGX_OK;
}

ngx_int_t
ngx_http_qqflv_open_index_file(ngx_str_t *path, ngx_file_t *index_file, 
                                    ngx_log_t *log, ngx_str_t *id, ngx_flag_t *lock_file)
{
    off_t                       file_size;
    ngx_str_t                   index_path;
    u_char                      *p;
    static u_char               pbuf[NGX_MAX_PATH + 1];
    ngx_err_t                   err;

    p = pbuf;
    p = ngx_cpymem(p, path->data, path->len);
    p = ngx_cpymem(p, ".index", 6);

    *p = 0;
    index_path.data = pbuf;
    index_path.len = p - pbuf;    

    ngx_memzero(index_file, sizeof(ngx_file_t));
    index_file->offset = 0;
    index_file->log = log;
    index_file->fd = ngx_open_file(index_path.data, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN,
                                        NGX_FILE_DEFAULT_ACCESS);
    ngx_str_set(&index_file->name, "indexed");
    if (index_file->fd == NGX_INVALID_FILE) {
        err = ngx_errno;
        if (err != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_CRIT, index_file->log, err,
                          "record: %V failed to open index file '%V'",
                          id, &index_path);
        }
        return NGX_OK;
    }

#if !(NGX_WIN32)
      if (*lock_file) {
          err = ngx_lock_fd(index_file->fd);
          if (err) {
              ngx_log_error(NGX_LOG_CRIT, index_file->log, err,
                            "record: %V lock failed", id);
          }
      }
#endif

    file_size = 0;

#if (NGX_WIN32)
    {
        LONG  lo, hi;

        lo = 0;
        hi = 0;
        lo = SetFilePointer(index_file->fd, lo, &hi, FILE_END);
        file_size = (lo == INVALID_SET_FILE_POINTER ?
                     (off_t) -1 : (off_t) hi << 32 | (off_t) lo);
    }
#else
    file_size = lseek(index_file->fd, 0, SEEK_END);
#endif

    if (file_size == (off_t) -1) {
        ngx_log_error(NGX_LOG_CRIT, index_file->log, ngx_errno,
                      "record: %V seek failed", id);
        goto done;
    }

    if (file_size % NGX_QQ_FLV_INDEX_SIZE != 0) {
        u_char edr[NGX_QQ_FLV_INDEX_SIZE];
        ngx_memzero(edr, sizeof(edr));
        index_file->offset = file_size;
        if (ngx_write_file(index_file, edr, file_size % NGX_QQ_FLV_INDEX_SIZE, 
                            index_file->offset) == NGX_ERROR) {
              return NGX_ERROR;
        }
        file_size = index_file->offset;
    }

done:

    index_file->offset = file_size;

    return NGX_OK;
}

ngx_int_t
ngx_http_qqflv_write_index_file(ngx_file_t *index_file, ngx_qq_flv_header_t *qqflvhdr,
                            off_t index_offset)
{
    u_char                      hdr[NGX_QQ_FLV_INDEX_SIZE + 1], *p, *ph;
    size_t                      i;
        
    ph = hdr;
  #define NGX_RTMP_RECORD_QQ_FLV_HEADER(target, var)                              \
    p = (u_char*)&var;                                                            \
    for (i=0; i<sizeof(var); i++)                                                 \
        *target++ = p[i];

    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->usize);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->huheadersize);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->huversion);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->uctype);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->uckeyframe);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->usec);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->useq);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->usegid);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, qqflvhdr->ucheck);
    NGX_RTMP_RECORD_QQ_FLV_HEADER(ph, index_offset);
  #undef NGX_RTMP_RECORD_QQ_FLV_HEADER

    *ph++ = 1;
    *ph = 0;

    if (ngx_write_file(index_file, hdr, NGX_QQ_FLV_INDEX_SIZE, index_file->offset)
        == NGX_ERROR)
    {
        ngx_close_file(index_file->fd);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_qqflv_read_index_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
	u_char                                   *left, *last, *p;
    u_char                                    buf[NGX_QQ_FLV_INDEX_SIZE + 1];
    ngx_str_t                                 channel_name, timestamp, block_key;
    ngx_qq_flv_index_t                       *qq_flv_index;
    ngx_qq_flv_header_t                       qqflvhdr;
    ngx_file_t                                file;    
    off_t                                     file_size, file_offset;
    ngx_map_node_t                           *node;
    ngx_uint_t                                i;

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

    node = ngx_map_find(&qqflv_main_conf->channel_map, (intptr_t) &channel_name);
    if (node == NULL) {
        printf("create\n");
        node = ngx_http_qqflv_create_channel(channel_name, 0, 1);
        //ngx_delete_file(path->data);
        //return NGX_OK;
	}

	qq_flv_index = (ngx_qq_flv_index_t *)
        ((char *) node - offsetof(ngx_qq_flv_index_t, node));

    if (qq_flv_index == NULL) {
    	return NGX_OK;
	}

	if (ngx_cached_time->sec - ngx_atoi(timestamp.data, timestamp.len) > qq_flv_index->backdelay) {
    	ngx_delete_file(path->data);   	
    	return NGX_OK;
	}

    if (ngx_memcmp(left, ".index", last - left) != 0) {
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

        	p = buf;
    	#define READ_QQ_FLV_HEADER_FROM_BUFFER(var)                         \
    		ngx_cpymem(&var, p, sizeof(var));                               \
    		p += sizeof(var);
            
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usize);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.huheadersize);
            if (qqflvhdr.huheadersize != NGX_QQ_FLV_HEADER_SIZE) {
                return NGX_OK;
            }
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.huversion);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.uctype);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.uckeyframe);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usec);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.useq);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usegid);
            READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.ucheck);
            READ_QQ_FLV_HEADER_FROM_BUFFER(file_offset);

        #undef READ_QQ_FLV_HEADER_FROM_BUFFER	  

            ngx_http_qqflv_insert_block_index(channel_name, (time_t)ngx_atoi(timestamp.data, timestamp.len),
                                            qqflvhdr, file_offset, qq_flv_index);
        }else {
            break;
        }
    }

    return NGX_OK;    
}

static ngx_int_t 
ngx_http_qqflv_keyframe_cmd(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_qq_flv_block_index_t             *keyframe_one;
    ngx_qq_flv_block_index_t             *keyframe_two;
    keyframe_one = ngx_queue_data(one, ngx_qq_flv_block_index_t, kq);
    keyframe_two = ngx_queue_data(two, ngx_qq_flv_block_index_t, kq);
    if (keyframe_one->qqflvhdr.useq > keyframe_two->qqflvhdr.useq) {
        return 1;
    }
    return 0;
}

static ngx_int_t 
ngx_http_qqflv_block_cmd(const ngx_queue_t *one, const ngx_queue_t *two)
{
    ngx_qq_flv_block_index_t             *block_one;
    ngx_qq_flv_block_index_t             *block_two;
    block_one = ngx_queue_data(one, ngx_qq_flv_block_index_t, q);
    block_two = ngx_queue_data(two, ngx_qq_flv_block_index_t, q);
    if (block_one->qqflvhdr.useq > block_two->qqflvhdr.useq) {
        return 1;
    }
    return 0;
}

static ngx_int_t
ngx_http_qqflv_read_index(ngx_http_qqflv_main_conf_t *qmcf)
{   
    ngx_tree_ctx_t                           tree;
    ngx_qq_flv_index_t                      *qq_flv_index;
    ngx_queue_t                             *tq;

    tree.init_handler = NULL;
    tree.file_handler = ngx_http_qqflv_read_index_file;
    tree.alloc = 0;
    ngx_walk_tree(&tree, &qmcf->path);

    for (tq = ngx_queue_head(&qmcf->channel_queue); tq != ngx_queue_sentinel(&qmcf->channel_queue);
            tq = ngx_queue_next(tq))
    {
        qq_flv_index = ngx_queue_data(tq, ngx_qq_flv_index_t, q);
        ngx_queue_sort(&qq_flv_index->keyframe_queue, ngx_http_qqflv_keyframe_cmd);
        ngx_queue_sort(&qq_flv_index->index_queue, ngx_http_qqflv_block_cmd);
    }
    return NGX_OK;
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
