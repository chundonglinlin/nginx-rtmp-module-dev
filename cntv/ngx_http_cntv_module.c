#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_cntv_module.h"
#include "../http/ngx_http_set_header.h"
#include "../remux/ngx_remux_flv2ts.h"

typedef struct {
	ngx_file_t						*dfile;
	ngx_http_cntv_slice_index_t		si;
}ngx_http_cntv_slice_index_data_t;

typedef struct {
	ngx_file_t		dfile;
	ngx_int_t		frag_time;
}ngx_http_cntv_frag_t;

typedef struct {

	ngx_str_t		name;
	ngx_str_t		channel_path;

	ngx_http_cntv_slice_index_data_t  *ids;
	ngx_http_cntv_frag_t		 	  *frags;

}ngx_http_cntv_channel_t;

typedef struct {
	ngx_int_t       id;         // channel id
	ngx_str_t       name;       // channel name

}ngx_http_cntv_channel_name_t;

typedef struct {

	ngx_str_t       name;
	ngx_array_t     channels;   /* ngx_http_cntv_channel_name_t */
	ngx_flag_t      variant_playback;

}ngx_http_cntv_show_t;


#define  NGX_HTTP_CNTV_AUTH_LENGTH      128

typedef struct {
	ngx_rbtree_node_t		node;
	u_char			name[NGX_HTTP_CNTV_AUTH_LENGTH];
	u_short			len;

	ngx_int_t		at;				/* access time */
	uint32_t		id_time;
	ngx_http_cntv_channel_t	*channel;

	ngx_queue_t		q;

}ngx_http_cntv_session_t;


typedef struct {

	ngx_str_t		path;
	ngx_str_t		flv_path;
	ngx_array_t		shows;

	ngx_pool_t		*pool;
	ngx_buf_t		*buf;

	ngx_array_t		cfs;	/* ngx_http_cntv_channel_t */

	/* for timeback request */
	ngx_rbtree_t        session_tree;
	ngx_rbtree_node_t   session_sentinel;
	ngx_queue_t         session_busy;
	ngx_queue_t         session_idle;
	ngx_event_t         session_ev;

	/* for old file delete */
	ngx_event_t         del_ev;
	ngx_str_t			del_root;
	ngx_str_t			del_path;
	ngx_str_t			del_file;

} ngx_http_cntv_main_conf_t;

typedef struct {
	ngx_flag_t			enable;
} ngx_http_cntv_loc_conf_t;

typedef struct {

	ngx_int_t		type;

	ngx_flag_t		variant_playback;
	ngx_http_cntv_show_t	*show;

	ngx_int_t		start_time;
	ngx_int_t		end_time;

	ngx_str_t		auth;
	ngx_str_t		contentid;
	ngx_str_t		session_id;
	ngx_str_t		channel_name;

	ngx_http_cntv_channel_t	*channel;

}ngx_http_cntv_ctx_t;


typedef ngx_int_t (*ngx_http_cntv_request_handler_pt)(ngx_http_request_t *r);


typedef struct {

    ngx_int_t                                type;
    ngx_str_t                                name;
	ngx_http_cntv_request_handler_pt		 handler;

} ngx_http_cntv_request_cmd_t;


#define NGX_HTTP_CNTV_HLS_TIMEBACK		     0x0001
#define NGX_HTTP_CNTV_HLS_PLAYBACK		     0x0002
#define NGX_HTTP_CNTV_HLS_TS				 0x0004

#define NGX_HTTP_CNTV_PATH_SIZE				 256

#define NGX_HTTP_CNTV_INDEX_BUF_SIZE		1048576 // 1024*1024

#define CHANNEL_NAME_LENGTH     64
#define PATH_MAX_LENGTH			128

#define NGX_HTTP_CNTV_SESSION_CHECK_INTERVAL 60000  // 1 min
#define NGX_HTTP_CNTV_SESSION_TTL	 3600 //1 hour

//#define NGX_HTTP_CNTV_FRAG_LEN						300   //300s for test
//#define NGX_HTTP_CNTV_FRAG_NUM					2304  // 8*24*60*60/300 for test

#define NGX_HTTP_CNTV_FRAG_LEN						21600  // 6 hour 
#define NGX_HTTP_CNTV_FRAG_NUM					32     // 8*24*60*60/(6*3600)

#define NGX_HTTP_CNTV_SLICE_INDEX_NUM			69120 // 8*24*60*60/10 
#define NGX_HTTP_CNTV_TS_NUM	3


#define NGX_HTTP_CNTV_EXPIRE_FLV			0x0001
#define NGX_HTTP_CNTV_EXPIRE_HDS			0x0002

static ngx_int_t ngx_http_cntv_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cntv_init(ngx_conf_t *cf);
static void * ngx_http_cntv_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_cntv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static void * ngx_http_cntv_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_cntv_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_cntv_init_process(ngx_cycle_t *cycle);

static char * ngx_http_cntv_channel_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_cntv_parse_request_type(ngx_http_request_t *r);
static ngx_int_t ngx_http_cntv_get_arg_time(ngx_http_request_t *r, u_char *name, size_t len);

static ngx_int_t ngx_http_cntv_get_channel_name(ngx_http_request_t *r);
static ngx_http_cntv_channel_t *ngx_http_cntv_find_channel(ngx_http_request_t *r);
static void ngx_http_cntv_parse_slice_index(ngx_http_cntv_main_conf_t *cmcf, ngx_http_cntv_channel_t *channel, ngx_file_t *dfile);
static ngx_http_cntv_channel_t * ngx_http_cntv_create_channel(ngx_http_cntv_main_conf_t *cmcf, ngx_str_t *channel_name,
		ngx_flag_t rebuild, ngx_log_t *log);

static void ngx_http_cntv_ts_cleanup(void *data);

static ngx_int_t ngx_http_cntv_hls_timeback_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cntv_hls_playback_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cntv_hls_ts_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cntv_variant_playback_handler(ngx_http_request_t *r);

static void ngx_http_cntv_get_session_id(ngx_http_request_t *r);

static void ngx_http_cntv_session_expire_handler(ngx_event_t *event);
static void ngx_http_cntv_cleanup_file(ngx_event_t *event, ngx_int_t type);
static void ngx_http_cntv_delete_expire_file_handler(ngx_event_t *event);

static ngx_int_t ngx_http_cntv_create_main_m3u8(ngx_conf_t *cf, ngx_http_cntv_main_conf_t *cmcf);
static ngx_int_t ngx_http_cntv_create_main_f4m(ngx_conf_t *cf, ngx_http_cntv_main_conf_t *cmcf);

static ngx_http_cntv_session_t* ngx_http_cntv_get_session(ngx_http_cntv_main_conf_t *cmcf);
static void ngx_http_cntv_put_session(ngx_http_cntv_main_conf_t *cmcf, ngx_http_cntv_session_t *s);
static ngx_http_cntv_session_t* ngx_http_cntv_find_session(ngx_rbtree_t *tree, ngx_str_t *key);
static void ngx_http_cntv_session_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

static ngx_http_cntv_frag_t *ngx_http_cntv_get_frag(ngx_http_cntv_channel_t *channel, ngx_int_t frag_time);
static ngx_http_cntv_slice_index_data_t *ngx_http_cntv_get_slice(ngx_http_cntv_channel_t *channel, uint32_t id_time);

static ngx_command_t ngx_http_cntv_commands[] = {

	{ ngx_string("cntv_playback"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_cntv_loc_conf_t, enable),
		NULL },

	{ ngx_string("cntv_path"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_cntv_main_conf_t, path),
		NULL },

	{ ngx_string("cntv_channel_map"),
		NGX_HTTP_MAIN_CONF| NGX_CONF_2MORE,
		ngx_http_cntv_channel_map,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL },

	ngx_null_command
};

static ngx_http_module_t  ngx_http_cntv_module_ctx = {
	NULL,                                  /* preconfiguration */
	ngx_http_cntv_init,         	   /* postconfiguration */

	ngx_http_cntv_create_main_conf,    /* create main configuration */
	ngx_http_cntv_init_main_conf,      /* init main configuration */

	NULL,                              /* create server configuration */
	NULL,                              /* merge server configuration */

	ngx_http_cntv_create_loc_conf,     /* create location configuration */
	ngx_http_cntv_merge_loc_conf	   /* merge location configuration */
};


ngx_module_t  ngx_http_cntv_module = {
	NGX_MODULE_V1,
	&ngx_http_cntv_module_ctx,         /* module context */
	ngx_http_cntv_commands,            /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	ngx_http_cntv_init_process,            /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

/* hls */
static ngx_str_t m3u8_req_prefix = ngx_string("/live/no/");

static ngx_str_t ts_req_prefix = ngx_string("/hls/");
static ngx_str_t convered_req_prefix = ngx_string("/hls/");

static ngx_str_t playback_session_field = ngx_string("X-Playback-Session-Id");

static ngx_keyval_t m3u8_headers[] = {
	//{ ngx_string("Cache-Control"),  ngx_string("max-age=0") },
	{ ngx_string("Content-Type"),   ngx_string("audio/x-mpegurl") },
	//{ ngx_string("Content-Type"),   ngx_string("video/mpegurl") },
	{ ngx_null_string, ngx_null_string }
};

static ngx_keyval_t ts_headers[] = {
	//{ ngx_string("Cache-Control"),  ngx_string("no-cache") },
	//{ ngx_string("Cache-Control"),  ngx_string("max-age=0") },
	//{ ngx_string("Content-Type"),   ngx_string("video/mpegurl") },
	{ ngx_null_string, ngx_null_string }
};

static ngx_http_cntv_main_conf_t   *cntv_main_conf = NULL;

static ngx_http_cntv_request_cmd_t ngx_http_cntv_request_cmds[] = {

	{
		NGX_HTTP_CNTV_HLS_TIMEBACK,
		ngx_string("hls timeback"),
		ngx_http_cntv_hls_timeback_handler,
	},

	{
		NGX_HTTP_CNTV_HLS_PLAYBACK,
		ngx_string("hls playback"),
		ngx_http_cntv_hls_playback_handler,
	},

	{
		NGX_HTTP_CNTV_HLS_TS,
		ngx_string("hls ts"),
		ngx_http_cntv_hls_ts_handler,
	}

};

static ngx_int_t
ngx_http_cntv_handler(ngx_http_request_t *r)
{
	ngx_int_t							rc;
	ngx_log_t							*log;
	ngx_uint_t							i;
	ngx_http_cntv_ctx_t					*ctx;

	ngx_http_cntv_loc_conf_t			*conf;
	ngx_http_cntv_main_conf_t			*cmcf;
	ngx_http_cntv_request_cmd_t			*cmd;

	log = r->connection->log;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_cntv_module);
	conf = ngx_http_get_module_loc_conf(r, ngx_http_cntv_module);

	if (cmcf->flv_path.len == 0 || !conf->enable || r != r->main) {
		return NGX_DECLINED;
	}

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	if (r->uri.data[r->uri.len - 1] == '/') {
		return NGX_DECLINED;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);

	if(ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cntv_ctx_t));
	
		ngx_http_set_ctx(r, ctx, ngx_http_cntv_module);
	}

	/* set cntv request type and time arg */
	rc = ngx_http_cntv_parse_request_type(r);
	if(rc == NGX_ERROR) {
		return NGX_HTTP_BAD_REQUEST;
	}

	/* get session id */
	ngx_http_cntv_get_session_id(r);

	/* get channel name */
	if(ngx_http_cntv_get_channel_name(r) != NGX_OK) {
		return NGX_HTTP_BAD_REQUEST;
	}

	/* find channel */
	ctx->channel = ngx_http_cntv_find_channel(r);
	if(ctx->channel == NULL) {
		return NGX_HTTP_NOT_FOUND;
	}

	cmd = NULL;
	for( i = 0; i < sizeof(ngx_http_cntv_request_cmds)/sizeof(ngx_http_cntv_request_cmd_t); i++) {
		if(ngx_http_cntv_request_cmds[i].type == ctx->type) {
			cmd = &ngx_http_cntv_request_cmds[i];
			break;
		}
	}
	
	if(cmd == NULL) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "unknown type cntv request");
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	
	rc = cmd->handler(r);
	return rc;
}

static ngx_int_t
ngx_http_cntv_hls_timeback_handler(ngx_http_request_t *r)
{
	u_char						*last;
	uint32_t					et, max = 0, seq = 0, next_slice = 0;
	ngx_int_t					rc;
	ngx_uint_t					i, n = 0;
	ngx_buf_t					*b;
	ngx_str_t					session_id;
	ngx_log_t					*log;
	ngx_chain_t					out;
	ngx_keyval_t				*h;
	ngx_http_cntv_ctx_t			*ctx;
	ngx_http_cntv_channel_t		*channel;
	ngx_http_cntv_session_t		*s;
	ngx_http_cntv_main_conf_t	*cmcf;
	ngx_http_cntv_slice_index_data_t *d;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_cntv_module);
	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	log = r->connection->log;

	channel = ctx->channel;

	/* timeback request all from pc, so session id is arg auth, and single bitrate*/
	if(ctx->auth.len == 0 && ctx->contentid.len == 0) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "pc timeback request, not found arg auth or contentid");
		return NGX_HTTP_BAD_REQUEST;
	}

	if(ctx->auth.len) {
		session_id = ctx->auth;
	} else {
		session_id = ctx->contentid;
	}

	if(session_id.len > NGX_HTTP_CNTV_AUTH_LENGTH) {
		session_id.len = NGX_HTTP_CNTV_AUTH_LENGTH;
	}

	s = ngx_http_cntv_find_session(&cmcf->session_tree, &session_id);
	if(s != NULL) {
		/* update session acces time */
		s->at = ngx_time();
	} else {

		s = ngx_http_cntv_get_session(cmcf);
		//init session
		s->id_time = ctx->start_time/10;

		//s->channel = channel;
		s->len = session_id.len;
		last = ngx_cpymem(s->name, session_id.data, session_id.len);
		s->at = ngx_time();
		ngx_http_cntv_put_session(cmcf, s);
	}

	b = ngx_create_temp_buf(r->pool, 128 + 256 * NGX_HTTP_CNTV_TS_NUM);
	if(b == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	et = ngx_time()/10;

	for( i = 0; ; i++) {

		d = ngx_http_cntv_get_slice(channel, s->id_time + i);

		if(s->id_time + i >= et) {
			break;
		} 

		if(d->si.id_time != (s->id_time + i)) {
			continue;
		}

		if(n++ ==  NGX_HTTP_CNTV_TS_NUM) {
			break;
		}

		if( n == 1) {
			seq = s->id_time + i;
		} else if( n == 2) {
			next_slice = s->id_time + i;
		}

		max = ngx_max(d->si.end_time - d->si.start_time, max);
	}

	b->last = ngx_sprintf(b->pos, "#EXTM3U\n"
					   			  "#EXT-X-MEDIA-SEQUENCE:%uD\n"
				  				  "#EXT-X-TARGETDURATION:%uD\n"
								  ,seq, max);

	n = 0;

	for( i = 0; ; i++) {

		d = ngx_http_cntv_get_slice(channel, s->id_time + i);

		if(s->id_time + i >= et) {
			break;
		} 

		if(d->si.id_time != (s->id_time + i)) {
			continue;
		}

		if(n++ ==  NGX_HTTP_CNTV_TS_NUM) {
			break;
		}

		b->last = ngx_sprintf(b->last, "#EXTINF:%uD,\n"
				"/hls/%V/%uD.ts\n"
				, d->si.end_time - d->si.start_time, &ctx->channel_name, d->si.id_time);
	}

	//move to next
	if( next_slice) {
		s->id_time = next_slice;
	}

	r->allow_ranges = 1;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	h = m3u8_headers;
	while (h->key.len) {
		rc = ngx_http_set_header_out(r, &h->key, &h->value);
		if (rc != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}    
		++h; 
	}

	rc = ngx_http_send_header(r);

	if( rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	b->memory = 1;
	
	b->last_buf = 1;
	b->last_in_chain = 1;

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_cntv_hls_playback_handler(ngx_http_request_t *r)
{
	u_char						*last;
	uint32_t					max = 0, st, et, tt, seq = 0, next_slice = 0;
	ngx_int_t					rc;
	ngx_buf_t					*b;
	ngx_log_t					*log;
	ngx_keyval_t				*h;
	ngx_uint_t					n = 0, i, len;
	ngx_chain_t					out;
	ngx_http_cntv_ctx_t			*ctx;
	ngx_http_cntv_session_t		*s;
	ngx_http_cntv_main_conf_t	*cmcf;
	ngx_http_cntv_slice_index_data_t	*d;
	
	b = NULL;
	log = r->connection->log;
	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	cmcf = ngx_http_get_module_main_conf(r, ngx_http_cntv_module);

	if(ctx->session_id.len) {
		/* mobile request , variant playback only for ios */
		if(ctx->variant_playback) {
			return ngx_http_cntv_variant_playback_handler(r);
		}

		if(ctx->session_id.len > NGX_HTTP_CNTV_AUTH_LENGTH) {
			ctx->session_id.len = NGX_HTTP_CNTV_AUTH_LENGTH;
		}
		
		/* ios request */
		s = ngx_http_cntv_find_session(&cmcf->session_tree, &ctx->session_id);
		if( s != NULL) {
			/* update session acces time */
			s->at = ngx_time();
		} else {
			s = ngx_http_cntv_get_session(cmcf);
			//init session
			s->id_time = ctx->start_time/10;

			//s->channel = channel;
			s->len = ctx->session_id.len;
			last = ngx_cpymem(s->name, ctx->session_id.data, ctx->session_id.len);
			s->at = ngx_time();
			ngx_http_cntv_put_session(cmcf, s);
		}

		et = ctx->end_time/10;

		for( i = 0; ;i++) {
			d = ngx_http_cntv_get_slice(ctx->channel, s->id_time + i);

			if(s->id_time + i > et) {
				break;
			}

			if(d->si.id_time != (s->id_time + i)) {
				continue;
			}

			if(n++ ==  NGX_HTTP_CNTV_TS_NUM) {
				break;
			}

			if( n == 1) {
				seq = s->id_time + i;
			} else if( n == 2) {
				next_slice = s->id_time + i;
			}

			max = ngx_max(d->si.end_time - d->si.start_time, max);
		}

		b = ngx_create_temp_buf(r->pool, 128 + 256 * NGX_HTTP_CNTV_TS_NUM);
		if(b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		b->last = ngx_sprintf(b->pos, "#EXTM3U\n"
				"#EXT-X-MEDIA-SEQUENCE:%uD\n"
				"#EXT-X-TARGETDURATION:%uD\n"
				,seq, max);

		n = 0;
		for( i = 0; ;i++) {
			d = ngx_http_cntv_get_slice(ctx->channel, s->id_time + i);

			if(s->id_time + i > et) {
				break;
			}

			if(d->si.id_time != (s->id_time + i)) {
				continue;
			}

			if(n++ ==  NGX_HTTP_CNTV_TS_NUM) {
				break;
			}

			b->last = ngx_sprintf(b->last, "#EXTINF:%uD,\n"
					"/hls/%V/%uD.ts\n"
					, d->si.end_time - d->si.start_time, &ctx->channel_name, d->si.id_time);
		}

		//move to next
		if( next_slice) {
			s->id_time = next_slice;
		}

	} else {
		/* android reqeust */

		st = ctx->start_time/10;
		et = ctx->end_time/10;

		n = 0;

		for(tt = st; tt<=et; tt++) {
			d = ngx_http_cntv_get_slice(ctx->channel, tt);
			if( tt != d->si.id_time) {
				continue;
			}
			n ++;
			max = ngx_max(d->si.end_time - d->si.start_time, max);
		}
		
		len = 128 + 256*n;
		
		b = ngx_create_temp_buf(r->pool, len);
		if(b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		
		b->last = ngx_sprintf(b->pos, "#EXTM3U\n"
				"#EXT-X-MEDIA-SEQUENCE:0\n"
				"#EXT-X-TARGETDURATION:%uD\n"
				, max);

		for(tt = st; tt<=et; tt++) {

			d = ngx_http_cntv_get_slice(ctx->channel, tt);

			if( tt != d->si.id_time) {
				continue;
			}
			
			// /hls/channel14/1523279064.ts
			b->last = ngx_sprintf(b->last, "#EXTINF:%uD,\n"
					"/hls/%V/%uD.ts\n"
					, d->si.end_time - d->si.start_time, &ctx->channel_name, d->si.id_time);
		}

		b->last = ngx_cpymem(b->last, "#EXT-X-ENDLIST\n", sizeof("#EXT-X-ENDLIST\n") - 1);
	}


	r->allow_ranges = 1;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	h = m3u8_headers;
	while (h->key.len) {
		rc = ngx_http_set_header_out(r, &h->key, &h->value);
		if (rc != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		++h; 
	}

	rc = ngx_http_send_header(r);

	if( rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	b->memory = 1;
	
	b->last_buf = 1;
	b->last_in_chain = 1;

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_cntv_hls_ts_handler(ngx_http_request_t *r)
{
	u_char						*ps, *pe;
	ngx_log_t					*log;
	ngx_int_t					rc, id;
	ngx_keyval_t				*h;
	ngx_remux_file_t			*rf;
	ngx_http_cleanup_t			*cln;
	ngx_http_cntv_ctx_t			*ctx;
	ngx_http_cntv_loc_conf_t	*conf;
	ngx_http_cntv_slice_index_data_t	*d;

	log = r->connection->log;
	conf = ngx_http_get_module_loc_conf(r, ngx_http_cntv_module);
	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);

	pe = r->uri.data + (r->uri.len - 3);
	
	//ts: /hls/channel11/152307201.ts
	ps = r->uri.data + ts_req_prefix.len + ctx->channel_name.len + 1;

	if(pe - ps != 9) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "invalid ts request");
		return NGX_HTTP_BAD_REQUEST;
	}
	
	id = ngx_atoi(ps, pe - ps);
	
	if(id == NGX_ERROR) {
		ngx_log_error(NGX_LOG_ERR, log, 0, "invalid ts request");
		return NGX_HTTP_BAD_REQUEST;
	}

	d = ngx_http_cntv_get_slice(ctx->channel, id);

	if(d->si.id_time != id) {
		return NGX_HTTP_NOT_FOUND;
	}

	rf = ngx_pcalloc(r->pool, sizeof(ngx_remux_file_t));

	rc = ngx_remux_flv2ts(d->dfile->fd, d->si.offset, d->si.offset + d->si.size, rf);

	if(rc != NGX_OK) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	cln = ngx_http_cleanup_add(r, 0);
	if(cln == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	cln->handler = ngx_http_cntv_ts_cleanup;
	cln->data = rf;

	r->allow_ranges = 1;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = rf->content_length;

	h = ts_headers;
	while (h->key.len) {
		rc = ngx_http_set_header_out(r, &h->key, &h->value);
		if (rc != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}    
		++h; 
	}

	rc = ngx_http_send_header(r);

	if( rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	return ngx_http_output_filter(r, rf->content);
}

static ngx_int_t 
ngx_http_cntv_variant_playback_handler(ngx_http_request_t *r)
{
	ngx_int_t				rc;
	ngx_buf_t				*b;
	ngx_chain_t				out;
	ngx_keyval_t				*h;
	ngx_http_cntv_ctx_t			*ctx;
	ngx_http_cntv_channel_name_t		*cn;

	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	b = ngx_create_temp_buf(r->pool, 4096);

	cn = ctx->show->channels.elts;
	b->last = ngx_sprintf(b->last, "#EXTM3U\n"
				"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=850000\n"
				"/hls/%V/index.m3u8?%V\n"
				"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=500000\n"
				"/hls/%V/index.m3u8?%V\n"
				"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=1500000\n"
				"/hls/%V/index.m3u8?%V\n"
				"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=2000000\n"
				"/hls/%V/index.m3u8?%V\n",
				&cn[0].name, &r->args, &cn[1].name,&r->args, &cn[2].name,&r->args, &cn[3].name, &r->args);

	r->allow_ranges = 1;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = b->last - b->pos;

	h = m3u8_headers;
	while (h->key.len) {
		rc = ngx_http_set_header_out(r, &h->key, &h->value);
		if (rc != NGX_OK) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}    
		++h; 
	}

	rc = ngx_http_send_header(r);

	if( rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	b->memory = 1;

	b->last_buf = 1;
	b->last_in_chain = 1;

	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r, &out);
}

static void
ngx_http_cntv_session_expire_handler(ngx_event_t *event)
{
	ngx_queue_t					*tq, *nq;
	ngx_http_cntv_session_t		*s;
	ngx_http_cntv_main_conf_t	*cmcf;

	if( ngx_terminate || ngx_exiting || ngx_quit) {
		return ;
	}
	
	cmcf = event->data;

	for(tq = ngx_queue_head(&cmcf->session_busy); tq != ngx_queue_sentinel(&cmcf->session_busy); ) {

		nq = ngx_queue_next(tq);
		s = ngx_queue_data(tq, ngx_http_cntv_session_t, q);
		if (ngx_time() - s->at >= NGX_HTTP_CNTV_SESSION_TTL) {
			ngx_queue_remove(tq);
			ngx_rbtree_delete(&cmcf->session_tree, &s->node);
			ngx_queue_insert_tail(&cmcf->session_idle, tq);
			//ngx_queue_insert_tail(&cmcf->session_idle, &s->q);
		} else {
			break;
		}

		tq = nq;
	}
	
	ngx_add_timer(event, NGX_HTTP_CNTV_SESSION_CHECK_INTERVAL);
}

static void
ngx_http_cntv_delete_expire_file_handler(ngx_event_t *event)
{
	if( ngx_terminate || ngx_exiting || ngx_quit) {
		return ;
	}

	ngx_http_cntv_cleanup_file(event, NGX_HTTP_CNTV_EXPIRE_FLV);

	// one day delete old file once
	ngx_add_timer(event, 86400000);
}

static void
ngx_http_cntv_cleanup_file(ngx_event_t *event, ngx_int_t type)
{
	ngx_err_t					err;
	u_char						*name, *last;
	ssize_t						len;
	ngx_int_t					file_time;
	ngx_dir_t					root_dir, sub_dir;
	ngx_file_info_t				fi;
	ngx_http_cntv_main_conf_t	*cmcf;

	cmcf = event->data;

	last = ngx_cpymem(cmcf->del_root.data, cmcf->path.data, cmcf->path.len);

	if(cmcf->path.data[cmcf->path.len - 1] != '/') {
		last = ngx_cpymem(last, "/", 1);
	}

	switch(type) {
		case NGX_HTTP_CNTV_EXPIRE_FLV:
			last = ngx_cpymem(last, "flv", 3);
			break;
		case NGX_HTTP_CNTV_EXPIRE_HDS:
			last = ngx_cpymem(last, "hds", 3);
			break;
	}

	cmcf->del_root.len = last - cmcf->del_root.data;
	*last = '\0';
	
	/* delete flv and hds old file */
	if(ngx_open_dir(&cmcf->del_root, &root_dir) == NGX_ERROR) {
		ngx_log_error(NGX_LOG_EMERG, event->log, ngx_errno, 
				ngx_open_dir_n "\"%s\" failed", &cmcf->del_root.data);
		return;
	}

	for(; ;) {
		ngx_set_errno(0);

		if(ngx_read_dir(&root_dir) == NGX_ERROR) {
			err = ngx_errno;
			if(err == NGX_ENOMOREFILES) {
				break;
			} else {
				ngx_log_error(NGX_LOG_ERR, event->log, ngx_errno,
						ngx_read_dir_n "\"%s\" failed ", cmcf->del_root.data);
				return;
			}
		}

		len = ngx_de_namelen(&root_dir);
		name = ngx_de_name(&root_dir);
		if( len == 1 && name[0] == '.') {
			continue;
		}
		if(len == 2 && name[0] == '.' && name[1] == '.') {
			continue;
		}

		if(!ngx_de_is_dir(&root_dir)) {
			continue;
		}

		last = ngx_sprintf(cmcf->del_path.data, "%V/%s", &cmcf->del_root, name);
		cmcf->del_path.len = last - cmcf->del_path.data;
		*last = '\0';

		/* sub dir */
		if(ngx_open_dir(&cmcf->del_path, &sub_dir) == NGX_ERROR) {
			ngx_log_error(NGX_LOG_EMERG, event->log, ngx_errno, 
					ngx_open_dir_n "\"%s\" failed", &cmcf->del_path.data);
			continue;
		}

		for(;;) {
			ngx_set_errno(0);

			if(ngx_read_dir(&sub_dir) == NGX_ERROR) {
				err = ngx_errno;
				if(err == NGX_ENOMOREFILES) {
					break;
				} else {
					ngx_log_error(NGX_LOG_ERR, event->log, ngx_errno,
							ngx_read_dir_n "\"%s\" failed ", cmcf->del_path.data);
					break;
				}
			}

			len = ngx_de_namelen(&sub_dir);
			name = ngx_de_name(&sub_dir);
			if( len == 1 && name[0] == '.') {
				continue;
			}
			if(len == 2 && name[0] == '.' && name[1] == '.') {
				continue;
			}

			if(!ngx_de_is_file(&sub_dir)) {
				continue;
			}
			
			*ngx_sprintf(cmcf->del_file.data, "%V/%s", &cmcf->del_path, name) = 0;

			if( type == NGX_HTTP_CNTV_EXPIRE_FLV) {
				file_time = ngx_atoi(name, 10);
				if(file_time == NGX_ERROR || ngx_time() - file_time >= 8*24*3600) {
					ngx_delete_file(cmcf->del_file.data);
				}
			} else {
				if(ngx_file_info(cmcf->del_file.data, &fi) == NGX_FILE_ERROR) {
					ngx_log_error(NGX_LOG_EMERG, event->log, ngx_errno, "stat file \"%s\" failed", cmcf->del_file.data);
					continue;
				}

				file_time = ngx_file_mtime(&fi);
				if(ngx_time() - file_time >= 300) {
					ngx_delete_file(cmcf->del_file.data);
				}
			}
		}
	}
}

static void
ngx_http_cntv_ts_cleanup(void *data)
{
	ngx_remux_file_t		*rf = data;

	ngx_remux_flv2ts_destory(rf);
}

static ngx_http_cntv_channel_t *
ngx_http_cntv_find_channel(ngx_http_request_t *r)
{
	ngx_uint_t							i, k, found;
	ngx_log_t							*log;
	ngx_http_cntv_ctx_t					*ctx;
	ngx_http_cntv_channel_t				*channel;
	ngx_http_cntv_channel_name_t		*cn;
	ngx_http_cntv_loc_conf_t			*conf;
	ngx_http_cntv_main_conf_t			*cmcf;
	ngx_http_cntv_show_t			*show;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_cntv_module);
	conf = ngx_http_get_module_loc_conf(r, ngx_http_cntv_module);

	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	log = r->connection->log;

	found = 0;

	channel = cmcf->cfs.elts;
	for(i = 0; i < cmcf->cfs.nelts; i++) {
		if(channel[i].name.len == ctx->channel_name.len &&
				ngx_strncmp(channel[i].name.data, ctx->channel_name.data, ctx->channel_name.len) == 0){
			//ctx->channel = &channel[i];
			return &channel[i];
		}
	}

	show = cmcf->shows.elts;
	for(i = 0; i < cmcf->shows.nelts; i++) {
		cn = show[i].channels.elts;
		for(k = 0; k < show[i].channels.nelts; k++) {

			if(cn[k].name.len == ctx->channel_name.len &&
					ngx_strncmp(cn[k].name.data, ctx->channel_name.data, ctx->channel_name.len) == 0){
				return ngx_http_cntv_create_channel(cmcf, &ctx->channel_name, 0, r->connection->log);
			}

		}
	}

	ngx_log_error(NGX_LOG_ERR, log, 0, "unknown channel \"%V\"", &ctx->channel_name);
	return NULL;
}

static ngx_int_t
ngx_http_cntv_parse_request_type(ngx_http_request_t *r)
{
	ngx_int_t start_time, end_time;
	ngx_http_cntv_ctx_t		*ctx;
	ngx_log_t				*log;

	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	log = r->connection->log;

	start_time = 0;
	end_time = 0;

	/* check: ts request */
	if(ngx_strncmp(r->uri.data, ts_req_prefix.data, ts_req_prefix.len) == 0 && 
			ngx_strncmp(r->uri.data + (r->uri.len-3), ".ts", 3) == 0) {
		ctx->type = NGX_HTTP_CNTV_HLS_TS;
		return NGX_OK;
	}

	/*
		http://cctv1.vtime.cntv.dnion.com/live/no/14_/seg0/index.m3u8?begin=1501207200&end=1501210800
		http://cctv1.vtime.cntv.dnion.com/hls/channel11/index.m3u8?begin=1501207200&end=1501210800
	*/

	/* check: hls request */
//	if(ngx_strncmp(r->uri.data, m3u8_req_prefix.data, m3u8_req_prefix.len) == 0 &&
//			ngx_strncmp(r->uri.data + (r->uri.len - 5), ".m3u8", 5) == 0 ) {

	if(ngx_strncmp(r->uri.data + (r->uri.len - 5), ".m3u8", 5) == 0 ) {
		/* hls time back  request */
		start_time = ngx_http_cntv_get_arg_time(r, (u_char *) "begintimeback", sizeof("begintimeback") -1);
		if( start_time != NGX_ERROR) {

			start_time = start_time/1000;

			if( start_time > 7*24*60*60) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "hls time back request:"
					   	"invalid arg time back more than 7 days in arg: ", r->args);
				return NGX_ERROR;
			}

			ctx->type = NGX_HTTP_CNTV_HLS_TIMEBACK;
			ctx->start_time = ngx_time() - start_time;
			return NGX_OK;
		}

		/* hls time back request or play back request */

		///begin time 
		start_time = ngx_http_cntv_get_arg_time(r, (u_char *) "begin", sizeof("begin") -1);
		if( start_time == NGX_ERROR) {
			start_time = ngx_http_cntv_get_arg_time(r, (u_char *)"begintimeabs", sizeof("begintimeabs")-1);
			if( start_time == NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, log, 0, "hls request:"
					   	"arg \"begin\" or \"begintimeabs\" not found or invalid");
				return NGX_ERROR;
			} else {
				start_time = start_time/1000;
			}
		}

		if (start_time < ngx_time() - 7*24*60*60) {
			ngx_log_error(NGX_LOG_ERR, log, 0, "hls play back request:"
				   	"invalid arg time back more than 7 days in arg");
			return NGX_ERROR;
		}


		///end time
		end_time = ngx_http_cntv_get_arg_time(r, (u_char *) "end", sizeof("end") -1);
		if( end_time == NGX_ERROR) {
			end_time = ngx_http_cntv_get_arg_time(r, (u_char *)"endtimeabs", sizeof("endtimeabs")-1);
			if(end_time == NGX_ERROR) {
				end_time = 0;
			}else {
				end_time = end_time/1000;
			}
		}

		if(end_time == 0) {
			ctx->type = NGX_HTTP_CNTV_HLS_TIMEBACK;
			ctx->start_time = start_time;
			return NGX_OK;
		}

		if( end_time != 0 && end_time < start_time) {
			ngx_log_error(NGX_LOG_ERR, log, 0, "hls play back request:"
					"invalid arg  start_time > end_time  in arg");
			return NGX_ERROR;
		}

		ctx->type = NGX_HTTP_CNTV_HLS_PLAYBACK;
		ctx->start_time = start_time;
		ctx->end_time = end_time;

		return NGX_OK;
	}
	
	ngx_log_error(NGX_LOG_ERR, log, 0, "invalid cntv request");

	return NGX_ERROR;

}

static void 
ngx_http_cntv_get_session_id(ngx_http_request_t *r)
{
	ngx_uint_t				i;
	ngx_table_elt_t			*tb;
	ngx_list_part_t			*part;
	ngx_http_cntv_ctx_t		*ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	/* auth */
	if(ngx_http_arg(r, (u_char *)"AUTH", 4, &ctx->auth) != NGX_OK) {
		ngx_http_arg(r, (u_char *)"auth", 4, &ctx->auth);
	}

	ngx_http_arg(r, (u_char *)"contentid", 4, &ctx->contentid);

	/*x-playback-session-id for iphone */
	part = &r->headers_in.headers.part;
	tb = part->elts;

	for(i = 0; /* void */ ; i ++) {
		if( i >= part->nelts) {
			if( part->next == NULL) {
				break;
			}
			part = part->next;
			tb = part->elts;
			i = 0;
		}

		if(tb[i].key.len == playback_session_field.len &&
				ngx_strncmp(tb[i].key.data, playback_session_field.data, playback_session_field.len) == 0) {
			ctx->session_id = tb[i].value;
		}
	}
}


/*
static void ngx_http_cntv_get_reqeust_os(ngx_http_request_t *r)
{
	// windows Lavf for pc, other for mobile
	if( r->headers_in.user_agent != NULL) {
		agent = r->headers_in.user_agent;
		agt = agent->value.data;
		if(ngx_strstrn(agt, "Windows",  7-1) || ngx_strstrn(agt, "Lavf", 4 -1)) {
			ctx->pc = 1;
		}
	}
}
*/


static ngx_int_t
ngx_http_cntv_get_arg_time(ngx_http_request_t *r, u_char *name, size_t len)
{
	ngx_int_t		t, rc;
	ngx_str_t		targ;

	rc = ngx_http_arg(r, name, len, &targ);
	if( rc != NGX_OK) {
		return  NGX_ERROR;
	} else {
		t = ngx_atoi(targ.data, targ.len);
		if( t == NGX_ERROR) {
			return NGX_ERROR;
		}
	}

	return t;
	
}

static ngx_int_t
ngx_http_cntv_get_channel_name(ngx_http_request_t *r)
{
	u_char			*pe, *ps, *last;
	ngx_str_t		name;
	ngx_log_t		*log;
	ngx_int_t		id, variant_check = 0;
	ngx_uint_t		i, k;
	ngx_http_cntv_ctx_t					*ctx;
	ngx_http_cntv_channel_name_t		*ch;
	ngx_http_cntv_main_conf_t			*cmcf;
	ngx_http_cntv_show_t				*sw;

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_cntv_module);
	ctx = ngx_http_get_module_ctx(r, ngx_http_cntv_module);
	log = r->connection->log;

	switch(ctx->type) {
		case NGX_HTTP_CNTV_HLS_TS:
			{
				/* uri:  /hls/channel11/1523071800/1523072017.ts */
				last = r->uri.data + r->uri.len;
				ps = r->uri.data + ts_req_prefix.len;

				pe = ngx_strlchr(ps, last, '/');
				if(pe == NULL || pe - ps <= 7 ) {
					goto failed;
				}

				name.data = ps;
				name.len = pe - ps;

				id = ngx_atoi(name.data + 7 , name.len - 7);
				if( id == NGX_ERROR) {
					goto failed;
				}
			}
			break;
		case NGX_HTTP_CNTV_HLS_TIMEBACK:
		case NGX_HTTP_CNTV_HLS_PLAYBACK:
			{
				/*
				origin :  /live/no/14_/seg0/index.m3u8?begin=1501207200&end=1501210800
				convered: /hls/channel11/index.m3u8?begin=1501207200&end=1501210800
			    */

				/* check convered m3u8 request, prefix with "/hls/" */
				if(ngx_strncmp(r->uri.data, convered_req_prefix.data, convered_req_prefix.len) == 0) {

					last = r->uri.data + r->uri.len;
					ps = r->uri.data + convered_req_prefix.len;

					pe = ngx_strlchr(ps, last, '/');
					if(pe == NULL || pe - ps <= 7 ) {
						goto failed;
					}

					name.data = ps;
					name.len = pe - ps;

					id = ngx_atoi(name.data + 7 , name.len - 7);
					if( id == NGX_ERROR) {
						goto failed;
					}

					goto done;
				}

				/* origin m3u8 request */
				variant_check = 1;

				ps = r->uri.data + m3u8_req_prefix.len;

				last = r->uri.data + r->uri.len;

				pe = ngx_strlchr(ps, last, '_');

				if(pe == NULL) {
					goto failed;
				}

				name.data = ps;
				name.len = pe - ps;

				id = ngx_atoi(name.data, name.len);

				if( id == NGX_ERROR ) {
					goto failed;
				}
			}
			break;
	}

done:
	/* check channel exist*/
	sw = cmcf->shows.elts;
	for( i = 0; i < cmcf->shows.nelts; i++) {
		ch = sw[i].channels.elts;
		for(k = 0; k < sw[i].channels.nelts; k++) {
			if(ch[k].id == id) {
				if(variant_check && sw[i].variant_playback) {
					ctx->variant_playback = 1;
					ctx->show = &sw[i];
				}

				ctx->channel_name = ch[k].name;
				return NGX_OK;
			}
		}
	}

	ngx_log_error(NGX_LOG_ERR, log, 0, "not found channel \"%i\" in config", id);
	return NGX_ERROR;

failed:
	ngx_log_error(NGX_LOG_ERR, log, 0, "invalid hls uri \"%V\"", &r->uri);
	return NGX_ERROR;

}

static char *
ngx_http_cntv_channel_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	u_char								*last;
	ngx_int_t							n;
	ngx_str_t							*value ;
	//ngx_uint_t							i, j, k;
	ngx_uint_t							i;
	//ngx_http_cntv_channel_name_t		*channel, *ch;
	ngx_http_cntv_channel_name_t		*channel;
	ngx_http_cntv_show_t			*show, *sw;

	ngx_http_cntv_main_conf_t			*cmcf = conf;
	
	value = cf->args->elts;

	sw = cmcf->shows.elts;
	for(i = 0; i < cmcf->shows.nelts; i++) {
		if(sw[i].name.len == value[1].len &&
				ngx_strncmp(sw[i].name.data, value[1].data, value[1].len) == 0) {

			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "channel name \"%V\" is duplicate, ignore it", &value[1]);
			
			return NGX_CONF_OK;
		}
	}

	show = ngx_array_push(&cmcf->shows);
	if(show == NULL) {
		return NGX_CONF_ERROR;
	}

	show->name = value[1];
	show->variant_playback = 0;

	if(ngx_array_init(&show->channels, cf->pool, 4, sizeof(ngx_http_cntv_channel_name_t)) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	for(i = 2; i < cf->args->nelts; i++) {

		//cntv_name_map   cctv1hls  11 12 13 14 variant_playback=on;

		if(ngx_strncmp(value[i].data, "variant_playback", 16) == 0) {
			show->variant_playback = 1;
			continue;
		}

		n = ngx_atoi(value[i].data, value[i].len);

		if(n == NGX_ERROR) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[i]);
			return NGX_CONF_ERROR;
		}

		/*
		sw = cmcf->shows.elts;
		for(j = 0; j < cmcf->shows.nelts; j++) {
			ch = sw[j].channels.elts;
			for(k = 0; k < sw[j].channels.nelts; k++) {
				if(n == ch[k].id) {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "channel id: \"%i\" is duplicate in ", n);
					return NGX_CONF_ERROR;
				}
			}
		}
		*/
		
		channel = ngx_array_push(&show->channels); 
		if(channel == NULL) {
			return NGX_CONF_ERROR;
		}
		
		channel->id = n;

		channel->name.data = ngx_pcalloc(cf->pool, CHANNEL_NAME_LENGTH);

		last = ngx_sprintf(channel->name.data, "channel%i", n);

		channel->name.len = last - channel->name.data;
	}

	return NGX_CONF_OK;
}


static void *
ngx_http_cntv_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_cntv_loc_conf_t		*cfcf;

	cfcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cntv_loc_conf_t));
	if (cfcf == NULL) {
		return NULL;
	}

	cfcf->enable = NGX_CONF_UNSET;

	return cfcf;
}

static char *
ngx_http_cntv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_cntv_loc_conf_t		*prev = parent;
	ngx_http_cntv_loc_conf_t		*conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, 0);
	
	return NGX_CONF_OK;
	
}

static void *
ngx_http_cntv_create_main_conf(ngx_conf_t *cf)
{
	ngx_http_cntv_main_conf_t	*cmcf;

	cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cntv_main_conf_t));
	if(cmcf == NULL) {
		return NULL;
	}

	if(ngx_array_init(&cmcf->shows, cf->pool, 64, sizeof(ngx_http_cntv_show_t)) != NGX_OK) {
		return NULL;
	}

	return cmcf;
}

static char *
ngx_http_cntv_init_main_conf(ngx_conf_t *cf, void *conf)
{
	u_char						*last;
	ngx_dir_t					dir;
	ngx_err_t					err;
	ngx_str_t					channel_name;

	ngx_http_cntv_main_conf_t	*cmcf = conf;

	cntv_main_conf = conf;

	/*
	if(cmcf->shows.nelts == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cntv name channel not set");
		return NGX_CONF_ERROR;
	}
	*/

	if(cmcf->shows.nelts == 0) {
		return NGX_CONF_OK;
	}

	cmcf->pool = ngx_create_pool(100*1024*1024, cf->log);
	if(cmcf->pool == NULL) {
		return NGX_CONF_ERROR;
	}

	if( ngx_array_init(&cmcf->cfs, cmcf->pool, 64, sizeof(ngx_http_cntv_channel_t)) == NGX_ERROR) {
		return NGX_CONF_ERROR;
	}

	cmcf->buf = ngx_create_temp_buf(cmcf->pool, NGX_HTTP_CNTV_INDEX_BUF_SIZE);
	if(cmcf->buf == NULL) {
		return NGX_CONF_ERROR;
	}
	
	if(cmcf->path.data[cmcf->path.len - 1] == '/') {
		cmcf->path.len -= 1;
	}

	cmcf->flv_path.data = ngx_palloc(cf->pool, NGX_HTTP_CNTV_PATH_SIZE);
	
	cmcf->flv_path.data = ngx_palloc(cf->pool, NGX_HTTP_CNTV_PATH_SIZE);
	last = ngx_sprintf(cmcf->flv_path.data, "%V/flv", &cmcf->path);
	cmcf->flv_path.len = last - cmcf->flv_path.data;
	*last = 0;

	if (ngx_open_dir(&cmcf->flv_path, &dir) == NGX_ERROR) {

		ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, 
				ngx_open_dir_n "\"%s\" failed", cmcf->flv_path.data);
		goto next;
	}

	for(;;) {

		ngx_set_errno(0);
		if (ngx_read_dir(&dir) == NGX_ERROR) {
			err = ngx_errno;

			if (err == NGX_ENOMOREFILES) {

				break;

			} else {

				ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, 
						ngx_read_dir_n "\"%s\" failed", cmcf->flv_path.data);

				ngx_close_dir(&dir);

				goto next;
			}

		}

		channel_name.len = ngx_de_namelen(&dir);
		channel_name.data = ngx_de_name(&dir);

		if (channel_name.len == 1 && channel_name.data[0] == '.') {
			continue;
		}

		if (channel_name.len == 2 && channel_name.data[0] == '.' && channel_name.data[1] == '.') {
			continue;
		}

		if(!ngx_de_is_dir(&dir)) {
			continue;
		}

		ngx_http_cntv_create_channel(cmcf, &channel_name, 1, cf->log);
	}

	ngx_close_dir(&dir);

next:
	// init multi rate hds's f4m  and multi rate hls's m3u8
	
	if(ngx_http_cntv_create_main_m3u8(cf, cmcf) != NGX_OK) {
		return NGX_CONF_ERROR;
	}
	
	if(ngx_http_cntv_create_main_f4m(cf, cmcf) != NGX_OK ) {
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;

}


static ngx_int_t
ngx_http_cntv_create_main_m3u8(ngx_conf_t *cf, ngx_http_cntv_main_conf_t *cmcf)
{
	u_char						*last;
	ngx_uint_t					dir_len;
	ngx_buf_t					*b;
	ngx_str_t					path;
	ngx_file_t					file;
	ngx_uint_t					i;
	ngx_file_info_t				fi;
	ngx_http_cntv_channel_name_t	*cn;
	ngx_http_cntv_show_t		*show;

	b = cmcf->buf;

	path.data = ngx_palloc(cf->pool, PATH_MAX_LENGTH);
	//last = ngx_sprintf(path.data, "%V/hls", &cmcf->path);
	last = ngx_sprintf(path.data, "%V", &cmcf->path);
	path.len = last - path.data;
	*last = 0;

	dir_len = path.len;

	if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
					ngx_file_info_n " failed on '%V'", &path);

			return NGX_ERROR;
		}   

		if(ngx_create_dir(path.data, 0744) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
					ngx_create_dir_n " failed on '%V'", &path);
			return NGX_ERROR;
		}   
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0,
					" '%V' exists and is not a directory", &path);
			return NGX_ERROR;
		}   
	}

	
	show = cmcf->shows.elts;
	for(i = 0; i < cmcf->shows.nelts; i++ )
	{
		if(ngx_strncmp(show[i].name.data + (show[i].name.len - 3), "hls", 3) != 0){
			continue;
		}

		last = path.data + dir_len;
		last = ngx_sprintf(last, "/%V.m3u8", &show[i].name);
		path.len = last - path.data;
		*last = 0;

		if(ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
			if (ngx_errno != NGX_ENOENT) {

				ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
						"hls: " ngx_file_info_n " failed on '%V'", path);
				return NGX_ERROR;
			}

			//crate m3u8 file
			file.fd = ngx_open_file(path.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
			if( file.fd == NGX_INVALID_FILE) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "open file \"%V\" failed", &path);
				return NGX_ERROR;
			}

			cn = show[i].channels.elts;
			
			b->pos = b->start; b->last = b->start;
			
			b->last = ngx_sprintf(b->last, "#EXTM3U\n"
					"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=850000\n"
					"/hls/%V/index.m3u8\n"
					"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=500000\n"
					"/hls/%V/index.m3u8\n"
					"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=1500000\n"
					"/hls/%V/index.m3u8\n"
					"#EXT-X-STREAM-INF:PROGRAM-ID=2,BANDWIDTH=2000000\n"
					"/hls/%V/index.m3u8\n",
				   &cn[0].name, &cn[1].name, &cn[2].name, &cn[3].name);

			ngx_write_file(&file, b->pos, b->last - b->pos, 0);

			ngx_close_file(file.fd);
			
		} else {
			if (ngx_is_dir(&fi)) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
						"hls: '%V' exists and is a directory", &path);
				return  NGX_ERROR;
			}
		}
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_cntv_create_main_f4m(ngx_conf_t *cf, ngx_http_cntv_main_conf_t *cmcf)
{
	u_char						*last;
	ngx_buf_t					*b;
	ngx_str_t					path;
	ngx_uint_t					dir_len;
	ngx_file_t					file;
	ngx_uint_t					i;
	ngx_file_info_t				fi;
	ngx_http_cntv_channel_name_t	*cn;
	ngx_http_cntv_show_t		*show;

	b = cmcf->buf;
	path.data = ngx_palloc(cf->pool, PATH_MAX_LENGTH);

	path.data = ngx_palloc(cf->pool, PATH_MAX_LENGTH);
	last = ngx_sprintf(path.data, "%V/hds", &cmcf->path);
	path.len = last - path.data;
	*last = 0;

	dir_len = path.len;

	if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
					ngx_file_info_n " failed on '%V'", &path);

			return NGX_ERROR;
		}   

		if(ngx_create_dir(path.data, 0744) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
					ngx_create_dir_n " failed on '%V'", &path);
			return NGX_ERROR;
		}   
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, cf->log, 0,
					" '%V' exists and is not a directory", &path);
			return NGX_ERROR;
		}   
	}
	
	show = cmcf->shows.elts;
	for(i = 0; i < cmcf->shows.nelts; i++ )
	{
		if(ngx_strncmp(show[i].name.data + (show[i].name.len - 3), "hds", 3) != 0){
			continue;
		}

		last = path.data + dir_len;
		last = ngx_sprintf(last, "/%V.f4m", &show[i].name);
		path.len = last - path.data;
		*last = 0;

		if(ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
			if (ngx_errno != NGX_ENOENT) {

				ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno,
						"hds: " ngx_file_info_n " failed on '%V'", path);
				return NGX_ERROR;
			}

			//crate m3u8 file
			file.fd = ngx_open_file(path.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
			if( file.fd == NGX_INVALID_FILE) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "open file \"%V\" failed", &path);
				return NGX_ERROR;
			}

			cn = show[i].channels.elts;
			b->pos = b->start; b->last = b->start;

			b->last = ngx_sprintf(b->last, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
					"<manifest xmlns=\"http://ns.adobe.com/f4m/1.0\">\n"
					"<id>%V</id>\n"
					"<streamType>live</streamType>\n\t"
					"<bootstrapInfo profile=\"named\" url=\"%V/%V.abst\" id=\"bootstrap0\"></bootstrapInfo>\n\t"
					"<media streamId=\"%V_0\" bitrate=\"850\" url=\"%V/%V\" bootstrapInfoId=\"bootstrap0\"></media>\n\t"
					"<media streamId=\"%V_1\" bitrate=\"500\" url=\"%V/%V\" bootstrapInfoId=\"bootstrap0\"></media>\n\t"
					"<media streamId=\"%V_2\" bitrate=\"1500\" url=\"%V/%V\" bootstrapInfoId=\"bootstrap0\"></media>\n\t"
					"<media streamId=\"%V_3\" bitrate=\"2000\" url=\"%V/%V\" bootstrapInfoId=\"bootstrap0\"></media>\n"
					"</manifest>\n",
					&show[i].name,
					&cn[0].name, &cn[0].name,
					&show[i].name, &cn[0].name, &cn[0].name,
					&show[i].name, &cn[1].name, &cn[1].name,
					&show[i].name, &cn[2].name, &cn[2].name,
					&show[i].name, &cn[3].name, &cn[3].name);

			ngx_write_file(&file, b->pos, b->last - b->pos, 0);

			ngx_close_file(file.fd);
			
		} else {
			if (ngx_is_dir(&fi)) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
						"hds: '%V' exists and is a directory", &path);
				return  NGX_ERROR;
			}
		}
	}

	return NGX_OK;
}

static ngx_http_cntv_channel_t *
ngx_http_cntv_create_channel(ngx_http_cntv_main_conf_t *cmcf, ngx_str_t *channel_name, ngx_flag_t rebuild, ngx_log_t *log)
{
	u_char							*last, *ps, *pe, *name;
	ngx_err_t						err;
	ssize_t							n, readlen, len;
	ngx_str_t						fn;
	ngx_buf_t						*b;
	ngx_dir_t						dir;
	ngx_int_t						frag_time;
	ngx_file_t						ifile, *dfile;
	ngx_file_info_t					fi;
	ngx_http_cntv_frag_t			*frag;
	ngx_http_cntv_channel_t			*channel;

	b = cmcf->buf;

	channel = ngx_array_push(&cmcf->cfs);

	if(channel == NULL) {
		return NULL;
	}

	///init channel
	channel->name.len = channel_name->len;
	channel->name.data = ngx_palloc(cmcf->pool, channel_name->len);
	last = ngx_cpymem(channel->name.data, channel_name->data, channel_name->len);
	///
	channel->channel_path.data = ngx_palloc(cmcf->pool, NGX_HTTP_CNTV_PATH_SIZE);
	last = ngx_sprintf(channel->channel_path.data, "%V/%V", &cmcf->flv_path, channel_name);
	channel->channel_path.len = last - channel->channel_path.data;
	*last = 0;

	channel->ids = ngx_pcalloc(cmcf->pool, sizeof(ngx_http_cntv_slice_index_data_t) * NGX_HTTP_CNTV_SLICE_INDEX_NUM);
	if(channel->ids == NULL) {
		return NULL;
	}

	channel->frags = ngx_pcalloc(cmcf->pool, sizeof(ngx_http_cntv_frag_t) * NGX_HTTP_CNTV_FRAG_NUM);
	if(channel->frags == NULL) {
		return NULL;
	}

	///
	if( !rebuild ) {
		return channel;
	}

	ifile.name.data = ngx_palloc(cmcf->pool, NGX_HTTP_CNTV_PATH_SIZE);

	//open dir
	if (ngx_open_dir(&channel->channel_path, &dir) == NGX_ERROR) {

		ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, 
				ngx_open_dir_n "\"%s\" failed", &channel->channel_path.data);
		return channel;
	}

	for( ; ; ) {
		ngx_set_errno(0);

		if (ngx_read_dir(&dir) == NGX_ERROR) {
			err = ngx_errno;

			if (err == NGX_ENOMOREFILES) {
				break;
			} else {

				ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, 
						ngx_read_dir_n "\"%s\" failed", &channel->channel_path.data);
				ngx_close_dir(&dir);
				return channel;
			}

		}

		len = ngx_de_namelen(&dir);
		name = ngx_de_name(&dir);

		if (len == 1 && name[0] == '.') {
			continue;
		}

		if (len == 2 && name[0] == '.' && name[1] == '.') {
			continue;
		}

		if(!ngx_de_is_file(&dir)) {
			continue;
		}

		if(ngx_strncmp(name + (len - 4), ".idx", 4) != 0) {
			continue;
		}

		ps = name;
		pe = name + (len - 4);
		
		frag_time = ngx_atoi(ps, pe - ps);

		if(frag_time == NGX_ERROR || ngx_time() -frag_time > 7*24*3600) {
			continue;
		}

		fn.data = name;
		fn.len = pe - name;

		ifile.offset = 0;
		ifile.sys_offset = 0;

		last = ngx_sprintf(ifile.name.data, "%V/%V.idx", &channel->channel_path, &fn);
		ifile.name.len = last - ifile.name.data;
		*last = 0;

		/* idx file */
		ifile.fd = ngx_open_file(ifile.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
		if( ifile.fd == NGX_INVALID_FILE) {
			ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "open file \"%V\" failed", &ifile.name);
			continue;
		}

		if(ngx_file_info(ifile.name.data, &fi) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "stat file \"%V\" failed", &ifile.name);
			continue;
		}

		b->pos = b->start; b->last = b->start;
		readlen = ngx_min(NGX_HTTP_CNTV_INDEX_BUF_SIZE, ngx_file_size(&fi));
		n = ngx_read_file(&ifile, b->pos, readlen, 0);
		if(n <= 0) {
			continue;
		}

		b->last += n;

		frag = ngx_http_cntv_get_frag(channel, frag_time);
		frag->frag_time = frag_time;

		/* dfile */
		dfile = &frag->dfile;
		dfile->name.data = ngx_palloc(cmcf->pool, NGX_HTTP_CNTV_PATH_SIZE);
		last = ngx_sprintf(dfile->name.data, "%V/%V.flv", &channel->channel_path, &fn);
		dfile->name.len = last - dfile->name.data;
		*last = 0;

		dfile->fd = ngx_open_file(dfile->name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
		if( dfile->fd == NGX_INVALID_FILE) {
			ngx_log_error(NGX_LOG_EMERG, log, ngx_errno, "open file \"%V\" failed", &dfile->name);
			ngx_close_file(ifile.fd);
			continue;
		}

		/* load slice index*/
		ngx_http_cntv_parse_slice_index(cmcf, channel, dfile);

		ngx_close_file(ifile.fd);

	}

	return channel;
}

static ngx_http_cntv_frag_t *ngx_http_cntv_get_frag(ngx_http_cntv_channel_t *channel, ngx_int_t frag_time)
{
	return &channel->frags[(frag_time/NGX_HTTP_CNTV_FRAG_LEN)%NGX_HTTP_CNTV_FRAG_NUM];
}

static ngx_http_cntv_slice_index_data_t *ngx_http_cntv_get_slice(ngx_http_cntv_channel_t *channel, uint32_t id_time)
{
	return &channel->ids[id_time%NGX_HTTP_CNTV_SLICE_INDEX_NUM];
}

static ngx_http_cntv_session_t*
ngx_http_cntv_get_session(ngx_http_cntv_main_conf_t *cmcf) 
{
	ngx_queue_t					*tail;
	ngx_http_cntv_session_t		*s;

	if(ngx_queue_empty(&cmcf->session_idle)) {
		s = ngx_pcalloc(cmcf->pool, sizeof(ngx_http_cntv_session_t));
	} else {
		tail = ngx_queue_last(&cmcf->session_idle);
		ngx_queue_remove(tail);
		s = ngx_queue_data(tail, ngx_http_cntv_session_t, q);
	}

	//ngx_memzero(s, sizeof(ngx_http_cntv_session_t));
	return s;
}

static void
ngx_http_cntv_put_session(ngx_http_cntv_main_conf_t *cmcf, ngx_http_cntv_session_t *s)
{
	s->node.key = ngx_crc32_short(s->name, s->len);
	ngx_queue_insert_tail(&cmcf->session_busy, &s->q);
	ngx_rbtree_insert(&cmcf->session_tree, &s->node);
	return;
}

static ngx_http_cntv_session_t *
ngx_http_cntv_find_session(ngx_rbtree_t *tree, ngx_str_t *auth)
{
	uint32_t			  hash;
	ngx_int_t             rc;
	ngx_rbtree_node_t    *node, *sentinel;
	ngx_http_cntv_session_t		*rn;

	node = tree->root;
	sentinel = tree->sentinel;

	hash = ngx_crc32_short(auth->data, auth->len);

	while (node != sentinel) {

		if (hash < node->key) {
			node = node->left;
			continue;
		}

		if (hash > node->key) {
			node = node->right;
			continue;
		}

		rn = (ngx_http_cntv_session_t *) node;

		rc = ngx_memn2cmp(auth->data, rn->name, auth->len, rn->len);

		if(rc == 0){
			return rn;
		}

		node = (rc < 0) ? node->left : node->right;
	}

	return NULL;
}

static void 
ngx_http_cntv_session_rbtree_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
	ngx_rbtree_node_t    **p;
	ngx_http_cntv_session_t *rn, *rn_temp;

	for ( ;; ) {

		if (node->key < temp->key) {

			p = &temp->left;

		} else if (node->key > temp->key) {

			p = &temp->right;

		} else {

			rn = (ngx_http_cntv_session_t *) node;
			rn_temp = (ngx_http_cntv_session_t *) temp;

			p = (ngx_memn2cmp(rn->name, rn_temp->name, rn->len, rn_temp->len)
					< 0) ? &temp->left : &temp->right;
		}

		if (*p == sentinel) {
			break;
		}

		temp = *p;
	}

	*p = node;
	node->parent = temp;
	node->left = sentinel;
	node->right = sentinel;
	ngx_rbt_red(node);
}

static void
ngx_http_cntv_parse_slice_index(ngx_http_cntv_main_conf_t *cmcf, ngx_http_cntv_channel_t *channel, ngx_file_t *dfile)
{
	ngx_buf_t					*b;
	ngx_uint_t					i, idx_len, len;
	ngx_http_cntv_slice_index_t			*si;
	ngx_http_cntv_slice_index_data_t	*d;
	
	idx_len = sizeof(ngx_http_cntv_slice_index_t);

	b = cmcf->buf;
	len = b->last - b->pos;

	if( len < idx_len ) {
		return;
	}

	//i = idx_len;

	while(i < len) {
		si = (ngx_http_cntv_slice_index_t *)&b->pos[i];

		d = ngx_http_cntv_get_slice(channel, si->id_time);

		d->si = *si;
		d->dfile = dfile;

		i += idx_len;
	}
}

void 
ngx_http_cntv_add_slice_index(ngx_str_t *name, ngx_int_t frag_time, ngx_http_cntv_slice_index_t *si, ngx_str_t *dat_path)
{
//printf("write index: name:%s, frag time:%ld, start[%u],end[%u], diff[%u],  [%u][%u][%u]\n",
	   	//name->data, frag_time, si->start_time, si->end_time, si->end_time - si->start_time,  si->id_time, si->offset, si->size);
	u_char								*last;
	ngx_uint_t							i, k;
	ngx_file_t							*dfile = NULL;
	ngx_http_cntv_channel_t				*channel, *ch;
	ngx_http_cntv_frag_t				*frag;
	ngx_http_cntv_show_t				*show;
	ngx_http_cntv_channel_name_t		*cn;
	ngx_http_cntv_slice_index_data_t	*d;

	if( cntv_main_conf == NULL ) {
		return;
	}

	channel = NULL;

	ch = cntv_main_conf->cfs.elts;
	for(i = 0; i < cntv_main_conf->cfs.nelts; i++) {
		if(ch[i].name.len == name->len &&
				ngx_strncmp(ch[i].name.data, name->data, name->len) == 0){
			channel = &ch[i];
			goto next;
		}
	}

	if(channel == NULL) {
		show = cntv_main_conf->shows.elts;
		for(i = 0; i < cntv_main_conf->shows.nelts; i++) {
			cn = show[i].channels.elts;
			for(k = 0; k < show[i].channels.nelts; k++) {

				if(cn[k].name.len == name->len &&
						ngx_strncmp(cn[k].name.data, name->data, name->len) == 0){
					channel = ngx_http_cntv_create_channel(cntv_main_conf, name, 0, ngx_cycle->log);
					/* hls and hds has same channel, be careful create channel twice */
					goto next;
				}

			}
		}
	}
	
next:

	if(channel == NULL) {
		return ;
	}
	
	frag = ngx_http_cntv_get_frag(channel, frag_time);
	dfile = &frag->dfile;

	if(frag->frag_time != frag_time) {

		frag->frag_time = frag_time;

		if(dfile->fd > 0) {
			ngx_close_file(dfile->fd);
			dfile->fd = NGX_INVALID_FILE;
		}
		dfile->offset = 0;
		dfile->sys_offset = 0;

		if(dfile->name.len == 0) {
			dfile->name.data = ngx_palloc(cntv_main_conf->pool, NGX_HTTP_CNTV_PATH_SIZE);
		}

		last = ngx_cpymem(dfile->name.data, dat_path->data, dat_path->len);
		dfile->name.len = last - dfile->name.data;
		*last = 0;

		dfile->fd = ngx_open_file(dfile->name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
		if( dfile->fd == NGX_INVALID_FILE) {
			ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno, "open file \"%V\" failed", &dfile->name);
		}
	}

	d = ngx_http_cntv_get_slice(channel, si->id_time);

	d->si = *si;
	d->dfile = dfile;
}

ngx_flag_t 
ngx_http_cntv_check_channel_record(ngx_int_t channel_id)
{
	ngx_uint_t							i, k;
	ngx_http_cntv_show_t				*show;
	ngx_http_cntv_channel_name_t		*cn;

	show = cntv_main_conf->shows.elts;
	for(i = 0; i < cntv_main_conf->shows.nelts; i++) {
		cn = show[i].channels.elts;
		for(k = 0; k < show[i].channels.nelts; k++) {
			if(cn[k].id == channel_id) {
				if(show[i].variant_playback || channel_id % 10 == 4 || channel_id % 10 == 9) {
					return 1;
				}
			}

		}
	}

	return 0;

}

static ngx_int_t
ngx_http_cntv_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_cntv_handler;

	return NGX_OK;
}


static ngx_int_t ngx_http_cntv_init_process(ngx_cycle_t *cycle)
{
	if( cntv_main_conf == NULL || cntv_main_conf->path.len == 0) {
		return NGX_OK;
	}
	///
	ngx_rbtree_init(&cntv_main_conf->session_tree, &cntv_main_conf->session_sentinel, ngx_http_cntv_session_rbtree_insert);
	ngx_queue_init(&cntv_main_conf->session_busy);
	ngx_queue_init(&cntv_main_conf->session_idle);
	///
	cntv_main_conf->session_ev.handler = ngx_http_cntv_session_expire_handler;
	cntv_main_conf->session_ev.log = cycle->log;
	cntv_main_conf->session_ev.data = cntv_main_conf;
	cntv_main_conf->session_ev.timer_set = 0;

	ngx_add_timer(&cntv_main_conf->session_ev, NGX_HTTP_CNTV_SESSION_CHECK_INTERVAL);


	if( ngx_process_slot != 0) {
		return NGX_OK;
	}

	/* clean flv file */
	cntv_main_conf->del_ev.handler = ngx_http_cntv_delete_expire_file_handler;
	cntv_main_conf->del_ev.log = cycle->log;
	cntv_main_conf->del_ev.data = cntv_main_conf;
	cntv_main_conf->del_ev.timer_set = 0;

	time_t	t = time(0);
	struct tm *m= localtime(&t);
	ngx_int_t	tt;
	m->tm_hour = 1;
	m->tm_min = 0;
	m->tm_sec = 0;

	tt = mktime(m) + 86400 - t;
	
	ngx_add_timer(&cntv_main_conf->del_ev, tt * 1000);
	
	cntv_main_conf->del_path.data = ngx_palloc(cycle->pool, 256);
	cntv_main_conf->del_file.data = ngx_palloc(cycle->pool, 256);
	cntv_main_conf->del_root.data = ngx_palloc(cycle->pool, 256);

	/* clean hds file */
	ngx_http_cntv_cleanup_file(&cntv_main_conf->del_ev, NGX_HTTP_CNTV_EXPIRE_HDS);

	return NGX_OK;
}


