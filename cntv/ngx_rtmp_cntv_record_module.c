#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>
#include "ngx_http_cntv_module.h"

typedef struct {

	ngx_file_t		dat_file;
	ngx_file_t		idx_file;
	
    time_t          start_time;
    time_t          end_time;

}ngx_rtmp_cntv_record_frag_t;

typedef struct {

	unsigned		opened:1;
	unsigned		is_first:1;
	unsigned		is_record:1;

    ngx_str_t       name;
	ngx_str_t		last_name;

	ngx_buf_t		*idx_buf;
	ngx_buf_t		*buffer;

	ngx_str_t		record_dir;
	ngx_str_t		channel_dir;

	time_t							frag_time;
    ngx_rtmp_cntv_record_frag_t     cur_frag;
	ngx_http_cntv_slice_index_t		fi;

} ngx_rtmp_cntv_record_ctx_t;

typedef struct {
    ngx_flag_t                          cntv_record;
    time_t								fraglen;
    ngx_str_t                           path;
} ngx_rtmp_cntv_record_app_conf_t;

#define NGX_RTMP_CNTV_RECORD_FRAG_PATH_SIZE     512
#define NGX_RTMP_CNTV_RECORD_BUFFER_SIZE		(1024*1024)
#define NGX_RTMP_CNTV_RECORD_INDEX_BUFFER_SIZE	32
#define NGX_RTMP_CNTV_RECORD_TAG_HEADER_BODY_SIZE  15

#define NGX_RTMP_CNTV_RECORD_DIR_ACCESS         0744

static ngx_str_t flv_header = ngx_string("FLV\x1\0\0\0\0\x9\0\0\0\0");

static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

static ngx_int_t ngx_rtmp_cntv_record_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_cntv_record_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_cntv_record_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);
static ngx_int_t ngx_rtmp_cntv_record_init_process(ngx_cycle_t *cycle);
static void ngx_rtmp_cntv_record_write_index(ngx_rtmp_session_t *s);

//static void ngx_rtmp_cntv_record_write_1bytes(ngx_buf_t *b, int8_t value);
//static void ngx_rtmp_cntv_record_write_2bytes(ngx_buf_t *b, int16_t value);
static void ngx_rtmp_cntv_record_write_3bytes(ngx_buf_t *b, int32_t value);
static void ngx_rtmp_cntv_record_write_4bytes(ngx_buf_t *b, int32_t value);
//static void ngx_rtmp_cntv_record_write_8bytes(ngx_buf_t *b, int64_t value);

static ngx_uint_t ngx_rtmp_cntv_record_wrap_flv(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame);
static ngx_int_t ngx_rtmp_cntv_record_open_fragment(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h);

static ngx_int_t ngx_rtmp_cntv_record_close_fragment(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_cntv_record_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
		    ngx_chain_t **in);

static ngx_command_t ngx_rtmp_cntv_record_commands[] = {

    { ngx_string("cntv_record"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_cntv_record_app_conf_t, cntv_record),
      NULL },

    { ngx_string("cntv_record_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_cntv_record_app_conf_t, path),
      NULL },


    { ngx_string("cntv_record_fragment"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_cntv_record_app_conf_t, fraglen),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_cntv_record_module_ctx = {
    NULL, 							    /* preconfiguration */
    ngx_rtmp_cntv_record_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_cntv_record_create_app_conf,       /* create location configuration */
    ngx_rtmp_cntv_record_merge_app_conf,        /* merge location configuration */
};


ngx_module_t  ngx_rtmp_cntv_record_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_cntv_record_module_ctx,           /* module context */
    ngx_rtmp_cntv_record_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_rtmp_cntv_record_init_process,          /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_rtmp_cntv_record_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    u_char                         *last, *p;
	ssize_t						  name_len;
    ngx_int_t                     i, channel_id ;
	ngx_file_info_t				   fi;
    ngx_rtmp_cntv_record_ctx_t             *ctx;
    ngx_rtmp_cntv_record_app_conf_t        *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_cntv_record_module);
    if (hacf == NULL || !hacf->cntv_record || hacf->path.len == 0) {
		goto next;
    }

    if (s->interprocess) {
		goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "cntv_record: publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_cntv_record_ctx_t));
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_cntv_record_module);

		name_len = ngx_strlen(v->name);
		if(ngx_strncmp(v->name, "flv/channel", 11) != 0 ) {
			goto next;
		}

		channel_id = ngx_atoi(v->name + 11, name_len - 11);
		if( channel_id == NGX_ERROR ) {
			goto next;
		}

		if( !ngx_http_cntv_check_channel_record(channel_id)) {
			goto next;
		}

		ctx->is_record = 1;
		//
		ctx->record_dir.data = ngx_palloc(s->connection->pool, NGX_RTMP_CNTV_RECORD_FRAG_PATH_SIZE);
		ctx->channel_dir.data = ngx_palloc(s->connection->pool, NGX_RTMP_CNTV_RECORD_FRAG_PATH_SIZE);
		
		ctx->cur_frag.idx_file.name.data = ngx_palloc(s->connection->pool, NGX_RTMP_CNTV_RECORD_FRAG_PATH_SIZE);
		ctx->cur_frag.dat_file.name.data = ngx_palloc(s->connection->pool, NGX_RTMP_CNTV_RECORD_FRAG_PATH_SIZE);

		//index buffer
		ctx->idx_buf = ngx_create_temp_buf(s->connection->pool,NGX_RTMP_CNTV_RECORD_INDEX_BUFFER_SIZE);
		//data buffer
		ctx->buffer = ngx_create_temp_buf(s->connection->pool,NGX_RTMP_CNTV_RECORD_BUFFER_SIZE);
		ctx->is_first = 1;
    }

    // stream name
    ctx->name.len = ngx_strlen(v->name);
    ctx->name.data = ngx_palloc(s->connection->pool, ctx->name.len+1);
    *ngx_cpymem(ctx->name.data, v->name, ctx->name.len) = 0;

	// last name
	p = NULL;
	for(i = ctx->name.len-1; i >= 0; i--) {
		if(ctx->name.data[i] == '/') {
			p = ctx->name.data + (i+1);
			break;
		}
	}

	if (p == NULL) {
		ctx->last_name.len = ctx->name.len;
		ctx->last_name.data = ngx_palloc(s->connection->pool, ctx->last_name.len);
		last = ngx_cpymem(ctx->last_name.data, ctx->name.data , ctx->name.len);
	} else {
		ctx->last_name.len = ctx->name.len - (p -ctx->name.data);
		ctx->last_name.data = ngx_palloc(s->connection->pool, ctx->last_name.len);
		last = ngx_cpymem(ctx->last_name.data, p, ctx->last_name.len);
	}

	//cntv_record dir
	last = ngx_cpymem(ctx->record_dir.data, hacf->path.data, hacf->path.len);
    if (last[-1] != '/') {
        *last ++ = '/';
    }

	last = ngx_cpymem(last, "flv" , 3);
	ctx->record_dir.len = last - ctx->record_dir.data;
	*last = 0;

	if (ngx_file_info(ctx->record_dir.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"cntv_record: " ngx_file_info_n " failed on '%V'", &ctx->record_dir);

			goto next;
		}

		if(ngx_create_dir(ctx->record_dir.data, NGX_RTMP_CNTV_RECORD_DIR_ACCESS) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"cntv_record: " ngx_create_dir_n " failed on '%V'", &ctx->record_dir);
			goto next;
		}
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"cntv_record: '%V' exists and is not a directory", &ctx->record_dir);
			goto next;
		}
	}

	//channel dir
	p = NULL;
	last = ngx_cpymem(ctx->channel_dir.data, ctx->record_dir.data, ctx->record_dir.len);
	last = ngx_cpymem(last, "/", 1);

	last = ngx_cpymem(last, ctx->last_name.data , ctx->last_name.len);

	ctx->channel_dir.len = last - ctx->channel_dir.data;
	*last = 0;

	if (ngx_file_info(ctx->channel_dir.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"cntv_record: " ngx_file_info_n " failed on '%V'", &ctx->channel_dir);

			goto next;
		}

		if(ngx_create_dir(ctx->channel_dir.data, NGX_RTMP_CNTV_RECORD_DIR_ACCESS) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"cntv_record: " ngx_create_dir_n " failed on '%V'", &ctx->channel_dir);
			goto next;
		}
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"cntv_record: '%V' exists and is not a directory", &ctx->channel_dir);
			goto next;
		}
	}


next:
    return next_publish(s, v);
}


static ngx_int_t
ngx_rtmp_cntv_record_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_cntv_record_app_conf_t        *hacf;
    ngx_rtmp_cntv_record_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_cntv_record_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);

    if (hacf == NULL || !hacf->cntv_record || ctx == NULL) {
        goto next;
    }

    ngx_rtmp_cntv_record_close_fragment(s);

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_cntv_record_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
	u_char						   *p;
	time_t						   ftime, id_time;
	uint8_t						   ftype, fmt;
	ngx_uint_t					   flv_len;
	ngx_rtmp_frame_t			   frame;
    ngx_rtmp_cntv_record_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_cntv_record_app_conf_t        *hacf;

	ftype = 0;
	
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_cntv_record_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (hacf == NULL || !hacf->cntv_record || ctx == NULL || codec_ctx == NULL ||
        codec_ctx->avc_header == NULL || codec_ctx->aac_header == NULL || h->mlen < 1) {
            return NGX_OK;
    }

	if(!ctx->is_record) {
		return NGX_OK;
	}

	if (ngx_rtmp_is_codec_header(in)) {
		return NGX_OK;
	}

    /* Only H264 is supported */
    if (codec_ctx->video_codec_id != NGX_RTMP_VIDEO_H264 || codec_ctx->audio_codec_id != NGX_RTMP_AUDIO_AAC) {
        return NGX_OK;
    }

	/* first frag */
	if ( ctx->is_first ) {

		ctx->is_first = 0;
		ctx->frag_time = ngx_time()/hacf->fraglen * hacf->fraglen;
		ngx_rtmp_cntv_record_close_fragment(s);
		ngx_rtmp_cntv_record_open_fragment(s, h);
	}


	if(h->type == NGX_RTMP_MSG_VIDEO) {

		p = in->buf->pos;
		if (ngx_rtmp_cntv_record_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
			return NGX_ERROR;
		}
		//key frame
		ftype = (fmt & 0xf0) >> 4;

		if( ftype == 1) {

			/* wirte idx file */
			id_time = ngx_time() / 10;
			if(ctx->fi.id_time != id_time) {

				ngx_rtmp_cntv_record_write_index(s);

				ctx->fi.start_time = ngx_time();
				ctx->fi.id_time = id_time;
				ctx->fi.offset = ctx->cur_frag.dat_file.offset;

			}

			/* check switch frag */
			ftime = ngx_time()/hacf->fraglen * hacf->fraglen;
			if( ctx->frag_time != ftime) {

				ctx->frag_time = ftime;

				ngx_rtmp_cntv_record_close_fragment(s);
				ngx_rtmp_cntv_record_open_fragment(s, h);

			}
		}

	}

	///wrap flv packet
	frame.hdr = *h;
	frame.chain = in;

	flv_len = ngx_rtmp_cntv_record_wrap_flv(s, &frame);
	ctx->fi.size += flv_len;

	return NGX_OK;
}

static void
ngx_rtmp_cntv_record_write_index(ngx_rtmp_session_t *s)
{
	ssize_t							n;
	ngx_file_t						*file;
	ngx_rtmp_cntv_record_ctx_t		*ctx;
	
	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);
	if (ctx == NULL || !ctx->opened) {
		return;
	}

	file = &ctx->cur_frag.idx_file;

	ctx->fi.end_time = ngx_time();

//printf("id_time:%u, start_time:%u, end_time:%u, offset:%u, size:%u\n",
//	   	ctx->fi.id_time, ctx->fi.start_time, ctx->fi.end_time, ctx->fi.offset, ctx->fi.size);
	//write memory
	ngx_http_cntv_add_slice_index(&ctx->last_name, ctx->frag_time, &ctx->fi, &ctx->cur_frag.dat_file.name);

	//write file
	n = ngx_write_file(file, (u_char *)&ctx->fi, sizeof(ctx->fi), file->offset);

	if(n == NGX_ERROR) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
				"cntv_record: failed to write idx file: %V", &file->name);
	}

	//init frag index
	ngx_memzero(&ctx->fi, sizeof(ctx->fi));
}

static ngx_int_t
ngx_rtmp_cntv_record_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
		    ngx_chain_t **in)
{
	u_char  *last;
	size_t   pn;

	if (*in == NULL) {
		return NGX_ERROR;
	}

	for ( ;; ) {
		last = (*in)->buf->last;

		if ((size_t)(last - *src) >= n) {
			if (dst) {
				ngx_memcpy(dst, *src, n);
			}

			*src += n;

			while (*in && *src == (*in)->buf->last) {
				*in = (*in)->next;
				if (*in) {
					*src = (*in)->buf->pos;
				}
			}

			return NGX_OK;
		}

		pn = last - *src;

		if (dst) {
			ngx_memcpy(dst, *src, pn);
			dst = (u_char *)dst + pn;
		}

		n -= pn;
		*in = (*in)->next;

		if (*in == NULL) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"cntv_record: failed to read %uz byte(s)", n);
			return NGX_ERROR;
		}

		*src = (*in)->buf->pos;
	}
}

static ngx_int_t
ngx_rtmp_cntv_record_open_fragment(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h)
{
	u_char					*last;
	ngx_uint_t				aac_len, avc_len;
	ngx_rtmp_cntv_record_ctx_t		*ctx;
	ngx_rtmp_codec_ctx_t	*codec_ctx;
    ngx_rtmp_cntv_record_app_conf_t        *hacf;
	
    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_cntv_record_module);

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);
	if (ctx == NULL || ctx->opened) {
		return NGX_OK;
	}

	//flv path:		   path/flv/channel10/1522036800.flv
	//idx path:		   path/flv/channel10/1522036800.idx

	//idx
	last = ngx_sprintf(ctx->cur_frag.idx_file.name.data, "%V/%T.idx", &ctx->channel_dir, ctx->frag_time);

	ctx->cur_frag.idx_file.name.len = last - ctx->cur_frag.idx_file.name.data;
	*last = 0;

	//flv
	last = ngx_sprintf(ctx->cur_frag.dat_file.name.data, "%V/%T.flv", &ctx->channel_dir, ctx->frag_time);

	ctx->cur_frag.dat_file.name.len = last - ctx->cur_frag.dat_file.name.data;
	*last = 0;
	///

	if (ngx_file_info(ctx->cur_frag.dat_file.name.data, &ctx->cur_frag.dat_file.info) == NGX_FILE_ERROR) {
		ctx->cur_frag.dat_file.offset = 0;
		ctx->cur_frag.dat_file.sys_offset = 0;
	} else {

		if (ngx_is_dir(&ctx->cur_frag.dat_file.info)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"cntv_record: '%V' exists and is a directory", &ctx->cur_frag.dat_file.name);
			return NGX_ERROR;
		}

		ctx->cur_frag.dat_file.offset = ctx->cur_frag.dat_file.info.st_size;
		ctx->cur_frag.dat_file.sys_offset = ctx->cur_frag.dat_file.info.st_size;
	}

	if (ngx_file_info(ctx->cur_frag.idx_file.name.data, &ctx->cur_frag.idx_file.info) == NGX_FILE_ERROR) {
		ctx->cur_frag.idx_file.offset = 0;
		ctx->cur_frag.idx_file.sys_offset = 0;
	} else {

		if (ngx_is_dir(&ctx->cur_frag.dat_file.info)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"cntv_record: '%V' exists and is a directory", &ctx->cur_frag.idx_file.name);
			return NGX_ERROR;
		}

		ctx->cur_frag.idx_file.offset = ctx->cur_frag.idx_file.info.st_size;
		ctx->cur_frag.idx_file.sys_offset = ctx->cur_frag.idx_file.info.st_size;
	}


	//init  cur frag
	ctx->cur_frag.start_time = h->timestamp;
	ctx->cur_frag.end_time = 0;

	ctx->cur_frag.idx_file.fd = NGX_INVALID_FILE;
	ctx->cur_frag.idx_file.log = s->connection->log;

	ctx->cur_frag.dat_file.fd = NGX_INVALID_FILE;
	ctx->cur_frag.dat_file.log = s->connection->log;


	ctx->cur_frag.idx_file.fd = ngx_open_file(ctx->cur_frag.idx_file.name.data, 
			NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (ctx->cur_frag.idx_file.fd == NGX_INVALID_FILE) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"cntv_record: " ngx_open_file_n " failed: '%V'",
				&ctx->cur_frag.idx_file.name);
		return NGX_ERROR;
	}

	ctx->cur_frag.dat_file.fd = ngx_open_file(ctx->cur_frag.dat_file.name.data,
		   	NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);

	if (ctx->cur_frag.dat_file.fd == NGX_INVALID_FILE) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"cntv_record: " ngx_open_file_n " failed: '%V'",
				&ctx->cur_frag.dat_file.name);

		ngx_close_file(ctx->cur_frag.idx_file.fd);

		return NGX_ERROR;
	}

	ctx->opened = 1;

	codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);

	// flv header exist
	if(ctx->cur_frag.idx_file.offset >= (off_t)sizeof(ngx_http_cntv_slice_index_t)) {

		ctx->fi.id_time = ngx_time()/10;
		ctx->fi.start_time = ngx_time();
		ctx->fi.offset = ctx->cur_frag.dat_file.offset;

		return NGX_OK;
	}

	/* flv header */
	ngx_write_file(&ctx->cur_frag.dat_file, flv_header.data, flv_header.len, 0);

	/* pack avc header */ 
	//codec_ctx->avc_header->hdr.timestamp = ctx->cur_frag.start_time;
	avc_len = ngx_rtmp_cntv_record_wrap_flv(s, codec_ctx->avc_header);

	/* pack aac header */
	//codec_ctx->aac_header->hdr.timestamp = ctx->cur_frag.start_time;
	aac_len = ngx_rtmp_cntv_record_wrap_flv(s, codec_ctx->aac_header);

	ctx->fi.start_time = 0;
	ctx->fi.id_time = 0;
	ctx->fi.offset = flv_header.len;
	ctx->fi.size = avc_len + aac_len;

	ngx_rtmp_cntv_record_write_index(s);
	
	//init fi
	ctx->fi.id_time = ngx_time()/10;
	ctx->fi.start_time = ngx_time();
	ctx->fi.offset = ctx->cur_frag.dat_file.offset;

	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_cntv_record_close_fragment(ngx_rtmp_session_t *s)
{
	ngx_rtmp_cntv_record_ctx_t		*ctx;

    //ngx_rtmp_cntv_record_app_conf_t        *hacf;
    //hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_cntv_record_module);

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);
	if( ctx == NULL || !ctx->opened) {
		return NGX_OK;
	}

	ngx_close_file(ctx->cur_frag.idx_file.fd);
	ngx_close_file(ctx->cur_frag.dat_file.fd);

	ctx->cur_frag.idx_file.fd = NGX_INVALID_FILE;
	ctx->cur_frag.dat_file.fd = NGX_INVALID_FILE;

	ctx->opened = 0;

	return NGX_OK;
}

static ngx_uint_t
ngx_rtmp_cntv_record_wrap_flv(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame)
{
	ssize_t					n, size = 0;
	int32_t					tagsize;
	long long				dts;
	ngx_buf_t				*b, *bin;
	ngx_file_t				*file;
	ngx_chain_t				*in, *cl;
	ngx_rtmp_header_t		*h;
	ngx_rtmp_cntv_record_ctx_t		*ctx;

	h = &frame->hdr;
	in = frame->chain;

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_cntv_record_module);
	if (ctx == NULL || !ctx->opened) {
		return 0;
	}

	file = &ctx->cur_frag.dat_file;

	b = ctx->buffer;

	///init buffer
	b->pos = b->last = b->start;

	//tag header
	*b->last++ = frame->hdr.type==NGX_RTMP_MSG_VIDEO ? 0x09 : 0x08;

	dts = h->timestamp;

	ngx_rtmp_cntv_record_write_3bytes(b, h->mlen);
	
	ngx_rtmp_cntv_record_write_3bytes(b, dts);

	*b->last++ = (dts >> 24 & 0xFF);

	ngx_rtmp_cntv_record_write_3bytes(b, 0);

	n = ngx_write_file(file, b->pos, b->last - b->pos, file->offset);
	if( n > 0) {
		size += n;
	}

	for(cl = in; cl; cl= cl->next) {
		bin = cl->buf;
		n = ngx_write_file(file, bin->pos, bin->last - bin->pos, file->offset);
		if( n > 0) {
			size += n;
		}
	}

	// pre tag size
	tagsize = h->mlen + 11;

	b->pos = b->last = b->start;

	ngx_rtmp_cntv_record_write_4bytes(b, tagsize);
	n = ngx_write_file(file, b->pos, b->last - b->pos, file->offset);
	if( n > 0) {
		size += n;
	}

	ctx->cur_frag.end_time = h->timestamp;

	return size;
}

/*
static void
ngx_rtmp_cntv_record_write_1bytes(ngx_buf_t *b, int8_t value)
{
	*b->last ++ = value;
}

static void
ngx_rtmp_cntv_record_write_2bytes(ngx_buf_t *b, int16_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[1];
	*b->last ++ = p[0];
}
*/

static void
ngx_rtmp_cntv_record_write_3bytes(ngx_buf_t *b, int32_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[2];
	*b->last ++ = p[1];
	*b->last ++ = p[0];
}

static void
ngx_rtmp_cntv_record_write_4bytes(ngx_buf_t *b, int32_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[3];
	*b->last ++ = p[2];
	*b->last ++ = p[1];
	*b->last ++ = p[0];
}

/*
static void
ngx_rtmp_cntv_record_write_8bytes(ngx_buf_t *b, int64_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[7];
	*b->last ++ = p[6];
	*b->last ++ = p[5];
	*b->last ++ = p[4];

	*b->last ++ = p[3];
	*b->last ++ = p[2];
	*b->last ++ = p[1];
	*b->last ++ = p[0];
}
*/

static ngx_int_t
ngx_rtmp_cntv_record_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_cntv_record_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_cntv_record_close_fragment(s);

    return next_stream_eof(s, v);
}


static void *
ngx_rtmp_cntv_record_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_cntv_record_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_cntv_record_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }
	
	conf->cntv_record = NGX_CONF_UNSET;
	conf->fraglen = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_cntv_record_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_rtmp_cntv_record_app_conf_t    *prev = parent;
	ngx_rtmp_cntv_record_app_conf_t    *conf = child;

	ngx_conf_merge_sec_value(conf->fraglen, prev->fraglen, 6*3600);

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_cntv_record_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_cntv_record_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_cntv_record_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_cntv_record_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_cntv_record_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_cntv_record_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_cntv_record_stream_eof;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_cntv_record_init_process(ngx_cycle_t *cycle)
{
	return NGX_OK;
}


