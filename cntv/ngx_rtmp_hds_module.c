#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include <ngx_rtmp_cmd_module.h>
#include <ngx_rtmp_codec_module.h>

typedef struct {

	ngx_fd_t		fd;
    ngx_uint_t      start_time;
    ngx_uint_t		end_time;
	ngx_uint_t		index;
    ngx_str_t       path;
	ssize_t			size;

}ngx_rtmp_hds_frag_t;

typedef struct {
	unsigned		opened:1;
	unsigned		is_first:1;
    ngx_str_t       name;
	ngx_str_t		last_name;
    ngx_buf_t       *f4m_buf;
    ngx_str_t       f4m_path;
    ngx_str_t       f4m_path_bak;

	ngx_str_t		hds_dir;
	ngx_str_t		channel_dir;

	ngx_str_t		abst_path;
	ngx_str_t		abst_path_bak;

	ngx_buf_t		*buffer;

	ngx_uint_t				frag_time;
	ngx_uint_t				frag_id;
    ngx_rtmp_hds_frag_t     cur_frag;
    ngx_rtmp_hds_frag_t     *frags;


} ngx_rtmp_hds_ctx_t;

typedef struct {
    ngx_flag_t                          hds;
    ngx_str_t                           path;
} ngx_rtmp_hds_app_conf_t;


#define NGX_RTMP_HDS_MAINFEST_BUFSIZE   1024
#define NGX_RTMP_HDS_FRAG_PATH_SIZE     512
#define NGX_RTMP_HDS_BUFFER_SIZE		(1024*1024)
#define NGX_RTMP_HDS_TAG_HEADER_BODY_SIZE  15
#define NGX_RTMP_HDS_FRAG_NUM			10

#define NGX_RTMP_HDS_DIR_ACCESS         0744

static u_char box_header[] = {0x00, 0x00, 0x00, 0x00, 'm', 'd', 'a','t'};


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_close_stream_pt         next_close_stream;
static ngx_rtmp_stream_begin_pt         next_stream_begin;
static ngx_rtmp_stream_eof_pt           next_stream_eof;

static ngx_int_t ngx_rtmp_hds_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_hds_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_hds_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);

static ngx_int_t ngx_rtmp_hds_init_process(ngx_cycle_t *cycle);

static void ngx_rtmp_hds_write_1bytes(ngx_buf_t *b, int8_t value);
//static void ngx_rtmp_hds_write_2bytes(ngx_buf_t *b, int16_t value);
static void ngx_rtmp_hds_write_3bytes(ngx_buf_t *b, int32_t value);
static void ngx_rtmp_hds_write_4bytes(ngx_buf_t *b, int32_t value);
static void ngx_rtmp_hds_write_8bytes(ngx_buf_t *b, int64_t value);

static ngx_int_t ngx_rtmp_hds_write_abst(ngx_rtmp_session_t *s);
static void ngx_rtmp_hds_copy_frag(ngx_rtmp_hds_frag_t *src, ngx_rtmp_hds_frag_t *dst);
static void ngx_rtmp_hds_wrap_flv(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame);
static ngx_int_t ngx_rtmp_hds_write_f4m(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_hds_open_fragment(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h);

static ngx_int_t ngx_rtmp_hds_close_fragment(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_hds_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
		    ngx_chain_t **in);

static ngx_command_t ngx_rtmp_hds_commands[] = {

    { ngx_string("hds"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, hds),
      NULL },

    { ngx_string("hds_path"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_hds_app_conf_t, path),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t  ngx_rtmp_hds_module_ctx = {
    NULL, 							    /* preconfiguration */
    ngx_rtmp_hds_postconfiguration,     /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_rtmp_hds_create_app_conf,       /* create location configuration */
    ngx_rtmp_hds_merge_app_conf,        /* merge location configuration */
};


ngx_module_t  ngx_rtmp_hds_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_hds_module_ctx,           /* module context */
    ngx_rtmp_hds_commands,              /* module directives */
    NGX_RTMP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_rtmp_hds_init_process,          /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_rtmp_hds_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    u_char                         *last, *p;
    ngx_int_t                     i;
    ngx_uint_t                     k;
	ngx_file_info_t				   fi;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_hds_app_conf_t        *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);
    if (hacf == NULL || !hacf->hds || hacf->path.len == 0) {
		goto next;
    }

    if (s->interprocess) {
		goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "hds: publish: name='%s' type='%s'",
                   v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hds_ctx_t));

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_hds_module);

        ctx->f4m_buf = ngx_create_temp_buf(s->connection->pool, NGX_RTMP_HDS_MAINFEST_BUFSIZE);

		//
        ctx->frags = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_hds_frag_t) * NGX_RTMP_HDS_FRAG_NUM);
		for (k = 0; k < NGX_RTMP_HDS_FRAG_NUM; k++) {
			ctx->frags[k].path.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);
		}

		ctx->cur_frag.path.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);

        ctx->buffer = ngx_create_temp_buf(s->connection->pool, NGX_RTMP_HDS_BUFFER_SIZE);

		ctx->f4m_path.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);
		ctx->f4m_path_bak.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);

		ctx->abst_path.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);
		ctx->abst_path_bak.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);

		ctx->hds_dir.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);
		ctx->channel_dir.data = ngx_palloc(s->connection->pool, NGX_RTMP_HDS_FRAG_PATH_SIZE);

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

	//hds dir
	last = ngx_cpymem(ctx->hds_dir.data, hacf->path.data, hacf->path.len);
    if (last[-1] != '/') {
        *last ++ = '/';
    }

	last = ngx_cpymem(last, "hds" , 3);
	ctx->hds_dir.len = last - ctx->hds_dir.data;
	*last = 0;

	if (ngx_file_info(ctx->hds_dir.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"hds: " ngx_file_info_n " failed on '%V'", &ctx->hds_dir);

			goto next;
		}

		if(ngx_create_dir(ctx->hds_dir.data, NGX_RTMP_HDS_DIR_ACCESS) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"hds: " ngx_create_dir_n " failed on '%V'", &ctx->hds_dir);
			goto next;
		}
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"hds: '%V' exists and is not a directory", &ctx->hds_dir);
			goto next;
		}
	}

	//channel dir
	p = NULL;
	last = ngx_cpymem(ctx->channel_dir.data, ctx->hds_dir.data, ctx->hds_dir.len);
	last = ngx_cpymem(last, "/", 1);

	last = ngx_cpymem(last, ctx->last_name.data , ctx->last_name.len);

	ctx->channel_dir.len = last - ctx->channel_dir.data;
	*last = 0;

	if (ngx_file_info(ctx->channel_dir.data, &fi) == NGX_FILE_ERROR) {

		if (ngx_errno != NGX_ENOENT) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"hds: " ngx_file_info_n " failed on '%V'", &ctx->channel_dir);

			goto next;
		}

		if(ngx_create_dir(ctx->channel_dir.data, NGX_RTMP_HDS_DIR_ACCESS) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"hds: " ngx_create_dir_n " failed on '%V'", &ctx->channel_dir);
			goto next;
		}
	} else {

		if (!ngx_is_dir(&fi)) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
					"hds: '%V' exists and is not a directory", &ctx->channel_dir);
			goto next;
		}
	}

    //main f4m path:   path/cctv10hds.f4m
    //sub f4m path:    path/channel10/index.f4m
    //abst path:  path/channel10/index.abst

    // f4m path
    last = ngx_cpymem(ctx->f4m_path.data, ctx->channel_dir.data, ctx->channel_dir.len);
    //last = ngx_cpymem(last, "/index.f4m", sizeof("/index.f4m") -1);
    last = ngx_cpymem(last, "/", 1);
    last = ngx_cpymem(last, ctx->last_name.data, ctx->last_name.len);
    last = ngx_cpymem(last, ".f4m", 4);
	
	ctx->f4m_path.len = last - ctx->f4m_path.data;
    *last = 0;
    
    // f4m path bak
    last = ngx_cpymem(ctx->f4m_path_bak.data, ctx->f4m_path.data, ctx->f4m_path.len);
    last = ngx_cpymem(last, ".bak", sizeof(".bak") - 1);
    ctx->f4m_path_bak.len = last - ctx->f4m_path_bak.data;
    *last = 0;

	//abst path
    last = ngx_cpymem(ctx->abst_path.data, ctx->channel_dir.data, ctx->channel_dir.len);
	//last = ngx_cpymem(last, "/index.abst", sizeof("/index.abst") -1);
	last = ngx_cpymem(last, "/", 1);
    last = ngx_cpymem(last, ctx->last_name.data, ctx->last_name.len);
    last = ngx_cpymem(last, ".abst", 5);
	
	ctx->abst_path.len = last - ctx->abst_path.data;
	*last = 0;
	
	//abst path bak
    last = ngx_cpymem(ctx->abst_path_bak.data, ctx->abst_path.data, ctx->abst_path.len);
	last = ngx_cpymem(last, ".bak", sizeof(".bak") -1);
	ctx->abst_path_bak.len = last - ctx->abst_path_bak.data;
	*last = 0;

    //wrtie f4m
    ngx_rtmp_hds_write_f4m(s);

next:
    return next_publish(s, v);
}

static ngx_int_t
ngx_rtmp_hds_write_f4m(ngx_rtmp_session_t *s)
{
    ssize_t         n;
    ngx_fd_t        fd;
    ngx_rtmp_hds_ctx_t      *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    //mainfest buf
    ctx->f4m_buf->last = ngx_sprintf(ctx->f4m_buf->pos,
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                "<manifest xmlns=\"http://ns.adobe.com/f4m/1.0\">\n\t"
                "<id>%V.f4m</id>\n\t"
                "<streamType>live</streamType>\n\t"
                "<deliveryType>streaming</deliveryType>\n\t"
                "<bootstrapInfo profile=\"named\" url=\"%V.abst\" id=\"bootstrap0\" />\n\t"
                "<media bitrate=\"0\" url=\"%V\" bootstrapInfoId=\"bootstrap0\"></media>\n"
                "</manifest>"
                , &ctx->last_name, &ctx->last_name, &ctx->last_name);

    fd = ngx_open_file(ctx->f4m_path_bak.data, NGX_FILE_WRONLY,
                       NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: " ngx_open_file_n " failed: '%V'",
                      &ctx->f4m_path_bak);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, ctx->f4m_buf->pos, ctx->f4m_buf->last - ctx->f4m_buf->pos);

    if (n < 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: " ngx_write_fd_n " failed: '%V'",
                      &ctx->f4m_path_bak);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    ngx_close_file(fd);

    // rename
    if (ngx_rename_file(ctx->f4m_path_bak.data, ctx->f4m_path.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds: rename failed: '%V'->'%V'",
                      &ctx->f4m_path_bak, &ctx->f4m_path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hds_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_hds_app_conf_t        *hacf;
    ngx_rtmp_hds_ctx_t             *ctx;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);

    if (hacf == NULL || !hacf->hds || ctx == NULL) {
        goto next;
    }

    ngx_rtmp_hds_close_fragment(s);

next:
    return next_close_stream(s, v);
}

static ngx_int_t
ngx_rtmp_hds_av(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
	u_char						   *p;
	uint8_t						   ftype, fmt;
	ngx_uint_t					   frag_time;
	ngx_rtmp_frame_t			   frame;
    ngx_rtmp_hds_ctx_t             *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;
    ngx_rtmp_hds_app_conf_t        *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    if (hacf == NULL || !hacf->hds || ctx == NULL || codec_ctx == NULL ||
		codec_ctx->aac_header == NULL || codec_ctx->avc_header == NULL || h->mlen < 1) {

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
	if(ctx->is_first) {
		ctx->is_first = 0;
		ctx->frag_time = ngx_time()/10;
		ngx_rtmp_hds_close_fragment(s);
		ngx_rtmp_hds_open_fragment(s, h);
	}

	if(h->type == NGX_RTMP_MSG_VIDEO) {

		p = in->buf->pos;
		if (ngx_rtmp_hds_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
			return NGX_ERROR;
		}

		ftype = (fmt & 0xf0) >> 4;

		if(ftype == 1) {
			frag_time = ngx_time()/10;
			if( ctx->frag_time != frag_time) {
				ctx->frag_time = frag_time;
				ngx_rtmp_hds_close_fragment(s);
				ngx_rtmp_hds_open_fragment(s, h);
			}
		}
	}

	frame.hdr = *h;
	frame.chain = in;

	ngx_rtmp_hds_wrap_flv(s, &frame);


	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hds_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
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
					"hds: failed to read %uz byte(s)", n);
			return NGX_ERROR;
		}

		*src = (*in)->buf->pos;
	}
}

static ngx_int_t
ngx_rtmp_hds_open_fragment(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h)
{
	ssize_t					n;
	u_char					*last;
	ngx_rtmp_hds_ctx_t		*ctx;
	ngx_rtmp_codec_ctx_t	*codec_ctx;

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
	if (ctx == NULL ) {
		return NGX_OK;
	}

	last = ngx_snprintf(ctx->cur_frag.path.data, NGX_RTMP_HDS_FRAG_PATH_SIZE, "%V/%VSeg1-Frag%ui", 
	        &ctx->channel_dir, &ctx->last_name, ctx->frag_time);

	ctx->cur_frag.path.len = last - ctx->cur_frag.path.data;
	*last = 0;

	/// cur_frag init
	ctx->cur_frag.index = ctx->frag_time;
	ctx->cur_frag.size = 0;
	ctx->cur_frag.start_time = h->timestamp;
	ctx->cur_frag.end_time = h->timestamp;

	ctx->cur_frag.fd = ngx_open_file(ctx->cur_frag.path.data, NGX_FILE_WRONLY,
			NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);

	if (ctx->cur_frag.fd == NGX_INVALID_FILE) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"hds: " ngx_open_file_n " failed: '%V'",
				&ctx->cur_frag.path);
		return NGX_ERROR;
	}

	ctx->opened = 1;

	/* pack box header */
	n = ngx_write_fd(ctx->cur_frag.fd, box_header, sizeof(box_header));

	if (n < 0) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"hds: " ngx_write_fd_n " failed: '%V'",
				&ctx->cur_frag.path);
	}

	ctx->cur_frag.size += n;
	
	codec_ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
	
	/* pack avc header */ 
	if (codec_ctx->avc_header) {
		codec_ctx->avc_header->hdr.timestamp = ctx->cur_frag.start_time;
		ngx_rtmp_hds_wrap_flv(s, codec_ctx->avc_header);
	}

	/* pack aac header */
	if (codec_ctx->aac_header) {
		codec_ctx->aac_header->hdr.timestamp = ctx->cur_frag.start_time;
		ngx_rtmp_hds_wrap_flv(s, codec_ctx->aac_header);
	}

	return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hds_close_fragment(ngx_rtmp_session_t *s)
{
	off_t					offset;
	ssize_t					n;
	u_char					*p;
	int32_t					body_size;
	u_char					buf[4];
	ngx_rtmp_hds_ctx_t		*ctx;
	ngx_rtmp_hds_frag_t		*frag;

    ngx_rtmp_hds_app_conf_t        *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
	if( ctx == NULL || !ctx->opened) {
		return NGX_OK;
	}

	//modify box header
	offset = lseek(ctx->cur_frag.fd, 0, SEEK_SET);

	if(offset < 0 ) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"hds: lseek failed on '%V'", &ctx->cur_frag.path);
	} else {
		body_size = ctx->cur_frag.size;
		p = (u_char*)&body_size;
		buf[0] = p[3];
		buf[1] = p[2];
		buf[2] = p[1];
		buf[3] = p[0];

		n = ngx_write_fd(ctx->cur_frag.fd, buf, 4);

		if (n < 0) {
			ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
					"hds: " ngx_write_fd_n " failed: '%V'",
					&ctx->cur_frag.path);
		}
	}
	
	ctx->opened = 0;
	ngx_close_file(ctx->cur_frag.fd);
	
	
	//delete old frag
	frag = &ctx->frags[ctx->frag_id];
	
	if (frag->size > 0 && ngx_delete_file(frag->path.data) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"hds: cleanup " ngx_delete_file_n " failed on '%V'",
				&frag->path);
	}
	
	// replace old frag
	ngx_rtmp_hds_copy_frag(&ctx->cur_frag, frag);
	
	ctx->frag_id ++;
	ctx->frag_id %= NGX_RTMP_HDS_FRAG_NUM;

	//write abst
	ngx_rtmp_hds_write_abst(s);

	/* reinit cur_frag */
	//ngx_memzero(&ctx->cur_frag, sizeof(ctx->cur_frag));
	ctx->cur_frag.fd = -1;
	ctx->cur_frag.start_time = 0;
	ctx->cur_frag.end_time = 0;
	ctx->cur_frag.index = 0;
	ctx->cur_frag.size = 0;
	return NGX_OK;
}

static void
ngx_rtmp_hds_copy_frag(ngx_rtmp_hds_frag_t *src, ngx_rtmp_hds_frag_t *dst)
{
	dst->path.len = src->path.len;
	*ngx_cpymem(dst->path.data, src->path.data, src->path.len) = 0;
	dst->size = src->size;
	dst->index = src->index;
	dst->start_time = src->start_time;
	dst->end_time = src->end_time;
}

static void 
ngx_rtmp_hds_wrap_flv(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame)
{
	ssize_t					n, size = 0;
	int32_t					tagsize;
	long long				dts;
	ngx_buf_t				*b, *bin;
	ngx_chain_t				*in, *cl;
	ngx_rtmp_header_t		*h;
	ngx_rtmp_hds_ctx_t		*ctx;

	h = &frame->hdr;
	in = frame->chain;

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
	if (ctx == NULL || !ctx->opened) {
		return;
	}

	b = ctx->buffer;

	///init buffer
	b->pos = b->last = b->start;

	//tag header
	*b->last++ = frame->hdr.type==NGX_RTMP_MSG_VIDEO ? 0x09 : 0x08;

	dts = h->timestamp;

	ngx_rtmp_hds_write_3bytes(b, h->mlen);
	
	ngx_rtmp_hds_write_3bytes(b, dts);

	*b->last++ = (dts >> 24 & 0xFF);

	ngx_rtmp_hds_write_3bytes(b, 0);

	n = ngx_write_fd(ctx->cur_frag.fd, b->pos, b->last - b->pos);
	if( n > 0 ){
		ctx->cur_frag.size += n;
	}

	for(cl = in; cl; cl= cl->next) {
		bin = cl->buf;
		n = ngx_write_fd(ctx->cur_frag.fd, bin->pos, bin->last - bin->pos);
		if( n > 0 ){
			ctx->cur_frag.size += n;
		}
	}
	
	// pre tag size
	tagsize = h->mlen + 11;

	b->pos = b->last = b->start;

	ngx_rtmp_hds_write_4bytes(b, tagsize);

	n = ngx_write_fd(ctx->cur_frag.fd, b->pos, b->last - b->pos);
	if (n > 0) {
		ctx->cur_frag.size += n;
	}
	
	ctx->cur_frag.end_time = h->timestamp;
}

static ngx_int_t
ngx_rtmp_hds_write_abst(ngx_rtmp_session_t *s)
{
	int							i, n = 0;
	ssize_t						nw;
	u_char						*p, *asrt_start, *afrt_start;
	int32_t						size;
	ngx_fd_t					fd;
	ngx_buf_t					*b;
	ngx_uint_t					id;
	ngx_rtmp_hds_frag_t			*frag;
	ngx_rtmp_hds_ctx_t			*ctx;
	ngx_rtmp_hds_app_conf_t        *hacf;

    hacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_hds_module);

	ctx  = ngx_rtmp_get_module_ctx(s, ngx_rtmp_hds_module);
	if (ctx == NULL ) {
		return NGX_OK;
	}

	b = ctx->buffer;

	b->last = b->pos = b->start;
	
	ngx_rtmp_hds_write_4bytes(b, 0);
	b->last = ngx_cpymem(b->last, "abst" , 4);
	ngx_rtmp_hds_write_1bytes(b, 0x00);
	ngx_rtmp_hds_write_3bytes(b, 0x00);

	//abst info version
	ngx_rtmp_hds_write_4bytes(b, ctx->frag_time - 1);

	ngx_rtmp_hds_write_1bytes(b, 0x20);
	ngx_rtmp_hds_write_4bytes(b, 1000);

	ngx_rtmp_hds_write_8bytes(b, ctx->cur_frag.start_time);

	//SmpteTimeCodeOffset
	ngx_rtmp_hds_write_8bytes(b, 0);

	/*!
        @ServerEntryCount       UI8
        The number of ServerEntryTable entries.
        The minimum value is 0.
    */
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 1);

	// start asrt
	asrt_start = b->last;
	ngx_rtmp_hds_write_4bytes(b, 0);
	b->last = ngx_cpymem(b->last, "asrt", 4);
	ngx_rtmp_hds_write_4bytes(b, 0);
	ngx_rtmp_hds_write_1bytes(b, 0);
	ngx_rtmp_hds_write_4bytes(b, 1);

	for (i = 0; i < 1; ++i) {
		ngx_rtmp_hds_write_4bytes(b, 1);
		ngx_rtmp_hds_write_4bytes(b, ctx->frag_time - 1);
	}

	size = b->last - asrt_start; 
	p = (u_char *)&size;
	asrt_start[0] = p[3];
	asrt_start[1] = p[2];
	asrt_start[2] = p[1];
	asrt_start[3] = p[0];
	//
	ngx_rtmp_hds_write_1bytes(b, 1);

	afrt_start = b->last;
	ngx_rtmp_hds_write_4bytes(b, 0);
	b->last = ngx_cpymem(b->last, "afrt", 4);
	ngx_rtmp_hds_write_4bytes(b, 0);
	ngx_rtmp_hds_write_4bytes(b, 1000);
	ngx_rtmp_hds_write_1bytes(b, 0);
	
	for(i = 0; i < NGX_RTMP_HDS_FRAG_NUM; i ++) {
		frag = &ctx->frags[i];
		if(frag->size) {
			n ++;
		}
	}

	ngx_rtmp_hds_write_4bytes(b, n);

	id = ctx->frag_id;

	for(i = 0; i < NGX_RTMP_HDS_FRAG_NUM; i++) {
		frag = &ctx->frags[(id+i)%NGX_RTMP_HDS_FRAG_NUM];
		if(frag->size == 0) {
			continue;
		}
		ngx_rtmp_hds_write_4bytes(b, frag->index);
		ngx_rtmp_hds_write_8bytes(b, frag->start_time);
		ngx_rtmp_hds_write_4bytes(b, frag->end_time - frag->start_time);
	}

	size = b->last - afrt_start;
	p = (u_char *)&size;
	afrt_start[0] = p[3];
	afrt_start[1] = p[2];
	afrt_start[2] = p[1];
	afrt_start[3] = p[0];

	size = b->last - b->pos;
	p = (u_char *)&size;
	b->pos[0] = p[3];
	b->pos[1] = p[2];
	b->pos[2] = p[1];
	b->pos[3] = p[0];

	fd = ngx_open_file(ctx->abst_path_bak.data, NGX_FILE_WRONLY,
			NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
	
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds abst: " ngx_open_file_n " failed: '%V'",
                      &ctx->abst_path_bak);
        return NGX_ERROR;
    }

	nw = ngx_write_fd(fd, b->pos, b->last - b->pos);
 
	if (nw < 0) {
		ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
				"hds abst: " ngx_write_fd_n " failed: '%V'",
				&ctx->abst_path_bak);
		ngx_close_file(fd);
		return NGX_ERROR;
	}

	ngx_close_file(fd);

    if (ngx_rename_file(ctx->abst_path_bak.data, ctx->abst_path.data) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, ngx_errno,
                      "hds abst: rename failed: '%V'->'%V'",
                      &ctx->abst_path_bak, &ctx->abst_path);
        return NGX_ERROR;
    }

	return NGX_OK;
}

static void
ngx_rtmp_hds_write_1bytes(ngx_buf_t *b, int8_t value)
{
	*b->last ++ = value;
}

/*
static void
ngx_rtmp_hds_write_2bytes(ngx_buf_t *b, int16_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[1];
	*b->last ++ = p[0];
}
*/

static void
ngx_rtmp_hds_write_3bytes(ngx_buf_t *b, int32_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[2];
	*b->last ++ = p[1];
	*b->last ++ = p[0];
}

static void
ngx_rtmp_hds_write_4bytes(ngx_buf_t *b, int32_t value)
{
	u_char *p;
	p = (u_char *)&value;

	*b->last ++ = p[3];
	*b->last ++ = p[2];
	*b->last ++ = p[1];
	*b->last ++ = p[0];
}

static void
ngx_rtmp_hds_write_8bytes(ngx_buf_t *b, int64_t value)
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

static ngx_int_t
ngx_rtmp_hds_stream_begin(ngx_rtmp_session_t *s, ngx_rtmp_stream_begin_t *v)
{
    return next_stream_begin(s, v);
}


static ngx_int_t
ngx_rtmp_hds_stream_eof(ngx_rtmp_session_t *s, ngx_rtmp_stream_eof_t *v)
{
    ngx_rtmp_hds_close_fragment(s);

    return next_stream_eof(s, v);
}


static void *
ngx_rtmp_hds_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_hds_app_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_hds_app_conf_t));
    if (conf == NULL) {
        return NULL;
    }
	
	conf->hds = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_rtmp_hds_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_hds_app_conf_t    *prev = parent;
    ngx_rtmp_hds_app_conf_t    *conf = child;
	
	ngx_conf_merge_value(conf->hds, prev->hds, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_rtmp_hds_postconfiguration(ngx_conf_t *cf)
{
    ngx_rtmp_core_main_conf_t   *cmcf;
    ngx_rtmp_handler_pt         *h;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_VIDEO]);
    *h = ngx_rtmp_hds_av;

    h = ngx_array_push(&cmcf->events[NGX_RTMP_MSG_AUDIO]);
    *h = ngx_rtmp_hds_av;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_hds_publish;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_hds_close_stream;

    next_stream_begin = ngx_rtmp_stream_begin;
    ngx_rtmp_stream_begin = ngx_rtmp_hds_stream_begin;

    next_stream_eof = ngx_rtmp_stream_eof;
    ngx_rtmp_stream_eof = ngx_rtmp_hds_stream_eof;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_hds_init_process(ngx_cycle_t *cycle)
{
	return NGX_OK;
}


