#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_qqflv_module.h"
#include "../http/ngx_http_set_header.h"
//#include "../libVerifyTS/libVerifyTSLive.h"

#define NGX_FLV_TAG_SIZE           11
#define NGX_FLV_PTS_SIZE           4
#define NGX_QQFLV_MAX_BLOCK_SIZE   2048
#define ngx_null_qqflvhdr       {0, 0, 0, 0, 0, 0, 0, 0, 0}

static u_char  ngx_flv_live_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";
static u_char  ngx_flv_live_audio_header[] = "FLV\x1\x4\0\0\0\x9\0\0\0\0";

static ngx_int_t ngx_http_qqflv_add_value(ngx_conf_t *cf);
static ngx_int_t ngx_http_qqflv_postconfiguration(ngx_conf_t *cf);
static void * ngx_http_qqflv_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_qqflv_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_http_qqflv_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_qqflv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_qqflv_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_qqflv_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqflv_content_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_qqflv_read_index(ngx_http_qqflv_main_conf_t *qmcf); 
static ngx_int_t ngx_http_qqflv_read_index_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_qqflv_keyframe_cmd(const ngx_queue_t *one, const ngx_queue_t *two);
static ngx_int_t ngx_http_qqflv_block_cmd(const ngx_queue_t *one, const ngx_queue_t *two);

static ngx_qq_flv_index_t *ngx_http_qqflv_create_channel(ngx_str_t *channel_name, 
        uint32_t backdelay, unsigned buname, unsigned playbackchannel);
static ngx_qq_flv_index_t * ngx_http_qqflv_find_channel(ngx_str_t *channel_name);


static ngx_int_t ngx_http_qqflv_parse_request(ngx_http_request_t *r);

static u_char * ngx_http_qqflv_make_header(u_char *p, const ngx_qq_flv_header_t *qqflvhdr, 
            const uint32_t *usize, const uint32_t *useq, uint32_t usegid);
static ngx_int_t ngx_http_qqflv_send_header(ngx_http_request_t *r);
static void ngx_http_qqflv_open_source_file(ngx_file_t *file, const ngx_str_t *channel_name, 
                                            const time_t *timestamp);
static u_char * ngx_http_qqflv_read_source_file(u_char *p, ngx_file_t *file, const off_t *offset, 
                                                const uint32_t *size);


static ngx_int_t ngx_http_qqflv_playback_handler(ngx_http_request_t *r);
static void ngx_http_qqflv_playback_write_handler(ngx_http_request_t *r);
static ngx_chain_t *ngx_http_qqflv_playback_prepare_out_chain(ngx_http_request_t *r, unsigned sourceflag);

static u_char *ngx_http_qqflv_parse_block_data(ngx_buf_t *buf);
static ngx_int_t ngx_http_qqflv_parse_range(ngx_http_request_t *r, u_char *skey);
static ngx_chain_t * ngx_http_qqflv_create_chain_t(ngx_pool_t *pool, size_t size);

static ngx_int_t ngx_http_qqflv_block_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqflv_block_write_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqflv_make_block_repair(ngx_http_request_t *r, uint32_t blockid);
static ngx_int_t ngx_http_qqflv_block_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc);

static ngx_int_t ngx_http_qqflv_piece_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_qqflv_piece_write_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_qqflv_range_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);




static ngx_keyval_t qqflv_headers[] = {
    //{ ngx_string("Cache-Control"),  ngx_string("max-age=0") },
    { ngx_string("Content-Type"),   ngx_string("audio/x-mpegurl") },
    //{ ngx_string("Content-Type"),   ngx_string("video/mpegurl") },
    { ngx_null_string, ngx_null_string }
};

static ngx_keyval_t ngx_http_qqflv_live_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("video/x-flv") },
    { ngx_null_string, ngx_null_string }
};

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

static ngx_http_qqflv_request_cmd_t ngx_http_qqflv_request_cmds[] = {

    {
        NGX_HTTP_QQFLV_PLAYBACK,
        ngx_string("qqflv playback"),
        ngx_http_qqflv_playback_handler,
    },
    {
        NGX_HTTP_QQFLV_BLOCK,
        ngx_string("qqflv block"),
        ngx_http_qqflv_block_handler,
    },
    {
        NGX_HTTP_QQFLV_PIECE,
        ngx_string("qqflv piece"),
        ngx_http_qqflv_piece_handler,
    },
};

static ngx_http_variable_t ngx_http_qqflv_add_variable[] = {

    {ngx_string("qqflv_range"), NULL, ngx_http_qqflv_range_get_variable,
     0, NGX_HTTP_VAR_NOCACHEABLE, 0},

    {ngx_null_string, NULL, NULL, 0, 0, 0}
};

static ngx_http_module_t  ngx_http_qqflv_module_ctx = {
	ngx_http_qqflv_add_value,              /* preconfiguration */
	ngx_http_qqflv_postconfiguration,      /* postconfiguration */

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

static ngx_int_t ngx_http_qqflv_add_value(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;
    for (v = ngx_http_qqflv_add_variable; v->name.len; v++)
    {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
        {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_qqflv_range_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{

    ngx_http_qqflv_ctx_t                  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);

    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_ERROR;
    }

    v->data = ctx->range.data;
    v->valid = 1;
    v->not_found = 0;
    v->no_cacheable = 1;
    v->len = ctx->range.len;
    if(v->len == 0)
    {
        v->not_found = 1;
        return NGX_ERROR;
    }

    return NGX_OK;
}

static u_char *
ngx_http_qqflv_make_header(u_char *p, const ngx_qq_flv_header_t *qqflvhdr, const uint32_t *usize,
                        const uint32_t *useq, uint32_t usegid)
{
    if (qqflvhdr) {
        p = ngx_cpymem(p, usize, 4);
        p = ngx_cpymem(p, &qqflvhdr->huheadersize, 2);
        p = ngx_cpymem(p, &qqflvhdr->huversion, 2);
        p = ngx_cpymem(p, &qqflvhdr->uctype, 1);
        p = ngx_cpymem(p, &qqflvhdr->uckeyframe, 1);
        p = ngx_cpymem(p, &qqflvhdr->usec, 4);
        p = ngx_cpymem(p, useq, 4);
        p = ngx_cpymem(p, &usegid, 4);
        p = ngx_cpymem(p, &qqflvhdr->ucheck, 4);
    } else {
        p = ngx_cpymem(p, usize, 4);
        p = ngx_cpymem(p, (u_char *) "\x1a", 2);
        p = ngx_cpymem(p, (u_char *) "\0", 2);
        p = ngx_cpymem(p, (u_char *) "\0", 1);
        p = ngx_cpymem(p, (u_char *) "\0", 1);
        p = ngx_cpymem(p, (u_char *) "\0", 4);
        p = ngx_cpymem(p, useq, 4);
        p = ngx_cpymem(p, &usegid, 4);
        p = ngx_cpymem(p, (u_char *) "\0", 4);
    }
    return p;
}

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




static ngx_int_t
ngx_http_qqflv_send_header(ngx_http_request_t *r)
{
    ngx_int_t                           rc;
    ngx_keyval_t                       *h;

    r->headers_out.status = NGX_HTTP_OK;
    r->keepalive = 0; /* set Connection to closed */

    h = ngx_http_qqflv_live_headers;
    while (h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
}


ngx_chain_t *
ngx_http_qqflv_live_prepare_out_chain(ngx_http_request_t *r,
        ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame, unsigned sourceflag)
{
    ngx_chain_t                        *head, **ll, *cl;
    u_char                             *p;
    size_t                              datasize, prev_tag_size;
    ngx_int_t                           rc;
    uint32_t                            timestamp;
    ngx_qq_flv_index_t                 *qq_flv_index;

    head = NULL;
    datasize = 0;
    ll = &head;

    /* timestamp */
    timestamp = frame->hdr.timestamp;
    timestamp = ngx_rtmp_timestamp_fix(s, timestamp, 0);

    /* first send */
    if (!r->header_sent) {
        rc = ngx_http_qqflv_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return NULL;
        }        

        if (sourceflag) {
            *ll = ngx_get_chainbuf(NGX_QQ_FLV_HEADER_SIZE, 1);
            if (*ll == NULL) {
                return NULL;
            }
            p = (*ll)->buf->pos;
            p = ngx_http_qqflv_make_header(p, &frame->hdr.qqflvhdr, &frame->hdr.qqflvhdr.usize,
                        &frame->hdr.qqflvhdr.useq, frame->hdr.qqflvhdr.usegid);
            (*ll)->buf->last = p;
            ll = &(*ll)->next;

        }
        /* flv header */
        *ll = ngx_get_chainbuf(0, 0);
        if (*ll == NULL) {
            goto falied;
        }
        if (s->filter == NGX_RTMP_FILTER_KEEPAUDIO) {
            (*ll)->buf->pos = ngx_flv_live_audio_header;
            (*ll)->buf->last = ngx_flv_live_audio_header
                                  + sizeof(ngx_flv_live_audio_header) - 1;
        } else {
            (*ll)->buf->pos = ngx_flv_live_header;
            (*ll)->buf->last = ngx_flv_live_header
                                  + sizeof(ngx_flv_live_header) - 1;
        }
        ll = &(*ll)->next;
    }

    for (ll = &head; *ll; ll = &(*ll)->next);

    if (sourceflag && (frame->hdr.type == NGX_RTMP_MSG_VIDEO || frame->hdr.type == NGX_RTMP_MSG_AUDIO))
    {
        *ll = ngx_get_chainbuf(NGX_QQ_FLV_HEADER_SIZE, 1);
        if (*ll == NULL) {
            goto falied;
        }
        p = (*ll)->buf->pos;
        p = ngx_http_qqflv_make_header(p, &frame->hdr.qqflvhdr, &frame->hdr.qqflvhdr.usize,
                    &frame->hdr.qqflvhdr.useq, frame->hdr.qqflvhdr.usegid);
        (*ll)->buf->last = p;
        ll = &(*ll)->next;
    }

    for (cl = frame->chain; cl; cl = cl->next) {
        datasize += (cl->buf->last - cl->buf->pos);
    }
    prev_tag_size = datasize + NGX_FLV_TAG_SIZE;

    /* flv tag header */
    *ll = ngx_get_chainbuf(NGX_FLV_TAG_SIZE, 1);
    if (*ll == NULL) {
        goto falied;
    }
    p = (*ll)->buf->pos;

    /* TagType 1 byte */
    *p++ = frame->hdr.type;

    /* DataSize 3 bytes */
    *p++ = ((u_char *) &datasize)[2];
    *p++ = ((u_char *) &datasize)[1];
    *p++ = ((u_char *) &datasize)[0];

    /* Timestamp 4 bytes */
    *p++ = ((u_char *) &timestamp)[2];
    *p++ = ((u_char *) &timestamp)[1];
    *p++ = ((u_char *) &timestamp)[0];
    *p++ = ((u_char *) &timestamp)[3];

    /* StreamID 4 bytes, always set to 0 */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    (*ll)->buf->last = p;
    ll = &(*ll)->next;

    /* flv payload */
    for (cl = frame->chain; cl; cl = cl->next) {
        (*ll) = ngx_get_chainbuf(0, 0);
        if (*ll == NULL) {
            goto falied;
        }
        (*ll)->buf->pos = cl->buf->pos;
        (*ll)->buf->last = cl->buf->last;
        ll = &(*ll)->next;
    }

    /* flv previous tag size */
    *ll = ngx_get_chainbuf(NGX_FLV_PTS_SIZE, 1);
    if (*ll == NULL) {
        goto falied;
    }
    p = (*ll)->buf->pos;

    *p++ = ((u_char *) &prev_tag_size)[3];
    *p++ = ((u_char *) &prev_tag_size)[2];
    *p++ = ((u_char *) &prev_tag_size)[1];
    *p++ = ((u_char *) &prev_tag_size)[0];

    (*ll)->buf->last = p;
    (*ll)->buf->flush = 1;

    ngx_rtmp_monitor_frame(s, &frame->hdr, NULL, frame->av_header, 0);

    return head;

falied:
    for (cl = head; cl; cl = cl->next) {
        head = cl->next;
        ngx_put_chainbuf(cl);
        cl = head;
    }

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);

    return NULL;
}

ngx_int_t
ngx_http_relay_parse_qq_flv(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    u_char                      ch, *p, *pc;
    ngx_rtmp_stream_t          *st;
    ngx_rtmp_header_t          *h;
    ngx_qq_flv_header_t        *qqflvhdr;
    ngx_qq_flv_index_t         *qq_flv_index;
    ngx_chain_t               **ll;
    size_t                      len;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_int_t                   rc = NGX_AGAIN;
    enum {
        qq_flv_usize0 = 0,
        qq_flv_usize1,
        qq_flv_usize2,
        qq_flv_usize3,
        qq_flv_huheadersize0,
        qq_flv_huheadersize1,
        qq_flv_huversion0,
        qq_flv_huversion1,
        qq_flv_uctype,
        qq_flv_uckeyframe,
        qq_flv_usec0,
        qq_flv_usec1,
        qq_flv_usec2,
        qq_flv_usec3,
        qq_flv_useq0,
        qq_flv_useq1,
        qq_flv_useq2,
        qq_flv_useq3,
        qq_flv_usegid0,
        qq_flv_usegid1,
        qq_flv_usegid2,
        qq_flv_usegid3,
        qq_flv_ucheck0,
        qq_flv_ucheck1,
        qq_flv_ucheck2,
        qq_flv_ucheck3,

        flv_header_F,
        flv_header_FL,
        flv_header_FLV,
        flv_header_Version,
        flv_header_Flags,
        flv_header_DataOffset0,
        flv_header_DataOffset1,
        flv_header_DataOffset2,
        flv_header_DataOffset3,
        flv_tagsize0,
        flv_tagsize1,
        flv_tagsize2,
        flv_tagsize3,
        flv_tagtype,
        flv_datasize0,
        flv_datasize1,
        flv_datasize2,
        flv_timestamp0,
        flv_timestamp1,
        flv_timestamp2,
        flv_timestamp_extended,
        flv_streamid0,
        flv_streamid1,
        flv_streamid2,
        flv_data
    } state;

    state = s->qq_flv_state;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

        //printf("s->qq_flv_index NULL\n");
    qq_flv_index = ngx_http_qqflv_find_channel(&s->name);
    if (qq_flv_index == NULL) {
        qq_flv_index = ngx_http_qqflv_create_channel(&s->name, 0, 0, 0);
    }

    for (p = b->pos; p < b->last; ++p) {
        ch = *p;

        if (state >= flv_header_F && s->qqflvhdr.uckeyframe == 0 && state != flv_data) {            
            if (qq_flv_index->meta_data.data == NULL) {
                ngx_http_qqflv_make_header(qq_flv_index->meta_header, &s->qqflvhdr, &s->qqflvhdr.usize,
                                        &s->qqflvhdr.useq, s->qqflvhdr.usegid);
                qq_flv_index->meta_data.data = ngx_palloc(qqflv_main_conf->pool, s->qqflvhdr.usize);
                qq_flv_index->meta_data.len = 0;
            }
            if (qq_flv_index->meta_data.len < s->qqflvhdr.usize) {
                //printf("%x-%d-%d\n", ch, qq_flv_index->meta_data.len, state);
                *(qq_flv_index->meta_data.data + qq_flv_index->meta_data.len) = ch;
                qq_flv_index->meta_data.len++;
            }        
        }
        
        switch (state) {

        case qq_flv_usize0:
            s->qqhdrtype = NGX_RTMP_HEADER_TYPE_QQ_FLV;
            qqflvhdr = &s->qqflvhdr;            
            qqflvhdr->usize = 0;
            pc = (u_char *) &qqflvhdr->usize;
            pc[0] = ch;
            state = qq_flv_usize1;
            break;

        case qq_flv_usize1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usize;
            pc[1] = ch;
            state = qq_flv_usize2;
            break;

        case qq_flv_usize2:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usize;
            pc[2] = ch;
            state = qq_flv_usize3;
            break;

        case qq_flv_usize3:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usize;
            pc[3] = ch;
            s->qq_flv_len = qqflvhdr->usize;
            state = qq_flv_huheadersize0;
            break;

        case qq_flv_huheadersize0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->huheadersize = 0;
            pc = (u_char *) &qqflvhdr->huheadersize;
            pc[0] = ch;
            state = qq_flv_huheadersize1;
            break;

        case qq_flv_huheadersize1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->huheadersize;
            pc[1] = ch;
            if (qqflvhdr->huheadersize != NGX_QQ_FLV_HEADER_SIZE) {
                rc = NGX_ERROR;
                goto done;
            }
            state = qq_flv_huversion0;
            break;

        case qq_flv_huversion0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->huversion = 0;
            pc = (u_char *) &qqflvhdr->huversion;
            pc[0] = ch;
            state = qq_flv_huversion1;
            break;

        case qq_flv_huversion1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->huversion;
            pc[1] = ch;
            state = qq_flv_uctype;
            break;

        case qq_flv_uctype:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->uctype = ch;
            state = qq_flv_uckeyframe;
            break;

        case qq_flv_uckeyframe:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->uckeyframe = ch;
            state = qq_flv_usec0;
            break;

        case qq_flv_usec0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->usec = 0;
            pc = (u_char *) &qqflvhdr->usec;
            pc[0] = ch;
            state = qq_flv_usec1;
            break;

        case qq_flv_usec1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usec;
            pc[1] = ch;
            state = qq_flv_usec2;
            break;

        case qq_flv_usec2:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usec;
            pc[2] = ch;
            state = qq_flv_usec3;
            break;

        case qq_flv_usec3:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usec;
            pc[3] = ch;
            state = qq_flv_useq0;
            break;

        case qq_flv_useq0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->useq = 0;
            pc = (u_char *) &qqflvhdr->useq;
            pc[0] = ch;
            state = qq_flv_useq1;
            break;

        case qq_flv_useq1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->useq;
            pc[1] = ch;
            state = qq_flv_useq2;
            break;

        case qq_flv_useq2:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->useq;
            pc[2] = ch;
            state = qq_flv_useq3;
            break;

        case qq_flv_useq3:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->useq;
            pc[3] = ch;
            state = qq_flv_usegid0;
            break;

        case qq_flv_usegid0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->usegid = 0;
            pc = (u_char *) &qqflvhdr->usegid;
            pc[0] = ch;
            state = qq_flv_usegid1;
            break;

        case qq_flv_usegid1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usegid;
            pc[1] = ch;
            state = qq_flv_usegid2;
            break;

        case qq_flv_usegid2:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usegid;
            pc[2] = ch;
            state = qq_flv_usegid3;
            break;

        case qq_flv_usegid3:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->usegid;
            pc[3] = ch;
            state = qq_flv_ucheck0;
            break;

        case qq_flv_ucheck0:
            qqflvhdr = &s->qqflvhdr;
            qqflvhdr->ucheck = 0;
            pc = (u_char *) &qqflvhdr->ucheck;
            pc[0] = ch;
            state = qq_flv_ucheck1;
            break;

        case qq_flv_ucheck1:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->ucheck;
            pc[1] = ch;
            state = qq_flv_ucheck2;
            break;

        case qq_flv_ucheck2:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->ucheck;
            pc[2] = ch;
            state = qq_flv_ucheck3;
            break;

        case qq_flv_ucheck3:
            qqflvhdr = &s->qqflvhdr;
            pc = (u_char *) &qqflvhdr->ucheck;
            pc[3] = ch;
            switch (qqflvhdr->uckeyframe) {
            case 0:
                state = flv_header_F;
                break;
            case 1:
            case 2:
                state = flv_tagtype; 
                break;
            default:
                rc = NGX_ERROR;
                goto done;
            }
            break;



        case flv_header_F:
            switch (ch) {
            case 'F':
                state = flv_header_FL;
                break;
            default:
                rc = NGX_ERROR;
                goto done;
            }
            s->qq_flv_len--;
            break;

        case flv_header_FL:
            switch (ch) {
            case 'L':
                state = flv_header_FLV;
                break;
            default:
                rc = NGX_ERROR;
                goto done;
            }
            s->qq_flv_len--;
            break;

        case flv_header_FLV:
            switch (ch) {
            case 'V':
                state = flv_header_Version;
                break;
            default:
                rc = NGX_ERROR;
                goto done;
            }
            s->qq_flv_len--;
            break;

        case flv_header_Version:
            s->flv_version = ch;
            if (s->flv_version != 1) {
                rc = NGX_ERROR;
                goto done;
            }
            s->qq_flv_len--;
            state = flv_header_Flags;
            break;

        case flv_header_Flags:
            s->flv_flags = ch;
            s->qq_flv_len--;
            state = flv_header_DataOffset0;
            break;

        case flv_header_DataOffset0:
            pc = (u_char *) &s->flv_data_offset;
            pc[3] = ch;
            s->qq_flv_len--;
            state = flv_header_DataOffset1;
            break;

        case flv_header_DataOffset1:
            pc = (u_char *) &s->flv_data_offset;
            pc[2] = ch;
            s->qq_flv_len--;
            state = flv_header_DataOffset2;
            break;

        case flv_header_DataOffset2:
            pc = (u_char *) &s->flv_data_offset;
            pc[1] = ch;
            s->qq_flv_len--;
            state = flv_header_DataOffset3;
            break;

        case flv_header_DataOffset3:
            pc = (u_char *) &s->flv_data_offset;
            pc[0] = ch;
            s->qq_flv_len--;
            state = flv_tagsize0;
            break;

        case flv_tagsize0:
            s->flv_tagsize = 0;
            pc = (u_char *) &s->flv_tagsize;
            pc[3] = ch;
            s->qq_flv_len--;
            state = flv_tagsize1;
            break;

        case flv_tagsize1:
            pc = (u_char *) &s->flv_tagsize;
            pc[2] = ch;
            s->qq_flv_len--;
            state = flv_tagsize2;
            break;

        case flv_tagsize2:
            pc = (u_char *) &s->flv_tagsize;
            pc[1] = ch;
            s->qq_flv_len--;
            state = flv_tagsize3;
            break;

        case flv_tagsize3:
            pc = (u_char *) &s->flv_tagsize;
            pc[0] = ch;

            st = &s->in_streams[0];
            h = &st->hdr;

            if (h->mlen == 0) {
                if (s->flv_tagsize != 0) {
                    rc = NGX_ERROR;
                    goto done;
                }
            } else {
                if (h->mlen + 11 != s->flv_tagsize) {
                    rc = NGX_ERROR;
                    goto done;
                }
            }
            s->qq_flv_len--;
            if (s->qq_flv_len != 0) {
                state = flv_tagtype;
            }else {
                state = qq_flv_usize0;
            }            

            break;

        case flv_tagtype:
            if (ch != NGX_RTMP_MSG_AMF_META && ch != NGX_RTMP_MSG_AUDIO
                    && ch != NGX_RTMP_MSG_VIDEO)
            {
                rc = NGX_ERROR;
                goto done;
            }

            st = &s->in_streams[0];
            h = &st->hdr;
            h->type = ch;
            state = flv_datasize0;
            s->qq_flv_len--;
            break;

        case flv_datasize0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->mlen = 0;
            pc = (u_char *) &h->mlen;

            pc[2] = ch;
            state = flv_datasize1;
            s->qq_flv_len--;
            break;

        case flv_datasize1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[1] = ch;
            state = flv_datasize2;
            s->qq_flv_len--;
            break;

        case flv_datasize2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[0] = ch;
            state = flv_timestamp0;
            st->len = h->mlen;
            s->qq_flv_len--;
            break;

        case flv_timestamp0:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[2] = ch;
            state = flv_timestamp1;
            s->qq_flv_len--;
            break;

        case flv_timestamp1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[1] = ch;
            state = flv_timestamp2;
            s->qq_flv_len--;
            break;

        case flv_timestamp2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[0] = ch;
            state = flv_timestamp_extended;
            s->qq_flv_len--;
            break;

        case flv_timestamp_extended:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[3] = ch;
            state = flv_streamid0;
            s->qq_flv_len--;
            break;

        case flv_streamid0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->msid = 0;
            pc = (u_char *) &h->msid;

            pc[2] = ch;
            state = flv_streamid1;
            s->qq_flv_len--;
            break;

        case flv_streamid1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[1] = ch;
            state = flv_streamid2;
            s->qq_flv_len--;
            break;

        case flv_streamid2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[0] = ch;
            state = flv_data;
            s->qq_flv_len--;
            break;

        case flv_data:
            st = &s->in_streams[0];

            for (ll = &st->in; (*ll) && (*ll)->buf->last == (*ll)->buf->end;
                    ll = &(*ll)->next);

            for (;;) {
                if (*ll == NULL) {
                    *ll = ngx_get_chainbuf(cscf->chunk_size, 1);
                }

                len = ngx_min(st->len, b->last - p);
                len = ngx_min(s->qq_flv_len, len);
                if ((*ll)->buf->end - (*ll)->buf->last >= (long) len) {
                    if (s->qqflvhdr.uckeyframe == 0) {   
                        /*size_t pp;
                        for(pp = 0; pp < len; pp++)
                            printf("%x-%d-%d\n", *(p+pp), qq_flv_index->meta_data.len + pp, state);*/
                        ngx_cpymem(qq_flv_index->meta_data.data + qq_flv_index->meta_data.len, p, len);
                        qq_flv_index->meta_data.len += len;    
                    }

                    (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                    p += len;
                    st->len -= len;
                    s->qq_flv_len -= len;
                    break;
                }

                len = (*ll)->buf->end - (*ll)->buf->last;
                if (s->qqflvhdr.uckeyframe == 0) {   
                    /*size_t ppp;
                    for(ppp = 0; ppp < len; ppp++)
                        printf("%x-%d-%d-\n", *(p+ppp), qq_flv_index->meta_data.len + ppp, state);*/
                    ngx_cpymem(qq_flv_index->meta_data.data + qq_flv_index->meta_data.len, p, len);
                    qq_flv_index->meta_data.len += len;    
                }
                (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                p += len;
                st->len -= len;
                s->qq_flv_len -= len;
                ll = &(*ll)->next;
            }

            if (st->len != 0) {
                rc = NGX_AGAIN;
                goto done;
            }

            if (s->qq_flv_len != 0) {
                state = flv_tagsize0;
                rc = NGX_OK;
                goto done;
            }

            state = qq_flv_usize0;
            rc = NGX_OK;
            goto done;
        }
    }

done:
    b->pos = p;
    s->qq_flv_state = state;

    /* qq flv header */
    if (rc == NGX_OK) {
        st = &s->in_streams[0];
        h = &st->hdr;
        h->qqhdrtype = s->qqhdrtype;
        if (s->qqhdrtype == NGX_RTMP_HEADER_TYPE_QQ_FLV) {
            s->qqhdrtype = NGX_RTMP_HEADER_TYPE_DEFAULT;
            qqflvhdr = &h->qqflvhdr;
            qqflvhdr->usize = (&s->qqflvhdr)->usize;
            qqflvhdr->huheadersize = (&s->qqflvhdr)->huheadersize;
            qqflvhdr->huversion = (&s->qqflvhdr)->huversion;
            qqflvhdr->uctype = (&s->qqflvhdr)->uctype;
            qqflvhdr->uckeyframe = (&s->qqflvhdr)->uckeyframe;
            qqflvhdr->usec = (&s->qqflvhdr)->usec;
            qqflvhdr->useq = (&s->qqflvhdr)->useq;
            qqflvhdr->usegid = (&s->qqflvhdr)->usegid;
            qqflvhdr->ucheck = (&s->qqflvhdr)->ucheck;

            /*printf("usize:\t%u\n", qqflvhdr->usize);
            printf("huheadersize:\t%u\n", qqflvhdr->huheadersize);
            printf("huversion:\t%u\n", qqflvhdr->huversion);
            printf("uctype:\t%u\n", qqflvhdr->uctype);
            printf("uckeyframe:\t%u\n", qqflvhdr->uckeyframe);
            printf("usec:\t%u\n", qqflvhdr->usec);
            printf("useq:\t%u\n", qqflvhdr->useq);
            printf("usegid:\t%u\n", qqflvhdr->usegid);
            printf("ucheck:\t%u\n", qqflvhdr->ucheck);*/
        }        
    }

    return rc;
}

static ngx_qq_flv_index_t *
ngx_http_qqflv_create_channel(ngx_str_t *channel_name, uint32_t backdelay, 
							unsigned buname, unsigned playbackchannel)
{
    ngx_qq_flv_index_t                       *qq_flv_index;
    qq_flv_index = ngx_palloc(qqflv_main_conf->pool, sizeof(ngx_qq_flv_index_t));
    qq_flv_index->buname = buname;
    qq_flv_index->playbackchannel = playbackchannel;
    if (qq_flv_index->buname) {
        qq_flv_index->backdelay = (backdelay == 0) ? 15 : backdelay;
    }
    else {
        qq_flv_index->backdelay = (backdelay == 0) ? 45 : backdelay;
    }
    qq_flv_index->channel_name.data = ngx_palloc(qqflv_main_conf->pool, channel_name->len);
    ngx_cpymem(qq_flv_index->channel_name.data, channel_name->data, channel_name->len);
    qq_flv_index->channel_name.len = channel_name->len;

    qq_flv_index->current_time = 0;
    qq_flv_index->meta_data.data = NULL;
    ngx_queue_init(&qq_flv_index->index_queue);
    ngx_queue_init(&qq_flv_index->keyframe_queue);
    ngx_map_init(&qq_flv_index->block_map, ngx_map_hash_str, ngx_cmp_str);
    qq_flv_index->node.raw_key = (intptr_t) &qq_flv_index->channel_name;
    ngx_map_insert(&qqflv_main_conf->channel_map, &qq_flv_index->node, 0);
    ngx_queue_insert_tail(&qqflv_main_conf->channel_queue, &qq_flv_index->q);
    return qq_flv_index;
}

static ngx_qq_flv_index_t *
ngx_http_qqflv_find_channel(ngx_str_t *channel_name)
{
    ngx_qq_flv_index_t                       *qq_flv_index;
    ngx_map_node_t                           *node;

    node = ngx_map_find(&qqflv_main_conf->channel_map, (intptr_t) channel_name);
    if (node == NULL) {
        return NULL;
    }
    qq_flv_index = (ngx_qq_flv_index_t *)
            ((char *) node - offsetof(ngx_qq_flv_index_t, node));
    return qq_flv_index;
}

ngx_int_t
ngx_http_qqflv_insert_block_index(ngx_str_t channel_name, time_t timestamp,
                                ngx_qq_flv_header_t qqflvhdr, off_t file_offset,
                                ngx_qq_flv_index_t *qq_flv_index, unsigned curflag)
{
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_queue_t                              *tq;
    ngx_map_node_t                           *node;

    if (qq_flv_index == NULL) {
        qq_flv_index = ngx_http_qqflv_find_channel(&channel_name);
        if (qq_flv_index == NULL) {
            qq_flv_index = ngx_http_qqflv_create_channel(&channel_name, 0, 0, 0);
            //printf("node not found!\n");
            //return NGX_OK;
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
    qq_flv_block_index->block_key.data = &qq_flv_block_index->qqflvhdr.useq;
    qq_flv_block_index->block_key.len = sizeof(uint32_t);
    qq_flv_block_index->node.raw_key = (intptr_t) &qq_flv_block_index->block_key;
    ngx_map_insert(&qq_flv_index->block_map, &qq_flv_block_index->node, 0);
    if (qq_flv_block_index->qqflvhdr.uckeyframe == 2) {
        if (curflag) {
            qq_flv_index->current_time = qq_flv_block_index->qqflvhdr.usec;
        }
        ngx_queue_insert_tail(&qq_flv_index->keyframe_queue, &qq_flv_block_index->kq);
    }
    return NGX_OK;
}

ngx_int_t
ngx_http_qqflv_open_index_file(ngx_str_t *path, ngx_file_t *index_file, 
                        ngx_log_t *log, ngx_str_t *id, ngx_flag_t *lock_file, u_char *channel_name)
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

    qq_flv_index = ngx_http_qqflv_find_channel(&channel_name);
    if (qq_flv_index == NULL) {
        //printf("create\n");
        qq_flv_index = ngx_http_qqflv_create_channel(&channel_name, 0, 0, 0);
        //ngx_delete_file(path->data);
        //return NGX_OK;
	}

	/*if (ngx_cached_time->sec - ngx_atoi(timestamp.data, timestamp.len) > qq_flv_index->backdelay) {
    	ngx_delete_file(path->data);   	
    	return NGX_OK;
	}*/

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
                                            qqflvhdr, file_offset, qq_flv_index, 0);
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

static ngx_chain_t *
ngx_http_qqflv_playback_prepare_out_chain(ngx_http_request_t *r, unsigned sourceflag)
{
    ngx_chain_t                        *cl, **ll, *head;
    u_char                             *p;
    ngx_qq_flv_header_t                *qqflvhdr;
    ngx_qq_flv_block_index_t           *qq_flv_block_index;
    ngx_http_qqflv_ctx_t               *ctx;
    ngx_int_t                           rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    if (ctx == NULL) {
        return;
    }

    head = NULL;
    ll = &head;
    qq_flv_block_index = ctx->qq_flv_block_index;
    qqflvhdr = &qq_flv_block_index->qqflvhdr;

    if (!r->header_sent) {

        rc = ngx_http_qqflv_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return NULL;
        }        

        if (sourceflag) {
            (*ll) = ngx_get_chainbuf(0, 0);
            if (*ll == NULL) {
                goto falied;
            }
            (*ll)->buf->pos =  ctx->qq_flv_index->meta_header;
            (*ll)->buf->last = ctx->qq_flv_index->meta_header + NGX_QQ_FLV_HEADER_SIZE;
            ll = &(*ll)->next;
        }

        (*ll) = ngx_get_chainbuf(0, 0);
        if (*ll == NULL) {
            goto falied;
        }
        (*ll)->buf->pos = ctx->qq_flv_index->meta_data.data;
        (*ll)->buf->last = ctx->qq_flv_index->meta_data.data + ctx->qq_flv_index->meta_data.len;
        ll = &(*ll)->next;
    }


    if (sourceflag) {
        (*ll) = ngx_get_chainbuf(NGX_QQ_FLV_HEADER_SIZE, 1);
        if (*ll == NULL)
        {
            goto falied;
        }
        p = (*ll)->buf->pos;
        p = ngx_http_qqflv_make_header(p, qqflvhdr, &qqflvhdr->usize, &qqflvhdr->useq, qqflvhdr->usegid);
        (*ll)->buf->last = p;
        ll = &(*ll)->next;
    }

    (*ll) = ngx_get_chainbuf(qqflvhdr->usize, 1);
    if (*ll == NULL)
    {
        goto falied;
    }
    p = (*ll)->buf->pos;
    p = ngx_http_qqflv_read_source_file(p, &ctx->file, &qq_flv_block_index->file_offset, &qqflvhdr->usize);
    (*ll)->buf->last = p;
    ll = &(*ll)->next;
    return head;

falied:
    for (cl = head; cl; cl = cl->next) {
        head = cl->next;
        ngx_put_chainbuf(cl);
        cl = head;
    }

    ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);

    return NULL;
}

static ngx_int_t
ngx_http_qqflv_playback_handler(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t                     *ctx;
    uint32_t                                  current_time;
    ngx_queue_t                              *tq;
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_int_t                                 rc;
    ngx_keyval_t                             *h;

    /*if (!ctx->qq_flv_index->playbackchannel || ctx->buname) {
        r->header_only = 1;
        return NGX_HTTP_NOT_FOUND;
    }*/

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    current_time = ctx->qq_flv_index->current_time ? ctx->qq_flv_index->current_time : ngx_time();

    for (tq = ngx_queue_last(&ctx->qq_flv_index->keyframe_queue); 
        tq != ngx_queue_sentinel(&ctx->qq_flv_index->keyframe_queue); tq = ngx_queue_prev(tq))
    {
        qq_flv_block_index = ngx_queue_data(tq, ngx_qq_flv_block_index_t, kq);
        if (qq_flv_block_index->qqflvhdr.usec + ctx->backsec <= current_time)
        {
            break;
        }
    }

    ctx->qq_flv_block_index = qq_flv_block_index;

    ngx_add_timer(r->connection->write, 1000);

    r->read_event_handler = ngx_http_test_reading;
    r->write_event_handler = ngx_http_qqflv_playback_write_handler;

    ++r->count;

    return NGX_DONE;
}


static void
ngx_http_qqflv_playback_write_handler(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t                     *ctx;
    ngx_log_t                                *log;
    ngx_event_t                              *wev;
    ngx_int_t                                 rc;
    ngx_chain_t                              *cl;
    ngx_queue_t                              *tq;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    if (ctx == NULL) {
        return;
    }
    log = r->connection->log;
    wev = r->connection->write;

    ctx->timestamp = ctx->qq_flv_block_index->timestamp;

    if (wev->timedout) {
        /*ngx_log_error(NGX_LOG_INFO, r->connection->log, NGX_ETIMEDOUT,
                "http qqflv playback, client timed out");
        r->connection->timedout = 1;
        if (r->header_sent) {
            ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
            ngx_http_run_posted_requests(r->connection);
        } else {
            r->error_page = 1;
            ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
        }
        return;*/
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    if (ctx->file.fd == NGX_INVALID_FILE) {
        ngx_http_qqflv_open_source_file(&ctx->file, &ctx->qq_flv_index->channel_name, &ctx->timestamp);
    }

    if (ctx->out_chain == NULL && !ctx->block_sent) {
        ctx->out_chain = ngx_http_qqflv_playback_prepare_out_chain(r, 0);
    } 
    
    while (ctx->out_chain || ctx->block_sent) {
        if (ctx->out_chain) {
            if (r->connection->buffered) {
                rc = ngx_http_output_filter(r, NULL);
            } else {
                rc = ngx_http_output_filter(r, ctx->out_chain);
            }
        } else {
            rc = ngx_http_output_filter(r, NULL);
        }

        if (rc == NGX_AGAIN) {
            ngx_add_timer(wev, 1000);
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http qqflv playback, handle write event failed");
                ngx_close_file(ctx->file.fd);
                ctx->file.fd = NGX_INVALID_FILE;
                ngx_http_finalize_request(r, NGX_ERROR);
            }
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                    "http qqflv playback, send error");
            ngx_close_file(ctx->file.fd);
            ctx->file.fd = NGX_INVALID_FILE;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

        if (ctx->out_chain) {
            ctx->block_sent = 1;
        }

        cl = ctx->out_chain;
        while (cl) {
            ctx->out_chain = cl->next;
            ngx_put_chainbuf(cl);
            cl = ctx->out_chain;
        }
        
        tq = ngx_queue_next(&ctx->qq_flv_block_index->q);
        if (tq == ngx_queue_sentinel(&ctx->qq_flv_index->index_queue)) {
            ngx_add_timer(wev, 1000);
            if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                ngx_close_file(ctx->file.fd);
                ctx->file.fd = NGX_INVALID_FILE;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                        "http qqflv playback, handle write event failed");
                ngx_http_finalize_request(r, NGX_ERROR);
            }
            return;
        }
        ctx->qq_flv_block_index = ngx_queue_data(tq, ngx_qq_flv_block_index_t, q);
        ctx->block_sent = 0;
        if (ctx->qq_flv_block_index->timestamp != ctx->timestamp) {
            ctx->timestamp = ctx->qq_flv_block_index->timestamp;
            ngx_close_file(ctx->file.fd);
            ctx->file.fd = NGX_INVALID_FILE;
            ngx_http_qqflv_open_source_file(&ctx->file, &ctx->qq_flv_index->channel_name, &ctx->timestamp);
        }
        ctx->out_chain = ngx_http_qqflv_playback_prepare_out_chain(r, 0);
    }
    ngx_close_file(ctx->file.fd);
    ctx->file.fd = NGX_INVALID_FILE;
    return;
}

static ngx_int_t ngx_http_qqflv_parse_range(ngx_http_request_t *r, u_char *skey)
{
    u_char                                *p;
    uint32_t                               start, end;
    ngx_queue_t                           *tq;
    ngx_http_qqflv_intqueue_node_t        *node;
    ngx_str_t                             *range;
    ngx_int_t                              size;
    ngx_http_qqflv_ctx_t                  *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    printf("parse_range\n");
    ngx_queue_init(&ctx->intqueue);
    size = 0;

    if (r->headers_in.range) {
        range = &(r->headers_in.range)->value;
        if (!ngx_strstr(range->data, skey)) {
            return size;
        }
    } else {
        return size;
    }

    for (p = range->data; p < range->data + range->len; p++)
    {
        if (*p == '=' || *p == ',') 
        {
            if (sscanf(p + 1, "%u-%u", &start, &end) == 2)
            {
                for (; start <= end; start ++) {
                    node = ngx_palloc(r->pool, sizeof(ngx_http_qqflv_intqueue_node_t));
                    node->data = start;
                    ngx_queue_insert_tail(&ctx->intqueue, &node->q);
                    size ++;
                }
            }
        }
    }
    return size;
}

static void
ngx_http_qqflv_open_source_file(ngx_file_t *file, const ngx_str_t *channel_name, const time_t *timestamp)
{
    static u_char                   pbuf[NGX_MAX_PATH + 1];
    static u_char                   buf[NGX_TIME_T_LEN + 1];
    u_char                         *p;

    p = pbuf;
    p = ngx_cpymem(p, (u_char *) "/usr/local/nginx/flv/", sizeof("/usr/local/nginx/flv/") - 1);
    p = (u_char *)ngx_escape_uri(p, channel_name->data, channel_name->len, NGX_ESCAPE_URI_COMPONENT);
    p = ngx_cpymem(p, buf, ngx_sprintf(buf, "-%T", *timestamp) - buf);
    p = ngx_cpymem(p, (u_char *) ".flv", sizeof(".flv") - 1);
    *p = 0;
    file->fd = ngx_open_file(pbuf, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
}

static u_char *
ngx_http_qqflv_read_source_file(u_char *p, ngx_file_t *file, const off_t *offset, const uint32_t *size)
{

    if (ngx_read_file(file, p, *size, *offset) != *size)
    {
        ngx_close_file(file->fd);
        return p;
    }
    //ngx_close_file(file->fd);
    return p + *size;
}


static ngx_int_t ngx_http_qqflv_send_response(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t                     *ctx;
    ngx_buf_t                                *b;
    ngx_keyval_t                             *h;
    ngx_int_t                                 rc;
    ngx_chain_t                              *cl;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);


    r->headers_out.content_length_n = 0;
    r->header_only = 1;
    if (ctx->out_chain) {
        for (cl = ctx->out_chain; cl; cl = cl->next) {
            b = cl->buf;
            r->headers_out.content_length_n += b->last - b->pos;
        }
        b->last_buf = 1;
        b->flush = 1;
        b->last_in_chain = 1; 
        r->header_only = 0;
        r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    }

    r->headers_out.status = NGX_HTTP_OK;
    h = qqflv_headers;
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

    rc = ngx_http_output_filter(r, ctx->out_chain);
    ngx_http_finalize_request(r, rc);
    return rc;
}

static ngx_int_t ngx_http_qqflv_piece_write_handler(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t                     *ctx;
    ngx_chain_t                             **ll;
    off_t                                     ReadPos;
    uint32_t                                  ReadSize;
    ngx_http_qqflv_intqueue_node_t           *intnode;
    ngx_str_t                                 block_key;
    ngx_map_node_t                           *node;
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_qq_flv_header_t                      *qqflvhdr;
    ngx_file_t                                file;
    u_char                                   *p;
    ngx_queue_t                              *tq;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    printf("piece write handler\n");


    if (!ctx->done) {
        ctx->done = 1;
        block_key.data = &ctx->blockid;
        block_key.len = sizeof(uint32_t); 
        node = ngx_map_find(&ctx->qq_flv_index->block_map, (intptr_t) &block_key);
        if (node) {
            qq_flv_block_index = (ngx_qq_flv_block_index_t *)
                ((char *) node - offsetof(ngx_qq_flv_block_index_t, node));
        }
        if (qq_flv_block_index) {
            qqflvhdr = &qq_flv_block_index->qqflvhdr;
            ctx->strBlock.data = ngx_pcalloc(r->pool, qqflvhdr->usize);
            ngx_http_qqflv_open_source_file(&file, &ctx->qq_flv_index->channel_name, &qq_flv_block_index->timestamp);
            ctx->strBlock.len = ngx_http_qqflv_read_source_file(ctx->strBlock.data, &file,
                &qq_flv_block_index->file_offset, &qqflvhdr->usize) - ctx->strBlock.data;
            ngx_close_file(file.fd);
        } else {
            return ngx_http_qqflv_make_block_repair(r, ctx->blockid);
        }
    }  

    if (ctx->strBlock.len) {
        ll = &ctx->out_chain;
        while (!ngx_queue_empty(&ctx->intqueue)) {
            tq = ngx_queue_head(&ctx->intqueue);
            ngx_queue_remove(tq);
            intnode = ngx_queue_data(tq, ngx_http_qqflv_intqueue_node_t, q);      

            ReadPos = intnode->data * ctx->piecesize;
            ReadSize = ctx->strBlock.len - ReadPos >= ctx->piecesize ? ctx->piecesize : (ctx->strBlock.len - ReadPos);
            if (ReadPos > ctx->strBlock.len) ReadSize = 0;
            *ll = ngx_http_qqflv_create_chain_t(r->pool, NGX_QQ_FLV_HEADER_SIZE + ReadSize);
            if (*ll == NULL) {
                break;
            }
            p = (*ll)->buf->pos;
            p = ngx_http_qqflv_make_header(p, NULL, &ReadSize, &ctx->blockid, intnode->data);
            p = ngx_cpymem(p, ctx->strBlock.data + ReadPos, ReadSize);
            (*ll)->buf->last = p;
            ll = &(*ll)->next;
        }
    }

    return ngx_http_qqflv_send_response(r);    
}

static ngx_int_t
ngx_http_qqflv_piece_handler(ngx_http_request_t *r)
{
    ngx_int_t                                 size;
    printf("piece handler\n");
    size = ngx_http_qqflv_parse_range(r, "pieces=");

    if (size == 0) {
        return ngx_http_qqflv_send_response(r);
    }

    return ngx_http_qqflv_piece_write_handler(r);
}

static ngx_chain_t *
ngx_http_qqflv_create_chain_t(ngx_pool_t *pool, size_t size)
{
    ngx_chain_t                              *chain;
    ngx_buf_t                                *b;
    
    if (size) {
        b = ngx_create_temp_buf(pool, size);
        if (b == NULL) {
            return NULL;
        }
        chain = ngx_pcalloc(pool, sizeof(ngx_chain_t));
        if (chain == NULL) {
            return NULL;
        }
        chain->buf = b;
    } else {
        chain = ngx_pcalloc(pool, sizeof(ngx_chain_t));
        if (chain == NULL) {
            return NULL;
        }
    }
    
    return chain;
}

static u_char *ngx_http_qqflv_parse_block_data(ngx_buf_t *buf)
{
    u_char                                    *p;
    ngx_qq_flv_header_t                        qqflvhdr;
    if (buf->last - buf->pos <= NGX_QQ_FLV_HEADER_SIZE) {
        return NULL;
    }

    p = buf->pos;

#define READ_QQ_FLV_HEADER_FROM_BUFFER(var)                         \
    ngx_cpymem(&var, p, sizeof(var));                               \
    p += sizeof(var);
    
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usize);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.huheadersize);
    if (qqflvhdr.huheadersize != NGX_QQ_FLV_HEADER_SIZE) {
        return NULL;
    }
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.huversion);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.uctype);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.uckeyframe);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usec);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.useq);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.usegid);
    READ_QQ_FLV_HEADER_FROM_BUFFER(qqflvhdr.ucheck);

#undef READ_QQ_FLV_HEADER_FROM_BUFFER

    if (buf->last - p != qqflvhdr.usize) {
        return NULL;
    }
    return p;
}

static ngx_int_t ngx_http_qqflv_block_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t                        *pr = r->parent;
    ngx_chain_t                              **ll;
    u_char                                    *p;
    ngx_http_qqflv_ctx_t                      *ctx;

    ctx = ngx_http_get_module_ctx(pr, ngx_http_qqflv_module);

    if (ctx->type == NGX_HTTP_QQFLV_BLOCK) {

        for (ll = &ctx->out_chain; *ll; ll = &(*ll)->next);
        if (r->headers_out.status == NGX_HTTP_OK && ngx_http_qqflv_parse_block_data(&r->upstream->buffer)) {
            *ll = ngx_http_qqflv_create_chain_t(pr->pool, 0);
            (*ll)->buf = &r->upstream->buffer;            
        } else {
            *ll = ngx_http_qqflv_create_chain_t(pr->pool, NGX_QQ_FLV_HEADER_SIZE);
            p = (*ll)->buf->pos;
            p = ngx_http_qqflv_make_header(p, NULL, (u_char *) "\0", &ctx->blockid, INT_MAX);
            (*ll)->buf->last = p;
        }
        pr->write_event_handler = ngx_http_qqflv_block_write_handler;

    } else {
        if (r->headers_out.status == NGX_HTTP_OK) {
            ctx->strBlock.data = ngx_http_qqflv_parse_block_data(&r->upstream->buffer);
            if (ctx->strBlock.data) {
                ctx->strBlock.len = r->upstream->buffer.last - ctx->strBlock.data;
            }
            
        }
        pr->write_event_handler = ngx_http_qqflv_piece_write_handler;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_qqflv_make_block_repair(ngx_http_request_t *r, uint32_t blockid)
{
    static u_char                             buf[NGX_MAX_PATH + 1];
    u_char                                   *p;
    static ngx_str_t                          uri;
    static ngx_str_t                          args;
    ngx_http_post_subrequest_t               *ps;
    ngx_http_request_t                       *sr;
    ngx_http_qqflv_ctx_t                     *ctx, *sctx;

    printf("block repair");
    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);

    p = buf;

    p = ngx_cpymem(p, (u_char *) "/playback/", sizeof("/playback/") - 1);
    p = ngx_cpymem(p, ctx->qq_flv_index->channel_name.data, ctx->qq_flv_index->channel_name.len - 1);
    p = ngx_cpymem(p, (u_char *) ".flv", sizeof(".flv") - 1);
    *p = 0;

    uri.data = buf;
    uri.len = p - buf;

    p = p + 1;
    args.data = p;
    p = ngx_cpymem(p, (u_char *) "apptype=flashp2p&xHttpTrunk=1&version=0&protocol=1795&buname=", 
            sizeof("apptype=flashp2p&xHttpTrunk=1&version=0&protocol=1795&buname=") - 1);
    if (ctx->qq_flv_index->buname) {
        p = ngx_cpymem(p, (u_char *) "qt", sizeof("qt") - 1);
    } else {
        p = ngx_cpymem(p, (u_char *) "qqlive", sizeof("qqlive") - 1);
    }
    *p = 0;
    args.len = p - args.data;

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        return NGX_ERROR;
    }

    ps->handler = ngx_http_qqflv_block_subrequest_done;
    //ps->data = ctx;
    ctx->blockid = blockid;
    if (ngx_http_subrequest(r, &uri, &args, &sr, ps, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
        return NGX_ERROR;
    }

    sctx = ngx_http_get_module_ctx(sr, ngx_http_qqflv_module);
    if (sctx == NULL) {
        sctx = ngx_pcalloc(r->pool, sizeof(ngx_http_qqflv_ctx_t));
        ngx_http_set_ctx(sr, sctx, ngx_http_qqflv_module);
    }

    sctx->range.data = ngx_palloc(r->pool, 64);
    p = sctx->range.data;
    p = ngx_sprintf(p, "blocks=%D-%D", blockid, blockid);
    *p = 0;
    sctx->range.len = p - sctx->range.data;

    return NGX_DONE;
}

static ngx_int_t ngx_http_qqflv_block_write_handler(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t                     *ctx;
    ngx_chain_t                              *cl, **ll;
    ngx_buf_t                                *b;
    ngx_queue_t                              *tq;
    ngx_http_qqflv_intqueue_node_t           *intnode;
    ngx_str_t                                 block_key;
    ngx_map_node_t                           *node;
    ngx_qq_flv_block_index_t                 *qq_flv_block_index;
    ngx_qq_flv_header_t                      *qqflvhdr;
    u_char                                   *p;
    ngx_keyval_t                             *h;
    ngx_int_t                                 rc;
    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    printf("write handler");
    for (ll = &ctx->out_chain; *ll; ll = &(*ll)->next);
    block_key.len = sizeof(uint32_t);

    if (ctx->intqueue_size <= NGX_QQFLV_MAX_BLOCK_SIZE) {
        while (!ngx_queue_empty(&ctx->intqueue)) {
            tq = ngx_queue_head(&ctx->intqueue);
            ngx_queue_remove(tq);
            intnode = ngx_queue_data(tq, ngx_http_qqflv_intqueue_node_t, q);
            block_key.data = &intnode->data;
            node = qq_flv_block_index = NULL;
            node = ngx_map_find(&ctx->qq_flv_index->block_map, (intptr_t) &block_key);
            if (node) {
                qq_flv_block_index = (ngx_qq_flv_block_index_t *)
                        ((char *) node - offsetof(ngx_qq_flv_block_index_t, node));
            }
            if (qq_flv_block_index) {
                qqflvhdr = &qq_flv_block_index->qqflvhdr;
                *ll = ngx_http_qqflv_create_chain_t(r->pool, NGX_QQ_FLV_HEADER_SIZE + qqflvhdr->usize);
                if (*ll == NULL) {
                    break;
                }
                p = (*ll)->buf->pos;
                p = ngx_http_qqflv_make_header(p, qqflvhdr, &qqflvhdr->usize, &qqflvhdr->useq, INT_MAX);
                if(ctx->timestamp != qq_flv_block_index->timestamp || ctx->file.fd == NGX_INVALID_FILE)
                {
                    ctx->timestamp = qq_flv_block_index->timestamp;
                    ngx_close_file(ctx->file.fd);
                    ngx_http_qqflv_open_source_file(&ctx->file, &ctx->qq_flv_index->channel_name, &ctx->timestamp);
                }
                 p = ngx_http_qqflv_read_source_file(p, &ctx->file, &qq_flv_block_index->file_offset, &qqflvhdr->usize);
                (*ll)->buf->last = p;
                ll = &(*ll)->next;
            } else {
                return ngx_http_qqflv_make_block_repair(r, intnode->data);
            }
        }
    }
    return ngx_http_qqflv_send_response(r); 
}

static ngx_int_t
ngx_http_qqflv_block_handler(ngx_http_request_t *r)
{
    ngx_int_t                                 size;

    size = ngx_http_qqflv_parse_range(r, "blocks=");
    if (size == 0 || size > NGX_QQFLV_MAX_BLOCK_SIZE) {
        return ngx_http_qqflv_send_response(r);
    }

    return ngx_http_qqflv_block_write_handler(r);
}

static ngx_int_t
ngx_http_qqflv_parse_request(ngx_http_request_t *r)
{
    ngx_http_qqflv_ctx_t           *ctx;
    ngx_log_t                      *log;
    u_char                         *p;
    ngx_str_t                       data, vkey;
    ngx_int_t                       protocol;

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);
    log = r->connection->log;

    ctx->type = NGX_HTTP_DEFAULT;

    if (r->headers_in.range) {
        ctx->range = (r->headers_in.range)->value;
    }

    if(ngx_strncmp(r->uri.data + r->uri.len - 4, ".flv", 4) != 0) {        
        return NGX_OK;
    }

    for (p = r->uri.data + r->uri.len - 5; p >= r->uri.data && *p != '/'; p--);

    if (ngx_atoi(p + 1, r->uri.data + r->uri.len - 5 - p) == -1)
    {
        return NGX_OK;
    }

    ctx->channel_name.data = ngx_pcalloc(r->pool, r->uri.data + r->uri.len - 3 - p);
    ngx_memcpy(ctx->channel_name.data, p + 1, r->uri.data + r->uri.len - 5 - p);
    ctx->channel_name.len = r->uri.data + r->uri.len - 5 - p;

    ctx->buname = 0;
    if (ngx_http_arg(r, (u_char *) "buname", sizeof("buname") - 1,
                     &data) == NGX_OK)
    {
        if (ngx_strncmp(data.data, (u_char *)"qt", data.len) == 0 || 
                    ngx_strncmp(data.data, (u_char *)"qtlol", data.len) == 0)
        {
            ctx->buname = 1;
        }
    }

    if (ctx->buname) {
        *(ctx->channel_name.data + ctx->channel_name.len) = 'Q';
    }
    else {
        *(ctx->channel_name.data + ctx->channel_name.len) = 'F';
    }
    ctx->channel_name.len ++;

    ctx->backsec = -1;
    if (ngx_http_arg(r, (u_char *) "rsec", sizeof("rsec") - 1,
                     &data) == NGX_OK)
    {
        ctx->backsec = ngx_atoi(data.data, data.len);
    }

    if (ngx_http_arg(r, (u_char *) "playback", sizeof("playback") - 1,
                     &data) == NGX_OK)
    {
        ctx->backsec = ngx_atoi(data.data, data.len);
    }

    if (ngx_http_arg(r, (u_char *) "wsStreamTimeABS", sizeof("wsStreamTimeABS") - 1,
                     &data) == NGX_OK)
    {
        ctx->backsec = ngx_atoi(data.data, data.len);
        if (ctx->backsec != -1) {
            ctx->backsec = (ngx_time() - ctx->backsec) / 5 * 5;
        }
    }

    if (ngx_http_arg(r, (u_char *) "reStreamTimeABS", sizeof("reStreamTimeABS") - 1,
                     &data) == NGX_OK)
    {
        ctx->backsec = ngx_atoi(data.data, data.len);
        if (ctx->backsec != -1) {
            ctx->backsec = ctx->backsec / 5 * 5;
        }
    }

    if (ngx_http_arg(r, (u_char *) "xHttpTrunk", sizeof("xHttpTrunk") - 1,
                     &data) == NGX_OK)
    {
        if (ngx_strncmp(data.data, (u_char *)"1", data.len) == 0)
        {
            ctx->xHttpTrunk = 1;
        }
    }

    if (ngx_http_arg(r, (u_char *) "protocol", sizeof("protocol") - 1,
                     &data) == NGX_OK)
    {
        protocol = ngx_atoi(data.data, data.len);            
    }

    if (ngx_http_arg(r, (u_char *) "blockid", sizeof("blockid") - 1,
                     &data) == NGX_OK)
    {
        ctx->blockid = ngx_atoi(data.data, data.len);            
    }

    if (ngx_http_arg(r, (u_char *) "piecesize", sizeof("piecesize") - 1,
                     &data) == NGX_OK)
    {
        ctx->piecesize = ngx_atoi(data.data, data.len);            
    }


    switch(protocol) {
    case 1795:
        ctx->type = NGX_HTTP_QQFLV_BLOCK;
        break;
    case 1797:
        ctx->type = NGX_HTTP_QQFLV_PIECE;
        break;
    case 1804:
        ctx->type = NGX_HTTP_QQFLV_IDLE;
        break;
    default:
        if (ctx->xHttpTrunk) {
            ctx->type = NGX_HTTP_QQFLV_SOURCE;
        }
        else {
            if (ctx->backsec != -1) {
                ctx->type = NGX_HTTP_QQFLV_PLAYBACK;
            }
            else {
                ctx->type = NGX_HTTP_QQFLV_NORMAL;
            }            
        }
        break;
    }
    /*if (ctx->type == NGX_HTTP_QQFLV_PLAYBACK || ctx->type == NGX_HTTP_QQFLV_NORMAL) {        
        ngx_http_arg(r, (u_char *) "vkey", sizeof("vkey") - 1, &vkey);
        ngx_int_t keyflag = ctx->buname ? 3 : 11;
        stKeyLive keyLive;
        keyLive.cdnIP = 9887;
        ngx_int_t res = qqvideo_verifyLiveTstreamKey(20120814, 00000000, "100103700.flv",
                                            1,
                                            &keyLive.uin,
                                            &keyLive.speed,
                                            &keyLive.platform,
                                            &keyLive.start_time,
                                            &keyLive.end_time,
                                            &keyLive.dtfrom,
                                            &keyLive.cgi_name,
                                            keyLive.cdnIP,
                                            &keyLive.streamID,
                                            vkey.data, vkey.len, keyflag, 16);
        printf("%d-%d\n", keyLive.speed, keyLive.end_time);
    }*/
    


    if (ctx->type == NGX_HTTP_QQFLV_PLAYBACK && ctx->buname) {
        return NGX_ERROR;
    }

    ctx->qq_flv_index = ngx_http_qqflv_find_channel(&ctx->channel_name);
    if (ctx->qq_flv_index == NULL) {
        ctx->qq_flv_index = ngx_http_qqflv_create_channel(&ctx->channel_name, 0, ctx->buname, 0);
    }
    if (ctx->qq_flv_index == NULL) {
        return NGX_ERROR;
    }

    /*printf("buname:%d\n", ctx->buname);
    printf("xHttpTrunk:%d\n", ctx->xHttpTrunk);
    printf("type:%d\n", ctx->type);
    printf("backsec:%d\n", ctx->backsec);
    printf("protocol:%d\n", protocol);
    printf("blockid:%d\n", ctx->blockid);
    printf("piecesize:%d\n", ctx->piecesize);
    printf("channel_name:%s\n", ctx->channel_name.data);*/

    return NGX_OK;
}

static ngx_int_t
ngx_http_qqflv_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                             rc;
    ngx_log_t                            *log;
    ngx_http_qqflv_ctx_t                 *ctx;

    log = r->connection->log;

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_qqflv_ctx_t));    
        ngx_http_set_ctx(r, ctx, ngx_http_qqflv_module);
        ctx->file.fd = NGX_INVALID_FILE;
    }

    /* set qqflv request type and time arg */
    rc = ngx_http_qqflv_parse_request(r);
    if(rc == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }
    return rc;
}

static ngx_int_t
ngx_http_qqflv_content_handler(ngx_http_request_t *r)
{
    if (r != r->main && r->post_subrequest) {
        return NGX_OK;
    }

    ngx_int_t                             rc;
    ngx_log_t                            *log;
    ngx_uint_t                            i;
    ngx_http_qqflv_ctx_t                 *ctx;

    ngx_http_qqflv_loc_conf_t            *qlcf;
    ngx_http_qqflv_main_conf_t           *qmcf;
    ngx_http_qqflv_request_cmd_t         *cmd;

    log = r->connection->log;

    qmcf = ngx_http_get_module_main_conf(r, ngx_http_qqflv_module);
    qlcf = ngx_http_get_module_loc_conf(r, ngx_http_qqflv_module);

  //  if (cmcf->flv_path.len == 0 || !conf->enable || r != r->main) {
    //    return NGX_DECLINED;
    //}

    //if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
    //    return NGX_HTTP_NOT_ALLOWED;
    //}

    

    ctx = ngx_http_get_module_ctx(r, ngx_http_qqflv_module);

    if(ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_qqflv_ctx_t));    
        ngx_http_set_ctx(r, ctx, ngx_http_qqflv_module);
        ctx->file.fd = NGX_INVALID_FILE;
    }

    cmd = NULL;
    for( i = 0; i < sizeof(ngx_http_qqflv_request_cmds)/sizeof(ngx_http_qqflv_request_cmd_t); i++) {
        if(ngx_http_qqflv_request_cmds[i].type == ctx->type) {
            cmd = &ngx_http_qqflv_request_cmds[i];
            break;
        }
    }
    
    if(cmd == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0, "unknown type qqflv request");
        return NGX_HTTP_NOT_FOUND;
    }
    
    rc = cmd->handler(r);
    return rc;
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


static ngx_int_t
ngx_http_qqflv_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_qqflv_access_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_qqflv_content_handler;

    return NGX_OK;
}