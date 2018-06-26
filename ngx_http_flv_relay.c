/*
 * Copyright (C) AlexWoo(Wu Jie) wj19840501@gmail.com
 */


#include "ngx_http_client.h"
#include "ngx_rtmp.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rbuf.h"


typedef struct {
    ngx_uint_t                  status;
    char                       *code;
    char                       *level;
    char                       *desc;
} ngx_http_status_code_t;

static ngx_http_status_code_t ngx_http_relay_status_code[] = {
    { 400, "NetStream.Play.BadName", "error", "Bad Request" },
    { 404, "NetStream.Play.StreamNotFound", "error", "No such stream" },
    { 503, "NetStream.Play.ServiceUnavailable", "error", "Service Unavailable" },
    { 0, "NetStream.Play.StreamError", "error", "Stream Error" }
};

static ngx_int_t
ngx_http_relay_parse_qq_flv(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    u_char                      ch, *p, *pc;
    ngx_rtmp_stream_t          *st;
    ngx_rtmp_header_t          *h;
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

    for (p = b->pos; p < b->last; ++p) {
        ch = *p;

        switch (state) {

        case qq_flv_usize0:
            s->qq_flv_usize = 0;
            pc = (u_char *) &s->qq_flv_usize;
            pc[0] = ch;
            state = qq_flv_usize1;
            break;

        case qq_flv_usize1:
            pc = (u_char *) &s->qq_flv_usize;
            pc[1] = ch;
            state = qq_flv_usize2;
            break;

        case qq_flv_usize2:
            pc = (u_char *) &s->qq_flv_usize;
            pc[2] = ch;
            state = qq_flv_usize3;
            break;

        case qq_flv_usize3:
            pc = (u_char *) &s->qq_flv_usize;
            pc[3] = ch;
            st = &s->in_streams[0];
            st->qq_len = s->qq_flv_usize;
            state = qq_flv_huheadersize0;
            break;

        case qq_flv_huheadersize0:
            s->qq_flv_huheadersize = 0;
            pc = (u_char *) &s->qq_flv_huheadersize;
            pc[0] = ch;
            state = qq_flv_huheadersize1;
            break;

        case qq_flv_huheadersize1:
            pc = (u_char *) &s->qq_flv_huheadersize;
            pc[1] = ch;
            state = qq_flv_huversion0;
            break;

        case qq_flv_huversion0:
            s->qq_flv_huversion = 0;
            pc = (u_char *) &s->qq_flv_huversion;
            pc[0] = ch;
            state = qq_flv_huversion1;
            break;

        case qq_flv_huversion1:
            pc = (u_char *) &s->qq_flv_huversion;
            pc[1] = ch;
            state = qq_flv_uctype;
            break;

        case qq_flv_uctype:
            s->qq_flv_uctype = ch;
            state = qq_flv_uckeyframe;
            break;

        case qq_flv_uckeyframe:
            s->qq_flv_uckeyframe = ch;
            state = qq_flv_usec0;
            break;

        case qq_flv_usec0:
            s->qq_flv_usec = 0;
            pc = (u_char *) &s->qq_flv_usec;
            pc[0] = ch;
            state = qq_flv_usec1;
            break;

        case qq_flv_usec1:
            pc = (u_char *) &s->qq_flv_usec;
            pc[1] = ch;
            state = qq_flv_usec2;
            break;

        case qq_flv_usec2:
            pc = (u_char *) &s->qq_flv_usec;
            pc[2] = ch;
            state = qq_flv_usec3;
            break;

        case qq_flv_usec3:
            pc = (u_char *) &s->qq_flv_usec;
            pc[3] = ch;
            state = qq_flv_useq0;
            break;

        case qq_flv_useq0:
            s->qq_flv_useq = 0;
            pc = (u_char *) &s->qq_flv_useq;
            pc[0] = ch;
            state = qq_flv_useq1;
            break;

        case qq_flv_useq1:
            pc = (u_char *) &s->qq_flv_useq;
            pc[1] = ch;
            state = qq_flv_useq2;
            break;

        case qq_flv_useq2:
            pc = (u_char *) &s->qq_flv_useq;
            pc[2] = ch;
            state = qq_flv_useq3;
            break;

        case qq_flv_useq3:
            pc = (u_char *) &s->qq_flv_useq;
            pc[3] = ch;
            state = qq_flv_usegid0;
            break;

        case qq_flv_usegid0:
            s->qq_flv_usegid = 0;
            pc = (u_char *) &s->qq_flv_usegid;
            pc[0] = ch;
            state = qq_flv_usegid1;
            break;

        case qq_flv_usegid1:
            pc = (u_char *) &s->qq_flv_usegid;
            pc[1] = ch;
            state = qq_flv_usegid2;
            break;

        case qq_flv_usegid2:
            pc = (u_char *) &s->qq_flv_usegid;
            pc[2] = ch;
            state = qq_flv_usegid3;
            break;

        case qq_flv_usegid3:
            pc = (u_char *) &s->qq_flv_usegid;
            pc[3] = ch;
            state = qq_flv_ucheck0;
            break;

        case qq_flv_ucheck0:
            s->qq_flv_ucheck = 0;
            pc = (u_char *) &s->qq_flv_ucheck;
            pc[0] = ch;
            state = qq_flv_ucheck1;
            break;

        case qq_flv_ucheck1:
            pc = (u_char *) &s->qq_flv_ucheck;
            pc[1] = ch;
            state = qq_flv_ucheck2;
            break;

        case qq_flv_ucheck2:
            pc = (u_char *) &s->qq_flv_ucheck;
            pc[2] = ch;
            state = qq_flv_ucheck3;
            break;

        case qq_flv_ucheck3:
            pc = (u_char *) &s->qq_flv_ucheck;
            pc[3] = ch;
            switch (s->qq_flv_uckeyframe) {
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
            st = &s->in_streams[0];
            st->qq_len--;
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
            st = &s->in_streams[0];
            st->qq_len--;
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
            st = &s->in_streams[0];
            st->qq_len--;
            break;

        case flv_header_Version:
            s->flv_version = ch;
            if (s->flv_version != 1) {
                rc = NGX_ERROR;
                goto done;
            }
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_header_Flags;
            break;

        case flv_header_Flags:
            s->flv_flags = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_header_DataOffset0;
            break;

        case flv_header_DataOffset0:
            pc = (u_char *) &s->flv_data_offset;
            pc[3] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_header_DataOffset1;
            break;

        case flv_header_DataOffset1:
            pc = (u_char *) &s->flv_data_offset;
            pc[2] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_header_DataOffset2;
            break;

        case flv_header_DataOffset2:
            pc = (u_char *) &s->flv_data_offset;
            pc[1] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_header_DataOffset3;
            break;

        case flv_header_DataOffset3:
            pc = (u_char *) &s->flv_data_offset;
            pc[0] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_tagsize0;
            break;

        case flv_tagsize0:
            s->flv_tagsize = 0;
            pc = (u_char *) &s->flv_tagsize;
            pc[3] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_tagsize1;
            break;

        case flv_tagsize1:
            pc = (u_char *) &s->flv_tagsize;
            pc[2] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
            state = flv_tagsize2;
            break;

        case flv_tagsize2:
            pc = (u_char *) &s->flv_tagsize;
            pc[1] = ch;
            st = &s->in_streams[0];
            st->qq_len--;
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
            st->qq_len--;
            state = flv_tagtype;

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
            st->qq_len--;
            break;

        case flv_datasize0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->mlen = 0;
            pc = (u_char *) &h->mlen;

            pc[2] = ch;
            state = flv_datasize1;
            st->qq_len--;
            break;

        case flv_datasize1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[1] = ch;
            state = flv_datasize2;
            st->qq_len--;
            break;

        case flv_datasize2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[0] = ch;
            state = flv_timestamp0;
            st->len = h->mlen;
            st->qq_len--;
            break;

        case flv_timestamp0:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[2] = ch;
            state = flv_timestamp1;
            st->qq_len--;
            break;

        case flv_timestamp1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[1] = ch;
            state = flv_timestamp2;
            st->qq_len--;
            break;

        case flv_timestamp2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[0] = ch;
            state = flv_timestamp_extended;
            st->qq_len--;
            break;

        case flv_timestamp_extended:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[3] = ch;
            state = flv_streamid0;
            st->qq_len--;
            break;

        case flv_streamid0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->msid = 0;
            pc = (u_char *) &h->msid;

            pc[2] = ch;
            state = flv_streamid1;
            st->qq_len--;
            break;

        case flv_streamid1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[1] = ch;
            state = flv_streamid2;
            st->qq_len--;
            break;

        case flv_streamid2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[0] = ch;
            state = flv_data;
            st->qq_len--;
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
                len = ngx_min(st->qq_len, len);
                if ((*ll)->buf->end - (*ll)->buf->last >= (long) len) {
                    (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                    p += len;
                    st->len -= len;
                    st->qq_len -= len;
                    break;
                }

                len = (*ll)->buf->end - (*ll)->buf->last;
                (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                p += len;
                st->len -= len;
                st->qq_len -= len;
                ll = &(*ll)->next;
            }

            if (st->len != 0) {
                rc = NGX_AGAIN;
                goto done;
            }

            if (st->qq_len != 0) {
                state = flv_tagsize0;
                rc = NGX_AGAIN;
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

    return rc;
}

static ngx_int_t
ngx_http_relay_parse_flv(ngx_rtmp_session_t *s, ngx_buf_t *b)
{
    u_char                      ch, *p, *pc;
    ngx_rtmp_stream_t          *st;
    ngx_rtmp_header_t          *h;
    ngx_chain_t               **ll;
    size_t                      len;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_int_t                   rc = NGX_AGAIN;
    enum {
        flv_header_F = 0,
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

    state = s->flv_state;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    for (p = b->pos; p < b->last; ++p) {
        ch = *p;

        switch (state) {

        case flv_header_F:
            switch (ch) {
            case 'F':
                state = flv_header_FL;
                break;
            default:
                rc = NGX_ERROR;
                goto done;
            }
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
            break;

        case flv_header_Version:
            s->flv_version = ch;
            if (s->flv_version != 1) {
                rc = NGX_ERROR;
                goto done;
            }
            state = flv_header_Flags;
            break;

        case flv_header_Flags:
            s->flv_flags = ch;
            state = flv_header_DataOffset0;
            break;

        case flv_header_DataOffset0:
            pc = (u_char *) &s->flv_data_offset;
            pc[3] = ch;
            state = flv_header_DataOffset1;
            break;

        case flv_header_DataOffset1:
            pc = (u_char *) &s->flv_data_offset;
            pc[2] = ch;
            state = flv_header_DataOffset2;
            break;

        case flv_header_DataOffset2:
            pc = (u_char *) &s->flv_data_offset;
            pc[1] = ch;
            state = flv_header_DataOffset3;
            break;

        case flv_header_DataOffset3:
            pc = (u_char *) &s->flv_data_offset;
            pc[0] = ch;
            state = flv_tagsize0;
            break;

        case flv_tagsize0:
            s->flv_tagsize = 0;
            pc = (u_char *) &s->flv_tagsize;
            pc[3] = ch;
            state = flv_tagsize1;
            break;

        case flv_tagsize1:
            pc = (u_char *) &s->flv_tagsize;
            pc[2] = ch;
            state = flv_tagsize2;
            break;

        case flv_tagsize2:
            pc = (u_char *) &s->flv_tagsize;
            pc[1] = ch;
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
            state = flv_tagtype;

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

            break;

        case flv_datasize0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->mlen = 0;
            pc = (u_char *) &h->mlen;

            pc[2] = ch;
            state = flv_datasize1;

            break;

        case flv_datasize1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[1] = ch;
            state = flv_datasize2;

            break;

        case flv_datasize2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->mlen;

            pc[0] = ch;
            state = flv_timestamp0;
            st->len = h->mlen;

            break;

        case flv_timestamp0:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[2] = ch;
            state = flv_timestamp1;

            break;

        case flv_timestamp1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[1] = ch;
            state = flv_timestamp2;

            break;

        case flv_timestamp2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[0] = ch;
            state = flv_timestamp_extended;

            break;

        case flv_timestamp_extended:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->timestamp;

            pc[3] = ch;
            state = flv_streamid0;

            break;

        case flv_streamid0:
            st = &s->in_streams[0];
            h = &st->hdr;
            h->msid = 0;
            pc = (u_char *) &h->msid;

            pc[2] = ch;
            state = flv_streamid1;

            break;

        case flv_streamid1:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[1] = ch;
            state = flv_streamid2;

            break;

        case flv_streamid2:
            st = &s->in_streams[0];
            h = &st->hdr;
            pc = (u_char *) &h->msid;

            pc[0] = ch;
            state = flv_data;

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
                if ((*ll)->buf->end - (*ll)->buf->last >= (long) len) {
                    (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                    p += len;
                    st->len -= len;

                    break;
                }

                len = (*ll)->buf->end - (*ll)->buf->last;
                (*ll)->buf->last = ngx_cpymem((*ll)->buf->last, p, len);
                p += len;
                st->len -= len;

                ll = &(*ll)->next;
            }

            if (st->len != 0) {
                rc = NGX_AGAIN;
                goto done;
            }

            state = flv_tagsize0;
            rc = NGX_OK;
            goto done;
        }
    }

done:
    b->pos = p;
    s->flv_state = state;

    return rc;
}

static void
ngx_http_relay_recv_body(void *request, ngx_http_request_t *hcr)
{
    ngx_int_t                   n;
    ngx_client_session_t       *cs;
    ngx_http_client_ctx_t      *ctx;
    ngx_rtmp_session_t         *s;
    ngx_chain_t                *cl = NULL, *l, *in;
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_rtmp_header_t          *h;
    ngx_rtmp_stream_t          *st = NULL;

    ctx = hcr->ctx[0];
    cs = ctx->session;

    s = request;
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (cs->closed) {
        ngx_http_client_finalize_request(hcr, 1);
        return;
    }

    n = ngx_http_client_read_body(hcr, &cl, cscf->chunk_size);

    if (n == 0 || n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, s->connection->log, ngx_errno,
                "http relay, recv body error");
        ngx_rtmp_finalize_session(s);
        goto end;
    }

    ngx_rtmp_update_bandwidth(&s->bw_in,
                              (uint32_t)(cs->recv - s->flv_recv_bytes));
    s->flv_recv_bytes = cs->recv;

    l = cl;
    for (;;) {
        if (l && l->buf->pos == l->buf->last) {
            l = l->next;
        }

        if (l == NULL) {
            break;
        }

        n = ngx_http_relay_parse_flv(s, l->buf);

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "http relay, parse flv frame failed in state %d",
                    s->flv_state);
            ngx_rtmp_finalize_session(s);

            if (st != NULL) {
                ngx_put_chainbufs(st->in);
                st->in = NULL;
            }

            goto end;
        }

        if (n == NGX_AGAIN) {
            continue;
        }

        /* NGX_OK */
        st = &s->in_streams[0];
        h = &st->hdr;
        in = st->in;

        if (ngx_rtmp_receive_message(s, h, in) != NGX_OK) {
            ngx_rtmp_finalize_session(s);
            goto end;
        }

        ngx_put_chainbufs(st->in);
        st->in = NULL;
    }

end:
    ngx_put_chainbufs(cl);
}

static void
ngx_http_flv_client_cleanup(void *data)
{
    ngx_http_request_t         *hcr;
    ngx_http_client_ctx_t      *ctx;
    ngx_rtmp_session_t         *s;

    hcr = data;

    ctx = hcr->ctx[0];
    s = ctx->request;

    if (ctx == NULL) {
        return;
    }

    if (s) {
        if (s->close.posted) {
            ngx_delete_posted_event(&s->close);
        }
        ngx_rtmp_finalize_fake_session(s);
    }

    ngx_log_error(NGX_LOG_INFO, hcr->connection->log, 0,
            "http flv client, cleanup");
}

static void
ngx_http_relay_error(ngx_rtmp_session_t *s, ngx_uint_t status)
{
    ngx_live_stream_t          *st;
    ngx_rtmp_core_ctx_t        *cctx;
    char                       *code, *level, *desc;
    size_t                      i;

    for (i = 0; ngx_http_relay_status_code[i].status != 0; ++i) {

        if (status != ngx_http_relay_status_code[i].status) {
            continue;
        }

        break;
    }

    code = ngx_http_relay_status_code[i].code;
    level = ngx_http_relay_status_code[i].level;
    desc = ngx_http_relay_status_code[i].desc;

    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
            "http relay transit, %d: level='%s' code='%s' description='%s'",
            status, level, code, desc);

    st = ngx_live_create_stream(&s->serverid, &s->stream);
    if (st == NULL) {
        return;
    }

    cctx = st->play_ctx;

    for (; cctx; cctx = cctx->next) {
        cctx->session->status = status;
        ngx_rtmp_send_status(cctx->session, code, level, desc);

        if (ngx_strcmp(level, "error") == 0) {
            ngx_rtmp_finalize_session(cctx->session);
        }
    }
}

static void
ngx_http_relay_recv(void *request, ngx_http_request_t *hcr)
{
    ngx_rtmp_session_t         *s;
    ngx_client_session_t       *cs;
    ngx_http_client_ctx_t      *ctx;
    ngx_uint_t                  status_code;

    s = request;
    ctx = hcr->ctx[0];
    cs = ctx->session;
    ngx_rtmp_update_bandwidth(&s->bw_out, (uint32_t)cs->connection->sent);
    status_code = ngx_http_client_status_code(hcr);

    if (status_code != NGX_HTTP_OK) {
        ngx_http_relay_error(s, status_code);
        ngx_http_client_finalize_request(hcr, 1);
        return;
    }

    ngx_rtmp_relay_publish_local(s);

    ctx->read_handler = ngx_http_relay_recv_body;
    ngx_http_relay_recv_body(request, hcr);
}

static ngx_int_t
ngx_http_relay_send_request(ngx_rtmp_session_t *s, ngx_client_session_t *cs)
{
    ngx_http_request_t         *hcr;
    ngx_str_t                   request_url;
    size_t                      len;
    ngx_rtmp_relay_ctx_t       *ctx;
    ngx_request_url_t           rurl;
    ngx_http_cleanup_t         *cln;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    if (ngx_parse_request_url(&rurl, &ctx->tc_url) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "parse tc_url(%V) failed", &ctx->tc_url);
        return NGX_ERROR;
    }

    len = s->scheme.len + 3 + rurl.host.len + 1 + ctx->app.len + 1
        + ctx->name.len;
    if (ctx->pargs.len) {
        len = len + 1 + ctx->pargs.len;
    }

    request_url.data = ngx_pcalloc(cs->connection->pool, len);
    if (request_url.data == NULL) {
        return NGX_ERROR;
    }
    request_url.len = len;

    if (ctx->pargs.len) {
        ngx_snprintf(request_url.data, len, "%V://%V/%V/%V?%V", &s->scheme,
                &rurl.host, &ctx->app, &ctx->name, &ctx->pargs);
    } else {
        ngx_snprintf(request_url.data, len, "%V://%V/%V/%V", &s->scheme,
                &rurl.host, &ctx->app, &ctx->name);
    }

    hcr = ngx_http_client_create_request(&request_url, NGX_HTTP_CLIENT_GET,
            NGX_HTTP_CLIENT_VERSION_10, NULL, cs->connection->log,
            ngx_http_relay_recv, NULL);

    if (ngx_http_client_send(hcr, cs, s, cs->connection->log) != NGX_OK) {
        return NGX_ERROR;
    }

    cln = ngx_http_cleanup_add(hcr, 0);
    if (cln == NULL) {
        ngx_http_relay_error(s, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_client_finalize_request(hcr, 1);
        return NGX_ERROR;
    }
    cln->handler = ngx_http_flv_client_cleanup;
    cln->data = hcr;

    s->request = hcr;
    s->live_type = NGX_HTTP_FLV_LIVE;

    return NGX_OK;
}

static ngx_int_t
ngx_http_relay_copy_str(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    if (src->len == 0) {
        return NGX_OK;
    }
    dst->len = src->len;
    dst->data = ngx_palloc(pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    return NGX_OK;
}


ngx_rtmp_relay_ctx_t *
ngx_http_relay_create_connection(ngx_rtmp_session_t *s,
        ngx_rtmp_conf_ctx_t *cctx, ngx_str_t* name,
        ngx_rtmp_relay_target_t *target)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_client_session_t       *cs;
    ngx_client_init_t          *ci;
    ngx_rtmp_addr_conf_t       *addr_conf;
    ngx_rtmp_conf_ctx_t        *addr_ctx;
    ngx_rtmp_session_t         *rs;
    ngx_pool_t                 *pool;
    ngx_rtmp_relay_ctx_t       *rctx;
    ngx_str_t                   v, *uri;
    u_char                     *first, *last, *p;

    /* init client session */
    ci = ngx_client_init(&target->url.host, NULL, 0, s->connection->log);
    if (ci == NULL) {
        return NULL;
    }
    ci->port = target->url.port;
    ci->max_retries = 0;
    pool = ci->pool;

    cs = ngx_client_connect(ci, s->connection->log);
    if (cs == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    /* create fake rtmp session */
    addr_conf = ngx_pcalloc(pool, sizeof(ngx_rtmp_addr_conf_t));
    if (addr_conf == NULL) {
        goto clear;
    }
    addr_ctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_conf_ctx_t));
    if (addr_ctx == NULL) {
        goto clear;
    }

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    addr_conf->default_server = cscf;
    addr_ctx->main_conf = cctx->main_conf;
    addr_ctx->srv_conf  = cctx->srv_conf;

    rs = ngx_rtmp_init_fake_session(cs->connection, addr_conf);
    if (rs == NULL) {
        goto clear;
    }
    rs->app_conf = cctx->app_conf;
    rs->relay = 1;
    rs->publishing = target->publishing;

    /* set parameters */
    #define NGX_RTMP_SESSION_STR_COPY(to, from)                             \
    if (s && ngx_http_relay_copy_str(pool, &rs->to, &s->from) != NGX_OK) {  \
        goto clear;                                                         \
    }

    NGX_RTMP_SESSION_STR_COPY(stream,   stream);

    NGX_RTMP_SESSION_STR_COPY(name,     name);
    NGX_RTMP_SESSION_STR_COPY(pargs,    pargs);

    NGX_RTMP_SESSION_STR_COPY(app,      app);
    NGX_RTMP_SESSION_STR_COPY(args,     args);
    NGX_RTMP_SESSION_STR_COPY(flashver, flashver);
    NGX_RTMP_SESSION_STR_COPY(swf_url,  swf_url);
    NGX_RTMP_SESSION_STR_COPY(tc_url,   tc_url);
    NGX_RTMP_SESSION_STR_COPY(page_url, page_url);

    if (s) {
        rs->acodecs = s->acodecs;
        rs->vcodecs = s->vcodecs;
    }

    NGX_RTMP_SESSION_STR_COPY(serverid, serverid);

#undef NGX_RTMP_SESSION_STR_COPY

#define NGX_HTTP_TARGET_STR_COPY(to, from)                                 \
    if (target && ngx_http_relay_copy_str(pool, &rs->to, &target->from)    \
                  != NGX_OK)                                               \
    {                                                                      \
        goto clear;                                                        \
    }

    NGX_HTTP_TARGET_STR_COPY(groupid, groupid);

#undef NGX_HTTP_TARGET_STR_COPY

    ngx_rtmp_cmd_middleware_init(rs);

    /* rctx from here */
    rctx = ngx_pcalloc(pool, sizeof(ngx_rtmp_relay_ctx_t));
    if (rctx == NULL) {
        goto clear;
    }

    if (name && ngx_http_relay_copy_str(pool, &rctx->name, name) != NGX_OK) {
        goto clear;
    }

    if (ngx_http_relay_copy_str(pool, &rctx->url, &target->url.url) != NGX_OK) {
        goto clear;
    }

#define NGX_RTMP_RELAY_STR_COPY(to, from)                                     \
    if (ngx_http_relay_copy_str(pool, &rctx->to, &target->from) != NGX_OK) {  \
        goto clear;                                                           \
    }                                                                         \

    NGX_RTMP_RELAY_STR_COPY(app,        app);
    NGX_RTMP_RELAY_STR_COPY(tc_url,     tc_url);
    NGX_RTMP_RELAY_STR_COPY(page_url,   page_url);
    NGX_RTMP_RELAY_STR_COPY(swf_url,    swf_url);
    NGX_RTMP_RELAY_STR_COPY(flash_ver,  flash_ver);
    NGX_RTMP_RELAY_STR_COPY(play_path,  play_path);

    rctx->live  = target->live;
    rctx->start = target->start;
    rctx->stop  = target->stop;

#undef NGX_RTMP_RELAY_STR_COPY

/* if target not set, set rctx default */
#define NGX_RTMP_DEFAULT_STR(to, from)          \
    if (rctx->to.len == 0) {                    \
        rctx->to = rs->from;                    \
    }

    NGX_RTMP_DEFAULT_STR(pargs,     pargs);

    NGX_RTMP_DEFAULT_STR(app,       app);
    NGX_RTMP_DEFAULT_STR(args,      args);
    NGX_RTMP_DEFAULT_STR(tc_url,    tc_url);
    NGX_RTMP_DEFAULT_STR(page_url,  page_url);
    NGX_RTMP_DEFAULT_STR(swf_url,   swf_url);
    NGX_RTMP_DEFAULT_STR(flash_ver, flashver);

    if (rctx->acodecs == 0) {
        rctx->acodecs = rs->acodecs;
    }

    if (rctx->vcodecs == 0) {
        rctx->vcodecs = rs->vcodecs;
    }

#undef NGX_RTMP_DEFAULT_STR

    if (rctx->app.len == 0 || rctx->play_path.len == 0) {
        /* parse uri */
        uri = &target->url.uri;
        first = uri->data;
        last  = uri->data + uri->len;

        if (first != last && *first == '/') {
            ++first;
        }

        if (first != last) {

            /* deduce app */
            p = ngx_strlchr(first, last, '/');
            if (p == NULL) {
                p = last;
            }

            if (rctx->app.len == 0 && first != p) {
                v.data = first;
                v.len = p - first;
                if (ngx_http_relay_copy_str(pool, &rctx->app, &v) != NGX_OK) {
                    goto clear;
                }
            }

            /* deduce play_path */
            if (p != last) {
                ++p;
            }

            if (rctx->play_path.len == 0 && p != last) {
                v.data = p;
                v.len = last - p;
                if (ngx_http_relay_copy_str(pool, &rctx->play_path, &v)
                        != NGX_OK)
                {
                    goto clear;
                }
            }
        }
    }

    rctx->tag = target->tag;
    rctx->idx = target->idx;
    rctx->session = rs;
    ngx_rtmp_set_ctx(rs, rctx, ngx_rtmp_relay_module);

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

    /* send http request */
    ngx_http_relay_send_request(rs, cs);

    return rctx;

clear:
    ngx_client_close(cs);

    return NULL;
}
