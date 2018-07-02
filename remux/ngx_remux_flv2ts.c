#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_rtmp_bitop.h"
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rbuf.h"
#include "../hls/ngx_rtmp_mpegts.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_remux_flv2ts.h"

#define NGX_REMUX_FRAME_SIZE 2048000
#define NGX_REMUX_BLOCK_SIZE 1024*1024
#define NGX_REMUX_MPEGTS_DELAY 63000

typedef struct ngx_remux_mpegts_s {
    ngx_remux_file_t                   *of;

    ngx_uint_t                  aac_profile;
    ngx_uint_t                  aac_chan_conf;
    ngx_uint_t                  aac_sbr;
    ngx_uint_t                  aac_ps;
    ngx_uint_t                  avc_profile;
    ngx_uint_t                  avc_compat;
    ngx_uint_t                  avc_level;
    ngx_uint_t                  avc_nal_bytes;
    ngx_uint_t                  avc_ref_frames;
    ngx_uint_t                  sample_rate;    /* 5512, 11025, 22050, 44100 */
    ngx_uint_t                  sample_size;    /* 1=8bit, 2=16bit */
    ngx_uint_t                  audio_channels; /* 1, 2 */

    size_t                      audio_buffer_size;
    ngx_msec_t                  max_audio_delay;
    ngx_msec_t                  sync;

    ngx_rtmp_frame_t           *aac_header;
    ngx_rtmp_frame_t           *avc_header;

    uint64_t                    frag;
    uint64_t                    frag_ts;

    ngx_uint_t                  audio_cc;
    ngx_uint_t                  video_cc;

    uint64_t                    aframe_base;
    uint64_t                    aframe_num;

    ngx_buf_t                  *aframe;
    uint64_t                    aframe_pts;

    ngx_log_t                  *log;
    ngx_pool_t                 *pool;
} ngx_remux_mpegts_t;

static u_char ngx_rtmp_mpegts_header[] = {

    /* TS */
    0x47, 0x40, 0x00, 0x10, 0x00,
    /* PSI */
    0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PAT */
    0x00, 0x01, 0xf0, 0x01,
    /* CRC */
    0x2e, 0x70, 0x19, 0x05,
    /* stuffing 167 bytes */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,

    /* TS */
    0x47, 0x50, 0x01, 0x10, 0x00,
    /* PSI */
    0x02, 0xb0, 0x17, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x00,
    0xf0, 0x00,
    0x1b, 0xe1, 0x00, 0xf0, 0x00, /* h264 */
    0x0f, 0xe1, 0x01, 0xf0, 0x00, /* aac */
    /*0x03, 0xe1, 0x01, 0xf0, 0x00,*/ /* mp3 */
    /* CRC */
    0x2f, 0x44, 0xb9, 0x9b, /* crc for aac */
    /*0x4e, 0x59, 0x3d, 0x1e,*/ /* crc for mp3 */
    /* stuffing 157 bytes */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};


/* 700 ms PCR delay */
#define NGX_RTMP_MEGPTS_DELAY  63000
#define NGX_REMUX_MPEGTS_AUDIO_BUFSIZE            (1024*1024)

static ngx_int_t
ngx_remux_flv2ts_copy(void *dst, u_char **src, size_t n, ngx_chain_t **in)
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
            return NGX_ERROR;
        }

        *src = (*in)->buf->pos;
    }
}


static ngx_int_t
ngx_remux_flv2ts_write_file(ngx_remux_file_t *file, u_char *in, size_t in_size)
{
    ngx_chain_t                           *cl;
    u_char                                *p, *e;
    ngx_buf_t                             *b;
    ngx_uint_t                             datalen;
/*
    static FILE                           *fd = NULL;
    static ngx_int_t                       idx = 0;
    static char                            filename[1024] = {0};

    ngx_snprintf(filename, sizeof(filename), "%d.ts", idx);
    fd = fopen(filename, "ab+");

    fwrite(in, 1, in_size, fd);
    fclose(fd);
*/
    p = in;
    e = in + in_size;

    while (p != e) {
        if (!file->tail || file->tail->buf->end == file->tail->buf->last) {
            cl = ngx_get_chainbuf(NGX_REMUX_BLOCK_SIZE, 1);
            if (cl == NULL) {
                return NGX_ERROR;
            }
            if (file->tail) {
                file->tail->next = cl;
            }
            file->tail = cl;

        } else {
            cl = file->tail;
        }

        b = cl->buf;
        datalen = e - p > b->end - b->last ? b->end - b->last : e - p;
        b->last = ngx_cpymem(b->last, p, datalen);
        p += datalen;
        file->content_length += datalen;

        if (file->content == NULL) {
            file->content = cl;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_write_header(ngx_remux_file_t *file)
{
    return ngx_remux_flv2ts_write_file(file, ngx_rtmp_mpegts_header,
                                      sizeof(ngx_rtmp_mpegts_header));
}


static u_char *
ngx_remux_flv2ts_write_pcr(u_char *p, uint64_t pcr)
{
    *p++ = (u_char) (pcr >> 25);
    *p++ = (u_char) (pcr >> 17);
    *p++ = (u_char) (pcr >> 9);
    *p++ = (u_char) (pcr >> 1);
    *p++ = (u_char) (pcr << 7 | 0x7e);
    *p++ = 0;

    return p;
}


static u_char *
ngx_remux_flv2ts_write_pts(u_char *p, ngx_uint_t fb, uint64_t pts)
{
    ngx_uint_t val;

    val = fb << 4 | (((pts >> 30) & 0x07) << 1) | 1;
    *p++ = (u_char) val;

    val = (((pts >> 15) & 0x7fff) << 1) | 1;
    *p++ = (u_char) (val >> 8);
    *p++ = (u_char) val;

    val = (((pts) & 0x7fff) << 1) | 1;
    *p++ = (u_char) (val >> 8);
    *p++ = (u_char) val;

    return p;
}


ngx_int_t
ngx_remux_flv2ts_write_frame(ngx_remux_file_t *file,
    ngx_rtmp_mpegts_frame_t *f, ngx_buf_t *b)
{
    ngx_uint_t  pes_size, header_size, body_size, in_size, stuff_size, flags;
    u_char      packet[188], *p, *base;
    ngx_int_t   first, rc = 0;

    first = 1;

    while (b->pos < b->last) {
        p = packet;

        f->cc++;

        *p++ = 0x47;
        *p++ = (u_char) (f->pid >> 8);

        if (first) {
            p[-1] |= 0x40;
        }

        *p++ = (u_char) f->pid;
        *p++ = 0x10 | (f->cc & 0x0f); /* payload */

        if (first) {

            if (f->key) {
                packet[3] |= 0x20; /* adaptation */

                *p++ = 7;    /* size */
                *p++ = 0x50; /* random access + PCR */

                p = ngx_remux_flv2ts_write_pcr(p, f->dts - NGX_REMUX_MPEGTS_DELAY);
            }

            /* PES header */

            *p++ = 0x00;
            *p++ = 0x00;
            *p++ = 0x01;
            *p++ = (u_char) f->sid;

            header_size = 5;
            flags = 0x80; /* PTS */

            if (f->dts != f->pts) {
                header_size += 5;
                flags |= 0x40; /* DTS */
            }

            pes_size = (b->last - b->pos) + header_size + 3;
            if (pes_size > 0xffff) {
                pes_size = 0;
            }

            *p++ = (u_char) (pes_size >> 8);
            *p++ = (u_char) pes_size;
            *p++ = 0x80; /* H222 */
            *p++ = (u_char) flags;
            *p++ = (u_char) header_size;

            p = ngx_remux_flv2ts_write_pts(p, flags >> 6, f->pts +
                                                         NGX_REMUX_MPEGTS_DELAY);

            if (f->dts != f->pts) {
                p = ngx_remux_flv2ts_write_pts(p, 1, f->dts +
                                                    NGX_REMUX_MPEGTS_DELAY);
            }

            first = 0;
        }

        body_size = (ngx_uint_t) (packet + sizeof(packet) - p);
        in_size = (ngx_uint_t) (b->last - b->pos);

        if (body_size <= in_size) {
            ngx_memcpy(p, b->pos, body_size);
            b->pos += body_size;

        } else {
            stuff_size = (body_size - in_size);

            if (packet[3] & 0x20) {

                /* has adaptation */

                base = &packet[5] + packet[4];
                p = ngx_movemem(base + stuff_size, base, p - base);
                ngx_memset(base, 0xff, stuff_size);
                packet[4] += (u_char) stuff_size;

            } else {

                /* no adaptation */

                packet[3] |= 0x20;
                p = ngx_movemem(&packet[4] + stuff_size, &packet[4],
                                p - &packet[4]);

                packet[4] = (u_char) (stuff_size - 1);
                if (stuff_size >= 2) {
                    packet[5] = 0;
                    ngx_memset(&packet[6], 0xff, stuff_size - 2);
                }
            }

            ngx_memcpy(p, b->pos, in_size);
            b->pos = b->last;
        }

        rc = ngx_remux_flv2ts_write_file(file, packet, sizeof(packet));
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_append_aud(ngx_buf_t *out)
{
    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0xf0 };

    if (out->last + sizeof(aud_nal) > out->end) {
        return NGX_ERROR;
    }

    out->last = ngx_cpymem(out->last, aud_nal, sizeof(aud_nal));

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_append_sps_pps(ngx_remux_mpegts_t *mpegts, ngx_buf_t *out)
{
    u_char                         *p;
    ngx_chain_t                    *in;
    int8_t                          nnals;
    uint16_t                        len, rlen;
    ngx_int_t                       n;

    in = mpegts->avc_header->chain;
    if (in == NULL) {
        return NGX_ERROR;
    }

    p = in->buf->pos;

    /*
     * Skip bytes:
     * - flv fmt
     * - H264 CONF/PICT (0x00)
     * - 0
     * - 0
     * - 0
     * - version
     * - profile
     * - compatibility
     * - level
     * - nal bytes
     */

    if (ngx_remux_flv2ts_copy(NULL, &p, 10, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* number of SPS NALs */
    if (ngx_remux_flv2ts_copy(&nnals, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    nnals &= 0x1f; /* 5lsb */

    /* SPS */
    for (n = 0; ; ++n) {
        for (; nnals; --nnals) {

            /* NAL length */
            if (ngx_remux_flv2ts_copy(&rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_rtmp_rmemcpy(&len, &rlen, 2);

            /* AnnexB prefix */
            if (out->end - out->last < 4) {
                ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                              "remux-flv2ts: append_sps_pps| "
                              "too small buffer for header NAL size");
                return NGX_ERROR;
            }

            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 1;

            /* NAL body */
            if (out->end - out->last < len) {
                ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                              "remux-flv2ts: append_sps_pps| "
                              "too small buffer for header NAL");
                return NGX_ERROR;
            }

            if (ngx_remux_flv2ts_copy(out->last, &p, len, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out->last += len;
        }

        if (n == 1) {
            break;
        }

        /* number of PPS NALs */
        if (ngx_remux_flv2ts_copy(&nnals, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_parse_aac_header(ngx_remux_mpegts_t *mpegts, ngx_uint_t *objtype,
    ngx_uint_t *srindex, ngx_uint_t *chconf)
{
    ngx_chain_t            *cl;
    u_char                 *p, b0, b1;

    cl = mpegts->aac_header->chain;

    p = cl->buf->pos;

    if (ngx_remux_flv2ts_copy(NULL, &p, 2, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_remux_flv2ts_copy(&b0, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_remux_flv2ts_copy(&b1, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    *objtype = b0 >> 3;
    if (*objtype == 0 || *objtype == 0x1f) {
        return NGX_ERROR;
    }

    if (*objtype > 4) {

        /*
         * Mark all extended profiles as LC
         * to make Android as happy as possible.
         */

        *objtype = 2;
    }

    *srindex = ((b0 << 1) & 0x0f) | ((b1 & 0x80) >> 7);
    if (*srindex == 0x0f) {
        return NGX_ERROR;
    }

    *chconf = (b1 >> 3) & 0x0f;

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_flush_audio(ngx_remux_mpegts_t *mpegts)
{
    ngx_rtmp_mpegts_frame_t         frame;
    ngx_int_t                       rc;
    ngx_buf_t                      *b;

    b = mpegts->aframe;

    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.dts = mpegts->aframe_pts;
    frame.pts = frame.dts;
    frame.cc = mpegts->audio_cc;
    frame.pid = 0x101;
    frame.sid = 0xc0;

    rc = ngx_remux_flv2ts_write_frame(mpegts->of, &frame, b);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                      "remux-flv2ts: flush_audio| audio flush failed");
    }

    mpegts->audio_cc = frame.cc;
    b->pos = b->last = b->start;

    return rc;
}


static ngx_int_t
ngx_remux_flv2ts_append_aac(ngx_remux_mpegts_t *mpegts, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    uint64_t                        pts, est_pts;
    int64_t                         dpts;
    size_t                          bsize;
    ngx_buf_t                      *b;
    u_char                         *p;
    ngx_uint_t                      objtype, srindex, chconf, size;

    if (h->mlen < 2) {
        return NGX_OK;
    }

    if (mpegts->aac_header == NULL) {
        return NGX_OK;
    }

    b = mpegts->aframe;

    if (b == NULL) {

        b = ngx_pcalloc(mpegts->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        mpegts->aframe = b;

        b->start = ngx_palloc(mpegts->pool, mpegts->audio_buffer_size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + mpegts->audio_buffer_size;
        b->pos = b->last = b->start;
    }

    size = h->mlen - 2 + 7;
    pts = (uint64_t) h->timestamp * 90;

    if (b->start + size > b->end) {
        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                      "hls: too big audio frame");
        return NGX_OK;
    }

    /*
     * start new fragment here if
     * there's no video at all, otherwise
     * do it in video handler
     */

    if ((b && b->last > b->pos &&
        mpegts->aframe_pts + (uint64_t) mpegts->max_audio_delay * 90 / 2 < pts) ||
        (b->last + size > b->end))
    {
        ngx_remux_flv2ts_flush_audio(mpegts);
    }

    if (b->last + 7 > b->end) {
        return NGX_OK;
    }

    p = b->last;
    b->last += 5;

    /* copy payload */

    for (; in && b->last < b->end; in = in->next) {

        bsize = in->buf->last - in->buf->pos;
        if (b->last + bsize > b->end) {
            bsize = b->end - b->last;
        }

        b->last = ngx_cpymem(b->last, in->buf->pos, bsize);
    }

    /* make up ADTS header */

    if (ngx_remux_flv2ts_parse_aac_header(mpegts, &objtype, &srindex, &chconf)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                      "remux-flv2ts: append_aac| aac header error");
        return NGX_OK;
    }

    /* we have 5 free bytes + 2 bytes of RTMP frame header */

    p[0] = 0xff;
    p[1] = 0xf1;
    p[2] = (u_char) (((objtype - 1) << 6) | (srindex << 2) |
                     ((chconf & 0x04) >> 2));
    p[3] = (u_char) (((chconf & 0x03) << 6) | ((size >> 11) & 0x03));
    p[4] = (u_char) (size >> 3);
    p[5] = (u_char) ((size << 5) | 0x1f);
    p[6] = 0xfc;

    if (p != b->start) {
        mpegts->aframe_num++;
        return NGX_OK;
    }

    mpegts->aframe_pts = pts;

    if (!mpegts->sync || mpegts->sample_rate == 0) {
        return NGX_OK;
    }

    /* align audio frames */

    /* TODO: We assume here AAC frame size is 1024
     *       Need to handle AAC frames with frame size of 960 */

    est_pts = mpegts->aframe_base + mpegts->aframe_num * 90000 * 1024 /
                                 mpegts->sample_rate;
    dpts = (int64_t) (est_pts - pts);

    if (dpts <= (int64_t) mpegts->sync * 90 &&
        dpts >= (int64_t) mpegts->sync * -90)
    {
        mpegts->aframe_num++;
        mpegts->aframe_pts = est_pts;
        return NGX_OK;
    }

    mpegts->aframe_base = pts;
    mpegts->aframe_num  = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_remux_flv2ts_append_h264(ngx_remux_mpegts_t *mpegts, ngx_rtmp_header_t *h,
    ngx_chain_t *in)
{
    u_char                         *p;
    uint8_t                         fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                        len, rlen;
    ngx_buf_t                       out;
    uint32_t                        cts;
    ngx_rtmp_mpegts_frame_t         frame;
    ngx_uint_t                      nal_bytes;
    ngx_int_t                       aud_sent, sps_pps_sent;
    ngx_buf_t                      *b;
    static u_char                   buffer[NGX_REMUX_FRAME_SIZE];

    if (mpegts->avc_header == NULL || h->mlen < 1) {
        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_remux_flv2ts_copy(&fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame */

    ftype = (fmt & 0xf0) >> 4;

    /* H264 HDR/PICT */

    if (ngx_remux_flv2ts_copy(&htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* proceed only with PICT */

    if (htype != 1) {
        return NGX_OK;
    }

    /* 3 bytes: decoder delay */

    if (ngx_remux_flv2ts_copy(&cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
          (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + sizeof(buffer);
    out.pos = out.start;
    out.last = out.pos;

    nal_bytes = 4;//mpegts->avc_nal_bytes;
    aud_sent = 0;
    sps_pps_sent = 0;

    while (in) {
        if (ngx_remux_flv2ts_copy(&rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_remux_flv2ts_copy(&src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = src_nal_type & 0x1f;

        if (nal_type >= 7 && nal_type <= 9) {
            if (ngx_remux_flv2ts_copy(NULL, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        if (!aud_sent) {
            switch (nal_type) {
                case 1:
                case 5:
                case 6:
                    if (ngx_remux_flv2ts_append_aud(&out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                          "remux-flv2ts: append_h264| error appending AUD NAL");
                    }
                case 9:
                    aud_sent = 1;
                    break;
            }
        }

        switch (nal_type) {
            case 1:
                sps_pps_sent = 0;
                break;
            case 5:
                if (sps_pps_sent) {
                    break;
                }
                if (ngx_remux_flv2ts_append_sps_pps(mpegts, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                     "remux-flv2ts: append_h264| error appenging SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
        }

        /* AnnexB prefix */

        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
               "remux-flv2ts: append_h264| not enough buffer for AnnexB prefix");
            return NGX_OK;
        }

        /* first AnnexB prefix is long (4 bytes) */

        if (out.last == out.pos) {
            *out.last++ = 0;
        }

        *out.last++ = 0;
        *out.last++ = 0;
        *out.last++ = 1;
        *out.last++ = src_nal_type;

        /* NAL body */

        if (out.end - out.last < (ngx_int_t) len) {
            ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                        "remux-flv2ts: append_h264| not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_remux_flv2ts_copy(out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    ngx_memzero(&frame, sizeof(frame));

    frame.cc = mpegts->video_cc;
    frame.dts = (uint64_t) h->timestamp * 90;
    frame.pts = frame.dts + cts * 90;
    frame.pid = 0x100;
    frame.sid = 0xe0;
    frame.key = (ftype == 1);

    b = mpegts->aframe;
    if (b && b->last > b->pos &&
        mpegts->aframe_pts + (uint64_t) mpegts->max_audio_delay * 90 < frame.pts)
    {
        ngx_remux_flv2ts_flush_audio(mpegts);
    }

    if (ngx_remux_flv2ts_write_frame(mpegts->of, &frame, &out) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                      "remux-flv2ts: append_video| video frame failed");
    }

    mpegts->video_cc = frame.cc;

    return NGX_OK;
}


static void
ngx_remux_flv2ts_init_aac_header(ngx_remux_mpegts_t *mpegts, ngx_chain_t *in)
{
    ngx_uint_t              idx;
    ngx_rtmp_bit_reader_t   br;

    static ngx_uint_t      aac_sample_rates[] =
        { 96000, 88200, 64000, 48000,
          44100, 32000, 24000, 22050,
          16000, 12000, 11025,  8000,
           7350,     0,     0,     0 };

    ngx_rtmp_bit_init_reader(&br, in->buf->pos, in->buf->last);

    ngx_rtmp_bit_read(&br, 16);

    mpegts->max_audio_delay = 300;
    mpegts->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
    if (mpegts->aac_profile == 31) {
        mpegts->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
    }

    idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
    if (idx == 15) {
        mpegts->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);
    } else {
        mpegts->sample_rate = aac_sample_rates[idx];
    }

    mpegts->aac_chan_conf = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);

    if (mpegts->aac_profile == 5 || mpegts->aac_profile == 29) {

        if (mpegts->aac_profile == 29) {
            mpegts->aac_ps = 1;
        }

        mpegts->aac_sbr = 1;

        idx = (ngx_uint_t) ngx_rtmp_bit_read(&br, 4);
        if (idx == 15) {
            mpegts->sample_rate = (ngx_uint_t) ngx_rtmp_bit_read(&br, 24);
        } else {
            mpegts->sample_rate = aac_sample_rates[idx];
        }

        mpegts->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 5);
        if (mpegts->aac_profile == 31) {
            mpegts->aac_profile = (ngx_uint_t) ngx_rtmp_bit_read(&br, 6) + 32;
        }
    }
    mpegts->aac_header = ngx_rtmp_shared_alloc_frame(1024, in, 0);
}


static void
ngx_remux_flv2ts_init_avc_header(ngx_remux_mpegts_t *mpegts, ngx_chain_t *in)
{
    mpegts->avc_header = ngx_rtmp_shared_alloc_frame(1024, in, 0);
}


ngx_int_t
ngx_remux_flv2ts(ngx_fd_t fd, off_t pos, off_t last, ngx_remux_file_t *of)
{
    ngx_file_t                       file;
    ssize_t                          ret;
    off_t                            offset;
    ngx_rtmp_header_t                hdr;
    ngx_remux_mpegts_t              *mpegts;
    ngx_pool_t                      *pool;

    static ngx_chain_t               cl;
    static ngx_buf_t                 buf;
    static u_char                    buffer[NGX_REMUX_FRAME_SIZE];
    static u_char                    tagheader_buffer[11];

    ngx_memzero(buffer, sizeof(buffer));
    ngx_memzero(tagheader_buffer, sizeof(tagheader_buffer));

    file.fd = fd;
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    pool = ngx_create_pool(1024, ngx_cycle->log);
    mpegts = ngx_pcalloc(pool, sizeof(ngx_remux_mpegts_t));
    mpegts->pool = pool;
    mpegts->sync = 2;
    mpegts->audio_buffer_size = 1024*1024;
    mpegts->of = of;
    of->remuxer = mpegts;
    mpegts->log = ngx_cycle->log;
    file.log = ngx_cycle->log;
    of->log = ngx_cycle->log;

    ngx_remux_flv2ts_write_header(of);

    offset = 13;
    while (offset < last) {
        if (mpegts->aac_header && mpegts->avc_header && pos) {
            offset = pos;
            pos = 0;
        }
        ret = ngx_read_file(&file, tagheader_buffer,
                             sizeof(tagheader_buffer), offset);
        if (ret <= 0) {
            break;
        }
        offset += sizeof(tagheader_buffer);
        ngx_memzero(&hdr, sizeof(hdr));
        hdr.type = tagheader_buffer[0];
        hdr.mlen = tagheader_buffer[1] << 16 |
                   tagheader_buffer[2] << 8 |
                   tagheader_buffer[3];
        hdr.timestamp = tagheader_buffer[7] << 24 |
                        tagheader_buffer[4] << 16 |
                        tagheader_buffer[5] << 8  |
                        tagheader_buffer[6];
        hdr.msid = tagheader_buffer[8] << 16 |
                   tagheader_buffer[9] << 8 |
                   tagheader_buffer[10];

		/*
        ngx_log_error(NGX_LOG_ERR, mpegts->log, 0,
                        "remux-flv2ts: flv2ts| type %d  time %d  mlen %d",
                        hdr.type, hdr.timestamp, hdr.mlen);
		*/

        ret = ngx_read_file(&file, buffer, hdr.mlen, offset);
        if (ret < 0) {
            break;
        }
        offset += hdr.mlen + 4;

        buf.pos = buf.start = &buffer[0];
        buf.last = buffer + ret;
        buf.end = &buffer[sizeof(buffer) - 1];
        cl.buf = &buf;
        cl.next = NULL;

        if (hdr.type == NGX_RTMP_MSG_AUDIO) {
            if (mpegts->aac_header == NULL) {
                if (!ngx_rtmp_is_codec_header(&cl)) {
                    continue;
                }
                ngx_remux_flv2ts_init_aac_header(mpegts, &cl);
                continue;
            }
            if (ngx_rtmp_is_codec_header(&cl)) {
                continue;
            }

            ngx_remux_flv2ts_append_aac(mpegts, &hdr, &cl);
        } else if (hdr.type == NGX_RTMP_MSG_VIDEO) {
            if (mpegts->avc_header == NULL) {
                if (!ngx_rtmp_is_codec_header(&cl)) {
                    continue;
                }
                ngx_remux_flv2ts_init_avc_header(mpegts, &cl);
                continue;
            }
            if (ngx_rtmp_is_codec_header(&cl)) {
                continue;
            }
            ngx_remux_flv2ts_append_h264(mpegts, &hdr, &cl);
        } else {
            continue;
        }
    }

    return NGX_OK;
}


void
ngx_remux_flv2ts_destory(ngx_remux_file_t *file)
{
    ngx_remux_mpegts_t            *mpegts;
    ngx_chain_t                   *ll, *l;

    l = file->content;
    while (l) {
        ll = l->next;
        ngx_put_chainbuf(l);
        l = ll;
    }

    mpegts = file->remuxer;
    ngx_rtmp_shared_free_frame(mpegts->aac_header);
    ngx_rtmp_shared_free_frame(mpegts->avc_header);
    ngx_destroy_pool(mpegts->pool);
}

