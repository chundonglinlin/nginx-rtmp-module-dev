#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rbuf.h"
#include "ngx_rtmp_mpegts_module.h"
#include "ngx_rtmp_codec_module.h"

static ngx_rtmp_close_stream_pt next_close_stream;

static u_char ngx_rtmp_mpegts_hevc_aac_header[] = {

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
    0x24, 0xe1, 0x00, 0xf0, 0x00, /* h265 */
    0x0f, 0xe1, 0x01, 0xf0, 0x00, /* aac */
    /*0x03, 0xe1, 0x01, 0xf0, 0x00,*/ /* mp3 */
    /* CRC */
    0xc7, 0x72, 0xb7, 0xcb, /* crc for aac */
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


static u_char ngx_rtmp_mpegts_hevc_header[] = {

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
    0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x00,
    0xf0, 0x00,
    0x24, 0xe1, 0x00, 0xf0, 0x00, /* h265 */

    /* CRC */
    0x2f, 0x00, 0x6e, 0xe7, /* crc for h265 */

    /* stuffing 162 bytes */
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
    0xff, 0xff
};


static u_char ngx_rtmp_mpegts_hevc_mp3_header[] = {

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
    0x24, 0xe1, 0x00, 0xf0, 0x00, /* h265 */
    0x03, 0xe1, 0x01, 0xf0, 0x00, /* mp3 */
    /* CRC */
    0xa6, 0x6f, 0x33, 0x4e, /* crc for mp3 */
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


static u_char ngx_rtmp_mpegts_h264_header[] = {

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
    0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x00,
    0xf0, 0x00,
    0x1b, 0xe1, 0x00, 0xf0, 0x00, /* h264 */

    /* CRC */
    0x15, 0xBD, 0x4D, 0x56, /* crc for h264 */

    /* stuffing 162 bytes */
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
    0xff, 0xff
};

static u_char ngx_rtmp_mpegts_h264_mp3_header[] = {

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
    0x03, 0xe1, 0x01, 0xf0, 0x00, /* mp3 */
    /* CRC */
    0x4e, 0x59, 0x3d, 0x1e, /* crc for mp3 */
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


static u_char ngx_rtmp_mpegts_mp3_header[] = {

    /* TS */
    0x47, 0x40, 0x00, 0x10, 0x00,
    /* PSI */
    0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PAT */
    0x00, 0x01, 0xef, 0xff,
    /* CRC */
    0x36, 0x90, 0xe2, 0x3d,
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
    0x47, 0x4f, 0xff, 0x10, 0x00,
    /* PSI */
    0x02, 0xb0, 0x37, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x01,
    0xf0, 0x11,

    0x25, 0x0f, 0xff, 0xff, 0x49, 0x44, 0x33, 0x20, 0xff, 0x49,
    0x44, 0x33, 0x20, 0x00, 0x1f, 0x00, 0x01, 0x15, 0xe1, 0x02,
    0xf0, 0x0f, 0x26, 0x0d, 0xff, 0xff, 0x49, 0x44, 0x33, 0x20,
    0xff, 0x49, 0x44, 0x33, 0x20, 0x00, 0x0f,

    0x03, 0xe1, 0x01, 0xf0, 0x00, /* mp3 */
    /* CRC */
    0x64, 0xD5, 0xDC, 0xB6, /* crc for mp3 */

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
    0xff, 0xff, 0xff, 0xff, 0xff

};


static u_char ngx_rtmp_mpegts_aac_header[] = {

    /* TS */
    0x47, 0x40, 0x00, 0x10, 0x00,
    /* PSI */
    0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PAT */
    0x00, 0x01, 0xef, 0xff,
    /* CRC */
    0x36, 0x90, 0xe2, 0x3d,
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
    0x47, 0x4f, 0xff, 0x10, 0x00,
    /* PSI */
    0x02, 0xb0, 0x37, 0x00, 0x01, 0xc1, 0x00, 0x00,
    /* PMT */
    0xe1, 0x01,
    0xf0, 0x11,

    0x25, 0x0f, 0xff, 0xff, 0x49, 0x44, 0x33, 0x20, 0xff, 0x49,
    0x44, 0x33, 0x20, 0x00, 0x1f, 0x00, 0x01, 0x15, 0xe1, 0x02,
    0xf0, 0x0f, 0x26, 0x0d, 0xff, 0xff, 0x49, 0x44, 0x33, 0x20,
    0xff, 0x49, 0x44, 0x33, 0x20, 0x00, 0x0f,

    //0x1b, 0xe1, 0x00, 0xf0, 0x00, /* h264 */
    0x0f, 0xe1, 0x01, 0xf0, 0x00, /* aac */
    /*0x03, 0xe1, 0x01, 0xf0, 0x00,*/ /* mp3 */
    /* CRC */
    0x05, 0xc8, 0x58, 0x33, /* crc for aac */
    //0xd3, 0xc6, 0xc6, 0xf7, /* crc for aac */
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
    0xff, 0xff, 0xff, 0xff, 0xff

};


/* 700 ms PCR delay */
#define NGX_RTMP_MEGPTS_DELAY  63000

static void *
ngx_rtmp_mpegts_create_app_conf(ngx_conf_t *cf);
static char *
ngx_rtmp_mpegts_merge_app_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_rtmp_mpegts_postconfiguration(ngx_conf_t *cf);

static ngx_command_t ngx_rtmp_mpegts_commands[] = {
    { ngx_string("mpegts_cache_time"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_mpegts_app_conf_t, cache_time),
      NULL },
    { ngx_string("mpegts_audio_buffer_size"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_mpegts_app_conf_t, audio_buffer_size),
      NULL },
    { ngx_string("mpegts_sync"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_mpegts_app_conf_t, sync),
      NULL },
    { ngx_string("mpegts_audio_delay"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_mpegts_app_conf_t, audio_delay),
      NULL },
    { ngx_string("mpegts_out_queue"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_mpegts_app_conf_t, out_queue),
      NULL },

    ngx_null_command
};


static ngx_rtmp_module_t ngx_rtmp_mpegts_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_mpegts_postconfiguration,      /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_mpegts_create_app_conf,        /* create app configuration */
    ngx_rtmp_mpegts_merge_app_conf          /* merge app configuration */
};


ngx_module_t ngx_rtmp_mpegts_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_mpegts_ctx,                   /* module context */
    ngx_rtmp_mpegts_commands,               /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_mpegts_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_mpegts_app_conf_t   *macf;

    macf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_mpegts_app_conf_t));
    if (!macf) {
        return NULL;
    }

    macf->free_session = NULL;
    macf->cache_time = NGX_CONF_UNSET_MSEC;
    macf->audio_buffer_size = NGX_CONF_UNSET;
    macf->sync = NGX_CONF_UNSET_MSEC;
    macf->audio_delay = NGX_CONF_UNSET_MSEC;
    macf->out_queue = NGX_CONF_UNSET;

    return macf;
}


static char *
ngx_rtmp_mpegts_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_mpegts_app_conf_t *prev = parent;
    ngx_rtmp_mpegts_app_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->cache_time, prev->cache_time, 30000);
    ngx_conf_merge_size_value(conf->audio_buffer_size, prev->audio_buffer_size,
                              NGX_RTMP_MPEG_BUFSIZE);
    ngx_conf_merge_msec_value(conf->sync, prev->sync, 2);
    ngx_conf_merge_msec_value(conf->audio_delay, prev->audio_delay, 300);
    ngx_conf_merge_size_value(conf->out_queue, prev->out_queue, 4096);
    conf->pool = ngx_create_pool(4096, &cf->cycle->new_log);
    if (!conf->pool) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void
ngx_rtmp_mpegts_reset_gop(ngx_rtmp_session_t *s,
                          ngx_rtmp_mpegts_ctx_t *ctx,
                          ngx_mpegts_frame_t *frame)
{
    ngx_mpegts_frame_t         *f, *next_keyframe;
    size_t                      pos;
    ngx_uint_t                  nmsg;

    /* reset av_header at the front of cache */
    pos = ctx->cache_pos;
    f = ctx->cache[pos];
    if (f == NULL) {
        return;
    }

    /* only audio in cache */
    if (ctx->keyframe == NULL) {
        if (frame->pts - ctx->cache[ctx->cache_pos]->pts
                > 90 * ctx->cache_time)
        {
            ngx_rtmp_shared_free_mpegts_frame(f);
            ctx->cache[ctx->cache_pos] = NULL;
            ctx->cache_pos = ngx_rtmp_mpegts_next(ctx, ctx->cache_pos);
        }

        return;
    }

    /* only video of video + audio */
    next_keyframe = ctx->keyframe->key_next;

    /* only one gop in cache */
    if (next_keyframe == NULL) {
        return;
    }

    if (ctx->cache_last >= ctx->cache_pos) {
        nmsg = ctx->cache_last - ctx->cache_pos;
    } else {
        nmsg = ctx->out_queue - (ctx->cache_pos - ctx->cache_last);
    }

    nmsg += 1;

    if (nmsg >= ctx->out_queue) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
            "rtmp-mpegts: reset_gop| nmsg(%z) >= out_queue(%z)",
            nmsg, ctx->out_queue);
        goto reset;
    }

    if (frame->type == NGX_RTMP_MPEGTS_TYPE_AUDIO) {
        return;
    }

    if (frame->type == NGX_RTMP_MPEGTS_TYPE_VIDEO &&
          (frame->pts - next_keyframe->pts) < 90 * ctx->cache_time)
    {
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
            "rtmp-mpegts: reset_gop| "
            "frame-pts(%z) - next_key-pts(%z) >= ctx->cache_time(%z)",
            frame->pts, next_keyframe->pts, ctx->cache_time);

reset:
    for (pos = ctx->cache_pos; ctx->cache[pos] != next_keyframe;
            pos = ngx_rtmp_mpegts_next(ctx, pos))
    {
        f = ctx->cache[pos];
        ngx_rtmp_shared_free_mpegts_frame(f);
        ctx->cache[pos] = NULL;
    }

    ctx->keyframe = next_keyframe;
    ctx->cache_pos = pos;
}


static void
ngx_rtmp_mpegts_print_cache(ngx_rtmp_session_t *s,
                             ngx_rtmp_mpegts_ctx_t *ctx)
{
#if (NGX_DEBUG)
    ngx_mpegts_frame_t         *frame;
    u_char                      content[10240] = {0}, *p;
    size_t                      pos;

    p = content;
    for (pos = ctx->cache_pos; pos != ctx->cache_last;
            pos = ngx_rtmp_mpegts_next(ctx, pos))
    {
        frame = ctx->cache[pos];
        switch (frame->type) {
        case NGX_RTMP_MPEGTS_TYPE_AUDIO:
            *p++ = 'A';
            break;
        case NGX_RTMP_MPEGTS_TYPE_VIDEO:
            *p++ = 'V';
            break;
        default:
            *p++ = 'O';
            break;
        }

        if (frame->key) {
            *p++ = 'I';
        }

        *p++ = ' ';
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
            "[%z %z] %s",
            ctx->cache_pos, ctx->cache_last, content);
#endif
}


static void
ngx_rtmp_mpegts_save_static_cache(ngx_mpegts_frame_t *frame)
{
    static FILE                   *fd = NULL;
    u_char                        *p;
    ngx_chain_t                   *cl;
    ngx_int_t                      rc;

    return;

    if (fd == NULL) {
        fd = fopen("cache.ts", "wb");
        if (fd) {
            fwrite(&ngx_rtmp_mpegts_header, sizeof(ngx_rtmp_mpegts_header), 1, fd);
        }
    }

    for(cl = frame->chain; cl; cl = cl->next) {
        p = cl->buf->pos;
        while (cl->buf->last > p) {
            rc = fwrite(p, 1, cl->buf->last- p, fd);
            if (rc <= 0) {
                printf("static_cache| fwrite = %d\r\n", (int)rc);
                return;
            }
            p += rc;
        }
    }
}


static ngx_int_t
ngx_rtmp_mpegts_gop_cache(ngx_rtmp_session_t *s,
                          ngx_mpegts_frame_t *frame)
{
    ngx_rtmp_mpegts_ctx_t         *ctx;
    ngx_mpegts_frame_t           **keyframe, *prev_frame;
    ngx_uint_t                     nmsg;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    if (ctx->cache_last >= ctx->cache_pos) {
        nmsg = ctx->cache_last - ctx->cache_pos;
    } else {
        nmsg = ctx->out_queue - (ctx->cache_pos - ctx->cache_last);
    }

    nmsg += 1;

    if (nmsg >= ctx->out_queue) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: gop_cache| "
                "cache frame nmsg(%ui) >= out_queue(%z)",
                nmsg, ctx->out_queue);
        return NGX_AGAIN;
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
            "rtmp-mpegts: gop_cache| "
            "cache frame: %ud[%d], %ud, %ud",
            frame->type, frame->key,
            frame->pts/90, frame->length);

    /* first video frame is not intra_frame or video header */
    if (ctx->keyframe == NULL && frame->type == NGX_RTMP_MPEGTS_TYPE_VIDEO
            && !frame->key)
    {
        return NGX_OK;
    }

    /* video intra_frame */
    if (frame->key) {
        for (keyframe = &ctx->keyframe; *keyframe;
                keyframe = &((*keyframe)->key_next));
        *keyframe = frame;
    }

    ctx->cache[ctx->cache_last] = frame;
    frame->pos = ctx->cache_last;
    prev_frame = ctx->cache[ngx_rtmp_mpegts_prev(ctx, ctx->cache_last)];
    if (prev_frame && prev_frame != frame) {
        prev_frame->next = frame;
    }

    if (frame->type == NGX_RTMP_MPEGTS_TYPE_AUDIO) {
        ctx->last_audio = frame;
    }

    if (frame->type == NGX_RTMP_MPEGTS_TYPE_VIDEO) {
        ctx->last_video = frame;
    }

    ctx->cache_last = ngx_rtmp_mpegts_next(ctx, ctx->cache_last);

    ngx_rtmp_shared_acquire_frame(frame);

    ngx_rtmp_mpegts_reset_gop(s, ctx, frame);

    ngx_rtmp_mpegts_print_cache(s, ctx);

    ngx_rtmp_mpegts_save_static_cache(frame);

    ngx_rtmp_fire_event(s, NGX_RTMP_MPEGTS_AV, NULL, NULL);

    return NGX_OK;
}


static u_char *
ngx_rtmp_mpegts_write_pcr(u_char *p, uint64_t pcr)
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
ngx_rtmp_mpegts_write_pts(u_char *p, ngx_uint_t fb, uint64_t pts)
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


static void
ngx_rtmp_mpegts_save_static_packet(u_char *c)
{
    static FILE       *fd = NULL;

    return;

    if (fd == NULL) {
        fd = fopen("packet.ts", "wb");
        if (fd) {
            fwrite(&ngx_rtmp_mpegts_header, sizeof(ngx_rtmp_mpegts_header), 1, fd);
        }
    }

    if (fd) {
        fwrite(c, 188, 1, fd);
    }
}


ngx_int_t
ngx_rtmp_mpegts_shared_append_chain(ngx_mpegts_frame_t *f, ngx_buf_t *b,
                                    ngx_flag_t mandatory)
{
    ngx_uint_t   pes_size, header_size, body_size, in_size, stuff_size, flags;
    u_char      *packet, *p, *base;
    ngx_int_t    first;
    ngx_chain_t *cl, **ll;
    uint64_t     pcr;

    for (ll = &f->chain; (*ll) && (*ll)->next; ll = &(*ll)->next);
    cl = *ll;

    if ((b == NULL || b->pos == b->last) && mandatory) {
        *ll = ngx_get_chainbuf(NGX_MPEGTS_BUF_SIZE, 1);
        return NGX_OK;
    }

    first = 1;

    while (b->pos < b->last) {
        if ((*ll) && (*ll)->buf->end - (*ll)->buf->last < 188) {
            ll = &(*ll)->next;
            cl = *ll;
        }

        if (*ll == NULL) {
            *ll = ngx_get_chainbuf(NGX_MPEGTS_BUF_SIZE, 1);
            cl = *ll;
        }

        packet = cl->buf->last;
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
                if (f->dts < NGX_RTMP_MEGPTS_DELAY) {
                    pcr = 0;
                } else {
                    pcr = f->dts;
                }
                p = ngx_rtmp_mpegts_write_pcr(p, pcr);
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

            p = ngx_rtmp_mpegts_write_pts(p, flags >> 6, f->pts +
                                                         NGX_RTMP_MEGPTS_DELAY);

            if (f->dts != f->pts) {
                p = ngx_rtmp_mpegts_write_pts(p, 1, f->dts +
                                                    NGX_RTMP_MEGPTS_DELAY);
            }

            first = 0;
        }

        body_size = (ngx_uint_t) (packet + 188 - p);
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

        cl->buf->last += 188;
        f->length += 188;
        ngx_rtmp_mpegts_save_static_packet(packet);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_copy(ngx_rtmp_session_t *s, void *dst, u_char **src, size_t n,
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
                          "rtmp-mpegts: mpegts_copy| failed to read %uz byte(s)", n);
            return NGX_ERROR;
        }

        *src = (*in)->buf->pos;
    }
}


static ngx_int_t
ngx_rtmp_mpegts_append_aud(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    static u_char   aud_nal[] = { 0x00, 0x00, 0x00, 0x01, 0x09, 0xf0 };

    if (out->last + sizeof(aud_nal) > out->end) {
        return NGX_ERROR;
    }

    out->last = ngx_cpymem(out->last, aud_nal, sizeof(aud_nal));

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_append_sps_pps(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    u_char                         *p;
    ngx_chain_t                    *in;
    ngx_rtmp_mpegts_ctx_t          *ctx;
    int8_t                          nnals;
    uint16_t                        len, rlen;
    ngx_int_t                       n;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    if (ctx == NULL || ctx->avc_codec == NULL) {
        return NGX_ERROR;
    }

    in = ctx->avc_codec->avc_header->chain;
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

    if (ngx_rtmp_mpegts_copy(s, NULL, &p, 10, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* number of SPS NALs */
    if (ngx_rtmp_mpegts_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    nnals &= 0x1f; /* 5lsb */

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: append_sps_pps| SPS number: %uz", nnals);

    /* SPS */
    for (n = 0; ; ++n) {
        for (; nnals; --nnals) {

            /* NAL length */
            if (ngx_rtmp_mpegts_copy(s, &rlen, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_rtmp_rmemcpy(&len, &rlen, 2);

            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                           "rtmp-mpegts: append_sps_pps| header NAL length: %uz", (size_t) len);

            /* AnnexB prefix */
            if (out->end - out->last < 4) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "rtmp-mpegts: append_sps_pps| too small buffer for header NAL size");
                return NGX_ERROR;
            }

            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 1;

            /* NAL body */
            if (out->end - out->last < len) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "rtmp-mpegts: append_sps_pps| too small buffer for header NAL");
                return NGX_ERROR;
            }

            if (ngx_rtmp_mpegts_copy(s, out->last, &p, len, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out->last += len;
        }

        if (n == 1) {
            break;
        }

        /* number of PPS NALs */
        if (ngx_rtmp_mpegts_copy(s, &nnals, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: append_sps_pps| PPS number: %uz", nnals);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_init_aac_codec(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mpegts_ctx_t          *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s->live_stream->publish_ctx->session, ngx_rtmp_codec_module);

    if (ctx->aac_codec) {
        return NGX_OK;
    }

    if (codec_ctx == NULL || codec_ctx->aac_header == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                   "rtmp-mpegts: aac_codec| codec ctx %p, aac_header is null", codec_ctx);
        return NGX_AGAIN;
    }

    ctx->aac_codec = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_mpegts_aac_codec_t));
    if (ctx->aac_codec == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: aac_codec| alloc mpegts aac_codec failed");
        return NGX_ERROR;
    }

    ctx->aac_codec->aac_header = ngx_rtmp_shared_alloc_frame(s->in_chunk_size,
                                    codec_ctx->aac_header->chain, 0);

    ctx->aac_codec->sample_rate = codec_ctx->sample_rate;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_init_avc_codec(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mpegts_ctx_t          *ctx;
    ngx_rtmp_codec_ctx_t           *codec_ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    codec_ctx = ngx_rtmp_get_module_ctx(s->live_stream->publish_ctx->session, ngx_rtmp_codec_module);

    if (ctx->avc_codec) {
        return NGX_OK;
    }

    if (codec_ctx == NULL || codec_ctx->avc_header == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                   "rtmp-mpegts: avc_codec| codec ctx %p, avc_header is null", codec_ctx);
        return NGX_AGAIN;
    }

    ctx->avc_codec = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_mpegts_avc_codec_t));
    if (ctx->avc_codec == NULL) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: avc_codec| alloc mpegts avc_codec failed");
        return NGX_ERROR;
    }

    ctx->avc_codec->video_codec_id = codec_ctx->video_codec_id;
    ctx->avc_codec->avc_nal_bytes = codec_ctx->avc_nal_bytes;
    ctx->avc_codec->avc_header = ngx_rtmp_shared_alloc_frame(s->in_chunk_size,
                                 codec_ctx->avc_header->chain, 0);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_flush_audio(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mpegts_ctx_t          *ctx;
    ngx_mpegts_frame_t             *frame;
    ngx_int_t                       rc;
    ngx_buf_t                      *b;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL || b->pos == b->last) {
        return NGX_OK;
    }

    frame = ngx_rtmp_shared_alloc_mpegts_frame();

    frame->dts = ctx->aframe_pts;
    frame->pts = frame->dts;
    frame->cc = ctx->audio_cc;
    frame->pid = 0x101;
    frame->sid = 0xc0;
    frame->type = NGX_RTMP_MPEGTS_TYPE_AUDIO;

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: flush_audio| pts=%uL", frame->pts);

    rc = ngx_rtmp_mpegts_shared_append_chain(frame, b, 1);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: flush_audio| flush failed");
    } else {
        ngx_rtmp_mpegts_gop_cache(s, frame);
    }

    ngx_rtmp_shared_free_mpegts_frame(frame);

    ctx->audio_cc = frame->cc;
    b->pos = b->last = b->start;

    return rc;
}


static ngx_int_t
ngx_rtmp_mpegts_append_hevc_vps_sps_pps(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    ngx_rtmp_mpegts_ctx_t          *ctx;
    u_char                         *p;
    ngx_chain_t                    *in;
    ngx_uint_t                      rnal_unit_len, nal_unit_len, i, j,
                                    num_arrays, nal_unit_type, rnum_nalus,
                                    num_nalus;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    if (ctx == NULL || ctx->avc_codec == NULL) {
        return NGX_ERROR;
    }

    in = ctx->avc_codec->avc_header->chain;
    if (in == NULL) {
        return NGX_ERROR;
    }

    p = in->buf->pos;
    /*  6 bytes
     * FrameType                                    4 bits
     * CodecID                                      4 bits
     * AVCPacketType                                1 byte
     * CompositionTime                              3 bytes
     * HEVCDecoderConfigurationRecord
     *      configurationVersion                    1 byte
     */

    /*  20 bytes
     * HEVCDecoderConfigurationRecord
     *      general_profile_space                   2 bits
     *      general_tier_flag                       1 bit
     *      general_profile_idc                     5 bits
     *      general_profile_compatibility_flags     4 bytes
     *      general_constraint_indicator_flags      6 bytes
     *      general_level_idc                       1 byte
     *      min_spatial_segmentation_idc            4 bits reserved + 12 bits
     *      parallelismType                         6 bits reserved + 2 bits
     *      chroma_format_idc                       6 bits reserved + 2 bits
     *      bit_depth_luma_minus8                   5 bits reserved + 3 bits
     *      bit_depth_chroma_minus8                 5 bits reserved + 3 bits
     *      avgFrameRate                            2 bytes
     */

    /* 1 bytes
     * HEVCDecoderConfigurationRecord
     *      constantFrameRate                       2 bits
     *      numTemporalLayers                       3 bits
     *      temporalIdNested                        1 bit
     *      lengthSizeMinusOne                      2 bits
     */

    if (ngx_rtmp_mpegts_copy(s, NULL, &p, 27, &in) != NGX_OK) {
        return NGX_ERROR;
    }

     /* 1 byte
     * HEVCDecoderConfigurationRecord
     *      numOfArrays                             1 byte
     */
    num_arrays = 0;
    if (ngx_rtmp_mpegts_copy(s, &num_arrays, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    for (i = 0; i < num_arrays; ++i) {
        /*
         * array_completeness                       1 bit
         * reserved                                 1 bit
         * NAL_unit_type                            6 bits
         * numNalus                                 2 bytes
         */
        if (ngx_rtmp_mpegts_copy(s, &nal_unit_type, &p, 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }
        nal_unit_type &= 0x3f;

        if (ngx_rtmp_mpegts_copy(s, &rnum_nalus, &p, 2, &in) != NGX_OK) {
            return NGX_ERROR;
        }
        num_nalus = 0;
        ngx_rtmp_rmemcpy(&num_nalus, &rnum_nalus, 2);

        for (j = 0; j < num_nalus; ++j) {
            /*
             * nalUnitLength                        2 bytes
             */
            if (ngx_rtmp_mpegts_copy(s, &rnal_unit_len, &p, 2, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            nal_unit_len = 0;
            ngx_rtmp_rmemcpy(&nal_unit_len, &rnal_unit_len, 2);
            if (out->end - out->last < 4) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "hls: too small buffer for header NAL size");
                return NGX_ERROR;
            }

            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 0;
            *out->last++ = 1;

            if (out->end - out->last < (ngx_int_t)nal_unit_len) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "hls: too small buffer for header NAL");
                return NGX_ERROR;
            }

            if (ngx_rtmp_mpegts_copy(s, out->last, &p, nal_unit_len, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out->last += nal_unit_len;
        }
    }
    return NGX_OK;
}


/* set h265 aud first, now is null*/
static ngx_int_t
ngx_rtmp_mpegts_append_hevc_aud(ngx_rtmp_session_t *s, ngx_buf_t *out)
{
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_h265_handler(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *f)
{
    ngx_rtmp_mpegts_ctx_t          *ctx;
    ngx_rtmp_mpegts_app_conf_t     *macf;
    u_char                         *p;
    uint8_t                         fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                        len, rlen;
    ngx_buf_t                       out;
    uint32_t                        cts;
    ngx_mpegts_frame_t             *frame;
    ngx_uint_t                      nal_bytes;
    ngx_int_t                       aud_sent, sps_pps_sent;
    u_char                         *buffer;
    ngx_rtmp_header_t              *h;
    ngx_chain_t                    *in;
    ngx_int_t                       rc;

    h = &f->hdr;
    in = f->chain;

    macf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_mpegts_module);
    buffer = macf->packet_buffer;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    if (ctx == NULL || h->mlen < 1) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h265_handler| "
                       "resource error, mpegts_ctx=%p, h->mlen=%d",
                       ctx, h->mlen);
        return NGX_OK;
    }

    if (ctx->avc_codec == NULL) {
        rc = ngx_rtmp_mpegts_init_avc_codec(s);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h265_handler| init avc_codec failed");
            return NGX_OK;
        } else if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
    }

    /* H265 is supported */
    if (ctx->avc_codec->video_codec_id != NGX_RTMP_VIDEO_H265)
    {
        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_rtmp_mpegts_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame */

    ftype = (fmt & 0xf0) >> 4;    // 0x17/0x27/...

    /* H264 HDR/PICT */

    if (ngx_rtmp_mpegts_copy(s, &htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* proceed only with PICT */

    if (htype != 1) { /*0:AVC sequence header,1:AVC NALU 2:AVC end of sequence*/
        return NGX_OK;
    }

    /* 3 bytes: decoder delay */

    if (ngx_rtmp_mpegts_copy(s, &cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }
    /* convert big end to little end */
    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
          (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + NGX_RTMP_MPEG_BUFSIZE;
    out.pos = out.start;
    out.last = out.pos;

    nal_bytes = ctx->avc_codec->avc_nal_bytes;
    aud_sent = 0;
    sps_pps_sent = 0;
    ngx_int_t vps_copy = 0;
    ngx_int_t sps_copy = 0;
    ngx_int_t pps_copy = 0;

    while (in) {
        if (ngx_rtmp_mpegts_copy(s, &rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_rtmp_mpegts_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = (src_nal_type & 0x7e) >> 1;

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h265_handler| h265 NAL type=%ui, len=%uD",
                       (ngx_uint_t) nal_type, len);

        /* h264 format of rtmp_flv contains NAL header Prefix "00 00 00 01" */
        if (0 == nal_type) {
            u_char nal_header[4] = {0};
            if (ngx_rtmp_mpegts_copy(s, nal_header, &p, 3, &in) != NGX_OK) {
                return NGX_OK;
            }

            if (0 != ngx_strcmp(nal_header, "\0\0\1")) {
                ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                            "mpegts module: h265 hander|"
                                "is not h265 NAL header [00 00 00 01]");
                p -= 3;
                goto NAL_TRAIL_N;
                return NGX_OK;
            }

            if (ngx_rtmp_mpegts_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
                return NGX_OK;
            }

            nal_type = (src_nal_type & 0x7e) >> 1;
            if (0 == nal_type) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "mpegts hls: h265 NAL type reparse error");
                return NGX_OK;
            }

#define HEVC_NAL_AUD_LENGTH 0
            if (out.end - out.last < (ngx_int_t) (len + HEVC_NAL_AUD_LENGTH)) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                              "hls: not enough buffer for NAL");
                return NGX_OK;
            }
#if 1
            if (ngx_rtmp_mpegts_append_hevc_aud(s, &out) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "hls: error appending AUD NAL");
            }
#endif
            /* back to 00 00 01 nal_type*/
            p = p - 4;
            if (ngx_rtmp_mpegts_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }

            out.last += (len - 1);
            break;
        }

NAL_TRAIL_N:

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "hls: h265 NAL type=%ui, len=%uD",
                       (ngx_uint_t) nal_type, len);

        /*
         *  NAL_VPS 32
         *  NAL_SPS 33
         *  NAL_PPS 34
         *  NAL_AUD 35
         *  NAL_SEI_PREFIX 39
         *  NAL_SEI_SUFFIX 40
         */
        if ((nal_type >= 32 && nal_type <= 35)
            || nal_type == 39 || nal_type == 40)
        {
            if (out.end - out.last < (5 + len -1)) {
                ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "hls: not enough buffer for AnnexB prefix");
                return NGX_OK;
            }
            if (32 == nal_type) {
                ++vps_copy;
                if(!aud_sent){
                    if (ngx_rtmp_mpegts_append_hevc_aud(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls: error appending AUD NAL");
                    }
                    aud_sent = 1;
                }
            } else if (33 == nal_type) {
                ++sps_copy;
            } else if (34 == nal_type) {
                ++pps_copy;
            } else if (35 == nal_type) {
                aud_sent = 1;
            }

            *out.last++ = 0;
            *out.last++ = 0;
            *out.last++ = 0;
            *out.last++ = 1;
            *out.last++ = src_nal_type;
            if (ngx_rtmp_mpegts_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            out.last += (len - 1);
            continue;
        }

        if (vps_copy > 0 && sps_copy > 0 && pps_copy > 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "mpegts vps_copy %i, sps_copy %i, pps_copy %i\n",
                        vps_copy, sps_copy, pps_copy);
            sps_pps_sent = 1;
        }

        if (!aud_sent) {
            if (35 == nal_type) {
                aud_sent = 1;
            } else if (!sps_pps_sent) {
                if (ngx_rtmp_mpegts_append_hevc_vps_sps_pps(s, &out) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "hls: error appending AUD NAL");
                }
                aud_sent = 1;
            }
        }


#define IS_IRAP(nal_type) (nal_type >= 16 && nal_type <= 23)

        if (IS_IRAP(nal_type)) {
            if (!sps_pps_sent) {
                if (ngx_rtmp_mpegts_append_hevc_vps_sps_pps(s, &out) != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "hls: error appenging VPS/SPS/PPS NALs");
                }
                sps_pps_sent = 1;
            }
        }

        /* AnnexB prefix */
        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for AnnexB prefix");
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
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "hls: not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_rtmp_mpegts_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    frame = ngx_rtmp_shared_alloc_mpegts_frame();
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: h265_handler| "
                      "memory error, alloc mpegts frame failed");
        return NGX_ERROR;
    }

    /* continuity counter */
    frame->cc = ctx->video_cc;
    frame->dts = (uint64_t) h->timestamp * 90;
    /* pts = dts + composition time */
    frame->pts = frame->dts + cts * 90;
    /* program id */
    frame->pid = 0x100;
    /* stream id, video range from 0xe0 to 0xef */
    frame->sid = 0xe0;
    frame->key = (ftype == 1);
    frame->type = NGX_RTMP_MPEGTS_TYPE_VIDEO;

    /*
     * start new fragment if
     * - we have video key frame AND
     * - we have audio buffered or have no audio at all or stream is closed
     */
    if (ctx->aframe && ctx->aframe->last > ctx->aframe->pos &&
        ctx->aframe_pts + (uint64_t) ctx->audio_delay * 90  < frame->dts)
    {
        ngx_rtmp_mpegts_flush_audio(s);
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: h265_handler| video pts=%uL, dts=%uL",
                   frame->pts, frame->dts);

    if (ngx_rtmp_mpegts_shared_append_chain(frame, &out, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: h264_handler| video frame failed");
    } else {
        ngx_rtmp_mpegts_gop_cache(s, frame);
    }

    ngx_rtmp_shared_free_mpegts_frame(frame);

    ctx->video_cc = frame->cc;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_h264_handler(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *f)
{
    ngx_rtmp_header_t              *h;
    ngx_chain_t                    *in;
    ngx_rtmp_mpegts_ctx_t          *ctx;
    u_char                         *p;
    uint8_t                         fmt, ftype, htype, nal_type, src_nal_type;
    uint32_t                        len, rlen;
    ngx_buf_t                       out;
    uint32_t                        cts;
    ngx_mpegts_frame_t             *frame;
    ngx_uint_t                      nal_bytes;
    ngx_int_t                       aud_sent, sps_pps_sent;
    u_char                         *buffer;
    ngx_rtmp_mpegts_app_conf_t     *macf;
    ngx_int_t                       rc;

    h = &f->hdr;
    in = f->chain;

    macf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_mpegts_module);
    buffer = macf->packet_buffer;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    if (ctx == NULL || h->mlen < 1)
    {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h264_handler| "
                       "resource error, mpegts_ctx=%p, h->mlen=%d",
                       ctx, h->mlen);
        return NGX_OK;
    }

    if (ctx->avc_codec == NULL) {
        rc = ngx_rtmp_mpegts_init_avc_codec(s);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h264_handler| init avc_codec failed");
            return NGX_OK;
        } else if (rc == NGX_AGAIN) {
            return NGX_OK;
        }
    }

    /* H264 is supported */
    if (ctx->avc_codec->video_codec_id != NGX_RTMP_VIDEO_H264) {
        return NGX_OK;
    }

    p = in->buf->pos;
    if (ngx_rtmp_mpegts_copy(s, &fmt, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* 1: keyframe (IDR)
     * 2: inter frame
     * 3: disposable inter frame */

    ftype = (fmt & 0xf0) >> 4;

    /* H264 HDR/PICT */

    if (ngx_rtmp_mpegts_copy(s, &htype, &p, 1, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    /* proceed only with PICT */

    if (htype != 1) {
        return NGX_OK;
    }

    /* 3 bytes: decoder delay */

    if (ngx_rtmp_mpegts_copy(s, &cts, &p, 3, &in) != NGX_OK) {
        return NGX_ERROR;
    }

    cts = ((cts & 0x00FF0000) >> 16) | ((cts & 0x000000FF) << 16) |
          (cts & 0x0000FF00);

    ngx_memzero(&out, sizeof(out));

    out.start = buffer;
    out.end = buffer + NGX_RTMP_MPEG_BUFSIZE;
    out.pos = out.start;
    out.last = out.pos;

    nal_bytes = ctx->avc_codec->avc_nal_bytes;
    aud_sent = 0;
    sps_pps_sent = 0;

    while (in) {
        if (ngx_rtmp_mpegts_copy(s, &rlen, &p, nal_bytes, &in) != NGX_OK) {
            return NGX_OK;
        }

        len = 0;
        ngx_rtmp_rmemcpy(&len, &rlen, nal_bytes);

        if (len == 0) {
            continue;
        }

        if (ngx_rtmp_mpegts_copy(s, &src_nal_type, &p, 1, &in) != NGX_OK) {
            return NGX_OK;
        }

        nal_type = src_nal_type & 0x1f;

        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: h264_handler| h264 NAL type=%ui, len=%uD",
                       (ngx_uint_t) nal_type, len);

        if (nal_type >= 7 && nal_type <= 9) {
            if (ngx_rtmp_mpegts_copy(s, NULL, &p, len - 1, &in) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }

        if (!aud_sent) {
            switch (nal_type) {
                case 1:
                case 5:
                case 6:
                    if (ngx_rtmp_mpegts_append_aud(s, &out) != NGX_OK) {
                        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                      "rtmp-mpegts: h264_handler| error appending AUD NAL");
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
                if (ngx_rtmp_mpegts_append_sps_pps(s, &out) != NGX_OK) {
                    ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                                  "rtmp-mpegts: h264_handler| error appenging SPS/PPS NALs");
                }
                sps_pps_sent = 1;
                break;
        }

        /* AnnexB prefix */

        if (out.end - out.last < 5) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "rtmp-mpegts: h264_handler| not enough buffer for AnnexB prefix");
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
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "rtmp-mpegts: h264_handler| not enough buffer for NAL");
            return NGX_OK;
        }

        if (ngx_rtmp_mpegts_copy(s, out.last, &p, len - 1, &in) != NGX_OK) {
            return NGX_ERROR;
        }

        out.last += (len - 1);
    }

    frame = ngx_rtmp_shared_alloc_mpegts_frame();
    if (frame == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: h264_handler| "
                      "memory error, alloc mpegts frame failed");
        return NGX_ERROR;
    }

    frame->cc = ctx->video_cc;
    frame->dts = (uint64_t) h->timestamp * 90;
    frame->pts = frame->dts + cts * 90;
    frame->pid = 0x100;
    frame->sid = 0xe0;
    frame->key = (ftype == 1);
    frame->type = NGX_RTMP_MPEGTS_TYPE_VIDEO;

    if (ctx->aframe && ctx->aframe->last > ctx->aframe->pos &&
        ctx->aframe_pts + (uint64_t) ctx->audio_delay * 90  < frame->dts)
    {
        ngx_rtmp_mpegts_flush_audio(s);
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: h264_handler| video pts=%uL, dts=%uL",
                   frame->pts, frame->dts);

    if (ngx_rtmp_mpegts_shared_append_chain(frame, &out, 1) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: h264_handler| video frame failed");
    } else {
        ngx_rtmp_mpegts_gop_cache(s, frame);
    }

    ngx_rtmp_shared_free_mpegts_frame(frame);

    ctx->video_cc = frame->cc;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_parse_aac_header(ngx_rtmp_session_t *s, ngx_uint_t *objtype,
    ngx_uint_t *srindex, ngx_uint_t *chconf)
{
    ngx_rtmp_mpegts_ctx_t  *ctx;
    ngx_chain_t            *cl;
    u_char                 *p, b0, b1;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    cl = ctx->aac_codec->aac_header->chain;

    p = cl->buf->pos;

    if (ngx_rtmp_mpegts_copy(s, NULL, &p, 2, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_mpegts_copy(s, &b0, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_rtmp_mpegts_copy(s, &b1, &p, 1, &cl) != NGX_OK) {
        return NGX_ERROR;
    }

    *objtype = b0 >> 3;
    if (*objtype == 0 || *objtype == 0x1f) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: parse_aac_header| "
                       "unsupported adts object type:%ui", *objtype);
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
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: parse_aac_header| "
                       "unsupported adts sample rate:%ui", *srindex);
        return NGX_ERROR;
    }

    *chconf = (b1 >> 3) & 0x0f;

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: parse_aac_header| "
                   "aac object_type:%ui, sample_rate_index:%ui, "
                   "channel_config:%ui", *objtype, *srindex, *chconf);

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_aac_handler(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *f)
{
    ngx_rtmp_header_t              *h;
    ngx_chain_t                    *in;
    ngx_rtmp_mpegts_ctx_t          *ctx;
    uint64_t                        pts, est_pts;
    int64_t                         dpts;
    size_t                          bsize;
    ngx_buf_t                      *b;
    u_char                         *p;
    ngx_uint_t                      objtype, srindex, chconf, size;
    ngx_int_t                       rc;

    h = &f->hdr;
    in = f->chain;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);

    if (ctx == NULL || h->mlen < 2){
        return NGX_OK;
    }

    if (ctx->aac_codec == NULL) {
        rc = ngx_rtmp_mpegts_init_aac_codec(s);
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: aac_handler| init aac_codec failed");
            return NGX_OK;
        } else if(rc == NGX_AGAIN) {
            return NGX_OK;
        }
    }

    if (ngx_rtmp_is_codec_header(in)){
        return NGX_OK;
    }

    b = ctx->aframe;

    if (b == NULL) {

        b = ngx_pcalloc(s->connection->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        ctx->aframe = b;

        b->start = ngx_palloc(s->connection->pool, ctx->audio_buffer_size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + ctx->audio_buffer_size;
        b->pos = b->last = b->start;
    }

    size = h->mlen - 2 + 7;
    pts = (uint64_t) h->timestamp * 90;

    if (b->start + size > b->end) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: aac_handler| too big audio frame");
        return NGX_OK;
    }

    if (b->last > b->pos &&
        ctx->aframe_pts + (uint64_t) ctx->audio_delay * 90 / 2 < pts)
    {
        ngx_rtmp_mpegts_flush_audio(s);
    }

    if (b->last + size > b->end) {
        ngx_rtmp_mpegts_flush_audio(s);
    }

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: aac_handler| audio pts=%uL", pts);

    if (b->last + 7 > b->end) {
        ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                       "rtmp-mpegts: aac_handler| not enough buffer for audio header");
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

    if (ngx_rtmp_mpegts_parse_aac_header(s, &objtype, &srindex, &chconf)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: aac_handler| aac header error");
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
        ctx->aframe_num++;
        return NGX_OK;
    }

    ctx->aframe_pts = pts;

    if (!ctx->sync || ctx->aac_codec->sample_rate == 0) {
        return NGX_OK;
    }

    /* align audio frames */

    /* TODO: We assume here AAC frame size is 1024
     *       Need to handle AAC frames with frame size of 960 */

    est_pts = ctx->aframe_base + ctx->aframe_num * 90000 * 1024 /
                                 ctx->aac_codec->sample_rate;
    dpts = (int64_t) (est_pts - pts);

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: aac_handler| audio sync dpts=%L (%.5fs)",
                   dpts, dpts / 90000.);

    if (dpts <= (int64_t) ctx->sync * 90 &&
        dpts >= (int64_t) ctx->sync * -90)
    {
        ctx->aframe_num++;
        ctx->aframe_pts = est_pts;
        return NGX_OK;
    }

    ctx->aframe_base = pts;
    ctx->aframe_num  = 1;

    ngx_log_error(NGX_LOG_DEBUG, s->connection->log, 0,
                   "rtmp-mpegts: aac_handler| audio sync gap dpts=%L (%.5fs)",
                   dpts, dpts / 90000.);

    return NGX_OK;
}


static void
ngx_rtmp_mpegts_av(ngx_event_t *wev)
{
    ngx_connection_t                   *c;
    ngx_rtmp_session_t                 *s;
    ngx_rtmp_mpegts_ctx_t              *ctx;
    ngx_rtmp_frame_t                   *f;
    ngx_rtmp_codec_ctx_t               *codec_ctx;

    c = wev->data;
    if (!c || !c->data) {
        return;
    }

    s = c->data;

    codec_ctx = ngx_rtmp_get_module_ctx(s->live_stream->publish_ctx->session,
                                        ngx_rtmp_codec_module);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    if (!ctx) {
        return;
    }

    if (s->out_pos == s->out_last) {
        return;
    }

    f = s->out[s->out_pos];

    while (f) {
        if (f->av_header) {
            ngx_rtmp_shared_free_frame(s->out[s->out_pos]);

            s->out_pos++;
            s->out_pos %= s->out_queue;
            if (s->out_pos == s->out_last) {
                break;
            }

            f = s->out[s->out_pos];

            continue;
        }

        switch (f->hdr.type) {
        case NGX_RTMP_MSG_AUDIO:
            // only aac, for now
            ngx_rtmp_mpegts_aac_handler(s, f);
            break;

        case NGX_RTMP_MSG_VIDEO:
            /* h264 h265 */
            if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H264) {
                ngx_rtmp_mpegts_h264_handler(s, f);
            } else if (codec_ctx->video_codec_id == NGX_RTMP_VIDEO_H265) {
                ngx_rtmp_mpegts_h265_handler(s, f);
            }
            break;

        default:
            ngx_log_debug1(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "rtmp-mpegts: av| unknown frame-type=%d", f->hdr.type);
            break;
        }

        if (s->out_pos == s->out_last) {
            break;
        }

        ngx_rtmp_shared_free_frame(s->out[s->out_pos]);

        s->out_pos++;
        s->out_pos %= s->out_queue;
        if (s->out_pos == s->out_last) {
            break;
        }

        f = s->out[s->out_pos];
    }
}


static ngx_int_t
ngx_rtmp_mpegts_parse_args(ngx_rtmp_session_t *s,
                      ngx_mpegts_play_t *v,
                      ngx_rtmp_play_t *rtmp_v)
{
#define NGX_MPEGTS_ARGS_COPY(dst, src)                        \
    ngx_memset(&dst, 0, sizeof(dst));                         \
    if (src.len){                                             \
        dst.data = ngx_pcalloc(s->connection->pool, src.len); \
        ngx_memcpy(dst.data, src.data, src.len);              \
        dst.len = src.len;                                    \
    }

    if (!v->app.len || !v->name.len || v->name.len > NGX_RTMP_MAX_NAME) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "rtmp-mpegts: parse_args| invalid args, app=%V, name=%V",
                      &v->app, &v->name);
        return NGX_ERROR;
    }
    NGX_MPEGTS_ARGS_COPY(s->app, v->app);
    NGX_MPEGTS_ARGS_COPY(s->tc_url, v->tc_url);
    NGX_MPEGTS_ARGS_COPY(s->swf_url, v->swf_url);
    NGX_MPEGTS_ARGS_COPY(s->page_url, v->page_url);
    NGX_MPEGTS_ARGS_COPY(s->serverid, v->serverid);

    s->acodecs = v->acodecs;
    s->vcodecs = v->vcodecs;

    ngx_memcpy(rtmp_v->name, v->name.data, v->name.len);

    if (v->args.len) {
        ngx_memcpy(rtmp_v->args, v->args.data, ngx_min(NGX_RTMP_MAX_ARGS, v->args.len));
    }
    rtmp_v->silent = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_ctx_init(ngx_rtmp_session_t *s)
{
    ngx_rtmp_mpegts_app_conf_t         *macf;
    ngx_rtmp_mpegts_ctx_t              *ctx;

    macf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_mpegts_module);
    if (macf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: ctx_init| get app conf failed");
        return NGX_ERROR;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_mpegts_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(s->connection->pool,
               sizeof(ngx_rtmp_mpegts_ctx_t) +
               sizeof(ngx_mpegts_frame_t) * macf->out_queue);
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: ctx_init| get ctx failed");
            return NGX_ERROR;
        }

        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_mpegts_module);
        ctx->session = s;
    }

    ctx->sync = macf->sync;
    ctx->audio_buffer_size = macf->audio_buffer_size;
    ctx->audio_delay = macf->audio_delay;
    ctx->cache_time = macf->cache_time;
    ctx->out_queue = macf->out_queue;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_close_stream(ngx_rtmp_session_t *s, ngx_rtmp_close_stream_t *v)
{
    if (s->live_type != NGX_HLS_LIVE) {
        goto next;
    }

    ngx_rtmp_fire_event(s, NGX_RTMP_MPEGTS_CLOSE_STREAM, NULL, NULL);
    ngx_live_delete_mpegts_ctx(s);

next:
    return next_close_stream(s, v);
}


ngx_msec_t
ngx_rtmp_mpegts_cache_length(ngx_rtmp_mpegts_ctx_t *ctx)
{
    return ctx->cache_length;
}


ngx_mpegts_frame_t *
ngx_rtmp_mpegts_patpmt(ngx_hls_session_t *hls)
{
    ngx_live_stream_t          *live_stream;
    ngx_rtmp_mpegts_ctx_t      *mctx;
    ngx_rtmp_codec_ctx_t       *codec_ctx;
    ngx_hls_cmd_ctx_t          *ctx;

    live_stream = hls->live_stream;

    if (NULL == live_stream) {
        return NULL;
    }

    mctx = live_stream->hls_publish_ctx;

    codec_ctx = ngx_rtmp_get_module_ctx(hls->live_stream->publish_ctx->session,
                                        ngx_rtmp_codec_module);
    
    ctx = ngx_rtmp_get_module_ctx(hls, ngx_hls_cmd_module);
    if (NULL == mctx || NULL == codec_ctx || NULL == ctx){
        return NULL;
    }

    if (mctx->patpmt == NULL) {
        mctx->patpmt = ngx_rtmp_shared_alloc_mpegts_frame();
        mctx->patpmt->type = NGX_RTMP_MPEGTS_TYPE_PATPMT;
        mctx->patpmt->chain = ngx_get_chainbuf(NGX_MPEGTS_BUF_SIZE, 1);

        if (0 == ctx->audio_only && 0 == ctx->video_only) {
            /* video + audio */
            if (ctx->audio_type == TS_AUDIO_TYPE_AAC) {
                if (ctx->video_type == TS_VIDEO_TYPE_H264) {
                    /* h264 + aac  .ts */
                    mctx->patpmt->length = sizeof(ngx_rtmp_mpegts_header);
                    mctx->patpmt->chain->buf->last =
                        ngx_cpymem(mctx->patpmt->chain->buf->pos,
                                   ngx_rtmp_mpegts_header,
                                   sizeof(ngx_rtmp_mpegts_header));
                } else if (ctx->video_type == TS_VIDEO_TYPE_H265) {
                    /* h265 + aac  .ts */
                    mctx->patpmt->length =
                        sizeof(ngx_rtmp_mpegts_hevc_aac_header);
                    mctx->patpmt->chain->buf->last =
                        ngx_cpymem(mctx->patpmt->chain->buf->pos,
                                   ngx_rtmp_mpegts_hevc_aac_header,
                                   sizeof(ngx_rtmp_mpegts_hevc_aac_header));
                }
            } else if (ctx->audio_type == TS_AUDIO_TYPE_MP3) {
                if (ctx->video_type == TS_VIDEO_TYPE_H264) {
                    /* h264 + mp3  .ts */
                    mctx->patpmt->length =
                        sizeof(ngx_rtmp_mpegts_h264_mp3_header);
                    mctx->patpmt->chain->buf->last =
                    ngx_cpymem(mctx->patpmt->chain->buf->pos,
                            ngx_rtmp_mpegts_h264_mp3_header,
                            sizeof(ngx_rtmp_mpegts_h264_mp3_header));
                } else if (ctx->video_type == TS_VIDEO_TYPE_H265) {
                    /* h265 + mp3  .ts */
                    mctx->patpmt->length =
                        sizeof(ngx_rtmp_mpegts_hevc_mp3_header);
                    mctx->patpmt->chain->buf->last =
                        ngx_cpymem(mctx->patpmt->chain->buf->pos,
                                   ngx_rtmp_mpegts_hevc_mp3_header,
                                   sizeof(ngx_rtmp_mpegts_hevc_mp3_header));
                }
            }
        } else if (1 == ctx->audio_only) {
            //pure audio
            if (ctx->audio_type == TS_AUDIO_TYPE_AAC) {
                /* aac  .ts */
                mctx->patpmt->length = sizeof(ngx_rtmp_mpegts_aac_header);
                mctx->patpmt->chain->buf->last =
                    ngx_cpymem(mctx->patpmt->chain->buf->pos,
                               ngx_rtmp_mpegts_aac_header,
                               sizeof(ngx_rtmp_mpegts_aac_header));
            } else if (ctx->audio_type == TS_AUDIO_TYPE_MP3) {
                /* mp3  .ts */
                mctx->patpmt->length = sizeof(ngx_rtmp_mpegts_mp3_header);
                mctx->patpmt->chain->buf->last =
                    ngx_cpymem(mctx->patpmt->chain->buf->pos,
                               ngx_rtmp_mpegts_mp3_header,
                               sizeof(ngx_rtmp_mpegts_mp3_header));
            }
        } else if (1 == ctx->video_only) {
            /* pure video*/
            if (ctx->video_type == TS_VIDEO_TYPE_H264) {
                /* h264  .ts */
                mctx->patpmt->length = sizeof(ngx_rtmp_mpegts_h264_header);
                mctx->patpmt->chain->buf->last =
                    ngx_cpymem(mctx->patpmt->chain->buf->pos,
                               ngx_rtmp_mpegts_h264_header,
                               sizeof(ngx_rtmp_mpegts_h264_header));
            } else if (ctx->video_type == TS_VIDEO_TYPE_H265) {
                /* h265  .ts*/
                mctx->patpmt->length = sizeof(ngx_rtmp_mpegts_hevc_header);
                mctx->patpmt->chain->buf->last =
                    ngx_cpymem(mctx->patpmt->chain->buf->pos,
                               ngx_rtmp_mpegts_hevc_header,
                               sizeof(ngx_rtmp_mpegts_hevc_header));
            }
        }
    } else {
        ngx_rtmp_shared_acquire_mpegts_frame(mctx->patpmt);
    }

    return mctx->patpmt;
}


ngx_int_t
ngx_rtmp_mpegts_start(ngx_mpegts_play_t *v)
{
    ngx_rtmp_addr_conf_t               *addr_conf;
    ngx_uint_t                          n;
    ngx_rtmp_session_t                 *s;
    ngx_connection_t                   *fc;
    ngx_rtmp_core_srv_conf_t           *cscf;
    ngx_rtmp_core_app_conf_t          **cacfp;
    ngx_rtmp_play_t                     rtmp_v;

    addr_conf = v->addr_conf;

    fc = ngx_rtmp_create_fake_connection(NULL, v->log);

    /* create fake session */
    s = ngx_rtmp_init_fake_session(fc, addr_conf);
    if (s == NULL) {
        ngx_log_error(NGX_LOG_ERR, fc->log, 0,
                "rtmp-mpegts: start| init fake session failed");

        return NGX_ERROR;
    }

    fc->data = s;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    ngx_memset(&rtmp_v, 0, sizeof(rtmp_v));
    if (ngx_rtmp_mpegts_parse_args(s, v, &rtmp_v) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: start| parse args failed");

        return NGX_ERROR;
    }

    s->live_type = NGX_HLS_LIVE;
    s->live_server = ngx_live_create_server(&s->serverid);
    s->handler = ngx_rtmp_mpegts_av;

    /* find application & set app_conf */
    cacfp = cscf->applications.elts;
    for (n = 0; n < cscf->applications.nelts; ++n, ++cacfp) {
        if ((*cacfp)->name.len == s->app.len &&
            ngx_strncmp((*cacfp)->name.data, s->app.data, s->app.len) == 0)
        {
            /* found app! */
            s->app_conf = (*cacfp)->app_conf;
            break;
        }
    }

    if (s->app_conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: start| application not found '%V'", &s->app);

        return NGX_ERROR;
    }

    if (ngx_rtmp_mpegts_ctx_init(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: start| load conf failed");
        return NGX_ERROR;
    }

    ngx_rtmp_cmd_stream_init(s, rtmp_v.name, rtmp_v.args, 0);

    if (ngx_rtmp_play(s, &rtmp_v) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: start| rtmp play failed");

        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                "rtmp-mpegts: start| fake rtmp session play");

    if (ngx_live_create_mpegts_ctx(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "rtmp-mpegts: start| create mpegts ctx failed");
        ngx_rtmp_finalize_fake_session(s);

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_mpegts_postconfiguration(ngx_conf_t *cf)
{
    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_mpegts_close_stream;

    return NGX_OK;
}

