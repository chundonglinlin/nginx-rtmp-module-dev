
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_BANDWIDTH_H_INCLUDED_
#define _NGX_RTMP_BANDWIDTH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* Bandwidth update interval in seconds */
#define NGX_RTMP_BANDWIDTH_INTERVAL        30
#define NGX_RTMP_DROPRATE_INTERVAL         60
#define NGX_RTMP_DATA_DELAY                500
#define NGX_RTMP_FRAMESTAT_MAX_COUNT       60
#define NGX_RTMP_FRAMESTAT_INTERVAL        30

typedef struct {
    uint64_t            bytes;
    uint64_t            bandwidth;      /* bytes/sec */

    time_t              intl_end;
    uint64_t            intl_bytes;
    uint64_t            last_trans_time;
    uint64_t            max_delay_interval;
    uint64_t            delay_count;
} ngx_rtmp_bandwidth_t;


typedef struct {
    uint64_t            packets;
    uint64_t            droppackets;
    float               droprate;

    time_t              intl_end;
    uint64_t            intl_drops;

    uint64_t            all_droppackets;
} ngx_rtmp_droprate_t;


typedef struct {
    ngx_uint_t          intl_frame;
    ngx_uint_t          count;
    ngx_int_t           intl_stat[NGX_RTMP_FRAMESTAT_MAX_COUNT];
    ngx_msec_t          intl_end;

    uint64_t            frames;
    float               frame_rate;
    time_t              frame_interal;
} ngx_rtmp_framestat_t;


void ngx_rtmp_update_bandwidth(ngx_rtmp_bandwidth_t *bw, uint32_t bytes);
void ngx_rtmp_update_droprate(ngx_rtmp_droprate_t *dr);
void ngx_rtmp_update_frames(ngx_rtmp_framestat_t *framestat, uint64_t num);


#endif /* _NGX_RTMP_BANDWIDTH_H_INCLUDED_ */
