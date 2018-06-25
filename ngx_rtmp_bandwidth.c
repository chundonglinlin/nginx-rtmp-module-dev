
/*
 * Copyright (C) Roman Arutyunyan
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_bandwidth.h"


void
ngx_rtmp_update_bandwidth(ngx_rtmp_bandwidth_t *bw, uint32_t bytes)
{
    uint64_t    delay_interval;

    delay_interval = ngx_current_msec - bw->last_trans_time;

    if (ngx_cached_time->sec > bw->intl_end) {
        bw->bandwidth = ngx_cached_time->sec >
                        bw->intl_end + NGX_RTMP_BANDWIDTH_INTERVAL ?
                        0 :
                        bw->intl_bytes / NGX_RTMP_BANDWIDTH_INTERVAL;
        bw->intl_bytes = 0;
        bw->intl_end = ngx_cached_time->sec + NGX_RTMP_BANDWIDTH_INTERVAL;
        bw->max_delay_interval = 0;
        bw->delay_count = 0;
    }

    if (bw->last_trans_time != 0 && delay_interval > NGX_RTMP_DATA_DELAY) {
        bw->delay_count++;
        bw->max_delay_interval = bw->max_delay_interval > delay_interval ?
                                 bw->max_delay_interval : delay_interval;

    }

    bw->bytes += bytes;
    bw->intl_bytes += bytes;
    bw->last_trans_time = ngx_current_msec;
}


void
ngx_rtmp_update_droprate(ngx_rtmp_droprate_t *dr)
{
    if (ngx_cached_time->sec > dr->intl_end) {
        if (dr->droppackets == 0 || dr->packets == 0) {
            dr->droprate = 0;
        } else {
            dr->droprate = ngx_cached_time->sec >
                           dr->intl_end + NGX_RTMP_DROPRATE_INTERVAL ?
                           0 : (float)dr->droppackets / dr->packets;
        }
        dr->intl_end = ngx_cached_time->sec + NGX_RTMP_DROPRATE_INTERVAL;
        dr->all_droppackets += dr->droppackets;

        dr->packets = 0;
        dr->droppackets = 0;
    }
}


void
ngx_rtmp_update_frames(ngx_rtmp_framestat_t *framestat, uint64_t num)
{
    ngx_int_t    interval;
    ngx_uint_t   mod, i;

    if (framestat->intl_end == 0) {
        framestat->intl_end = (ngx_current_msec / 1000 + 1) * 1000;
    }
    interval = ngx_current_msec - framestat->intl_end;

    if (ngx_cached_time->sec > framestat->frame_interal) {
        framestat->frame_rate = ngx_cached_time->sec >
                        framestat->frame_interal + NGX_RTMP_FRAMESTAT_INTERVAL ?
                        0 :
                        framestat->frames / NGX_RTMP_FRAMESTAT_INTERVAL;
        framestat->frames = 0;
        framestat->frame_interal = ngx_cached_time->sec +
                                   NGX_RTMP_FRAMESTAT_INTERVAL;
    }

    if (interval > 0) {
        mod = (interval / 1000) > NGX_RTMP_FRAMESTAT_MAX_COUNT ?
               NGX_RTMP_FRAMESTAT_MAX_COUNT :  (interval / 1000);

        for (i = 0; i < mod; i++) {
            framestat->intl_stat[framestat->count] = 0;
            framestat->count = (framestat->count + 1) %
                               NGX_RTMP_FRAMESTAT_MAX_COUNT;
        }

        framestat->intl_stat[framestat->count] = framestat->intl_frame;
        framestat->count = (framestat->count + 1) %
                           NGX_RTMP_FRAMESTAT_MAX_COUNT;
        framestat->intl_end = (ngx_current_msec / 1000 + 1) * 1000;
        framestat->intl_frame = num;
    } else {
        framestat->intl_frame += num;
    }

    framestat->frames += num;
}
