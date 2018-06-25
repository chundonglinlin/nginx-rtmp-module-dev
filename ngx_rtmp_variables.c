
#include "ngx_rtmp_variables.h"
#include "ngx_rtmp_live_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_dynamic.h"
#include "ngx_stream_zone_module.h"
#include "ngx_multiport.h"

static ngx_int_t ngx_rtmp_variable_publish_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_current_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_connect_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_session_string(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_session_bandwidth(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_session_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_session_weighted_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_local_addr(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_local_ip(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_remote_addr(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_remote_ip(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_total_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_total_weighted_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_rtmp_variables_instance_clientid(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t
ngx_rtmp_variable_scheme(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_bw_dynamic(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_ngx_role(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_process(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_worker_id(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_av_timestamp(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_outqueue_size(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_max_datainterval(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_over500ms_count(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_processid(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_sessiontype(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_useragent(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_stream_source(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_server_index(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_droprate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_alldroppackets(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_lastminute_framerate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_dnion_ua(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_log_timer(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_session_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_firstmeta_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_status(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_request_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_rtmp_variable_referer(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data);

static ngx_rtmp_variable_t  ngx_rtmp_core_variables[] = {

    { ngx_string("pub_time"), NULL,
      ngx_rtmp_variable_publish_time, 0, 0, 0 },

    { ngx_string("unix_time"), NULL,
      ngx_rtmp_variable_current_time, 0,
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("local_addr"), NULL,
      ngx_rtmp_variable_local_addr, 0, 0, 0 },

    { ngx_string("local_ip"), NULL,
      ngx_rtmp_variable_local_ip, 0, 0, 0 },

    { ngx_string("remote_addr"), NULL,
      ngx_rtmp_variable_remote_addr, 0, 0, 0 },

    { ngx_string("remote_ip"), NULL,
      ngx_rtmp_variable_remote_ip, 0, 0, 0 },

    { ngx_string("app"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, app), 0, 0 },

    { ngx_string("clientid"), NULL,
        ngx_rtmp_variables_instance_clientid, 0, 0, 0 },

    { ngx_string("name"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, name), 0, 0 },

    { ngx_string("tcUrl"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, tc_url), 0, 0 },

    { ngx_string("pageUrl"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, page_url), 0, 0 },

    { ngx_string("swfUrl"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, swf_url), 0, 0 },

    { ngx_string("flashVer"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, flashver), 0, 0 },

    { ngx_string("pargs"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, pargs), 0, 0 },

    { ngx_string("in_bandwidth"), NULL,
      ngx_rtmp_variable_session_bandwidth,
      offsetof(ngx_rtmp_session_t, bw_in), 0, 0 },

    { ngx_string("out_bandwidth"), NULL,
      ngx_rtmp_variable_session_bandwidth,
      offsetof(ngx_rtmp_session_t, bw_out), 0, 0 },

    { ngx_string("in_bytes"), NULL,
      ngx_rtmp_variable_session_bytes,
      offsetof(ngx_rtmp_session_t, bw_in), 0, 0 },

    { ngx_string("out_bytes"), NULL,
      ngx_rtmp_variable_session_bytes,
      offsetof(ngx_rtmp_session_t, bw_out), 0, 0 },

    { ngx_string("bytes"), NULL,
      ngx_rtmp_variable_total_bytes, 0, 0, 0 },

    { ngx_string("weighted_in_bytes"), NULL,
      ngx_rtmp_variable_session_weighted_bytes,
      offsetof(ngx_rtmp_session_t, bw_in), 0, 0 },

    { ngx_string("weighted_out_bytes"), NULL,
      ngx_rtmp_variable_session_weighted_bytes,
      offsetof(ngx_rtmp_session_t, bw_out), 0, 0 },

    { ngx_string("weighted_bytes"), NULL,
      ngx_rtmp_variable_total_weighted_bytes, 0, 0, 0 },

    { ngx_string("audio_bandwidth"), NULL,
      ngx_rtmp_variable_session_bandwidth,
      offsetof(ngx_rtmp_session_t, bw_audio), 0, 0 },

    { ngx_string("video_bandwidth"), NULL,
      ngx_rtmp_variable_session_bandwidth,
      offsetof(ngx_rtmp_session_t, bw_video), 0, 0 },

    { ngx_string("time"), NULL,
      ngx_rtmp_variable_time, 0,
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("AV_timestamp"), NULL,
      ngx_rtmp_variable_av_timestamp, 0,
      NGX_RTMP_VAR_NOCACHEABLE|NGX_RTMP_VAR_CHANGEABLE, 0 },

    { ngx_string("outqueue_size"), NULL,
      ngx_rtmp_variable_outqueue_size, 0, 0, 0 },

    { ngx_string("maxdata_interval"), NULL,
      ngx_rtmp_variable_max_datainterval, 0, 0, 0 },

    { ngx_string("over500mscount"), NULL,
      ngx_rtmp_variable_over500ms_count, 0, 0, 0 },

    { ngx_string("connection_time"), NULL,
      ngx_rtmp_variable_connect_time, 0, 0, 0 },

    { ngx_string("processid"), NULL,
      ngx_rtmp_variable_processid, 0, 0, 0 },

    { ngx_string("sessiontype"), NULL,
      ngx_rtmp_variable_sessiontype, 0, 0, 0 },

    { ngx_string("useragent"), NULL,
      ngx_rtmp_variable_useragent, 0, 0, 0 },

    { ngx_string("streamsource"), NULL,
      ngx_rtmp_variable_stream_source, 0, 0, 0 },

    { ngx_string("serverindex"), NULL,
      ngx_rtmp_variable_server_index, 0, 0, 0 },

    { ngx_string("droprate"), NULL,
      ngx_rtmp_variable_droprate, 0, 0, 0 },

    { ngx_string("totaldropframes"), NULL,
      ngx_rtmp_variable_alldroppackets, 0, 0, 0 },

    { ngx_string("lastmin_framerate"), NULL,
      ngx_rtmp_variable_lastminute_framerate, 0, 0, 0 },

    { ngx_string("timpstamp"), NULL,
      ngx_rtmp_variable_current_time, 0, 0, 0 },

    { ngx_string("domain"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, domain), 0, 0 },

    { ngx_string("serverid"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, serverid), 0, 0 },

    { ngx_string("scheme"), NULL,
      ngx_rtmp_variable_scheme, 0, 0, 0 },

    { ngx_string("bandwidth_dynamic"), NULL,
      ngx_rtmp_variable_bw_dynamic, 0, 0, 0 },

    { ngx_string("ngx_role"), NULL,
      ngx_rtmp_variable_ngx_role, 0, 0, 0 },

    { ngx_string("process"), NULL,
      ngx_rtmp_variable_process, 0, 0, 0 },

    { ngx_string("worker_id"), NULL,
      ngx_rtmp_variable_worker_id, 0, 0, 0 },

    /* For sessions that don't require billing, return 'Dnion-UA', else '' */
    { ngx_string("Dnion_ua"), NULL,
      ngx_rtmp_variable_dnion_ua, 0, 0, 0 },

    { ngx_string("log_timer"), NULL,
      ngx_rtmp_variable_log_timer, 0, 0, 0 },

    { ngx_string("session_time"), NULL,
      ngx_rtmp_variable_session_time, 0, 0, 0 },

    { ngx_string("firstmeta_time"), NULL,
      ngx_rtmp_variable_firstmeta_time, 0, 0, 0 },

    { ngx_string("status"), NULL,
      ngx_rtmp_variable_status, 0, 0, 0 },

    { ngx_string("request_time"), NULL,
      ngx_rtmp_variable_request_time, 0, 0, 0 },

    { ngx_string("session_id"), NULL,
      ngx_rtmp_variable_session_string,
      offsetof(ngx_rtmp_session_t, session_id), 0, 0 },

    { ngx_string("referer"), NULL,
      ngx_rtmp_variable_referer, 0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


ngx_rtmp_variable_value_t  ngx_rtmp_variable_null_value =
    ngx_rtmp_variable("");
ngx_rtmp_variable_value_t  ngx_rtmp_variable_true_value =
    ngx_rtmp_variable("1");


static ngx_uint_t  ngx_rtmp_variable_depth = 100;

static ngx_int_t
ngx_rtmp_variable_publish_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", s->epoch) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_variable_current_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", ngx_current_msec / 1000) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_connect_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", s->epoch / 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_local_addr(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                     sa[NGX_SOCKADDRLEN];
    ngx_addr_t                 addr;
    socklen_t                  len = NGX_SOCKADDRLEN;
    u_char                    *address;

    address = ngx_pcalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);

    addr.socklen = s->connection->socklen;
    if (s->live_type == NGX_HTTP_FLV_LIVE) {
        if (s->request == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "http flv fake session,but not found http request");
            return NGX_ERROR;
        }
        ngx_str_t  flv_local_addr;
        flv_local_addr.len = NGX_SOCKADDR_STRLEN;
        flv_local_addr.data = address;
        if (ngx_connection_local_sockaddr(s->request->connection,
                    &flv_local_addr, 1) != NGX_OK || flv_local_addr.len == 0)
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "http flv fake session get local addr failed");
            return NGX_ERROR;
        }
    } else if (s->live_type == NGX_RTMP_LIVE) {
        if (getsockname(s->connection->fd, (struct sockaddr *) &sa,
            &len) == -1)
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "variables: local_addr getsockname() failed");
            return NGX_ERROR;
        }
        addr.sockaddr = (struct sockaddr*)&sa;
        ngx_sock_ntop(addr.sockaddr,
#if (nginx_version >= 1005003)
                addr.socklen,
#endif
                address, NGX_SOCKADDR_STRLEN, 1);
    }

    v->len = ngx_strlen(address);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = address;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_remote_addr(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char             *p;
    u_char              sa[NGX_SOCKADDRLEN];
    socklen_t           len, len2;
    ngx_addr_t          addr;

    p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    addr.socklen = s->connection->socklen;
    len = NGX_SOCKADDR_STRLEN;

    if (s->connection->sockaddr) {
        addr.sockaddr = s->connection->sockaddr;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    } else {
        if (getpeername(s->connection->fd, (struct sockaddr *)&sa, &len) == -1) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "variables: remote_addr getpeername() failed");
            return NGX_ERROR;
         }
        addr.sockaddr = (struct sockaddr*)&sa;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    }
    v->len = len2;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variables_instance_clientid(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_buf_t                         *buf;
    ngx_str_t                          clientid;

    buf = ngx_create_temp_buf(s->connection->pool, 32);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->last = ngx_slprintf(buf->pos, buf->end, "%ui", s->connection->number);

    clientid.data = buf->pos;
    clientid.len = buf->last - buf->pos;

    ngx_rtmp_variables_var(&clientid, v);

    return NGX_OK;
}



static ngx_int_t
ngx_rtmp_variable_session_string(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_str_t   *str;

    str = (ngx_str_t *) ((u_char *) s + data);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    if (str) {
        v->len = str->len;
        v->data = str->data;
        return NGX_OK;
    }
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_session_bandwidth(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_bandwidth_t  *bandwidth;
    u_char                *p;

    bandwidth = (ngx_rtmp_bandwidth_t *) ((u_char *) s + data);

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_rtmp_update_bandwidth(bandwidth, 0);
    if (bandwidth) {
        v->len = ngx_sprintf(p, "%uL", bandwidth->bandwidth) - p;
        v->data = p;
    } else {
        v->len = sizeof("0");
        v->data = (u_char *)"0";
    }
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_session_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_bandwidth_t  *bandwidth;
    u_char                *p;

    bandwidth = (ngx_rtmp_bandwidth_t *) ((u_char *) s + data);

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    if (bandwidth) {
        v->len = ngx_sprintf(p, "%uL", bandwidth->bytes) - p;
        v->data = p;
    } else {
        v->len = 0;
        v->data = NULL;
    }
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_session_weighted_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_core_app_conf_t   *cacf;
    ngx_rtmp_bandwidth_t       *bandwidth;
    u_char                     *p;
    uint64_t                    bytes;

    bandwidth = (ngx_rtmp_bandwidth_t *) ((u_char *) s + data);

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (!bandwidth) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    bytes = bandwidth->bytes;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    if (cacf->tcp_cost_makeup && bytes != 0) {
        /* 1. TCP Maximum Segment Size tuning: 1460
         * 2. Protocol overhead per segment: 78
         * 3. Bytes <==> bits: 8
         */
        bytes += (bytes * 8 / 1460 + 1) * 78 / 8;
    }
    v->len = ngx_sprintf(p, "%uL", bytes) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_total_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    uint64_t              in_bytes;
    uint64_t              out_bytes;
    u_char               *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    in_bytes = s->bw_in.bytes;
    out_bytes = s->bw_out.bytes;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = ngx_sprintf(p, "%uL", in_bytes + out_bytes) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_total_weighted_bytes(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    ngx_rtmp_core_app_conf_t   *cacf;
    uint64_t                    bytes;
    u_char                     *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    bytes = s->bw_in.bytes + s->bw_out.bytes;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    if (cacf->tcp_cost_makeup && bytes != 0) {
        /* 1. TCP Maximum Segment Size tuning: 1460
         * 2. Protocol overhead per segment: 78
         * 3. Bytes <==> bits: 8
         */
        bytes += (bytes * 8 / 1460 + 1) * 78 / 8;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = ngx_sprintf(p, "%uL", bytes) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui",
                 (ngx_current_msec - s->live_stream->epoch) / 1000) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_av_timestamp(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    ngx_rtmp_live_app_dconf_t *ladcf;
    ngx_rtmp_live_ctx_t       *ctx;

    ladcf = ngx_rtmp_get_module_app_dconf(s, &ngx_rtmp_live_module);
    ctx = s->live_stream->ctx;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (ladcf->interleave) {
        v->len = ngx_sprintf(p, "%D", 0) - p;
        v->data = p;
        return NGX_OK;
    }

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;

        return NGX_OK;
    }

    v->len = ngx_sprintf(p, "%D",
                         ctx->cs[1].timestamp - ctx->cs[0].timestamp) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_outqueue_size(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    ngx_int_t             size;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    size = s->out_last >= s->out_pos ?
           (s->out_last - s->out_pos) :
           (s->out_queue - (s->out_pos - s->out_last));

    v->len = ngx_sprintf(p, "%i", size) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_max_datainterval(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    uint64_t              data_interval;
    ngx_rtmp_live_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (ctx->publishing) {
        data_interval = s->bw_in.max_delay_interval;
    } else {
        data_interval = s->bw_out.max_delay_interval;
    }

    v->len = ngx_sprintf(p, "%uL", data_interval) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_over500ms_count(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    uint64_t              count;
    ngx_rtmp_live_ctx_t  *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (ctx->publishing) {
        count = s->bw_in.delay_count;
    } else {
        count = s->bw_out.delay_count;
    }

    v->len = ngx_sprintf(p, "%uL", count) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_processid(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;

    p = ngx_pnalloc(s->connection->pool, NGX_PTR_SIZE);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", ngx_getpid()) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_sessiontype(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    ngx_rtmp_live_ctx_t  *ctx;

    p = ngx_pnalloc(s->connection->pool, sizeof("relay_pull"));
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);

    if (ctx == NULL) {
        v->len = 0;
        v->data = NULL;
        return NGX_OK;
    }

    if (ctx->publishing) {
        if (s->relay) {
            v->len = ngx_sprintf(p, "%s", "relay_pull") - p;
            v->data = p;
        } else {
            v->len = ngx_sprintf(p, "%s", "publisher") - p;
            v->data = p;
        }
    } else {
        if (s->relay) {
            v->len = ngx_sprintf(p, "%s", "relay_push") - p;
            v->data = p;
        } else {
            v->len = ngx_sprintf(p, "%s", "player") - p;
            v->data = p;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_useragent(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    ngx_table_elt_t      *user_agent;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (s->live_type == NGX_HTTP_FLV_LIVE) {
        if (s->back_source == 1) {
            p = ngx_pnalloc(s->connection->pool, sizeof("Dnion-UA") - 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            v->len = ngx_sprintf(p, "%s", "Dnion-UA") - p;
            v->data = p;
            return NGX_OK;
        } else if (s->request) {
            user_agent = s->request->headers_in.user_agent;
            if (user_agent) {
                p = ngx_pnalloc(s->connection->pool, user_agent->value.len);
                if (p == NULL) {
                    return NGX_ERROR;
                }

                v->len = user_agent->value.len;
                v->data = user_agent->value.data;
                return NGX_OK;
            }
        }
    }
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_stream_source(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", s->back_source) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_server_index(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_rtmp_core_srv_conf_t   *cscf;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", cscf->index) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_droprate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_update_droprate(&s->droprate);

    v->len = ngx_sprintf(p, "%.3f", s->droprate.droprate) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_alldroppackets(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_rtmp_update_droprate(&s->droprate);

    v->len = ngx_sprintf(p, "%L", s->droprate.all_droppackets) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_lastminute_framerate(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p, *q;
    ngx_uint_t   i;

    p = ngx_pnalloc(s->connection->pool,
        (NGX_INT_T_LEN +sizeof(",")) * NGX_RTMP_FRAMESTAT_MAX_COUNT);
    if (p == NULL) {
        return NGX_ERROR;
    }
    q = p;

    i = s->framestat.count;
    do{
        p = ngx_sprintf(p, "%i,", s->framestat.intl_stat[i]);
        i++;
        i %= NGX_RTMP_FRAMESTAT_MAX_COUNT;
    } while (i != s->framestat.count);

    v->len = p - q;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = q;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_scheme(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;

    p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->scheme.len == sizeof("rtmp") - 1 &&
        ngx_strncasecmp(s->scheme.data, (u_char *) "rtmp", s->scheme.len) == 0)
    {
        v->len = ngx_sprintf(p, "%s", (u_char *) "RTMP") - p;
        v->data = p;
        return NGX_OK;
    }

    v->len = ngx_sprintf(p, "%s", (u_char *) "HTTP_FLV") - p;
    v->data = p;
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_bw_dynamic(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    ngx_rtmp_core_app_conf_t   *cacf;

    p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);

    v->len = ngx_sprintf(p, "%ui", cacf->bandwidth_dynamic) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_ngx_role(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    if (ngx_role.len == 0) {
        v->data = NULL;
        v->len = 0;

        return NGX_OK;
    }
    v->len = ngx_sprintf(p, "%V", &ngx_role) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_process(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    ngx_int_t        pslot = -1;

    ngx_core_conf_t * ccf = (ngx_core_conf_t *)ngx_get_conf(
            ngx_cycle->conf_ctx, ngx_core_module);


    p = ngx_pnalloc(s->connection->pool, sizeof("extern"));
    if (p == NULL) {
        return NGX_ERROR;
    }

    if(ccf->worker_processes == 0) {
        pslot = -1;
        goto set_process;
    }

    if (s && s->live_stream) {
        pslot = s->live_stream->pslot;
    }

    if (pslot == ngx_process_slot)
        pslot = -1;

set_process:
    if (pslot == -1) {
        v->len = ngx_sprintf(p, "%s", "extern") - p;
        v->data = p;
    } else {
        v->len = ngx_sprintf(p, "%s", "intern") - p;
        v->data = p;
    }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    
    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_worker_id(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_sprintf(p, "%ui", ngx_worker) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_dnion_ua(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    if (s->back_source == 0) {
        v->data = NULL;
        v->len = 0;

        return NGX_OK;
    }

    p = ngx_pnalloc(s->connection->pool, sizeof("Dnion-UA") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    v->len = ngx_sprintf(p, "%s", "Dnion-UA") - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_local_ip(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char             *p, *ip;
    u_char              sa[NGX_SOCKADDRLEN];
    socklen_t           len, len2 = 0;
    ngx_addr_t          addr;
    ngx_str_t           flv_local_addr;

    p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    addr.socklen = s->connection->socklen;
    len = NGX_SOCKADDR_STRLEN;

    if (s->live_type == NGX_HTTP_FLV_LIVE) {
        if (s->request == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "http flv fake session,but not found http request");
            return NGX_ERROR;
        }

        flv_local_addr.len = NGX_SOCKADDR_STRLEN;
        flv_local_addr.data = p;
        if (ngx_connection_local_sockaddr(s->request->connection,
                    &flv_local_addr, 1) != NGX_OK || flv_local_addr.len == 0)
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "http flv fake session get local addr failed");
            return NGX_ERROR;
        }
        len2 = flv_local_addr.len;

    } else if (s->live_type == NGX_RTMP_LIVE) {
        if (getsockname(s->connection->fd, (struct sockaddr *) &sa,
            &len) == -1)
        {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "variables: local_ip getsockname() failed");
            return NGX_ERROR;
        }
        addr.sockaddr = (struct sockaddr*)&sa;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    }

    ip = p;
    p = ngx_strlchr(p, p + len2, ':');

    v->len = p - ip;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ip;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_remote_ip(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char             *p, *ip;
    u_char              sa[NGX_SOCKADDRLEN];
    socklen_t           len, len2;
    ngx_addr_t          addr;

    p = ngx_pnalloc(s->connection->pool, NGX_SOCKADDR_STRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    addr.socklen = s->connection->socklen;
    len = NGX_SOCKADDR_STRLEN;

    if (s->connection->sockaddr) {
        addr.sockaddr = s->connection->sockaddr;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    } else {
        if (getpeername(s->connection->fd, (struct sockaddr *)&sa, &len) == -1) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "variables: remote_ip getpeername() failed");
            return NGX_ERROR;
         }
        addr.sockaddr = (struct sockaddr*)&sa;
        len2 = ngx_sock_ntop(addr.sockaddr, addr.socklen,
                             p, NGX_SOCKADDR_STRLEN, 1);
    }

    ip = p;
    p = ngx_strlchr(p, p + len2, ':');

    v->len = p - ip;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ip;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_log_timer(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    ngx_msec_t   time;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (s->log_time == 0) {
        time = 0;
    } else {
        time = ngx_current_msec - s->log_time;
    }
    v->len = ngx_sprintf(p, "%ui", time / 1000) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_session_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    ngx_msec_t   time;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (s->log_time == 0) {
        time = ngx_current_msec - s->epoch;
    } else {
        time = ngx_current_msec - s->log_time;
    }
    v->len = ngx_sprintf(p, "%ui", time) - p;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_firstmeta_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char      *p;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (s->meta_epoch == 0) {
        v->len = 0;
        v->data = NULL;

        return NGX_OK;
    } 

    v->len = ngx_sprintf(p, "%ui", s->meta_epoch - s->epoch) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_status(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    ngx_uint_t            status = 0;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (s->live_type == NGX_HTTP_FLV_LIVE && s->request) {
        if (s->request->err_status) {
            status = s->request->err_status;

        } else if (s->request->headers_out.status) {
            status = s->request->headers_out.status;

        } else if (s->request->http_version == NGX_HTTP_VERSION_9) {
            status = 9;

        } else {
            status = 0;
        }

    } else if (s->live_type == NGX_RTMP_LIVE) {
        status = 200;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%03ui", status) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_variable_request_time(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p;
    ngx_time_t           *tp;
    ngx_msec_int_t        ms;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (s->live_type == NGX_HTTP_FLV_LIVE && s->request) {
        p = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN + 4);
        if (p == NULL) {
            return NGX_ERROR;
        }

        tp = ngx_timeofday();

        ms = (ngx_msec_int_t)
                 ((tp->sec - s->request->start_sec) * 1000 +
                  (tp->msec - s->request->start_msec));
        ms = ngx_max(ms, 0);

        v->len = ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
        v->data = p;

        return NGX_OK;
    }
    v->len = 0;
    v->data = NULL;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_variable_referer(ngx_rtmp_session_t *s,
    ngx_rtmp_variable_value_t *v, uintptr_t data)
{
    u_char               *p, *pageurl;
    ngx_str_t             str, args;

    p = ngx_pnalloc(s->connection->pool, NGX_RTMP_MAX_NAME);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

     if (s->page_url.len == 0 || s->page_url.data == NULL) {
        if (s->pargs.len == 0) {
            v->len = 0;
            v->data = NULL;
            return NGX_OK;
        }

        args = s->pargs;

        pageurl = ngx_strnstr(args.data, (char *)"pageUrl", args.len);
        if (pageurl == NULL) {
            str.len = 0;
            str.data = NULL;
        } else {
            str.data = pageurl + sizeof("pageUrl") -1;
            str.len = s->pargs.len - (str.data - args.data);
        }
        v->len = ngx_sprintf(p, "%V", &str) - p;
        v->data = p;
        return NGX_OK;
    } else {
        v->len = ngx_sprintf(p, "%V", &s->page_url) - p;
        v->data = p;
        return NGX_OK;
    }

    v->len = 0;
    v->data = NULL;
    return NGX_OK;
}

      
ngx_rtmp_variable_t *
ngx_rtmp_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_hash_key_t             *key;
    ngx_rtmp_variable_t        *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NGX_RTMP_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        v->flags &= flags;

        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_rtmp_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


ngx_int_t
ngx_rtmp_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_rtmp_variable_t        *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NGX_ERROR;
    }

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_rtmp_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


ngx_int_t
ngx_rtmp_get_http_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i = 0, n;
    ngx_rtmp_variable_t        *v, *av;
    ngx_rtmp_core_main_conf_t  *cmcf;
    ngx_rtmp_conf_ctx_t        *ctx;
    ngx_hash_key_t             *key;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid http variable name \"$\"");
        return NGX_ERROR;
    }

    ctx = (ngx_rtmp_conf_ctx_t *)
                ngx_get_conf(cf->cycle->conf_ctx, ngx_rtmp_module);
    cmcf = (ngx_rtmp_core_main_conf_t *)
                ctx->main_conf[ngx_rtmp_core_module.ctx_index];

    v = cmcf->variables.elts;
    key = cmcf->variables_keys->keys.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                sizeof(ngx_rtmp_variable_t)) != NGX_OK) {

            return NGX_ERROR;
        }

    } else {
        for (; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len ||
                    ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0) {
                continue;
            }
            //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "variables: exist var=%V", name);
            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;
        if (av->get_handler
            && v->name.len == key[n].key.len
            && ngx_strncmp(v->name.data, key[n].key.data, v->name.len) == 0)
        {
            v->get_handler = av->get_handler;
            v->data = av->data;
            av->flags= NGX_RTMP_VAR_INDEXED;
            v->flags = av->flags;
            av->index = i;

            goto next;
        }
    }

    ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                  "unknown \"%V\" variable", &v->name);

    return NGX_ERROR;

next:
    v->set_handler = NULL;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}

ngx_rtmp_variable_value_t *
ngx_rtmp_get_indexed_variable(ngx_rtmp_session_t *s, ngx_uint_t index)
{
    ngx_rtmp_variable_t        *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (!s->variables[index].no_cacheable
        && (s->variables[index].not_found || s->variables[index].valid))
    {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (ngx_rtmp_variable_depth == 0) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    ngx_rtmp_variable_depth--;

    if (v[index].get_handler(s, &s->variables[index], v[index].data)
        == NGX_OK)
    {
        ngx_rtmp_variable_depth++;

        if (v[index].flags & NGX_RTMP_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    ngx_rtmp_variable_depth++;

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}


ngx_rtmp_variable_value_t *
ngx_rtmp_get_flushed_variable(ngx_rtmp_session_t *s, ngx_uint_t index)
{
    ngx_rtmp_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_rtmp_get_indexed_variable(s, index);
}


ngx_rtmp_variable_value_t *
ngx_rtmp_get_variable(ngx_rtmp_session_t *s, ngx_str_t *name, ngx_uint_t key)
{
    ngx_rtmp_variable_t        *v;
    ngx_rtmp_variable_value_t  *vv;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_get_module_main_conf(s, ngx_rtmp_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_RTMP_VAR_INDEXED) {
            return ngx_rtmp_get_flushed_variable(s, v->index);
        }

        if (ngx_rtmp_variable_depth == 0) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        ngx_rtmp_variable_depth--;

        vv = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_variable_value_t));

        if (vv && v->get_handler(s, vv, v->data) == NGX_OK) {
            ngx_rtmp_variable_depth++;
            return vv;
        }

        ngx_rtmp_variable_depth++;
        return NULL;
    }

    vv = ngx_palloc(s->connection->pool, sizeof(ngx_rtmp_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


ngx_int_t
ngx_rtmp_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_rtmp_variable_t        *cv, *v;
    ngx_rtmp_core_main_conf_t  *cmcf;

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    cmcf->variables_keys = ngx_pcalloc(cf->pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (cv = ngx_rtmp_core_variables; cv->name.len; cv++) {
        v = ngx_rtmp_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;
    }

    return NGX_OK;
}


ngx_int_t
ngx_rtmp_variables_init_vars(ngx_conf_t *cf)
{
    ngx_uint_t                  i, n;
    ngx_hash_key_t             *key;
    ngx_hash_init_t             hash;
    ngx_rtmp_variable_t        *v, *av;
    ngx_rtmp_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed rtmp variables */

    cmcf = ngx_rtmp_conf_get_module_main_conf(cf, ngx_rtmp_core_module);

    v = cmcf->variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (av->get_handler
                && v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;
                av->flags |= NGX_RTMP_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                goto next;
            }
        }

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown \"%V\" variable", &v[i].name);

        return NGX_ERROR;

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_RTMP_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


