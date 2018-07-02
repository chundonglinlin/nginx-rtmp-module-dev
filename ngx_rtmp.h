
/*
 * Copyright (C) Roman Arutyunyan
 */


#ifndef _NGX_RTMP_H_INCLUDED_
#define _NGX_RTMP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <nginx.h>
#include <ngx_http.h>


typedef struct ngx_rtmp_session_s   ngx_rtmp_session_t;


#include "ngx_rtmp_amf.h"
#include "ngx_rtmp_bandwidth.h"
#include "ngx_rtmp_variables.h"
#include "ngx_http_client.h"
#include "ngx_netcall.h"


#if (NGX_WIN32)
typedef __int8              int8_t;
typedef unsigned __int8     uint8_t;
#endif


#if (NGX_PCRE)
typedef struct {
    ngx_regex_t            *regex;
    ngx_str_t               name;
} ngx_rtmp_regex_t;
#endif


typedef struct {
    void                  **main_conf;
    void                  **srv_conf;
    void                  **app_conf;
} ngx_rtmp_conf_ctx_t;


typedef struct {
    void                   *addrs;
    ngx_uint_t              naddrs;
} ngx_rtmp_port_t;


typedef struct {
    int                     family;
    in_port_t               port;
    ngx_array_t             addrs;       /* array of ngx_rtmp_conf_addr_t */
} ngx_rtmp_conf_port_t;


#define NGX_RTMP_VERSION                3

#define NGX_LOG_DEBUG_RTMP              NGX_LOG_DEBUG_CORE

#define NGX_RTMP_DEFAULT_CHUNK_SIZE     128

#define NGX_RTMP_NO_FILTER              0
#define NGX_RTMP_FILTER_KEEPAUDIO       1

/* RTMP message types */
#define NGX_RTMP_MSG_CHUNK_SIZE         1
#define NGX_RTMP_MSG_ABORT              2
#define NGX_RTMP_MSG_ACK                3
#define NGX_RTMP_MSG_USER               4
#define NGX_RTMP_MSG_ACK_SIZE           5
#define NGX_RTMP_MSG_BANDWIDTH          6
#define NGX_RTMP_MSG_EDGE               7
#define NGX_RTMP_MSG_AUDIO              8
#define NGX_RTMP_MSG_VIDEO              9
#define NGX_RTMP_MSG_AMF3_META          15
#define NGX_RTMP_MSG_AMF3_SHARED        16
#define NGX_RTMP_MSG_AMF3_CMD           17
#define NGX_RTMP_MSG_AMF_META           18
#define NGX_RTMP_MSG_AMF_SHARED         19
#define NGX_RTMP_MSG_AMF_CMD            20
#define NGX_RTMP_MSG_AGGREGATE          22
#define NGX_RTMP_MSG_MAX                22

#define NGX_RTMP_CONNECT                NGX_RTMP_MSG_MAX + 1
#define NGX_RTMP_DISCONNECT             NGX_RTMP_MSG_MAX + 2
#define NGX_RTMP_HANDSHAKE_DONE         NGX_RTMP_MSG_MAX + 3
#define NGX_RTMP_MPEGTS_AV              NGX_RTMP_MSG_MAX + 4
#define NGX_RTMP_MPEGTS_CLOSE_STREAM    NGX_RTMP_MSG_MAX + 5
#define NGX_RTMP_MAX_EVENT              NGX_RTMP_MSG_MAX + 6


/* RMTP control message types */
#define NGX_RTMP_USER_STREAM_BEGIN      0
#define NGX_RTMP_USER_STREAM_EOF        1
#define NGX_RTMP_USER_STREAM_DRY        2
#define NGX_RTMP_USER_SET_BUFLEN        3
#define NGX_RTMP_USER_RECORDED          4
#define NGX_RTMP_USER_PING_REQUEST      6
#define NGX_RTMP_USER_PING_RESPONSE     7
#define NGX_RTMP_USER_UNKNOWN           8
#define NGX_RTMP_USER_BUFFER_END        31

/* Chunk header:
 *   max 3  basic header
 * + max 11 message header
 * + max 4  extended header (timestamp) */
#define NGX_RTMP_MAX_CHUNK_HEADER       18

#define NGX_RTMP_HEADER_TYPE_DEFAULT    0
#define NGX_RTMP_HEADER_TYPE_QQ_FLV     1
#define NGX_RTMP_HEADER_TYPE_QQ_HLS     2

#define NGX_QQ_FLV_INDEX_SIZE           35



typedef struct {    
    ngx_queue_t                     *index_queue;
    uint32_t                        backdelay;               //缓冲时间，qqlive默认为15，qt为45，回看频道由回看列表决定
    unsigned                        buname:1;                //0-qqlive,1-qt  
} ngx_qq_flv_index_t;


typedef struct {    
    ngx_qq_flv_header_t             qqflvhdr;                 
    off_t                           file_offset;             //文件索引
} ngx_qq_flv_block_index_t;

typedef struct {
    uint32_t                        usize;                   //大小(数据部分大小)
    uint16_t                        huheadersize;            //本数据结构头的大小，为26
    uint16_t                        huversion;               //版本号,一般为0
    uint8_t                         uctype;                  //类型
    uint8_t                         uckeyframe;              //标识是不是关键帧，0-flv头，1-普通帧，2-关键帧
    uint32_t                        usec;                    //时间戳 时间(秒)
    uint32_t                        useq;                    //序号，每一帧本序号加一，flv头帧序号为0
    uint32_t                        usegid;                  //段ID，确保全局唯一或者其代表的flv头是唯一的
    uint32_t                        ucheck;                  //校验和，本结构体后面数据内容的校验和
} ngx_qq_flv_header_t;

typedef struct {
    uint32_t                        usize;                     //  数据部分大小
    uint16_t                        huheadersize;              //  头大小，不固定（可能存在扩展协议）
    uint16_t                        uctype;                    //  2：音频 3：视频 4：新视频 5：新音频
    uint32_t                        duration;                  //  分片时长
    uint32_t                        useq;                      //  分片序号
    uint64_t                        usec;                      //  UTC时间戳
    uint16_t                        extendtype;                //  扩展类型 0 - 无扩展， 1 -扩展协议
    ngx_qq_hls_extend_t             qqhlsextend;
} ngx_qq_hls_header_t;

typedef struct {
    uint64_t                        timestamp;                 //  分片第一个关键帧PTS时间
    uint32_t                        width;                     //  视频宽度
    uint32_t                        height;                    //  视频高度
    uint8_t                         checktype;                 //  校验类型 1-crc16，2-crc32，3-md5
    uint32_t                        checksum;                  //  ts分片校验和
    uint8_t                         p2p_block_count;           //  psp分片总数
    ngx_queue_t                     *p2p_block_queue;
} ngx_qq_hls_extend_t;

typedef struct {
    uint8_t                         number;                    //  p2p分片号
    uint32_t                        size;                      //  p2p分片大小
    uint32_t                        checksum;                  //  p2p分片CRC16
} ngx_qq_p2p_block_t;

typedef struct {
    uint32_t                csid;       /* chunk stream id */
    uint32_t                timestamp;  /* timestamp (delta) */
    uint32_t                mlen;       /* message length */
    uint8_t                 type;       /* message type id */
    uint32_t                msid;       /* message stream id */
    ngx_qq_flv_header_t     qqflvhdr;   /* qq flv header */
    ngx_qq_hls_header_t     qqhlshdr;   /* qq hls header */
    ngx_flag_t              qqhdrtype;  /* qq header type */
} ngx_rtmp_header_t;


typedef struct {
    ngx_rtmp_header_t       hdr;
    uint32_t                dtime;
    uint32_t                len;        /* current fragment length */
    uint8_t                 ext;
    ngx_chain_t            *in;
} ngx_rtmp_stream_t;


typedef struct ngx_rtmp_frame_s     ngx_rtmp_frame_t;

struct ngx_rtmp_frame_s {
    ngx_rtmp_header_t       hdr;
    ngx_flag_t              av_header;
    ngx_flag_t              keyframe;
    ngx_flag_t              mandatory;
    ngx_uint_t              ref;

    ngx_rtmp_frame_t       *next;
    ngx_chain_t            *chain;
};

typedef struct ngx_mpegts_frame_s   ngx_mpegts_frame_t;

struct ngx_mpegts_frame_s {
    uint64_t                    pts;
    uint64_t                    dts;
    ngx_uint_t                  pid;
    ngx_uint_t                  sid;
    ngx_uint_t                  cc;
    unsigned                    key:1;
    ngx_uint_t                  ref;
    uint8_t                     type;
    ngx_mpegts_frame_t         *next;
    ngx_mpegts_frame_t         *key_next;
    ngx_uint_t                  length;
    ngx_uint_t                  pos;
    ngx_chain_t                *chain;
};

/* disable zero-sized array warning by msvc */

#if (NGX_WIN32)
#pragma warning(push)
#pragma warning(disable:4200)
#endif

#define NGX_RTMP_LIVE       0
#define NGX_HTTP_FLV_LIVE   1
#define NGX_HLS_LIVE        2


typedef struct ngx_live_stream_s    ngx_live_stream_t;
typedef struct ngx_live_server_s    ngx_live_server_t;
typedef struct ngx_rtmp_addr_conf_s ngx_rtmp_addr_conf_t;

struct ngx_rtmp_session_s {
    ngx_str_t                       session_id;
    uint32_t                        signature;  /* "RTMP" */ /* <-- FIXME wtf */

    ngx_event_t                     close;

    ngx_rtmp_addr_conf_t           *addr_conf;

    void                          **ctx;
    void                          **main_conf;
    void                          **srv_conf;
    void                          **app_conf;

    ngx_live_server_t              *live_server;
    ngx_live_stream_t              *live_stream;

    ngx_str_t                      *addr_text;
    int                             connected;

#if (nginx_version >= 1007005)
    ngx_queue_t                     posted_dry_events;
#else
    ngx_event_t                    *posted_dry_events;
#endif

    /* client buffer time in msec */
    uint32_t                        buflen;
    uint32_t                        ack_size;

    ngx_str_t                       stream;
    ngx_str_t                       name;
    ngx_str_t                       pargs;  /* play or publish args */

    /* connection parameters */
    ngx_str_t                       app;
    ngx_str_t                       args;
    ngx_str_t                       flashver;
    ngx_str_t                       swf_url;
    ngx_str_t                       tc_url;
    uint32_t                        acodecs;
    uint32_t                        vcodecs;
    ngx_str_t                       page_url;
    ngx_uint_t                      back_source:1;

    /* middleware */
    ngx_str_t                       scheme;
    ngx_str_t                       domain;
    ngx_str_t                       serverid;

    /* handshake data */
    ngx_buf_t                      *hs_buf;
    u_char                         *hs_digest;
    unsigned                        hs_old:1;
    ngx_uint_t                      hs_stage;

    /* connection timestamps */
    ngx_msec_t                      epoch;
    ngx_msec_t                      peer_epoch;
    ngx_msec_t                      meta_epoch;
    ngx_msec_t                      base_time;
    uint32_t                        current_time;

    /* publisher's epoch */
    ngx_msec_t                      publish_epoch;

    /* ping */
    ngx_event_t                     ping_evt;
    unsigned                        ping_active:1;
    unsigned                        ping_reset:1;

    /* auto-pushed? */
    unsigned                        interprocess:1;
    unsigned                        relay:1;
    unsigned                        played:1;
    unsigned                        published:1;
    unsigned                        closed:1;
    unsigned                        publishing:1;

    /* rtmp variables */
    ngx_rtmp_variable_value_t      *variables;

    /* sub metadata */
    ngx_rtmp_frame_t               *sub_meta;
    ngx_uint_t                      sub_meta_version;

    /* live type: 0- RTMP 1- http-flv 2- hls */
    unsigned                        live_type:2;
    ngx_uint_t                      status;
    ngx_http_request_t             *request;
    ngx_event_handler_pt            handler;

    unsigned                        flv_state;

    ngx_uint_t                      flv_version;
    ngx_uint_t                      flv_flags;
    unsigned                        flv_data_offset;
    unsigned                        flv_tagsize;
    uint64_t                        flv_recv_bytes;

    /* for qq flv header */
    uint32_t                        qq_flv_len;
    unsigned                        qq_flv_state;

    ngx_qq_flv_header_t             qqflvhdr;

    /* groupid for notify|control*/
    ngx_str_t                       groupid;

    /* for priority stream*/
    ngx_int_t                       priority;

    /* for play_send_gop*/
    ngx_event_t                     quick_play;

    /* for notify transocde return 200 */
    ngx_flag_t                      transcode_hang;

    /* input stream 0 (reserved by RTMP spec)
     * is used as free chain link */

    ngx_rtmp_stream_t              *in_streams;
    uint32_t                        in_csid;
    ngx_uint_t                      in_chunk_size;
    ngx_pool_t                     *in_pool;
    uint32_t                        in_bytes;
    uint32_t                        in_last_ack;

    ngx_pool_t                     *in_old_pool;
    ngx_int_t                       in_chunk_size_changing;

    ngx_connection_t               *connection;

    /* for bandwidth */
    ngx_rtmp_bandwidth_t            bw_in;
    ngx_rtmp_bandwidth_t            bw_out;
    ngx_rtmp_bandwidth_t            bw_video;
    ngx_rtmp_bandwidth_t            bw_audio;

    /* for droprate */
    ngx_rtmp_droprate_t             droprate;

    /* for framestat */
    ngx_rtmp_framestat_t            framestat;

    /* for frame-filtration */
    ngx_int_t                       filter;

    /* for output access log time*/
    ngx_msec_t                      log_time;

	/* for static pull */
	unsigned						static_pull_fake:1;
	/* second relay */
	unsigned						second_relay:1;

    /* circular buffer of RTMP message pointers */
    ngx_msec_t                      timeout;
    uint32_t                        out_bytes;
    size_t                          out_pos, out_last;
    ngx_chain_t                    *out_chain;
    unsigned                        out_buffer:1;
    size_t                          out_queue;
    size_t                          out_cork;
    ngx_rtmp_frame_t               *out[0];
};

/* live stream manage */
#define NGX_LIVE_SERVERID_LEN   512
#define NGX_LIVE_STREAM_LEN     512

typedef struct ngx_rtmp_core_ctx_s  ngx_rtmp_core_ctx_t;
typedef struct ngx_rtmp_live_ctx_s  ngx_rtmp_live_ctx_t;
typedef struct ngx_hls_cmd_ctx_s ngx_hls_cmd_ctx_t;
typedef struct ngx_rtmp_mpegts_ctx_s ngx_rtmp_mpegts_ctx_t;
typedef struct ngx_relay_reconnect_s    ngx_relay_reconnect_t;
typedef struct ngx_rtmp_notify_session_s ngx_rtmp_notify_session_t;

struct ngx_rtmp_core_ctx_s {
    ngx_rtmp_core_ctx_t    *next;
    ngx_rtmp_session_t     *session;

    unsigned                publishing:1;
};

struct ngx_relay_reconnect_s {
    ngx_event_t             reconnect;
    ngx_live_stream_t      *live_stream;

    ngx_relay_reconnect_t  *next;
};

#define NGX_RTMP_NOTIFY_MAX_COUNT 64
#define NGX_RTMP_MAX_OCLP   8
#define NGX_RTMP_MAX_PUSH   8

typedef struct {
    ngx_str_t                   name;
    ngx_str_t                   url;
    ngx_rtmp_session_t         *session;

    ngx_str_t                   pargs; /* play or publish ctx */

    ngx_str_t                   app;
    ngx_str_t                   args;
    ngx_str_t                   tc_url;
    ngx_str_t                   page_url;
    ngx_str_t                   swf_url;
    ngx_str_t                   flash_ver;
    ngx_str_t                   push_object;
    uint32_t                    acodecs;
    uint32_t                    vcodecs;

    ngx_str_t                   play_path;
    ngx_int_t                   live;
    ngx_int_t                   start;
    ngx_int_t                   stop;

    unsigned                    relay_completion:1;
    void                       *tag;
    ngx_uint_t                  idx;
} ngx_rtmp_relay_ctx_t;

struct ngx_live_stream_s {
    u_char                      name[NGX_LIVE_STREAM_LEN];
    ngx_int_t                   pslot;
    ngx_rtmp_core_ctx_t        *publish_ctx;
    ngx_rtmp_core_ctx_t        *play_ctx;

    /* oclp */
    ngx_netcall_ctx_t          *stream_nctx;
    ngx_netcall_ctx_t          *pull_nctx;
    ngx_netcall_ctx_t          *push_nctx[NGX_RTMP_MAX_OCLP];

    /* relay push */
    /* auto pull */
    ngx_rtmp_relay_ctx_t       *auto_pull_ctx;

    /* oclp */
    ngx_rtmp_relay_ctx_t       *oclp_ctx[NGX_RTMP_MAX_OCLP];

    /* relay */
    ngx_rtmp_relay_ctx_t       *relay_ctx[NGX_RTMP_MAX_PUSH];

    /* relay reconnect */
    ngx_relay_reconnect_t      *pull_reconnect;
    ngx_flag_t                  pull_relay;
    ngx_relay_reconnect_t      *push_reconnect;
    ngx_uint_t                  push_count;

    ngx_live_stream_t          *next;

    /* for notify */
    ngx_rtmp_notify_session_t  *nns[NGX_RTMP_NOTIFY_MAX_COUNT];
    ngx_flag_t                  idle_transcodes;

    /* for hls */
    ngx_rtmp_mpegts_ctx_t      *hls_publish_ctx;
    ngx_hls_cmd_ctx_t          *hls_play_ctx;

    /* for live */
    ngx_rtmp_live_ctx_t        *ctx;
    ngx_rtmp_bandwidth_t        bw_in;
    ngx_rtmp_bandwidth_t        bw_in_audio;
    ngx_rtmp_bandwidth_t        bw_in_video;
    ngx_rtmp_bandwidth_t        bw_out;
    ngx_msec_t                  epoch;
    unsigned                    active:1;
    unsigned                    publishing:1;
    unsigned                    oclp_meta:1;
};

struct ngx_live_server_s {
    u_char                      serverid[NGX_LIVE_SERVERID_LEN];
    ngx_uint_t                  n_stream;
    ngx_flag_t                  deleted;

    ngx_live_server_t          *next;

    ngx_live_stream_t         **streams;
};

/****         mpegts begin        ****/
#define NGX_RTMP_MPEGTS_TYPE_AUDIO   0x01
#define NGX_RTMP_MPEGTS_TYPE_VIDEO   0x02
#define NGX_RTMP_MPEGTS_TYPE_PATPMT  0x03


typedef struct ngx_mpegts_frag_s       ngx_mpegts_frag_t;
typedef struct ngx_m3u8_info_s         ngx_m3u8_info_t;
typedef struct ngx_hls_session_s       ngx_hls_session_t;

struct ngx_mpegts_frag_s {
    ngx_mpegts_frag_t          *next;
    ngx_mpegts_frame_t         *frame_header;
    ngx_mpegts_frame_t         *frame_tail;
    ngx_mpegts_frame_t         *patpmt;
    ngx_uint_t                  content_length;
    double                      duration;
    u_char                      name[256];
    ngx_uint_t                  frag_id;   //frag+nfrags
    unsigned                    discont;
    uint64_t                    key_id;
    ngx_uint_t                  ref;
};

struct ngx_m3u8_info_s {
    ngx_flag_t                      debug_log;
    ngx_uint_t                      type;
    ngx_uint_t                      slicing;
    uint64_t                        frag;
    ngx_uint_t                      nfrags;
    ngx_uint_t                      winfrags;
    ngx_uint_t                      minfrags;
    ngx_msec_t                      max_fraglen;
    ngx_msec_t                      fraglen;      //fragement length from conf
    ngx_msec_t                      current_timestamp;//current timestamp
    time_t                          modified_time;
    ngx_uint_t                      pos;
    ngx_uint_t                      last;
    ngx_uint_t                      pl;
    ngx_mpegts_frag_t               frags[]; // 2*playlist+1
};

typedef void (*ngx_hls_m3u8_handler_pt)(ngx_hls_session_t *hs);

struct ngx_hls_session_s {
	void                       *data;   //http_request_t
    ngx_str_t                   name;
    ngx_str_t                   stream;
    ngx_str_t                   session_id;
	ngx_connection_t           *connection;
    ngx_m3u8_info_t            *m3u8;
    void                      **ctx;
    void                      **main_conf;
    void                      **srv_conf;
    void                      **app_conf;
    ngx_live_stream_t          *live_stream;
    ngx_live_server_t          *live_server;
    ngx_pool_t                 *pool;
    ngx_log_t                  *log;
    ngx_uint_t                  out_buckets; // out array length from conf file
    ngx_uint_t                  out_queue;
	ngx_msec_t                  timeout;
    ngx_msec_t                  last_update;
};


typedef struct ngx_rtmp_mpegts_avc_codec_s {
    ngx_rtmp_frame_t       *avc_header;
    ngx_uint_t              video_codec_id;
    ngx_uint_t              avc_nal_bytes;
} ngx_rtmp_mpegts_avc_codec_t;

typedef struct ngx_rtmp_mpegts_aac_codec_s {
    ngx_rtmp_frame_t       *aac_header;
    uint64_t                sample_rate;
} ngx_rtmp_mpegts_aac_codec_t;

struct ngx_rtmp_mpegts_ctx_s {

    ngx_rtmp_mpegts_ctx_t        *next;
    ngx_rtmp_session_t           *session;

    /* mpegts-module config */
    ngx_msec_t                    cache_time;
    size_t                        audio_buffer_size;
    ngx_msec_t                    sync;
    ngx_msec_t                    audio_delay;
    size_t                        out_queue;


    /* pat pmt frame*/
    ngx_mpegts_frame_t           *patpmt;

    /* video packet */
    ngx_rtmp_mpegts_avc_codec_t  *avc_codec;
    ngx_uint_t                    video_cc;

    /* audio packet */
    ngx_rtmp_mpegts_aac_codec_t  *aac_codec;
    ngx_uint_t                    audio_cc;
    uint64_t                      aframe_pts;
    ngx_uint_t                    aframe_num;
    ngx_msec_t                    aframe_base;
    ngx_buf_t                    *aframe;

    /* gop cache */
    ngx_mpegts_frame_t           *last_video;
    ngx_mpegts_frame_t           *last_audio;
    ngx_mpegts_frame_t           *keyframe;
    ngx_msec_t                    cache_length;
    ngx_uint_t                    cache_pos;
    ngx_uint_t                    cache_last;
    ngx_mpegts_frame_t           *cache[];
};

struct ngx_hls_cmd_ctx_s {
    ngx_hls_cmd_ctx_t            *next;
    ngx_hls_session_t            *session;
    ngx_uint_t                    cache_pos;
    ngx_uint_t                    cache_last;
    ngx_flag_t                    updated;
    ngx_flag_t                    opened;
    uint64_t                      frag_ts;
    unsigned                      video_only:1;
    unsigned                      audio_only:1;
    unsigned                      video_type:1; // 0:h264 1:h265
    unsigned                      audio_type:1; // 0:aac 1:mp3
};

ngx_int_t ngx_live_create_hls_ctx(ngx_hls_session_t *hs);
void ngx_live_delete_hls_ctx(ngx_hls_session_t *hs);

ngx_int_t ngx_live_create_mpegts_ctx(ngx_rtmp_session_t *s);
void ngx_live_delete_mpegts_ctx(ngx_rtmp_session_t *s);
/****         mpegts end        ****/

ngx_relay_reconnect_t *ngx_live_get_relay_reconnect();
void ngx_live_put_relay_reconnect(ngx_relay_reconnect_t *rc);

ngx_live_server_t *ngx_live_create_server(ngx_str_t *serverid);
ngx_live_server_t *ngx_live_fetch_server(ngx_str_t *serverid);
void ngx_live_delete_server(ngx_str_t *serverid);

ngx_live_stream_t *ngx_live_create_stream(ngx_str_t *serverid,
        ngx_str_t *stream);
ngx_live_stream_t *ngx_live_fetch_stream(ngx_str_t *serverid,
        ngx_str_t *stream);
void ngx_live_delete_stream(ngx_str_t *serverid, ngx_str_t *stream);

void ngx_live_create_ctx(ngx_rtmp_session_t *s, unsigned publishing);
void ngx_live_delete_ctx(ngx_rtmp_session_t *s);

ngx_int_t ngx_live_handle_priority_stream(ngx_rtmp_session_t *s,
        ngx_int_t publishing, ngx_int_t priority);

void ngx_live_print();


#if (NGX_WIN32)
#pragma warning(pop)
#endif


/* handler result code:
 *  NGX_ERROR - error
 *  NGX_OK    - success, may continue
 *  NGX_DONE  - success, input parsed, reply sent; need no
 *      more calls on this event */
typedef ngx_int_t (*ngx_rtmp_handler_pt)(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


typedef struct {
    ngx_str_t               name;
    ngx_rtmp_handler_pt     handler;
} ngx_rtmp_amf_handler_t;


enum {
    NGX_RTMP_CUSTOM_MESSAGE_NONE,
    NGX_RTMP_CUSTOM_MESSAGE_ALL,
    NGX_RTMP_CUSTOM_MESSAGE_PART,
    NGX_RTMP_CUSTOM_MESSAGE_MAX
};


typedef struct {
    ngx_array_t                 servers;    /* ngx_rtmp_core_srv_conf_t */
    ngx_array_t                 listen;     /* ngx_rtmp_listen_t */

    ngx_array_t                 events[NGX_RTMP_MAX_EVENT];

    ngx_hash_t                  variables_hash;
    ngx_array_t                 variables;
    ngx_hash_keys_arrays_t     *variables_keys;

    ngx_uint_t                  variables_hash_max_size;
    ngx_uint_t                  variables_hash_bucket_size;

    ngx_hash_t                  amf_hash;
    ngx_array_t                 amf_arrays;
    ngx_array_t                 amf;

    ngx_array_t                 message_name;
    ngx_uint_t                  custom_message_flag;

    ngx_uint_t                  server_names_hash_max_size;
    ngx_uint_t                  server_names_hash_bucket_size;

    ngx_array_t                *ports;  /* ngx_rtmp_conf_port_t */
} ngx_rtmp_core_main_conf_t;


/* global main conf for stats */
extern ngx_rtmp_core_main_conf_t   *ngx_rtmp_core_main_conf;


typedef struct {
    ngx_array_t             applications; /* ngx_rtmp_core_app_conf_t */
    ngx_str_t               name;
    ngx_flag_t              bandwidth_dynamic;
    ngx_flag_t              tcp_cost_makeup;
    ngx_flag_t              media_filter;
    ngx_msec_t              pull_reconnect;
    ngx_msec_t              push_reconnect;
    void                  **app_conf;
} ngx_rtmp_core_app_conf_t;


typedef struct ngx_rtmp_core_srv_conf_s {
    ngx_array_t             applications; /* ngx_rtmp_core_app_conf_t */

    ngx_rtmp_core_app_conf_t *default_app;
    ngx_rtmp_core_app_conf_t *org_app;

    ngx_msec_t              timeout;
    ngx_msec_t              ping;
    ngx_msec_t              ping_timeout;
    ngx_flag_t              so_keepalive;
    ngx_int_t               max_streams;

    ngx_uint_t              ack_window;

    ngx_int_t               chunk_size;
    ngx_pool_t             *pool;
    ngx_chain_t            *free;
    ngx_chain_t            *free_hs;
    size_t                  max_message;
    ngx_flag_t              play_time_fix;
    ngx_flag_t              publish_time_fix;
    ngx_flag_t              busy;
    size_t                  out_queue;
    size_t                  out_cork;
    ngx_msec_t              buflen;

    ngx_rtmp_conf_ctx_t    *ctx;

    ngx_uint_t              index;

    unsigned                listen:1;
#if (NGX_PCRE)
    unsigned                captures:1;
#endif

    ngx_str_t               server_name;

    /* array of the ngx_rtmp_server_name_t, "server_name" directive */
    ngx_array_t             server_names;
} ngx_rtmp_core_srv_conf_t;


typedef struct {
#if (NGX_PCRE)
    ngx_rtmp_regex_t       *regex;
#endif
    ngx_rtmp_core_srv_conf_t *server; /* virtual name server conf */
    ngx_str_t               name;
} ngx_rtmp_server_name_t;


typedef struct {
    ngx_hash_combined_t     names;

    ngx_uint_t              nregex;
    ngx_rtmp_server_name_t *regex;
} ngx_rtmp_virtual_names_t;


struct ngx_rtmp_addr_conf_s {
    ngx_rtmp_core_srv_conf_t *default_server;
    ngx_rtmp_virtual_names_t *virtual_names;

    ngx_str_t               addr_text;
    unsigned                proxy_protocol:1;
};

typedef struct {
    in_addr_t               addr;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr         addr6;
    ngx_rtmp_addr_conf_t    conf;
} ngx_rtmp_in6_addr_t;

#endif


typedef struct {
    struct sockaddr        *sockaddr;
    socklen_t               socklen;

    unsigned                default_server:1;
    unsigned                bind:1;
    unsigned                wildcard:1;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                ipv6only:2;
#endif
    unsigned                so_keepalive:2;
    unsigned                proxy_protocol:1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                     tcp_keepidle;
    int                     tcp_keepintvl;
    int                     tcp_keepcnt;
#endif

    u_char                  addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_rtmp_listen_opt_t;


typedef struct {
    ngx_rtmp_listen_opt_t   opt;

    ngx_hash_t              hash;
    ngx_hash_wildcard_t    *wc_head;
    ngx_hash_wildcard_t    *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t              nregex;
    ngx_rtmp_server_name_t *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_rtmp_core_srv_conf_t   *default_server;
    ngx_array_t             servers;    /* array of ngx_http_core_srv_conf_t */
} ngx_rtmp_conf_addr_t;


/* nginx dynamic conf */
typedef struct {
    ngx_str_t               serverid;
} ngx_rtmp_core_srv_dconf_t;


typedef struct {
    ngx_str_t              *client;
    ngx_rtmp_session_t     *session;
} ngx_rtmp_error_log_ctx_t;


typedef struct {
    ngx_int_t             (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t             (*postconfiguration)(ngx_conf_t *cf);

    void                 *(*create_main_conf)(ngx_conf_t *cf);
    char                 *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void                 *(*create_srv_conf)(ngx_conf_t *cf);
    char                 *(*merge_srv_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);

    void                 *(*create_app_conf)(ngx_conf_t *cf);
    char                 *(*merge_app_conf)(ngx_conf_t *cf, void *prev,
                                    void *conf);
} ngx_rtmp_module_t;

#define NGX_RTMP_MODULE                 0x504D5452     /* "RTMP" */

#define NGX_RTMP_MAIN_CONF              0x02000000
#define NGX_RTMP_SRV_CONF               0x04000000
#define NGX_RTMP_APP_CONF               0x08000000
#define NGX_RTMP_REC_CONF               0x10000000


#define NGX_RTMP_MAIN_CONF_OFFSET  offsetof(ngx_rtmp_conf_ctx_t, main_conf)
#define NGX_RTMP_SRV_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, srv_conf)
#define NGX_RTMP_APP_CONF_OFFSET   offsetof(ngx_rtmp_conf_ctx_t, app_conf)


#define ngx_rtmp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_rtmp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define ngx_rtmp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;


#define ngx_rtmp_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_rtmp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
#define ngx_rtmp_get_module_app_conf(s, module)  ((s)->app_conf ? \
    (s)->app_conf[module.ctx_index] : NULL)

#define ngx_rtmp_conf_get_module_main_conf(cf, module)                       \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_rtmp_conf_get_module_app_conf(cf, module)                        \
    ((ngx_rtmp_conf_ctx_t *) cf->ctx)->app_conf[module.ctx_index]


/* for virtual server */
#if (NGX_PCRE)
ngx_rtmp_regex_t *ngx_rtmp_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
#endif
ngx_int_t ngx_rtmp_add_listen(ngx_conf_t *cf, ngx_rtmp_core_srv_conf_t *cscf,
    ngx_rtmp_listen_opt_t *lsopt);
ngx_int_t ngx_rtmp_set_virtual_server(ngx_rtmp_session_t *s, ngx_str_t *host);


#ifdef NGX_DEBUG
char* ngx_rtmp_message_type(uint8_t type);
char* ngx_rtmp_user_message_type(uint16_t evt);
#endif

void ngx_rtmp_init_connection(ngx_connection_t *c);
ngx_rtmp_session_t * ngx_rtmp_init_session(ngx_connection_t *c,
     ngx_rtmp_addr_conf_t *addr_conf);
void ngx_rtmp_finalize_session(ngx_rtmp_session_t *s);
void ngx_rtmp_handshake(ngx_rtmp_session_t *s);
void ngx_rtmp_client_handshake(ngx_rtmp_session_t *s, unsigned async);
void ngx_rtmp_free_handshake_buffers(ngx_rtmp_session_t *s);
void ngx_rtmp_cycle(ngx_rtmp_session_t *s);
void ngx_rtmp_reset_ping(ngx_rtmp_session_t *s);
ngx_int_t ngx_rtmp_fire_event(ngx_rtmp_session_t *s, ngx_uint_t evt,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


void ngx_rtmp_close_fake_connection(ngx_connection_t *c);
ngx_connection_t * ngx_rtmp_create_fake_connection(ngx_pool_t *pool, ngx_log_t *log);

void ngx_rtmp_finalize_fake_session(ngx_rtmp_session_t *s);
ngx_rtmp_session_t *ngx_rtmp_init_fake_session(ngx_connection_t *c,
     ngx_rtmp_addr_conf_t *addr_conf);
ngx_int_t ngx_rtmp_get_remoteaddr(ngx_connection_t *c,ngx_str_t *address);
ngx_int_t ngx_rtmp_arg(ngx_rtmp_session_t *s, u_char *name, size_t len,
     ngx_str_t *value);

ngx_int_t ngx_rtmp_set_chunk_size(ngx_rtmp_session_t *s, ngx_uint_t size);


/* Bit reverse: we need big-endians in many places  */
void * ngx_rtmp_rmemcpy(void *dst, const void* src, size_t n);

#define ngx_rtmp_rcpymem(dst, src, n) \
    (((u_char*)ngx_rtmp_rmemcpy(dst, src, n)) + (n))


static ngx_inline uint16_t
ngx_rtmp_r16(uint16_t n)
{
    return (n << 8) | (n >> 8);
}


static ngx_inline uint32_t
ngx_rtmp_r32(uint32_t n)
{
    return (n << 24) | ((n << 8) & 0xff0000) | ((n >> 8) & 0xff00) | (n >> 24);
}


static ngx_inline uint64_t
ngx_rtmp_r64(uint64_t n)
{
    return (uint64_t) ngx_rtmp_r32((uint32_t) n) << 32 |
                      ngx_rtmp_r32((uint32_t) (n >> 32));
}


/* Receiving messages */
ngx_int_t ngx_rtmp_receive_message(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_protocol_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_user_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_aggregate_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_amf_message_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);
ngx_int_t ngx_rtmp_amf_shared_object_handler(ngx_rtmp_session_t *s,
        ngx_rtmp_header_t *h, ngx_chain_t *in);


/* Shared output buffers */

void ngx_rtmp_shared_append_chain(ngx_rtmp_frame_t *frame, size_t size,
        ngx_chain_t *cl, ngx_flag_t mandatory);
ngx_rtmp_frame_t *ngx_rtmp_shared_alloc_frame(size_t size, ngx_chain_t *cl,
        ngx_flag_t mandatory);
void ngx_rtmp_shared_free_frame(ngx_rtmp_frame_t *frame);

#define ngx_rtmp_shared_acquire_frame(frame) ++frame->ref;

ngx_chain_t *ngx_rtmp_shared_state(ngx_http_request_t *r);

ngx_mpegts_frame_t *ngx_rtmp_shared_alloc_mpegts_frame();
void ngx_rtmp_shared_free_mpegts_frame(ngx_mpegts_frame_t *frame);

#define ngx_rtmp_shared_acquire_mpegts_frame(frame) ++frame->ref;

/* Sending messages */
ngx_int_t ngx_rtmp_send_message(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *out,
        ngx_uint_t priority);

/* GOP */
ngx_int_t ngx_rtmp_gop_cache(ngx_rtmp_session_t *s, ngx_rtmp_frame_t *frame);
ngx_int_t ngx_rtmp_gop_send(ngx_rtmp_session_t *s, ngx_rtmp_session_t *ss);

/* Timestamp Fix */
uint32_t ngx_rtmp_timestamp_fix(ngx_rtmp_session_t *s, uint32_t current_time,
        ngx_flag_t if_in);

/* RTMP Relation server */
ngx_rtmp_addr_conf_t *ngx_rtmp_get_addr_conf_by_listening(ngx_listening_t *ls,
        ngx_connection_t *c);
ngx_listening_t *ngx_rtmp_find_relation_port(ngx_cycle_t *cycle,
        ngx_str_t *url);

/* Note on priorities:
 * the bigger value the lower the priority.
 * priority=0 is the highest */


#define NGX_RTMP_LIMIT_SOFT         0
#define NGX_RTMP_LIMIT_HARD         1
#define NGX_RTMP_LIMIT_DYNAMIC      2

/* Protocol control messages */
ngx_rtmp_frame_t *ngx_rtmp_create_chunk_size(ngx_rtmp_session_t *s,
        uint32_t chunk_size);
ngx_rtmp_frame_t *ngx_rtmp_create_abort(ngx_rtmp_session_t *s,
        uint32_t csid);
ngx_rtmp_frame_t *ngx_rtmp_create_ack(ngx_rtmp_session_t *s,
        uint32_t seq);
ngx_rtmp_frame_t *ngx_rtmp_create_ack_size(ngx_rtmp_session_t *s,
        uint32_t ack_size);
ngx_rtmp_frame_t *ngx_rtmp_create_bandwidth(ngx_rtmp_session_t *s,
        uint32_t ack_size, uint8_t limit_type);

ngx_int_t ngx_rtmp_send_chunk_size(ngx_rtmp_session_t *s,
        uint32_t chunk_size);
ngx_int_t ngx_rtmp_send_abort(ngx_rtmp_session_t *s,
        uint32_t csid);
ngx_int_t ngx_rtmp_send_ack(ngx_rtmp_session_t *s,
        uint32_t seq);
ngx_int_t ngx_rtmp_send_ack_size(ngx_rtmp_session_t *s,
        uint32_t ack_size);
ngx_int_t ngx_rtmp_send_bandwidth(ngx_rtmp_session_t *s,
        uint32_t ack_size, uint8_t limit_type);

/* User control messages */
ngx_rtmp_frame_t *ngx_rtmp_create_stream_begin(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_rtmp_frame_t *ngx_rtmp_create_stream_eof(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_rtmp_frame_t *ngx_rtmp_create_stream_dry(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_rtmp_frame_t *ngx_rtmp_create_set_buflen(ngx_rtmp_session_t *s,
        uint32_t msid, uint32_t buflen_msec);
ngx_rtmp_frame_t *ngx_rtmp_create_recorded(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_rtmp_frame_t *ngx_rtmp_create_ping_request(ngx_rtmp_session_t *s,
        uint32_t timestamp);
ngx_rtmp_frame_t *ngx_rtmp_create_ping_response(ngx_rtmp_session_t *s,
        uint32_t timestamp);

ngx_int_t ngx_rtmp_send_stream_begin(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_stream_eof(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_stream_dry(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_set_buflen(ngx_rtmp_session_t *s,
        uint32_t msid, uint32_t buflen_msec);
ngx_int_t ngx_rtmp_send_recorded(ngx_rtmp_session_t *s,
        uint32_t msid);
ngx_int_t ngx_rtmp_send_ping_request(ngx_rtmp_session_t *s,
        uint32_t timestamp);
ngx_int_t ngx_rtmp_send_ping_response(ngx_rtmp_session_t *s,
        uint32_t timestamp);

/* AMF sender/receiver */
ngx_int_t ngx_rtmp_append_amf(ngx_rtmp_session_t *s,
        ngx_chain_t **first, ngx_chain_t **last,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);
ngx_int_t ngx_rtmp_receive_amf(ngx_rtmp_session_t *s, ngx_chain_t *in,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);

/* Metadata receiver */
ngx_int_t ngx_rtmp_receive_meta(ngx_rtmp_session_t *s,
        ngx_array_t *meta, ngx_chain_t *in);

ngx_rtmp_frame_t *ngx_rtmp_create_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);
ngx_int_t ngx_rtmp_send_amf(ngx_rtmp_session_t *s, ngx_rtmp_header_t *h,
        ngx_rtmp_amf_elt_t *elts, size_t nelts);

/* AMF status sender */
ngx_rtmp_frame_t *ngx_rtmp_create_error(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_rtmp_frame_t *ngx_rtmp_create_status(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_rtmp_frame_t *ngx_rtmp_create_play_status(ngx_rtmp_session_t *s, char *code,
        char* level, ngx_uint_t duration, ngx_uint_t bytes);
ngx_rtmp_frame_t *ngx_rtmp_create_sample_access(ngx_rtmp_session_t *s);

ngx_int_t ngx_rtmp_send_error(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_int_t ngx_rtmp_send_status(ngx_rtmp_session_t *s, char *code,
        char* level, char *desc);
ngx_int_t ngx_rtmp_send_play_status(ngx_rtmp_session_t *s, char *code,
        char* level, ngx_uint_t duration, ngx_uint_t bytes);
ngx_int_t ngx_rtmp_send_sample_access(ngx_rtmp_session_t *s);


/* Frame types */
#define NGX_RTMP_VIDEO_KEY_FRAME            1
#define NGX_RTMP_VIDEO_INTER_FRAME          2
#define NGX_RTMP_VIDEO_DISPOSABLE_FRAME     3


static ngx_inline ngx_int_t
ngx_rtmp_get_video_frame_type(ngx_chain_t *in)
{
    return (in->buf->pos[0] & 0xf0) >> 4;
}


static ngx_inline ngx_int_t
ngx_rtmp_is_codec_header(ngx_chain_t *in)
{
    return in->buf->pos + 1 < in->buf->last && in->buf->pos[1] == 0;
}


extern ngx_rtmp_bandwidth_t                 ngx_rtmp_bw_out;
extern ngx_rtmp_bandwidth_t                 ngx_rtmp_bw_in;


extern ngx_uint_t                           ngx_rtmp_naccepted;
#if (nginx_version >= 1007011)
extern ngx_queue_t                          ngx_rtmp_init_queue;
#elif (nginx_version >= 1007005)
extern ngx_thread_volatile ngx_queue_t      ngx_rtmp_init_queue;
#else
extern ngx_thread_volatile ngx_event_t     *ngx_rtmp_init_queue;
#endif

extern ngx_uint_t                           ngx_rtmp_max_module;
extern ngx_module_t                         ngx_rtmp_module;
extern ngx_module_t                         ngx_rtmp_core_module;
extern ngx_module_t                         ngx_rtmp_module;
extern ngx_module_t                         ngx_rtmp_mpegts_module;
extern ngx_module_t                         ngx_hls_cmd_module;
extern ngx_module_t                         ngx_rtmp_auto_pull_module;


#endif /* _NGX_RTMP_H_INCLUDED_ */
