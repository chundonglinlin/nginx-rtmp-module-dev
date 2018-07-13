#ifndef _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#define _NGX_HTTP_QQFLV_MODULE_H_INCLUDED_
#include "ngx_map.h"
#include "ngx_rtmp.h"

#define NGX_QQ_FLV_INDEX_SIZE           35
#define NGX_QQ_FLV_HEADER_SIZE          26

typedef struct ngx_http_qqflv_loc_conf_s ngx_http_qqflv_loc_conf_t;


typedef struct {
    ngx_str_t                       path;
    ngx_pool_t                     *pool;
    ngx_map_t                       channel_map;
    ngx_queue_t                     idle_block_index;
} ngx_http_qqflv_main_conf_t;

struct ngx_http_qqflv_loc_conf_s {
    ngx_http_qqflv_loc_conf_t      *parent;
};

typedef struct {
    ngx_str_t                       channel_name;
    ngx_queue_t                     index_queue;
    uint32_t                        backdelay;               //缓冲时间，qqlive默认为15，qt为45，回看频道由回看列表决定
    unsigned                        buname:1;                //0-qqlive,1-qt  
    ngx_map_node_t                  node;
} ngx_qq_flv_index_t;

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
    ngx_qq_flv_header_t             qqflvhdr;                 
    off_t                           file_offset;             //文件索引
    time_t                          timestamp;               //记录文件时间
    ngx_queue_t                     q;
} ngx_qq_flv_block_index_t;

#endif