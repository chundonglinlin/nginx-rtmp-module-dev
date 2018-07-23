#ifndef _QQVIDEO_LIBVERIFYTS_H_
#define _QQVIDEO_LIBVERIFYTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

#define KEY_EXPIRE_TIME_CLIENT 60

typedef struct stKeyLive_
{
    int magic_num;      //校验数
    unsigned int cur_time;  //当前时间
    int cookie_time;    //有效期
    unsigned int user_ip;   //用户ip
    unsigned int filename;      //文件名
    int level;          //请求级别
    unsigned int uin;       //用户QQ号码
    unsigned int speed;   //限速
    unsigned int platform; //播放平台
    unsigned int start_time; //开始时间
    unsigned int end_time; //结束时间
    unsigned int sdtfrom;//CDN平台
    unsigned int cgi_name;//播放 cgi编号
    unsigned int cdnIP;//cdn 调度ip
    int streamID;//心跳过期时间

    
    stKeyLive_() :
        magic_num(0),
        cur_time(0),
        cookie_time(0),
        user_ip(0),
        filename(0),
        level(0),
        uin(0),
        speed(0),
        platform(0),
        start_time(0),
        end_time(0),
        sdtfrom(0),
        cgi_name(0),
        cdnIP(7788),
        streamID(0){}
}stKeyLive;



/** 验证视频直播的vkey
* @param magic_num    校验数
* @param user_ip      用户IP
* @param filename     流ID+流类型  类型：hls/flv   例： 输入  1234567890.hls
* @param level        请求级别
* @param uin          用户QQ号码,从key中解析后返回
* @param speed        网速，单位KBps从key中解析后返回
* @param platform     播放平台,从key中解析后返回
* @param start_time   开始播放时间，单位秒,从key中解析后返回
* @param end_time     结束播放时间，单位秒,从key中解析后返回
* @param sdtfrom	  CDN平台号,从key中解析后返回
* @param cgi_name     来源cgi编号,从key中解析后返回
* new params,cdnIP and streamID 
* @param cdnIP       调度到cdn服务器的ip，,从key中解析后返回。cdn机器需要跟本机ip比较，相同或者cdnip等于7788才可以播放
* @param streamID 
* @param pEncryptData key值
* @param lDataLen     key长度
* @param flag         校验标志 相应的位为1表示检查,0表示不检查
        从最低位起，第一位检查magicnum，第二位检查时间戳，第三位检查user ip，第四位检查filename, 第五位检查level
        例如： 0x1b  表示检查magicnum、时间戳、文件名和level，ip不检查
* @param base key编码方式 16:十六进制编码 64:base64编码,默认值64
* @returns 是否成功 0:成功 非0:失败
            -1:检查key长度失败 -2:检查magicnum失败 -3:检查时间是否过期失败
            -4:检查用户IP失败 -5:检查文件名失败 -6:检查level失败 
*/
/*
int qqvideo_verifyLiveTstreamKey(int magic_num, unsigned user_ip, 
        const char* filename, int level, unsigned int *uin, 
        unsigned int *speed, unsigned int *platform, 
        unsigned int *start_time, unsigned int *end_time, 
        unsigned int *sdtfrom, unsigned int *cgi_name, 
        unsigned int *cdnIP,int *streamID,
        const char * pEncryptData, const int lDataLen , 
        int flag, const int base=64);
*/

int qqvideo_verifyLiveTstreamKey(int magic_num, unsigned user_ip, 
        const char* filename, int level, unsigned int *uin, 
        unsigned int *speed, unsigned int *platform, 
        unsigned int *start_time, unsigned int *end_time, 
        unsigned int *sdtfrom, unsigned int *cgi_name, 
        unsigned int *cdnIP,int *streamID,
        const char * pEncryptData, const int lDataLen , 
        int flag, const int base);

#ifdef __cplusplus
} /* extern "C" */
#endif



#endif /*_QQVIDEO_LIBVERIFYTS_H_*/
