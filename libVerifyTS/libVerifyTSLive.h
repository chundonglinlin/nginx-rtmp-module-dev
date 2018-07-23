#ifndef _LIB_VERIFYTS_LIVE_H
#define _LIB_VERIFYTS_LIVE_H


typedef struct stKeyLive_
{
    int magic_num;      //У����
    unsigned int cur_time;  //��ǰʱ��
    int cookie_time;    //��Ч��
    unsigned int user_ip;   //�û�ip
    unsigned int filename;      //�ļ���
    int level;          //���󼶱�
    unsigned int uin;       //�û�QQ����
    unsigned int speed;   //����
    unsigned int platform; //����ƽ̨
    unsigned int start_time; //��ʼʱ��
    unsigned int end_time; //����ʱ��
    unsigned int sdtfrom;//CDNƽ̨
    unsigned int cgi_name;//���� cgi���
    unsigned int cdnIP;//cdn ����ip
    int streamID;//��������ʱ��

    
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


/** ��֤��Ƶֱ����vkey
* @param magic_num    У����
* @param user_ip      �û�IP
* @param filename     �ļ���
* @param level        ���󼶱�
* @param uin          �û�QQ����,��key�н����󷵻�
* @param speed        ���٣���λKBps��key�н����󷵻�
* @param platform     ����ƽ̨,��key�н����󷵻�
* @param start_time   ��ʼ����ʱ�䣬��λ��,��key�н����󷵻�
* @param end_time     ��������ʱ�䣬��λ��,��key�н����󷵻�
* @param sdtfrom      CDNƽ̨��,��key�н����󷵻�
* @param cgi_name     ��Դcgi���,��key�н����󷵻�
* new params,cdnIP and streamID
* @param cdnIP       ���ȵ�CDN��������ip,�Խ�CDN��Ҫ������ip�Ƚ�,���CDN��Ҫ�����Ԥ����ı�űȽ�
* @param streamID    ��ID
* @param pEncryptData keyֵ
* @param lDataLen     key����
* @param flag         У���־ ��Ӧ��λΪ1��ʾ���,0��ʾ�����
�����λ�𣬵�һλ���magicnum���ڶ�λ���ʱ���������λ���user ip������λ���filename, ����λ���level ����λ���CDN IP
���磺 0x1b  ��ʾ���magicnum��ʱ������ļ�����level��ip�����
* @param base key���뷽ʽ 16:ʮ�����Ʊ��� 64:base64����,Ĭ��ֵ64
* @returns �Ƿ�ɹ� 0:�ɹ� ��0:ʧ��
-1:���key����ʧ�� -2:���magicnumʧ�� -3:���ʱ���Ƿ����ʧ��
-4:����û�IPʧ�� -5:����ļ���ʧ�� -6:���levelʧ�� -7:CDN ip���ʧ�� -8:cookietime����(����һ��)
*/
int qqvideo_verifyLiveTstreamKey(int magic_num, unsigned user_ip,
	const char* filename, int level, unsigned int *uin,
	unsigned int *speed, unsigned int *platform,
	unsigned int *start_time, unsigned int *end_time,
	unsigned int *sdtfrom, unsigned int *cgi_name, /*add sdtfrom and cgi_name */
	unsigned int cdnIP, int *streamID,
	const char * pEncryptData, const int lDataLen,
	int flag, const int base);

#endif
