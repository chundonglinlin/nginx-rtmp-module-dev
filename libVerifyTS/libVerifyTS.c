#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libVerifyTS.h"

//#define KEY_SOSO			"9viq!@p2HFBZ_m1a"
#define Key_TSTREAM_PRIVATE	"gk2$Lh-&l4#!4iow"

#ifdef __cplusplus
extern "C" 
{
#endif

const unsigned int DELTA = 0x9e3779b9;

// BKDR Hash 
unsigned int BKDRHash(const char *str)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned int hash = 0;
 
	while (*str)
	{
		hash = hash * seed + (*str++);
	}
 
	return (hash & 0x7FFFFFFF);
}

#ifndef ONLY_WITH_DECRYPT
static void TeaEncryptECB(const char *pInBuf, const char *pKey, char *pOutBuf)
{
    unsigned int y, z;
    unsigned int sum;
    unsigned int k[4];
    int i;
    /*plain-text is TCP/IP-endian;*/
    /*GetBlockBigEndian(in, y, z);*/
    y = ntohl(*((unsigned int*)pInBuf));
    z = ntohl(*((unsigned int*)(pInBuf+4)));
    /*TCP/IP network byte order (which is big-endian).*/
    for ( i = 0; i<4; i++)
    {
        /*now key is TCP/IP-endian;*/
        k[i] = ntohl(*((unsigned int*)(pKey+i*4)));
    }
    sum = 0;
    for (i=0; i<16; i++)
    {
        sum += DELTA;
        y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
        z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
    }
    *((unsigned int*)pOutBuf) = htonl(y);
    *((unsigned int*)(pOutBuf+4)) = htonl(z);
    /*now encrypted buf is TCP/IP-endian;*/
}
#endif

static void TeaDecryptECB(const char *pInBuf, const char *pKey, char *pOutBuf)
{
	unsigned int y, z, sum;
	unsigned int k[4];
	int i;
	/*now encrypted buf is TCP/IP-endian;*/
	/*TCP/IP network byte order (which is big-endian).*/
	y = ntohl(*((unsigned int*)pInBuf));
	z = ntohl(*((unsigned int*)(pInBuf+4)));
	for ( i=0; i<4; i++)
	{
		/*key is TCP/IP-endian;*/
		k[i] = ntohl(*((unsigned int*)(pKey+i*4)));
	}
	sum = DELTA << 4;
	for (i=0; i<16; i++)
	{
		z -= (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3]; 
		y -= (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
		sum -= DELTA;
	}
	*((unsigned int*)pOutBuf) = htonl(y);
	*((unsigned int*)(pOutBuf+4)) = htonl(z);
	/*now plain-text is TCP/IP-endian;*/
}

#ifndef ONLY_WITH_DECRYPT
static void oi_symmetry_encrypt2(const char* pInBuf, int nInBufLen, const char* pKey, char* pOutBuf, int *pOutBufLen)
{
	
	int nPadSaltBodyZeroLen/*PadLen(1byte)+Salt+Body+ZeroµÄ³¤¶È*/;
	int nPadlen;
	char src_buf[8], iv_plain[8], *iv_crypt;
	int src_i, i, j;

	/*¸ù¾ÝBody³¤¶È¼ÆËãPadLen,×îÐ¡±ØÐè³¤¶È±ØÐèÎª8byteµÄÕûÊý±¶*/
	nPadSaltBodyZeroLen = nInBufLen/*Body³¤¶È*/+1+2+7/*PadLen(1byte)+Salt(2byte)+Zero(8byte)*/;
	if ((nPadlen=(nPadSaltBodyZeroLen%8)) != 0)
	{
		/*Ä£8Óà0Ðè²¹0,Óà1²¹7,Óà2²¹6,...,Óà7²¹1*/
		nPadlen=8-nPadlen;
	}


	/*srand( (unsigned)time( NULL ) ); ³õÊ¼»¯Ëæ»úÊý*/
	/*¼ÓÃÜµÚÒ»¿éÊý¾Ý(8byte),È¡Ç°Ãæ10byte*/
	src_buf[0] = ((char)rand()) & 0x0f8/*×îµÍÈýÎ»´æPadLen,ÇåÁã*/ | (char)nPadlen;
	src_i = 1; /*src_iÖ¸Ïòsrc_bufÏÂÒ»¸öÎ»ÖÃ*/

	while(nPadlen--)
		src_buf[src_i++]=(char)rand(); /*Padding*/

	/*come here, src_i must <= 8*/

	for ( i=0; i<8; i++)
		iv_plain[i] = 0;

	iv_crypt = iv_plain; /*make zero iv*/
	*pOutBufLen = 0; /*init OutBufLen*/

	for (i=1;i<=2;) /*Salt(2byte)*/
	{
		if (src_i<8)
		{
			src_buf[src_i++]=(char)rand();
			i++; /*i inc in here*/
		}



		if (src_i==8)

		{

			/*src_i==8*/



			for (j=0;j<8;j++) /*¼ÓÃÜÇ°Òì»òÇ°8¸öbyteµÄÃÜÎÄ(iv_cryptÖ¸ÏòµÄ)*/

				src_buf[j]^=iv_crypt[j];



			/*pOutBuffer¡¢pInBuffer¾ùÎª8byte, pKeyÎª16byte*/

			/*¼ÓÃÜ*/

			TeaEncryptECB(src_buf, pKey, pOutBuf);



			for (j=0;j<8;j++) /*¼ÓÃÜºóÒì»òÇ°8¸öbyteµÄÃ÷ÎÄ(iv_plainÖ¸ÏòµÄ)*/

				pOutBuf[j]^=iv_plain[j];



			/*±£´æµ±Ç°µÄiv_plain*/

			for (j=0;j<8;j++)

				iv_plain[j]=src_buf[j];



			/*¸üÐÂiv_crypt*/

			src_i=0;

			iv_crypt=pOutBuf;

			*pOutBufLen+=8;

			pOutBuf+=8;

		}

	}



	/*src_iÖ¸Ïòsrc_bufÏÂÒ»¸öÎ»ÖÃ*/



	while(nInBufLen)

	{

		if (src_i<8)

		{

			src_buf[src_i++]=*(pInBuf++);

			nInBufLen--;

		}



		if (src_i==8)

		{

			/*src_i==8*/

			

			for (j=0;j<8;j++) /*¼ÓÃÜÇ°Òì»òÇ°8¸öbyteµÄÃÜÎÄ(iv_cryptÖ¸ÏòµÄ)*/

				src_buf[j]^=iv_crypt[j];

			/*pOutBuffer¡¢pInBuffer¾ùÎª8byte, pKeyÎª16byte*/

			TeaEncryptECB(src_buf, pKey, pOutBuf);



			for (j=0;j<8;j++) /*¼ÓÃÜºóÒì»òÇ°8¸öbyteµÄÃ÷ÎÄ(iv_plainÖ¸ÏòµÄ)*/

				pOutBuf[j]^=iv_plain[j];



			/*±£´æµ±Ç°µÄiv_plain*/

			for (j=0;j<8;j++)

				iv_plain[j]=src_buf[j];



			src_i=0;

			iv_crypt=pOutBuf;

			*pOutBufLen+=8;

			pOutBuf+=8;

		}

	}



	/*src_iÖ¸Ïòsrc_bufÏÂÒ»¸öÎ»ÖÃ*/



	for (i=1;i<=7;)

	{

		if (src_i<8)

		{

			src_buf[src_i++]=0;

			i++; /*i inc in here*/

		}



		if (src_i==8)

		{

			/*src_i==8*/

			

			for (j=0;j<8;j++) /*¼ÓÃÜÇ°Òì»òÇ°8¸öbyteµÄÃÜÎÄ(iv_cryptÖ¸ÏòµÄ)*/

				src_buf[j]^=iv_crypt[j];

			/*pOutBuffer¡¢pInBuffer¾ùÎª8byte, pKeyÎª16byte*/

			TeaEncryptECB(src_buf, pKey, pOutBuf);



			for (j=0;j<8;j++) /*¼ÓÃÜºóÒì»òÇ°8¸öbyteµÄÃ÷ÎÄ(iv_plainÖ¸ÏòµÄ)*/

				pOutBuf[j]^=iv_plain[j];



			/*±£´æµ±Ç°µÄiv_plain*/

			for (j=0;j<8;j++)

				iv_plain[j]=src_buf[j];



			src_i=0;

			iv_crypt=pOutBuf;

			*pOutBufLen+=8;

			pOutBuf+=8;

		}

	}



}
#endif

static void convertHexDataToString(char * pHexData, const int lHexDataLen, char * pStrBuf, const int lBufSize)
{
    int i, o;
    for (i=0, o=0; (i<lHexDataLen) && (o<lBufSize); i++, o+=2)
    {
        //sprintf(&pStrBuf[o], "%02X", pHexData[i] &0xff );
        snprintf(&pStrBuf[o], lBufSize-o-1, "%02X", pHexData[i] &0xff );
    }
}

#ifndef ONLY_WITH_DECRYPT
static int createKey( const char *pPublicData, const int lPublicDataLen, const char * pKey, char *pEncryptBuf, const int lBufSize )
{
    unsigned lCurTime;
    int lOffset =0, lTmp=0;
    char szTmp[1024];
    char szEnryptData[1024];

    if( lPublicDataLen + lOffset > (int)(sizeof(szTmp) ))
        return 0;

    memset( szTmp, 0, sizeof(szTmp));
    memcpy( &szTmp[lOffset], pPublicData, lPublicDataLen );
    lOffset += lPublicDataLen;

    if( lPublicDataLen + lOffset > (int)(sizeof(szTmp)) )
        return 0;

    time( (time_t*)&lCurTime );
    lCurTime = htonl( lCurTime );
    memcpy( &szTmp[lOffset], &lCurTime, sizeof(int) );
    lOffset += sizeof(int);

    lTmp = lBufSize;
    oi_symmetry_encrypt2(szTmp, (int)lOffset, pKey, szEnryptData, (int*)&lTmp);
    convertHexDataToString(szEnryptData, lTmp, pEncryptBuf, lBufSize);
    return strlen( pEncryptBuf );
}
#endif

int createUinKey(unsigned int uin, const char * pKey, char *pEncryptBuf, const int lBufSize)
{
    //unsigned lCurTime;
    int lOffset =0, lTmp=0;
    char szTmp[1024];
    char szEnryptData[1024];

	memset( szTmp, 0, sizeof(szTmp));
	uin = htonl(uin);
    memcpy( &szTmp[lOffset], &uin, sizeof(unsigned int) );
    lOffset += sizeof(unsigned int);

/*
    time( (time_t*)&lCurTime );
    lCurTime = htonl( lCurTime );
    memcpy( &szTmp[lOffset], &lCurTime, sizeof(int) );
    lOffset += sizeof(int);
*/

    lTmp = lBufSize;
    oi_symmetry_encrypt2(szTmp, (int)lOffset, pKey, szEnryptData, (int*)&lTmp);
    convertHexDataToString(szEnryptData, lTmp, pEncryptBuf, lBufSize);
    return strlen( pEncryptBuf );
}

static char oi_symmetry_decrypt2(const char* pInBuf, int nInBufLen, const char* pKey, char* pOutBuf, int *pOutBufLen)
{
	int nPadLen, nPlainLen;
	char dest_buf[8], zero_buf[8];
	const char *iv_pre_crypt, *iv_cur_crypt;
	int dest_i, i, j;
	//if (nInBufLen%8) return 0; BUG!
	if ((nInBufLen%8) || (nInBufLen<16)) return 0;
	TeaDecryptECB(pInBuf, pKey, dest_buf);
	nPadLen = dest_buf[0] & 0x7/*Ö»Òª×îµÍÈýÎ»*/;
	/*ÃÜÎÄ¸ñÊ½:PadLen(1byte)+Padding(var,0-7byte)+Salt(2byte)+Body(var byte)+Zero(8byte)*/
	i = nInBufLen-1/*PadLen(1byte)*/-nPadLen-2-7; /*Ã÷ÎÄ³¤¶È*/
	if (*pOutBufLen<i) return 0;
	*pOutBufLen = i;
	if (*pOutBufLen < 0) return 0;
	for ( i=0; i<8; i++)zero_buf[i] = 0;
	iv_pre_crypt = zero_buf;
	iv_cur_crypt = pInBuf; /*init iv*/
	nInBufLen -= 8;
	pInBuf += 8;
	dest_i=1; /*dest_iÖ¸Ïòdest_bufÏÂÒ»¸öÎ»ÖÃ*/
	/*°ÑPaddingÂËµô*/
	dest_i+=nPadLen;
	/*dest_i must <=8*/
	/*°ÑSaltÂËµô*/
	for (i=1; i<=2;)
	{
		if (dest_i<8)
		{
			dest_i++;
			i++;
		}
		else if (dest_i==8)
		{
			/*½â¿ªÒ»¸öÐÂµÄ¼ÓÃÜ¿é*/
			/*¸Ä±äÇ°Ò»¸ö¼ÓÃÜ¿éµÄÖ¸Õë*/
			iv_pre_crypt = iv_cur_crypt;
			iv_cur_crypt = pInBuf; 
			/*Òì»òÇ°Ò»¿éÃ÷ÎÄ(ÔÚdest_buf[]ÖÐ)*/
			for (j=0; j<8; j++)dest_buf[j]^=pInBuf[j];
			/*dest_i==8*/
			TeaDecryptECB(dest_buf, pKey, dest_buf);
			/*ÔÚÈ¡³öµÄÊ±ºò²ÅÒì»òÇ°Ò»¿éÃÜÎÄ(iv_pre_crypt)*/
			nInBufLen -= 8;
			pInBuf += 8;
			dest_i=0; /*dest_iÖ¸Ïòdest_bufÏÂÒ»¸öÎ»ÖÃ*/
		}
	}

	/*»¹Ô­Ã÷ÎÄ*/
	nPlainLen=*pOutBufLen;
	while (nPlainLen)
	{
		if (dest_i<8)
		{
			*(pOutBuf++)=dest_buf[dest_i]^iv_pre_crypt[dest_i];
			dest_i++;
			nPlainLen--;
		}
		else if (dest_i==8)
		{
			/*dest_i==8*/
			/*¸Ä±äÇ°Ò»¸ö¼ÓÃÜ¿éµÄÖ¸ë*/
			iv_pre_crypt = iv_cur_crypt;
			iv_cur_crypt = pInBuf; 
			/*½â¿ªÒ»¸öÐÂµÄ¼ÓÃÜ¿é*/
			/*Òì»òÇ°Ò»¿éÃ÷ÎÄ(ÔÚdest_buf[]ÖÐ)*/
			for (j=0; j<8; j++)dest_buf[j]^=pInBuf[j];
			TeaDecryptECB(dest_buf, pKey, dest_buf);
			/*ÔÚÈ¡³öµÄÊ±ºò²ÅÒì»òÇ°Ò»¿éÃÜÎÄ(iv_pre_crypt)*/
			nInBufLen -= 8;
			pInBuf += 8;
			dest_i=0; /*dest_iÖ¸Ïòdest_bufÏÂÒ»¸öÎ»ÖÃ*/
		}
	}

	/*Ð£ÑéZero*/
	for (i=1;i<=7;)
	{
		if (dest_i<8)
		{
			if(dest_buf[dest_i]^iv_pre_crypt[dest_i]) return 0;
			dest_i++;
			i++;
		}
		else if (dest_i==8)
		{
			/*¸Ä±äÇ°Ò»¸ö¼ÓÃÜ¿éµÄÖ¸Õë*/
			iv_pre_crypt = iv_cur_crypt;
			iv_cur_crypt = pInBuf; 
			/*½â¿ªÒ»¸öÐÂµÄ¼ÓÃÜ¿é*/
			/*Òì»òÇ°Ò»¿éÃ÷ÎÄ(ÔÚdest_buf[]ÖÐ)*/
			for (j=0; j<8; j++)dest_buf[j]^=pInBuf[j];
			TeaDecryptECB(dest_buf, pKey, dest_buf);
			/*ÔÚÈ¡³öµÄÊ±ºò²ÅÒì»òÇ°Ò»¿éÃÜÎÄ(iv_pre_crypt)*/
			nInBufLen -= 8;
			pInBuf += 8;
			dest_i=0; /*dest_iÖ¸Ïòdest_bufÏÂÒ»¸öÎ»ÖÃ*/
		}
	}
	return 1;
}


static void convertStringToHexData(const char* pStrData, const int lDataLen, char* pHexBuf, const int lBufSize)
{
	char one_byte[3];
	int i=0;
	char *pStop = NULL;

	for ( i = 0; (i < lBufSize) && (i < lDataLen/2); i++)
	{
		memcpy(one_byte, &pStrData[i * 2], 2);
		one_byte[2] = '\0';
		pHexBuf[i] = strtol(one_byte, &pStop, 16);
	}
}


static void verifyKey( const char *pEncryptData, int lEncryptDataLen, const char * pKey, char *pPublicDataBuf, int *lPublicDataBufSize )
{	
	char szTmp[128];

	convertStringToHexData(pEncryptData,lEncryptDataLen,szTmp,sizeof(szTmp));
	oi_symmetry_decrypt2(szTmp, lEncryptDataLen/2, pKey, pPublicDataBuf, lPublicDataBufSize);
}

unsigned int verifyUinKey(const char *pEncryptData, int lEncryptDataLen, const char * pKey)
{
	int lTmp = 1024;
	char szTmp[1024];
	verifyKey(pEncryptData, lEncryptDataLen, pKey, szTmp, &lTmp );
	unsigned int uin;
	memcpy(&uin, szTmp, sizeof(unsigned int));
	uin = ntohl(uin);
	return uin;
}

int my_verifyTstreamKey(int magic_num, const char* vid, unsigned lCurTime, const char * pEncryptData, const int lDataLen)
{
	int lTmp = 1024, lOffset = 0;
	stKey key_info;
	char szTmp[1024];
	memset( szTmp, 0, sizeof(szTmp) );
	
	verifyKey(pEncryptData, lDataLen, Key_TSTREAM_PRIVATE, szTmp, &lTmp);
	if( lTmp < 0 )
		return lTmp;
	
	if( lTmp < (int)(lOffset + 3*sizeof(int)) )
		return 1;	
	
	memcpy(&key_info.magic_num, &szTmp[lOffset], sizeof(int) );
	key_info.magic_num = ntohl( key_info.magic_num );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cur_time, &szTmp[lOffset], sizeof(int) );
	key_info.cur_time = ntohl( key_info.cur_time );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cookie_time, &szTmp[lOffset], sizeof(int) );
	key_info.cookie_time = ntohl( key_info.cookie_time );
	lOffset += sizeof(int);

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.user_ip, &szTmp[lOffset], sizeof(int) );
		key_info.user_ip = ntohl( key_info.user_ip );
		lOffset += sizeof(int);
	}
	else
	{
		//key_info.user_ip = user_ip;
		key_info.user_ip = 0;
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.vid, &szTmp[lOffset], sizeof(int) );
		key_info.vid = ntohl( key_info.vid );
		lOffset += sizeof(int);
	}
	else
	{
		//key_info.vid = BKDRHash(vid);
		key_info.vid = 0;
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.level, &szTmp[lOffset], sizeof(int) );
		key_info.level = ntohl( key_info.level );
		lOffset += sizeof(int);
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.uin, &szTmp[lOffset], sizeof(int) );
		key_info.uin = ntohl( key_info.uin );
		lOffset += sizeof(int);
	}
	else
	{
		key_info.uin = 0;
	}

/*
	printf("verifykey: magic_num=%d, cur_time=%u, cookie_time=%d, ip=%u, vid=%u, level=%d, uin=%u\n" , 
		key_info.magic_num,
		key_info.cur_time,
		key_info.cookie_time,
		key_info.user_ip,
		key_info.vid,
		key_info.level,
		key_info.uin);
*/

	if(magic_num != key_info.magic_num)
	{
		return 2;
	}
	
    long long key_time = key_info.cur_time + key_info.cookie_time;
    printf( "server_time: %lu, key.cur_time:%lu, key.cookie_time:%lu, key_time: %lu\n", lCurTime, key_info.cur_time, key_info.cookie_time, key_time);
	if(lCurTime > key_info.cur_time + key_info.cookie_time )
	{
		//printf( "CurTime:%lu; Encrypt Time:%lu\n", lCurTime, lUnixTime );
		return 3;
	}

	if(BKDRHash(vid) != key_info.vid)
	{
		return 4;
	}

	return 0;	
}

int qqvideo_verifyTstreamKey(int magic_num, unsigned user_ip, const char* vid, int level, unsigned *uin, const char * pEncryptData, const int lDataLen , int flag)
{
	unsigned lCurTime = 0;
	int lTmp = 1024, lOffset = 0;
	stKey key_info;
	char szTmp[1024];
	memset( szTmp, 0, sizeof(szTmp) );
	
	verifyKey(pEncryptData, lDataLen, Key_TSTREAM_PRIVATE, szTmp, &lTmp);
	if( lTmp < 0 )
		return lTmp;
	
	if( lTmp < (int)(lOffset + 3*sizeof(int)) )
		return -1;	
	
	memcpy(&key_info.magic_num, &szTmp[lOffset], sizeof(int) );
	key_info.magic_num = ntohl( key_info.magic_num );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cur_time, &szTmp[lOffset], sizeof(int) );
	key_info.cur_time = ntohl( key_info.cur_time );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cookie_time, &szTmp[lOffset], sizeof(int) );
	key_info.cookie_time = ntohl( key_info.cookie_time );
	lOffset += sizeof(int);

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.user_ip, &szTmp[lOffset], sizeof(int) );
		key_info.user_ip = ntohl( key_info.user_ip );
		lOffset += sizeof(int);
	}
	else
	{
		//key_info.user_ip = user_ip;
		key_info.user_ip = 0;
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.vid, &szTmp[lOffset], sizeof(int) );
		key_info.vid = ntohl( key_info.vid );
		lOffset += sizeof(int);
	}
	else
	{
		//key_info.vid = BKDRHash(vid);
		key_info.vid = 0;
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.level, &szTmp[lOffset], sizeof(int) );
		key_info.level = ntohl( key_info.level );
		lOffset += sizeof(int);
	}
	else
	{
		// old key, not have level
		key_info.level = level;
	}

	//if ( lOffset + sizeof(int) <= lTmp )
	if( lTmp >= (int)(lOffset + sizeof(int)) )
	{
		memcpy(&key_info.uin, &szTmp[lOffset], sizeof(int) );
		key_info.uin = ntohl( key_info.uin );
		lOffset += sizeof(int);
	}
	else
	{
		key_info.uin = 0;
	}
	if (uin != NULL)
	{
		*uin = key_info.uin;
	}

/*
	printf("verifykey: magic_num=%d, cur_time=%u, cookie_time=%d, ip=%u, vid=%u, level=%d, uin=%u\n" , 
		key_info.magic_num,
		key_info.cur_time,
		key_info.cookie_time,
		key_info.user_ip,
		key_info.vid,
		key_info.level,
		key_info.uin);
*/

	if((flag&0x01) && magic_num != key_info.magic_num)
	{
		return -2;
	}
	
	time( (time_t*)&lCurTime );
    long long key_time = key_info.cur_time + key_info.cookie_time;
    printf( "flag: 0x%x server_time: %lu, key.cur_time:%lu, key.cookie_time:%lu, key_time: %lu\n", flag, lCurTime, key_info.cur_time, key_info.cookie_time, key_time);
	if((flag&0x02) && lCurTime > key_info.cur_time + key_info.cookie_time )
	{
		//printf( "CurTime:%lu; Encrypt Time:%lu\n", lCurTime, lUnixTime );
		return -3;
	}

    printf("input IP is  %u, user IP is %u\n", ntohl(user_ip), ntohl(key_info.user_ip));
	if((flag&0x04) && user_ip != key_info.user_ip)
	{
		return -4;
	}
	
	if((flag&0x08) && BKDRHash(vid) != key_info.vid)
	{
		return -5;
	}

	if ((flag&0x10) && level != key_info.level)
	{
		return -6;
	}
	
	return 0;	
	
}

#ifndef ONLY_WITH_DECRYPT
int qqvideo_createTstreamKey(int magic_num, int cookie_time, unsigned user_ip, const char* vid, int level, unsigned uin, char * pEncryptBuf, const int lBufSize)
{
	//int ret = 0;
	unsigned lTmp = 0, lOffset = 0;
	char szTmp[1024] = {0};
	char szEnryptData[1024] = {0};
	stKey key_info;

	//magic num
	key_info.magic_num = htonl( magic_num);
	memcpy( szTmp+lOffset, &key_info.magic_num, sizeof(int) );
	lOffset += sizeof(int);
	//cur_time
	time( (time_t*)&lTmp );
   	key_info.cur_time = htonl( lTmp );	
	memcpy( szTmp+lOffset, &key_info.cur_time, sizeof(int) );
	lOffset += sizeof(int);
	//cookie_time
	key_info.cookie_time= htonl( cookie_time);
	memcpy( szTmp+lOffset, &key_info.cookie_time, sizeof(int) );
	lOffset += sizeof(int);
	//user ip
	key_info.user_ip= htonl(user_ip);
	memcpy( szTmp+lOffset, &key_info.user_ip, sizeof(int) );
	lOffset += sizeof(int);
	//vid
	key_info.vid= htonl(BKDRHash(vid));
	memcpy( szTmp+lOffset, &key_info.vid, sizeof(int) );
	lOffset += sizeof(int);
	//uin
	key_info.level = htonl(level);
	memcpy( szTmp+lOffset, &key_info.level, sizeof(int) );
	lOffset += sizeof(int);
	
	key_info.uin = htonl(uin);
	memcpy( szTmp+lOffset, &key_info.uin, sizeof(int) );
	lOffset += sizeof(int);
	
	if(lOffset*2 >= sizeof(szEnryptData))
	{
		return 0;
	}

	lTmp = lBufSize;
	
	oi_symmetry_encrypt2(szTmp, (int)lOffset, Key_TSTREAM_PRIVATE,  szEnryptData, (int *)&lTmp);
	convertHexDataToString(szEnryptData, lTmp, pEncryptBuf, lBufSize);

	return strlen(pEncryptBuf);
	
}
#endif

/*int main()
{
	int ret=0;
	char buf[1024]={0};
	int cookie_time=-1;
	stKey key;
	string vid="asd";
	ret=qqvideo_createTstreamKey(123 , 1 , 1234 , vid , buf , sizeof(buf));
	printf("buf=%s,len=%d\n" ,buf, ret);

	ret=qqvideo_verifyTstreamKey(123 ,1 , vid , buf , ret , 11);
	printf("ret=%d\n" , ret);

	return 0;
	
}
*/

#ifdef TEST_KEEP_OLD
int old_verifyTstreamKey(int magic_num , unsigned user_ip , const char* vid , const char * pEncryptData, const int lDataLen , int flag)
{
	
	char szTmp[1024];
	int lTmp=1024, lOffset=0;
	unsigned lCurTime=0;
	stKey key_info;
	memset( szTmp, 0, sizeof(szTmp) );
	verifyKey(pEncryptData,lDataLen,Key_TSTREAM_PRIVATE,szTmp,&lTmp);
	if( lTmp < 0 )
		return lTmp;
	
	if( lTmp < (int)(lOffset + 3*sizeof(int)) )
		return -1;	
	
	memcpy(&key_info.magic_num , &szTmp[lOffset], sizeof(int) );
	key_info.magic_num=ntohl( key_info.magic_num );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cur_time , &szTmp[lOffset], sizeof(int) );
	key_info.cur_time=ntohl( key_info.cur_time );
	lOffset += sizeof(int);
	
	memcpy(&key_info.cookie_time , &szTmp[lOffset], sizeof(int) );
	key_info.cookie_time=ntohl( key_info.cookie_time );
	lOffset += sizeof(int);

	memcpy(&key_info.user_ip , &szTmp[lOffset], sizeof(int) );
	key_info.user_ip=ntohl( key_info.user_ip );
	lOffset += sizeof(int);

	memcpy(&key_info.vid , &szTmp[lOffset], sizeof(int) );
	key_info.vid=ntohl( key_info.vid );
	lOffset += sizeof(int);
	
	//printf("magic_num=%d\ncur_time=%u\ncookie_time=%d\nip=%u\nvid=%u\n" , 
	//	key_info.magic_num,
	//	key_info.cur_time,
	//	key_info.cookie_time,
	//	key_info.user_ip,
	//	key_info.vid);
	
	time( (time_t*)&lCurTime );

	if((flag&0x01)&&magic_num!=key_info.magic_num)
	{
		return -2;
	}
	
	if((flag&0x02)&& lCurTime > key_info.cur_time + key_info.cookie_time )
	{
		//printf( "CurTime:%lu; Encrypt Time:%lu\n", lCurTime, lUnixTime );
		return -3;
	}

	if((flag&0x04)&&user_ip!=key_info.user_ip)
	{
		return -4;
	}
	
	if((flag&0x08)&&BKDRHash(vid)!=key_info.vid)
	{
		return -5;
	}
	
	return 0;	
	
}

int old_createTstreamKey(int magic_num , int cookie_time , unsigned user_ip , const char*  vid , char * pEncryptBuf, const int lBufSize)
{
	//int ret=0;
	char szTmp[1024]={0};
	char szEnryptData[1024]={0};
	int lTmp=0, lOffset=0;
	stKey key_info;

	//magic num
	key_info.magic_num = htonl( magic_num);
	memcpy( szTmp+lOffset , &key_info.magic_num, sizeof(int) );
	lOffset += sizeof(int);
	//cur_time
	time( (time_t*)&lTmp );
   	key_info.cur_time = htonl( lTmp );	
	memcpy( szTmp+lOffset , &key_info.cur_time, sizeof(int) );
	lOffset += sizeof(int);
	//cookie_time
	key_info.cookie_time= htonl( cookie_time);
	memcpy( szTmp+lOffset , &key_info.cookie_time, sizeof(int) );
	lOffset += sizeof(int);
	//user ip
	key_info.user_ip= htonl(user_ip);
	memcpy( szTmp+lOffset , &key_info.user_ip, sizeof(int) );
	lOffset += sizeof(int);

	//vid
	key_info.vid= htonl(BKDRHash(vid));
	memcpy( szTmp+lOffset , &key_info.vid, sizeof(int) );
	lOffset += sizeof(int);
	
	if(lOffset*2>=sizeof(szEnryptData))
	{
		return 0;
	}

	lTmp=lBufSize;
	
	oi_symmetry_encrypt2(szTmp, (int)lOffset, Key_TSTREAM_PRIVATE,  szEnryptData , (int *)&lTmp);
	convertHexDataToString(szEnryptData, lTmp, pEncryptBuf, lBufSize);

	return strlen(pEncryptBuf);
	
}

#endif

#ifdef __cplusplus
}
#endif

