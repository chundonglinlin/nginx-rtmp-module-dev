
/*
 * Copyright (C) Roman Arutyunyan
 */

#ifndef _NGX_RTMP_BITOP_H_INCLUDED_
#define _NGX_RTMP_BITOP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ngx_rtmp.h"


typedef struct {
    u_char      *pos;
    u_char      *last;
    ngx_uint_t   offs;
    ngx_uint_t   err;
} ngx_rtmp_bit_reader_t;


void ngx_rtmp_bit_init_reader(ngx_rtmp_bit_reader_t *br, u_char *pos,
    u_char *last);
uint64_t ngx_rtmp_bit_read(ngx_rtmp_bit_reader_t *br, ngx_uint_t n);
uint64_t ngx_rtmp_bit_read_golomb(ngx_rtmp_bit_reader_t *br);


#define ngx_rtmp_bit_read_err(br) ((br)->err)

#define ngx_rtmp_bit_read_eof(br) ((br)->pos == (br)->last)

#define ngx_rtmp_bit_read_8(br)                                               \
    ((uint8_t) ngx_rtmp_bit_read(br, 8))

#define ngx_rtmp_bit_read_16(br)                                              \
    ((uint16_t) ngx_rtmp_bit_read(br, 16))

#define ngx_rtmp_bit_read_32(br)                                              \
    ((uint32_t) ngx_rtmp_bit_read(br, 32))

#define ngx_rtmp_bit_read_64(br)                                              \
    ((uint64_t) ngx_rtmp_read(br, 64))

//pps
#if defined(__GNUC__)
#    define av_unused __attribute__((unused))
#else
#    define av_unused
#endif

/**
 * rational number numerator/denominator
 */
typedef struct AVRational{
    int num; ///< numerator
    int den; ///< denominator
} AVRational;

enum AVColorPrimaries {
    AVCOL_PRI_BT709       = 1, ///< also ITU-R BT1361 / IEC 61966-2-4 / SMPTE RP177 Annex B
    AVCOL_PRI_UNSPECIFIED = 2,
    AVCOL_PRI_RESERVED    = 3,
    AVCOL_PRI_BT470M      = 4,
    AVCOL_PRI_BT470BG     = 5, ///< also ITU-R BT601-6 625 / ITU-R BT1358 625 / ITU-R BT1700 625 PAL & SECAM
    AVCOL_PRI_SMPTE170M   = 6, ///< also ITU-R BT601-6 525 / ITU-R BT1358 525 / ITU-R BT1700 NTSC
    AVCOL_PRI_SMPTE240M   = 7, ///< functionally identical to above
    AVCOL_PRI_FILM        = 8,
    AVCOL_PRI_BT2020      = 9, ///< ITU-R BT2020
    AVCOL_PRI_NB,              ///< Not part of ABI
};

/**
 * Color Transfer Characteristic.
 */
enum AVColorTransferCharacteristic {
    AVCOL_TRC_BT709        = 1,  ///< also ITU-R BT1361
    AVCOL_TRC_UNSPECIFIED  = 2,
    AVCOL_TRC_RESERVED     = 3,
    AVCOL_TRC_GAMMA22      = 4,  ///< also ITU-R BT470M / ITU-R BT1700 625 PAL & SECAM
    AVCOL_TRC_GAMMA28      = 5,  ///< also ITU-R BT470BG
    AVCOL_TRC_SMPTE170M    = 6,  ///< also ITU-R BT601-6 525 or 625 / ITU-R BT1358 525 or 625 / ITU-R BT1700 NTSC
    AVCOL_TRC_SMPTE240M    = 7,
    AVCOL_TRC_LINEAR       = 8,  ///< "Linear transfer characteristics"
    AVCOL_TRC_LOG          = 9,  ///< "Logarithmic transfer characteristic (100:1 range)"
    AVCOL_TRC_LOG_SQRT     = 10, ///< "Logarithmic transfer characteristic (100 * Sqrt(10) : 1 range)"
    AVCOL_TRC_IEC61966_2_4 = 11, ///< IEC 61966-2-4
    AVCOL_TRC_BT1361_ECG   = 12, ///< ITU-R BT1361 Extended Colour Gamut
    AVCOL_TRC_IEC61966_2_1 = 13, ///< IEC 61966-2-1 (sRGB or sYCC)
    AVCOL_TRC_BT2020_10    = 14, ///< ITU-R BT2020 for 10 bit system
    AVCOL_TRC_BT2020_12    = 15, ///< ITU-R BT2020 for 12 bit system
    AVCOL_TRC_NB,                ///< Not part of ABI
};
    
/**
 * YUV colorspace type.
 */
enum AVColorSpace {
    AVCOL_SPC_RGB         = 0,
    AVCOL_SPC_BT709       = 1,  ///< also ITU-R BT1361 / IEC 61966-2-4 xvYCC709 / SMPTE RP177 Annex B
    AVCOL_SPC_UNSPECIFIED = 2,
    AVCOL_SPC_RESERVED    = 3,
    AVCOL_SPC_FCC         = 4,
    AVCOL_SPC_BT470BG     = 5,  ///< also ITU-R BT601-6 625 / ITU-R BT1358 625 / ITU-R BT1700 625 PAL & SECAM / IEC 61966-2-4 xvYCC601
    AVCOL_SPC_SMPTE170M   = 6,  ///< also ITU-R BT601-6 525 / ITU-R BT1358 525 / ITU-R BT1700 NTSC / functionally identical to above
    AVCOL_SPC_SMPTE240M   = 7,
    AVCOL_SPC_YCOCG       = 8,  ///< Used by Dirac / VC-2 and H.264 FRext, see ITU-T SG16
    AVCOL_SPC_BT2020_NCL  = 9,  ///< ITU-R BT2020 non-constant luminance system
    AVCOL_SPC_BT2020_CL   = 10, ///< ITU-R BT2020 constant luminance system
    AVCOL_SPC_NB,               ///< Not part of ABI
};
#define AVCOL_SPC_YCGCO AVCOL_SPC_YCOCG
/**
 * Sequence parameter set
 */
typedef struct SPS {
    unsigned int sps_id;
    int profile_idc;
    int level_idc;
    int chroma_format_idc;
    int transform_bypass;              ///< qpprime_y_zero_transform_bypass_flag
    int log2_max_frame_num;            ///< log2_max_frame_num_minus4 + 4
    int poc_type;                      ///< pic_order_cnt_type
    int log2_max_poc_lsb;              ///< log2_max_pic_order_cnt_lsb_minus4
    int delta_pic_order_always_zero_flag;
    int offset_for_non_ref_pic;
    int offset_for_top_to_bottom_field;
    int poc_cycle_length;              ///< num_ref_frames_in_pic_order_cnt_cycle
    int ref_frame_count;               ///< num_ref_frames
    int gaps_in_frame_num_allowed_flag;
    int mb_width;                      ///< pic_width_in_mbs_minus1 + 1
    int mb_height;                     ///< pic_height_in_map_units_minus1 + 1
    int frame_mbs_only_flag;
    int mb_aff;                        ///< mb_adaptive_frame_field_flag
    int direct_8x8_inference_flag;
    int crop;                          ///< frame_cropping_flag

    /* those 4 are already in luma samples */
    int vui_parameters_present_flag;
    AVRational sar;
    int video_signal_type_present_flag;
    int full_range;
    int colour_description_present_flag;
    enum AVColorPrimaries color_primaries;
    enum AVColorTransferCharacteristic color_trc;
    enum AVColorSpace colorspace;
    int timing_info_present_flag;
    uint32_t num_units_in_tick;
    uint32_t time_scale;
    int fixed_frame_rate_flag;
    short offset_for_ref_frame[256]; // FIXME dyn aloc?
    int bitstream_restriction_flag;
    int num_reorder_frames;
    int scaling_matrix_present;
    uint8_t scaling_matrix4[6][16];
    uint8_t scaling_matrix8[6][64];
    int nal_hrd_parameters_present_flag;
    int vcl_hrd_parameters_present_flag;
    int pic_struct_present_flag;
    int time_offset_length;
    int cpb_cnt;                          ///< See H.264 E.1.2
    int initial_cpb_removal_delay_length; ///< initial_cpb_removal_delay_length_minus1 + 1
    int cpb_removal_delay_length;         ///< cpb_removal_delay_length_minus1 + 1
    int dpb_output_delay_length;          ///< dpb_output_delay_length_minus1 + 1
    int bit_depth_luma;                   ///< bit_depth_luma_minus8 + 8
    int bit_depth_chroma;                 ///< bit_depth_chroma_minus8 + 8
    int residual_color_transform_flag;    ///< residual_colour_transform_flag
    int constraint_set_flags;             ///< constraint_set[0-3]_flag
} SPS;

typedef struct GetBitContext  {
    const uint8_t *buffer, *buffer_end;
    int index;
    int size_in_bits;
    int size_in_bits_plus8;
} GetBitContext;
  
#if UNCHECKED_BITSTREAM_READER
#define OPEN_READER(name, gb)                   \
        unsigned int name ## _index = (gb)->index;  \
        unsigned int av_unused name ## _cache
    
#define HAVE_BITS_REMAINING(name, gb) 1
#else
#define OPEN_READER(name, gb)                   \
        unsigned int name ## _index = (gb)->index;  \
        unsigned int av_unused name ## _cache = 0;  \
        unsigned int av_unused name ## _size_plus8 = (gb)->size_in_bits_plus8
    
#define HAVE_BITS_REMAINING(name, gb) name ## _index < name ## _size_plus8
#endif
    
    
#   define AV_RL32(x)                                \
        (((uint32_t)((const uint8_t*)(x))[3] << 24) |    \
                   (((const uint8_t*)(x))[2] << 16) |    \
                   (((const uint8_t*)(x))[1] <<  8) |    \
                    ((const uint8_t*)(x))[0])
    
#   define AV_RB32(x)                                \
        (((uint32_t)((const uint8_t*)(x))[0] << 24) |    \
                   (((const uint8_t*)(x))[1] << 16) |    \
                   (((const uint8_t*)(x))[2] <<  8) |    \
                    ((const uint8_t*)(x))[3])
    
#   define AV_RL64(x)                                   \
        (((uint64_t)((const uint8_t*)(x))[7] << 56) |       \
         ((uint64_t)((const uint8_t*)(x))[6] << 48) |       \
         ((uint64_t)((const uint8_t*)(x))[5] << 40) |       \
         ((uint64_t)((const uint8_t*)(x))[4] << 32) |       \
         ((uint64_t)((const uint8_t*)(x))[3] << 24) |       \
         ((uint64_t)((const uint8_t*)(x))[2] << 16) |       \
         ((uint64_t)((const uint8_t*)(x))[1] <<  8) |       \
          (uint64_t)((const uint8_t*)(x))[0])
    
#   define AV_RB64(x)                                   \
        (((uint64_t)((const uint8_t*)(x))[0] << 56) |       \
         ((uint64_t)((const uint8_t*)(x))[1] << 48) |       \
         ((uint64_t)((const uint8_t*)(x))[2] << 40) |       \
         ((uint64_t)((const uint8_t*)(x))[3] << 32) |       \
         ((uint64_t)((const uint8_t*)(x))[4] << 24) |       \
         ((uint64_t)((const uint8_t*)(x))[5] << 16) |       \
         ((uint64_t)((const uint8_t*)(x))[6] <<  8) |       \
          (uint64_t)((const uint8_t*)(x))[7])
    
# ifdef LONG_BITSTREAM_READER
    
# define UPDATE_CACHE_LE(name, gb) name ## _cache = \
          AV_RL64((gb)->buffer + (name ## _index >> 3)) >> (name ## _index & 7)
    
# define UPDATE_CACHE_BE(name, gb) name ## _cache = \
          AV_RB64((gb)->buffer + (name ## _index >> 3)) >> (32 - (name ## _index & 7))
    
#else
    
# define UPDATE_CACHE_LE(name, gb) name ## _cache = \
          AV_RL32((gb)->buffer + (name ## _index >> 3)) >> (name ## _index & 7)
    
# define UPDATE_CACHE_BE(name, gb) name ## _cache = \
          AV_RB32((gb)->buffer + (name ## _index >> 3)) << (name ## _index & 7)
    
#endif
    
#ifdef BITSTREAM_READER_LE
    
# define UPDATE_CACHE(name, gb) UPDATE_CACHE_LE(name, gb)
    
# define SKIP_CACHE(name, gb, num) name ## _cache >>= (num)
    
#else
    
# define UPDATE_CACHE(name, gb) UPDATE_CACHE_BE(name, gb)
    
# define SKIP_CACHE(name, gb, num) name ## _cache <<= (num)
    
#endif
    
#ifndef NEG_SSR32
#   define NEG_SSR32(a,s) ((( int32_t)(a))>>(32-(s)))
#endif
    
#ifndef NEG_USR32
#   define NEG_USR32(a,s) (((uint32_t)(a))>>(32-(s)))
#endif
    
#define SHOW_UBITS_LE(name, gb, num) zero_extend(name ## _cache, num)
#define SHOW_SBITS_LE(name, gb, num) sign_extend(name ## _cache, num)
    
#define SHOW_UBITS_BE(name, gb, num) NEG_USR32(name ## _cache, num)
#define SHOW_SBITS_BE(name, gb, num) NEG_SSR32(name ## _cache, num)
    
#ifdef BITSTREAM_READER_LE
#   define SHOW_UBITS(name, gb, num) SHOW_UBITS_LE(name, gb, num)
#   define SHOW_SBITS(name, gb, num) SHOW_SBITS_LE(name, gb, num)
#else
#   define SHOW_UBITS(name, gb, num) SHOW_UBITS_BE(name, gb, num)
#   define SHOW_SBITS(name, gb, num) SHOW_SBITS_BE(name, gb, num)
#endif
    
#define FFMAX(a,b) ((a) > (b) ? (a) : (b))
#define FFMIN(a,b) ((a) > (b) ? (b) : (a))
    
#if UNCHECKED_BITSTREAM_READER
#   define SKIP_COUNTER(name, gb, num) name ## _index += (num)
#else
#   define SKIP_COUNTER(name, gb, num) \
        name ## _index = FFMIN(name ## _size_plus8, name ## _index + (num))
#endif
    
#define LAST_SKIP_BITS(name, gb, num) SKIP_COUNTER(name, gb, num)
    
#define CLOSE_READER(name, gb) (gb)->index = name ## _index
    
#define GET_CACHE(name, gb) ((uint32_t) name ## _cache)
    
extern const uint8_t ff_golomb_vlc_len[512];
extern const uint8_t ff_ue_golomb_vlc_code[512];
extern const  int8_t ff_se_golomb_vlc_code[512];
extern const uint8_t ff_ue_golomb_len[256];

extern const uint8_t ff_interleaved_golomb_vlc_len[256];
extern const uint8_t ff_interleaved_ue_golomb_vlc_code[256];
extern const  int8_t ff_interleaved_se_golomb_vlc_code[256];
extern const uint8_t ff_interleaved_dirac_golomb_vlc_code[256];
extern const uint8_t ff_log2_tab[256];

int ngx_parse_h264_sps_fps(ngx_rtmp_session_t *s, unsigned char * p, int si);


#endif /* _NGX_RTMP_BITOP_H_INCLUDED_ */
