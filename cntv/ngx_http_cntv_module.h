#ifndef _NGX_HTTP_CNTV_MODULE_H_INCLUDED_
#define _NGX_HTTP_CNTV_MODULE_H_INCLUDED_

typedef struct {
	uint32_t		id_time;
    uint32_t        start_time;
    uint32_t        end_time;
    uint32_t        offset;
    uint32_t        size;
}ngx_http_cntv_slice_index_t;

ngx_flag_t ngx_http_cntv_check_channel_record(ngx_int_t channel_id);
void ngx_http_cntv_add_slice_index(ngx_str_t *name, ngx_int_t frag_time, ngx_http_cntv_slice_index_t *si, ngx_str_t *dat_path);
	

#endif


