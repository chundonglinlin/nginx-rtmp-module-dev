#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rbuf.h"
#include "../http/ngx_http_set_header.h"
#include "../remux/ngx_remux_flv2ts.h"

static ngx_keyval_t ngx_ts_headers[] = {
    { ngx_string("Cache-Control"),  ngx_string("no-cache") },
    { ngx_string("Content-Type"),   ngx_string("video/mp2t") },
    { ngx_null_string, ngx_null_string }
};


static char* ngx_http_testremux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_testremux_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_testremux_commands[]={
    { ngx_string("remux_test"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|
NGX_CONF_NOARGS,
      ngx_http_testremux,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

      ngx_null_command
};


static ngx_http_module_t ngx_http_testremux_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,
   
    NULL,
    NULL,

    NULL,
    NULL
};

ngx_module_t ngx_http_testremux_module = {
    NGX_MODULE_V1,
    &ngx_http_testremux_module_ctx,
    ngx_http_testremux_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_live_send_ts_header(ngx_http_request_t *r, ngx_uint_t status, ngx_keyval_t *h)
{
    ngx_int_t                           rc;

    r->headers_out.status = status;
    r->keepalive = 0; /* set Connection to closed */

    while (h && h->key.len) {
        rc = ngx_http_set_header_out(r, &h->key, &h->value);
        if (rc != NGX_OK) {
            return rc;
        }
        ++h;
    }

    return ngx_http_send_header(r);
}


static void
ngx_ts_live_cleanup_handler(void *data)
{
    ngx_remux_file_t                       *of;

    of = (ngx_remux_file_t*)data;

    ngx_remux_flv2ts_destory(of);
}

static ngx_int_t
ngx_http_testremux_handler(ngx_http_request_t *r)
{
    ngx_fd_t                            fd;
    ngx_http_cleanup_t                 *cln;
    ngx_remux_file_t                   *of;
    ngx_str_t                           filename;
    ngx_int_t                           rc;
    u_char                              filenamebuf[128];

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
         return NGX_HTTP_NOT_ALLOWED;
    }
    //drop http body
    rc = ngx_http_discard_request_body(r);
    if(rc != NGX_OK){
        return rc;
    }
    rc = ngx_http_arg(r, (u_char*)"filename", 8, &filename);
    if (rc != NGX_OK) {
        return rc;
    }
    ngx_memzero(filenamebuf, 128);
    ngx_memcpy(filenamebuf, filename.data, filename.len);
    fd = ngx_open_file(filenamebuf, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    of = ngx_pcalloc(r->connection->pool, sizeof(ngx_remux_file_t));
    off_t pos, last;
    pos = 444;
    last = 119583;
    rc = ngx_remux_flv2ts(fd, pos, last, of);
    if(rc != NGX_OK){
        return rc;
    }

    r->headers_out.content_length_n = of->content_length;

    rc = ngx_live_send_ts_header(r, NGX_HTTP_OK, ngx_ts_headers);
    if(rc != NGX_OK){
        return rc;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    cln->handler = ngx_ts_live_cleanup_handler;
    cln->data = of;

    r->read_event_handler = ngx_http_test_reading;

    return ngx_http_output_filter(r, of->content);
};


static char *
ngx_http_testremux(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_testremux_handler;
    return NGX_CONF_OK;
};