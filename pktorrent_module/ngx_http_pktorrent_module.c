/**
Copyright (c) 2021 SeaHaige

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
claim that you wrote the original software. If you use this software
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original software.

3. This notice may not be removed or altered from any source
distribution.
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef WIN32
#include<direct.h>

#else
#include <linux/limits.h>
#endif
  #define MAGNET_PARA "?magnetdownload="
typedef struct
{
        ngx_int_t pktorrent_magnetfolder;
        ngx_int_t pktorrent_magnetport;
}ngx_http_pktorrent_loc_conf_t;

typedef struct
{
        ngx_int_t pktorrent_folder;
        ngx_int_t pktorrent_generate;
        ngx_int_t pktorrent_allow;
}ngx_http_pktorrent_srv_conf_t;

static ngx_int_t ngx_http_pktorrent_init(ngx_conf_t *cf);

static void *ngx_http_pktorrent_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_pktorrent_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_pktorrent_allow(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_pktorrent_folder(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_http_pktorrent_magnetfolder(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
//static char *ngx_http_pktorrent_magnetport(ngx_conf_t *cf, ngx_command_t *cmd,
//        void *conf);

static ngx_command_t ngx_http_pktorrent_commands[] = {

        {
                ngx_string("torrent"),
                NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
                ngx_http_pktorrent_allow,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_http_pktorrent_srv_conf_t, pktorrent_allow),
                NULL },
        {
                ngx_string("torrent_generate"),
                NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
                ngx_conf_set_num_slot,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_http_pktorrent_srv_conf_t, pktorrent_generate),
                NULL },
        {
                ngx_string("torrent_folder"),
                NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
                ngx_http_pktorrent_folder,
                NGX_HTTP_SRV_CONF_OFFSET,
                offsetof(ngx_http_pktorrent_srv_conf_t, pktorrent_folder),
                NULL },
        {
                ngx_string("magnet_folder"),
                NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
                ngx_http_pktorrent_magnetfolder,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_pktorrent_loc_conf_t, pktorrent_magnetfolder),
                NULL },
        {
                ngx_string("magnet_port"),
                NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
                ngx_conf_set_num_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_pktorrent_loc_conf_t, pktorrent_magnetport),
                NULL },

        ngx_null_command
};


static ngx_http_module_t ngx_http_pktorrent_module_ctx = {
        NULL,                          /* preconfiguration */
        ngx_http_pktorrent_init,           /* postconfiguration */

        NULL,                          /* create main configuration */
        NULL,                          /* init main configuration */

        ngx_http_pktorrent_create_srv_conf,                          /* create server configuration */
        NULL,                          /* merge server configuration */

        ngx_http_pktorrent_create_loc_conf, /* create location configuration */
        NULL                            /* merge location configuration */
};


ngx_module_t ngx_http_pktorrent_module = {
        NGX_MODULE_V1,
        &ngx_http_pktorrent_module_ctx,    /* module context */
        ngx_http_pktorrent_commands,       /* module directives */
        NGX_HTTP_MODULE,               /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        NULL,                          /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        NULL,                          /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};
void generate_torrent(const char *p,const char *p2);
int download_magnet( const char *p,const char *p2);

void set_listen_port(int port);
static int File_Exist(const char*file){
  FILE*fp=fopen(file,"rb");
  if(!fp) return 0;
  fclose(fp);
  return 1;
}
#ifdef WIN32
#define PATH_MAX MAX_PATH
#endif
static ngx_int_t
ngx_http_pktorrent_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    //ngx_chain_t  out;
    ngx_http_pktorrent_srv_conf_t* my_conf;
    ngx_http_pktorrent_loc_conf_t* loc_conf;
    ngx_chain_t  out;
    ngx_str_t  path;
    size_t rt;
    char pathbuff[PATH_MAX];
    char pathlock[PATH_MAX];
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_pktorrent_module);
    if (loc_conf->pktorrent_magnetfolder==1 )
    {
        char *pdn=strstr((const char*)r->uri.data,MAGNET_PARA);
        if(pdn && strlen(pdn)<200){
          pdn+=strlen(MAGNET_PARA);
          char magneturl[256];
          sprintf(magneturl,"magnet:?xt=urn:btih:%s",pdn);
          if(strrchr(magneturl,' ')) strrchr(magneturl,' ')[0]=0;
          if(strstr(magneturl,"dn=")){
            return NGX_DECLINED;
          }
          if(ngx_http_map_uri_to_path(r,&path,&rt,0) ){
            if(strlen((char*)path.data)+strlen(pdn)>=PATH_MAX-10)
                return NGX_DECLINED;
            strcpy(pathbuff,(char*)path.data);
            strcat(pathbuff,pdn);
            if(strrchr(pathbuff,' ')) strrchr(pathbuff,' ')[0]=0;
            strcat(pathbuff,"_.torrent");
            int progress=0;
            if(File_Exist(pathbuff)){
              progress=100;
            }else{
              strrchr(pathbuff,'_')[0]=0;
              //mode_t mode = umask(0);
              if(!isFolder(pathbuff))
#ifdef WIN32
                mkdir(pathbuff);
#else
                mkdir(pathbuff,0777);
#endif
              //umask(mode);
              static int setportflag;
              if(!setportflag){
                setportflag=1;
                if(loc_conf->pktorrent_magnetport!=-1)
                set_listen_port(loc_conf->pktorrent_magnetport);
              }
              progress=download_magnet( magneturl,pathbuff);
            }
            b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
            if (b == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ngx_str_set(&r->headers_out.content_type, "application/json");
            char  ngx_buff[100];
            sprintf(ngx_buff,"{progress:%d}",progress);
            int content_length=strlen((char*)ngx_buff);
            out.buf = b;
            out.next = NULL;
            b->pos =(u_char*) ngx_buff;
            b->last = (u_char*)ngx_buff + content_length;
            b->memory = 1;    /* this buffer is in memory */
            b->last_buf = 1;
            r->headers_out.status = NGX_HTTP_OK;
            r->headers_out.content_length_n = content_length;
            rc = ngx_http_send_header(r);
            if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
                    return rc;
            }
            return ngx_http_output_filter(r, &out);
          }
        }
        return NGX_DECLINED;
    }
    my_conf = ngx_http_get_module_srv_conf(r, ngx_http_pktorrent_module);
    if (my_conf->pktorrent_allow == 0 )
    {
        //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "torrent is empty!");
        return NGX_DECLINED;
    }
    //char cbuf[1024];
    int istorrent=0;
    char *endp=strrchr((char*)r->uri.data,' ');
    if(endp && endp-(char*)r->uri.data<1024){
      int sz=endp-(char*)r->uri.data;
      if(sz>8 && strncmp(endp-8,".torrent",8)==0){
        istorrent=1;
      }
    }
    if(!istorrent){
      //ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, cbuf);
      return NGX_DECLINED;
    }
    if (!(r->method & (NGX_HTTP_GET))) {
            return NGX_HTTP_NOT_ALLOWED;
    }
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
      return rc;
    }
    ngx_str_set(&r->headers_out.content_type, "application/torrent");
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if(ngx_http_map_uri_to_path(r,&path,&rt,0) ){
      if(File_Exist((const char*)path.data))
        return NGX_DECLINED;
    }else
      return NGX_DECLINED;
    if(strlen((const char*)path.data)>=PATH_MAX)
      return NGX_DECLINED;
    strcpy(pathbuff,(char*)path.data);
    strrchr(pathbuff,'.')[0]=0;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, pathbuff);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, my_conf->pktorrent_folder?"folderon":"folderoff");
    if(isFolder((const char*)pathbuff) && my_conf->pktorrent_folder!=1 ){
      return NGX_DECLINED;
    }
    strcpy(pathlock,(char*)path.data);
    strrchr(pathlock,'.')[0]=0;
    strcat(pathlock,".pklock");
    if(File_Exist((const char*)pathlock)){
      return NGX_AGAIN;
      #if 0
      for(int k=0;k<my_conf->pktorrent_generate;k++){
        if(!File_Exist((const char*)pathlock))
          break;
#ifdef WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
      }
      if(File_Exist((const char*)pathlock))
        return NGX_DECLINED;
      #endif
    }
    FILE*lockfp=fopen(pathlock,"wb");
    char *plocaldata=strrchr((const char*)path.data,'.');
    *plocaldata=0;
    strcat(plocaldata,".XXXXXX");
    #ifdef WIN32
    _mktemp(path.data);
    #else
    int fd = mkstemp((char*)path.data);
    if(fd==-1){
    }else
      close(fd);
    #endif
    generate_torrent(pathbuff,(char*)path.data);
    strcat(pathbuff,".torrent");
    if(rename((char*)path.data,pathbuff)!=0){
      unlink((char*)path.data);
    }
    if(lockfp){
      fclose(lockfp);
      unlink(pathlock);
    }
    return NGX_DECLINED;
}

static void *ngx_http_pktorrent_create_loc_conf(ngx_conf_t *cf)
{
        ngx_http_pktorrent_loc_conf_t* local_conf = NULL;
        local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pktorrent_loc_conf_t));
        if (local_conf == NULL)
        {
                return NULL;
        }

        //ngx_str_null(&local_conf->pktorrent_string);
        //local_conf->pktorrent_counter = NGX_CONF_UNSET;
        local_conf->pktorrent_magnetfolder = NGX_CONF_UNSET;
        local_conf->pktorrent_magnetport = NGX_CONF_UNSET;

        return local_conf;
}

static void *ngx_http_pktorrent_create_srv_conf(ngx_conf_t *cf)
{
        ngx_http_pktorrent_srv_conf_t* local_conf = NULL;
        local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pktorrent_srv_conf_t));
        if (local_conf == NULL)
        {
                return NULL;
        }

        //ngx_str_null(&local_conf->pktorrent_string);
        local_conf->pktorrent_allow = NGX_CONF_UNSET;
        local_conf->pktorrent_folder = NGX_CONF_UNSET;
        local_conf->pktorrent_generate = 5;

        return local_conf;
}

static char *ngx_http_pktorrent_allow(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    char* rv = NULL;
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    return rv;
}

static char *ngx_http_pktorrent_folder(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    char* rv = NULL;
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    return rv;
}
static char *ngx_http_pktorrent_magnetfolder(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    ngx_http_pktorrent_loc_conf_t* local_conf;
    local_conf = conf;
    char* rv = NULL;
    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);
    if(ccf->worker_processes>1){
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "pktorrent_magnetfolder off,please set worker_processes to 1 !!!!!");
      local_conf->pktorrent_magnetfolder=0;
    }

    return rv;
}

static ngx_int_t
ngx_http_pktorrent_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
            return NGX_ERROR;
    }
    *h = ngx_http_pktorrent_handler;
    return NGX_OK;
}
