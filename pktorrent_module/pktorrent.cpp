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


#include <vector>
#include <thread>
#include <mutex>
#include <string> 
#ifdef WIN32
#define stat64 _stat64
#endif
#include "pktorrent.h"
using namespace Pktorrent;
struct MagnetDownload{
  TORRENT_FILE file;
  std::string magneturl;
  std::string folder;
  int addtime;
  int endtime;
  int64_t filesize;
  int64_t downloadsize;
  int status;//0 runing 1 success 2 fail
  int livetime;
};
static std::vector<MagnetDownload> downloadlist;
static std::mutex downloadmutex;
static TORRENT_SESSION sessionid=-1;

#pragma comment(lib,"pktorrent.lib")


extern "C"{

      void clear_timeout_session( ){

        std::lock_guard<std::mutex> lc(downloadmutex);
        int t=time(0);
        for(uint32_t k=0;k<downloadlist.size();k++){
        //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"start torrent loop!!");
          if(downloadlist[k].file!=invalid_file){
            if(downloadlist[k].filesize<0){
              downloadlist[k].filesize=get_file_size(downloadlist[k].file);
            }
            if(downloadlist[k].filesize>=0 && downloadlist[k].status==0){
              auto dnsize=get_downloaded_size(downloadlist[k].file);
              //ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"size getted:%d",(int)dnsize);
              if(dnsize!=downloadlist[k].downloadsize)
                downloadlist[k].livetime=t;
              downloadlist[k].downloadsize=dnsize;
              if(downloadlist[k].downloadsize>=downloadlist[k].filesize){
                generate_torrent_file(downloadlist[k].file
                  ,(downloadlist[k].folder+"_.torrent").c_str());
                close_file_handle(downloadlist[k].file);
                downloadlist[k].file=invalid_file;
                downloadlist[k].status=1;
                downloadlist[k].endtime=t;
              }
            }
          }
          if(t-downloadlist[k].livetime>1*60 && downloadlist[k].status==0){
            if(downloadlist[k].file!=invalid_file)
              close_file_handle(downloadlist[k].file);
            downloadlist[k].file=invalid_file;
            downloadlist[k].status=2;
            downloadlist[k].endtime=t;
          }
          if(downloadlist[k].endtime && t-downloadlist[k].endtime>5*60 ){
            downloadlist.erase(downloadlist.begin()+k);
            k--;
          }
        }
      }
  int isFolder(const char* folder) {
  #if 1
  		struct stat  s;
  		if (stat (folder, &s) == 0)
  			return  s.st_mode & S_IFDIR;
  #endif
  		return 0;
  	}
    void set_listen_port(int port){
      Pktorrent::set_listen_port(port,false);
    }
    void generate_torrent(const char *p,const char *p2){
      if(p && p[0])
      Pktorrent::generate_file_torrent(p,(char*)p2);
    }
    int download_magnet( const char *p,const char *p2){
      clear_timeout_session( );
      {
        std::lock_guard<std::mutex> lc(downloadmutex );
        int findf=-1;
        for(uint32_t k=0;k<downloadlist.size();k++){
          if(downloadlist[k].magneturl==p){
            findf=k;
            break;
          }
        }
        if(findf<0){
          TORRENT_FILE filehandle;

          sessionid=add_torrent(sessionid,filehandle,(char*)p,(char*)p2);
          downloadlist.push_back({filehandle,p,p2,(int)time(0),0,-1,0,0,(int)time(0)});
          return 0;
        }else{

          TORRENT_FILE filehandle=downloadlist[findf].file;
          if(downloadlist[findf].status==1) return 100;
          if(filehandle!=invalid_file){
              if(downloadlist[findf].filesize==-1 || downloadlist[findf].downloadsize<=0) return 0;
              if(downloadlist[findf].filesize==0) return 100;
              int progress=downloadlist[findf].downloadsize*100
                /downloadlist[findf].filesize;
              if(downloadlist[findf].downloadsize && progress==0) progress=1;
              if(downloadlist[findf].downloadsize>=downloadlist[findf].filesize) {
                progress=100;
              }
              return progress;
          }else return -1;
        }
      }
    }
}
