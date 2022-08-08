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

#ifndef _PKTORRENT_H_
#define _PKTORRENT_H_
namespace Pktorrent {
	char* get_version();
	typedef int TORRENT_SESSION;
	typedef int TORRENT_FILE;

	enum { invalid_session = -1 };
	enum { invalid_file = -1 };

	//set dht route address
  void set_dht_route_host(const char* phost);
	//set torrent session listen port
	void set_listen_port(int port, bool inenablev6);
	/** start download torrent
	* @param sessionhandle torrent session handle default -1
	* @param filehandle torrent file handle
	* @param purl Indicates torrent file address such as
	*				test.mp4,test.mp4.torrent,magnet:?xt=urn:btih:*
	* @param path Indicates torrent save path
	* @return torrent session handle
	*/
	int add_torrent(TORRENT_SESSION sessionhandle, TORRENT_FILE& filehandle
		, char* purl,char* path);

	/** check download torrent progress
	* @param filehandle torrent file handle
	* @return 0 fail,1 download fininshed 2 downloading
	*/
	int check_torrent_finish(TORRENT_FILE filehandle);

	int64_t get_file_size(int filehandle);

	int64_t get_downloaded_size(int filehandle);

	bool generate_torrent_file(int filehandle,const char *path);

	void close_file_handle(TORRENT_FILE filehandle);

	void close_session_handle(TORRENT_SESSION session);

	bool get_file_magneturl(const char* pfile, char* magneturl, int magneturlsize);

	bool get_file_magneturlv2(const char* pfile, char* magneturl, int magneturlsize);

	bool generate_file_torrent(const char* pfile, char* destfile);
}

#endif
