#include "dns.h"

#define LOOP_BACK "127.0.0.1"

#define ADDRESS_LOOKUP "v10.vortex-win.data.microsoft.com"

int main(int argc, char** argv){
 	struct sockaddr_in server_addr;
	int fd = 0;	
	recv_query();
	//fd = send_query(ADDRESS_LOOKUP,DNS_SERVER_1,&server_addr);
	//recv_response(fd, &server_addr);
	//close(fd);
	return 0;
}
