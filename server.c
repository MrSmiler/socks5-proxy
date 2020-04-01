
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define PRINT_ERROR() fprintf(stderr, "%s", strerror(errno))
#define SERVER_PORT 1080
#define SERVER_IP   "127.0.0.1"
#define BACKLOG_NUM 5

int main() {
    
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {	
	PRINT_ERROR();
    }
    puts("Socket created");
    
    struct sockaddr_in sockinfo;
    memset(&sockinfo, 0, sizeof(struct sockaddr_in));

    sockinfo.sin_family		= AF_INET;
    sockinfo.sin_port		= htons(SERVER_PORT);
    sockinfo.sin_addr.s_addr	= inet_addr(SERVER_IP);

    if (bind(sd, (struct sockaddr*)&sockinfo, sizeof(sockinfo)) < 0) {
	PRINT_ERROR();
    }
    printf("bind to port %d and ip %s\n", SERVER_PORT, SERVER_IP);

    if (listen(sd, BACKLOG_NUM) < 0) {
	PRINT_ERROR();
    }

    while (1) {
	
	struct sockaddr_in cli_addr;
	memset(&cli_addr, 0, sizeof(sockaddr_in));
	int cfd = accept(sd, (struct sockaddr)&cli_addr, sizeof(cli_addr)); 
	if (cfd < 0) {
	    PRINT_ERROR();
	}
    }

    return 0;
}

void handle_client(int cli) {
    printf("Hello From client\n");
    close(cli);
}

