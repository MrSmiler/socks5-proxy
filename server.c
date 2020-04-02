
/**
 * this file contains code for Socks 5 proxy server
 * @Author Mr.Smiler mr.smiler.0@gmail.com
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#define PRINT_ERROR() fprintf(stderr, "%s", strerror(errno))
#define SERVER_PORT 1080 /* that's the standard for Socks 5 Proxy */
#define SERVER_IP   "127.0.0.1"
#define BACKLOG_NUM 5

void handle_client(int csd);

int main() {
    
    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {	
	PRINT_ERROR();
	exit(1);
    }
    int val = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))) {
	PRINT_ERROR();
	exit(1);
    }

    puts("Socket created");
    
    struct sockaddr_in sockinfo;
    memset(&sockinfo, 0, sizeof(struct sockaddr_in));

    sockinfo.sin_family		= AF_INET;
    sockinfo.sin_port		= htons(SERVER_PORT);
    sockinfo.sin_addr.s_addr	= inet_addr(SERVER_IP);

    if (bind(sd, (struct sockaddr*)&sockinfo, sizeof(sockinfo)) < 0) {
	PRINT_ERROR();
	exit(1);
    }
    printf("bind to port %d and ip %s\n", SERVER_PORT, SERVER_IP);

    if (listen(sd, BACKLOG_NUM) < 0) {
	PRINT_ERROR();
	exit(1);
    }

    while (1) {

	struct sockaddr_in cli_addr;
	memset(&cli_addr, 0, sizeof(struct sockaddr_in));

	socklen_t cli_len;
	int cfd = accept(sd, (struct sockaddr*)&cli_addr, &cli_len); 
	if (cfd < 0) {
	    PRINT_ERROR();
	    exit(1);
	}

	handle_client(cfd);
    }

    return 0;
}


#define SOCKS_VERSION 0x05
#define NO_AUTH	      0x00
#define SOCKS_IP4     0x01

/* version selction message maximum size */
#define VS_MSG_SIZE 257

typedef unsigned char uchar_t;

/* version identifier/method selection message */
struct ver_msg {
    uchar_t ver;
    uchar_t nmethods;
    uchar_t methods[];
};

/* version identifier/method selection message response */
struct ver_msg_res {
    uchar_t ver;
    uchar_t method;
};

struct ipv4 {
    uint32_t ip;
    uint16_t port;
};

struct domain_name {
    uchar_t  size;
    uchar_t  name[255];
    uint16_t port;
};

struct ipv6 {
    uchar_t  ip[16];
    uint16_t port;
};

union addr {
    struct ipv4 v4;
    struct domain_name domain;
    struct ipv6 v6;
};

struct req_msg {
    /* protocol version */
    uchar_t ver;

    /** command either CONNECT 0x01
     *		       BIND    0x02
     *		       udp     0x03
     */
    uchar_t cmd;


    /* reserve must be 0x00 */
    uchar_t rsv;


    /** address type of following address 
     *	Ip v4	   0x01
     *	domin name 0x03
     *	ip v6	   0x04
     */
    uchar_t atyp;

    union addr dst_addr;
};


/**
 * socks 5 proxy client handler
 *
 * @Param csd client socket descriptor
 */
void handle_client(int csd) {
    printf("[+] new Client\n");

    char buf[VS_MSG_SIZE];
    read(csd, buf, VS_MSG_SIZE);

    struct ver_msg *msg = (struct ver_msg*)&buf;

    /* if protocol is not version 5 close the connection */
    if (msg->ver != SOCKS_VERSION || msg->nmethods < 1) {
	/* wrong protocol */
	close(csd);
	return;
    }

    for (int i = 0; i < msg->nmethods; i++) {
	if (msg->methods[i] != NO_AUTH) {
	    close(csd);
	    return;
	} 
    }
    
    struct ver_msg_res res_msg = {SOCKS_VERSION, NO_AUTH};
    
    write(csd, (char *)&res_msg, sizeof(res_msg));

    char buf2[sizeof(struct req_msg)];    
    read(csd, &buf2, sizeof(struct req_msg));

    struct req_msg *msg2 = (struct req_msg*)&buf2;

    printf("Version: %d, command: %d, atype: %d\n", msg2->ver, msg2->cmd, msg2->atyp);
    /* for (int i = 0; i < msg->nmethods; i++) { */
	/* printf("%d\n", msg->methods[i]); */ 
    /* } */

    close(csd);
}

