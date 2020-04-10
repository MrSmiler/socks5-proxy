
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
#include <pthread.h>

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

    puts("[+] Socket created");
    
    struct sockaddr_in sockinfo;
    memset(&sockinfo, 0, sizeof(struct sockaddr_in));

    sockinfo.sin_family		= AF_INET;
    sockinfo.sin_port		= htons(SERVER_PORT);
    sockinfo.sin_addr.s_addr	= inet_addr(SERVER_IP);

    if (bind(sd, (struct sockaddr*)&sockinfo, sizeof(sockinfo)) < 0) {
	PRINT_ERROR();
	exit(1);
    }
    printf("[+] bind to port %d and ip %s\n", SERVER_PORT, SERVER_IP);

    if (listen(sd, BACKLOG_NUM) < 0) {
	PRINT_ERROR();
	exit(1);
    }

    printf("[+] listening to new connections\n");

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
    struct ipv4		v4;
    struct domain_name	domain;
    struct ipv6		v6;
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

struct res_msg {
    uchar_t ver;

    /**
     * repli
     * X'00' succeeded
     * X'01' general SOCKS server failure
     * X'02' connection not allowed by ruleset
     * X'03' Network unreachable
     * X'04' Host unreachable
     * X'05' Connection refused
     * X'06' TTL expired
     * X'07' Command not supported
     * X'08' Address type not supported
     * X'09' to X'FF' unassigned
     */
    uchar_t rep;

    /* reserver */
    uchar_t rsv;


    /** address type of following address 
     *	Ip v4	   0x01
     *	domin name 0x03
     *	ip v6	   0x04
     */
    uchar_t atyp;

    struct ipv4 addr; 
};

struct tinfo {
    /* source and destination sockets passing to thread */
    int src_so;
    int dst_so;
};

void *transfer(void *args);

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

    #ifdef DEBUG 
    /* if protocol is not version 5 close the connection */
    printf("Version: %d, nmethods: %d\n", msg->ver, msg->nmethods);

    for (int i = 0; i < msg->nmethods; i++) {
	printf("%d\n", msg->methods[i]); 
    }
    #endif


    if (msg->ver != SOCKS_VERSION || msg->nmethods < 1) {
	/* wrong protocol */
	close(csd);
	return;
    }

    int flag = 0;
    for (int i = 0; i < msg->nmethods; i++) {
	if (msg->methods[i] == NO_AUTH) {
	    flag = 1;
	} 
    }

    if (!flag) {
	close(csd);
	return;
    }

    
    struct ver_msg_res res_msg = {SOCKS_VERSION, NO_AUTH};
    
    write(csd, (char *)&res_msg, sizeof(res_msg));

    char buf2[sizeof(struct req_msg)];    
    read(csd, &buf2, sizeof(struct req_msg));

    struct req_msg *msg2 = (struct req_msg*)&buf2;

    if (msg2->atyp != SOCKS_IP4) {
	puts("here atyp other thank ipv4"); 
	close(csd);
	return;
    }

    int sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {	
	PRINT_ERROR();
	close(csd);
	return;	
    }

    struct sockaddr_in soaddr;
    memset(&soaddr, 0, sizeof(soaddr));
    soaddr.sin_family	    = AF_INET;
    soaddr.sin_port	    = msg2->dst_addr.v4.port;
    soaddr.sin_addr.s_addr  = msg2->dst_addr.v4.ip;

    if (connect(sd, (struct sockaddr*)&soaddr, sizeof(soaddr)) < 0) {
	PRINT_ERROR();
	close(csd);
	close(sd);
	return;	
    }

    struct res_msg rmsg;
    memset(&rmsg, 0, sizeof(soaddr));

    rmsg.ver  = SOCKS_VERSION;
    rmsg.rep  = 0x00;	/* connection secceeded */
    rmsg.rsv  = 0x00;
    rmsg.atyp = SOCKS_IP4;
    rmsg.addr.port = soaddr.sin_port;
    rmsg.addr.ip   = soaddr.sin_addr.s_addr;

    write(csd, (char *)&rmsg, sizeof(rmsg));

    pthread_t t1, t2;
    struct tinfo info1 = {.src_so = csd, .dst_so = sd};
    struct tinfo info2 = {.src_so = sd, .dst_so = csd};
    pthread_create(&t1, NULL, transfer, (void *)&info1);
    pthread_create(&t2, NULL, transfer, (void *)&info2);

    /* printf("Version: %d, command: %d, atype: %d\n", msg2->ver, msg2->cmd, msg2->atyp); */

    /* for (int i = 0; i < msg->nmethods; i++) { */
	/* printf("%d\n", msg->methods[i]); */ 
    /* } */

    // close(csd);
}

void *transfer(void *args) {
    struct tinfo *arg = (struct tinfo*)args;
    /* source socket */
    int src_so = arg->src_so;

    /* destination socket */
    int dst_so = arg->dst_so;

    while (1) {
	char buf[1024];
	size_t s;

	if ((s = read(src_so, &buf, sizeof(buf))) <= 0) break;
	printf("read size: %ld\n", s);	
	printf("%s", buf);
	write(dst_so, &buf, s);
    }
    close(src_so);
    close(dst_so);
}




