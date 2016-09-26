#include <stdlib.h>
#include <string.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/tcp.h"
#include "lwip/timers.h"

#define MY_STRING	"Hello, how are you ?"

#define POLL_TIME 2
#define MSG_LEN 1024

ip_addr_t ipaddr;

enum mystates {myIDLE, myCONNECT, myJUSTCONNECTED, myOPEN, myCLOSING, myCLOSED};

static int state = myIDLE;

static void mysend(struct tcp_pcb *pcb)
{
// Try to send as much data as can fit in buffer
u16_t send_len = tcp_sndbuf(pcb);

	/* In real life, we will send what is available and keep moving
	pointer to data and bytes to send. Check real apps like SMTP.c */
	if (send_len >= strlen(MY_STRING)) {
		// all data should fit in buffer
	        if(tcp_write(pcb, MY_STRING, (u16_t)strlen(MY_STRING), TCP_WRITE_FLAG_COPY) == ERR_OK) {
		        // data sent
	        }
        }
        // if data was not sent, we'll retry when either mysent() or mypoll() are called later
}

static err_t mysent(void *arg, struct tcp_pcb* pcb, u16_t len)
{
	// keep sending data while receiver says he's got what we've sent
	// mysend(mypcb);
	return ERR_OK;
}

static void myerr(void *arg, err_t err)
{
	if(state == myCONNECT){
		printf("Could not connect\n");
	} else {
		printf("Oops, connection reset by remote end: %s\n",lwip_strerr(err));
		// free resources, if any
	}
	state = myCLOSED;
}

static void myclose(struct tcp_pcb* pcb)
{
	state = myCLOSING;
	if(tcp_close(pcb) == ERR_OK){
		tcp_recv(pcb, NULL);
		state = myCLOSED;
	}
}

static err_t mypoll(void *arg, struct tcp_pcb* pcb)
{
	if(state == myCLOSING){
		// Retry closing the connection
		myclose(pcb);
	} else {
		// Retry sending data we couldn't send before
		mysend(pcb);
	}
	return ERR_OK;
}

static err_t myrecv(void *arg, struct tcp_pcb* pcb, struct pbuf *p, err_t err)
{
static char buffer[MSG_LEN];
unsigned int len, willreject=0;

	if ((p == NULL) || (err != ERR_OK)){
		printf("Connection closed by remote end\n");
		myclose(pcb);
		return ERR_OK;
	}
	if(willreject){
		return ERR_ABRT;
	}
	len = p->tot_len;
	pbuf_copy_partial(p, buffer, p->tot_len, 0);
/*
	struct pbuf *q = p;
	int offset=0;
	while(q){
		memcpy(&buffer[offset],p->payload,p->len);
		offset += p->len;
		q = q->next;
	}
*/
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);

	buffer[len]='\0';
	printf("%s\n", buffer);
	return ERR_OK;
}

#ifdef TCP_CLIENT
	#include "tcp_client.c"
#else
#ifdef TCP_SERVER
	#include "tcp_server.c"
#else
	#error "Define either TCP_CLIENT or TCP_SERVER"
#endif
#endif

