/* Define UDP_SPECIFIC to receive from DEST_IP only,
otherwise, receive from anyone */
#include <stdlib.h>
#include <string.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/udp.h"
#include "lwip/timers.h"

#define DEST_IP(x)	IP4_ADDR((x),192,168,0,1)
#define DEST_PORT	6677
#define LOCAL_PORT	7766
#define MY_STRING	"Hello, how are you ?"

#define SEND_TIME 1000
#define MSG_LEN 1024

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

ip_addr_t ipaddr;

static void mysend(struct udp_pcb *pcb)
{
struct pbuf* p;

	if((p = pbuf_alloc(PBUF_TRANSPORT, MSG_LEN, PBUF_RAM)) == NULL){
		printf("Can't allocate packet buffer");
		return;
	}
	memcpy(p->payload, MY_STRING, strlen(MY_STRING));
	
#ifdef UDP_SPECIFIC
	udp_send(pcb, p);
#else
	udp_sendto(pcb, p, &ipaddr, DEST_PORT);
#endif
    
	pbuf_free(p);
	sys_timeout(SEND_TIME, (sys_timeout_handler) mysend, pcb);
}

static void myrecv(void *arg, struct udp_pcb* pcb, struct pbuf *p, ip_addr_t *addr, u16_t port)
{
static char buffer[MSG_LEN];
unsigned int len = p->tot_len;

	/* If you did not send or connect and need to filter on source IP or port,
	 do it here. Otherwise, once you send/connect you get only from that IP+port */
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
	pbuf_free(p);

	buffer[len]='\0';
	printf("%s\n", buffer);
}

int main()
{
static struct udp_pcb* mypcb;

        lwip_initlwip(IwilluseDHCP);

	if((mypcb = udp_new()) == NULL){
		printf("Can't create pcb");
		exit(1);
	}
        DEST_IP(&ipaddr);
#ifdef UDP_SPECIFIC
	if(udp_connect(mypcb, &ipaddr, DEST_PORT) != ERR_OK){
		printf("IP + port in use, or wrong destination IP");
		udp_remove(mypcb);
		exit(1);
	}
#else
	if(udp_bind(mypcb, IP_ADDR_ANY, LOCAL_PORT) != ERR_OK){
		printf("IP + port in use");
		udp_remove(mypcb);
		exit(1);
	}
#endif	    
	udp_recv(mypcb, myrecv, NULL);

	mysend(mypcb);

	while(1){
                lwip_handler();
	}
	
	sys_untimeout((sys_timeout_handler) mysend, mypcb);
#ifdef UDP_SPECIFIC
	udp_disconnect(mypcb);
#endif	    
 	udp_remove(mypcb);
}

