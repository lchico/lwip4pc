#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "smtp.h"
#include "lwip/timers.h"
#ifndef USE_DHCP
#include "lwip/dns.h"
#endif

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

/* Add this to your lwipopts.h
*/

void my_smtp_result_fn(void *arg, u8_t smtp_result, u16_t srv_err, err_t err)
{
  printf("mail (%p) sent with results: 0x%02x, 0x%04x, 0x%08x\n", arg,
         smtp_result, srv_err, err);
}


#define LINEAS 100

int my_smtp_bodydh_fn(void *arg, struct smtp_bodydh *bdh)
{
        if(bdh->state >= LINEAS)
                return BDH_DONE;

        sprintf(bdh->buffer,"Line #%2d\r\n",bdh->state);
        bdh->length = strlen(bdh->buffer);
        ++bdh->state;
	return BDH_WORKING;
}

int main()
{
int err;

        lwip_initlwip(IwilluseDHCP);

#ifndef USE_DHCP
	{
	ip_addr_t dns_server;
	dns_init();
	ipaddr_aton("192.168.69.1", &dns_server);
	dns_setserver(0, &dns_server); // DNS_MAX_SERVERS
	}
#endif

	smtp_set_server_addr("192.168.69.1");
	smtp_set_server_port(2500);
	smtp_set_auth(NULL, NULL);
	err = smtp_send_mail_bodycback("sender@somehost.somenet", "scaprile@localhost", "This is the subject", my_smtp_bodydh_fn, my_smtp_result_fn, NULL);

	if (err != ERR_OK){
		printf("Error trying to start sending\n");
		exit(1);
	}
	while(1){
                lwip_handler();
	}
	
}

