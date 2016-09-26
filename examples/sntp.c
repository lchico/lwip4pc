#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "sntp.h"
#include "lwip/timers.h"
#if SNTP_SERVER_DNS
#include "lwip/dns.h"
#endif

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

static volatile u32_t mytime = 0;

void sys_settime(u32_t sec)
{
	mytime = sec;
}
void sys_gettime(u32_t *sec, u32_t *us)
{
	*sec = mytime;
	*us = 0;
}

/* Add this to your lwipopts.h
#define SNTP_SET_SYSTEM_TIME(t)	sys_settime(t)
#define SNTP_GET_SYSTEM_TIME(sec, us)	sys_gettime(&(sec), &(us))
*/

/**
If you have your DHCP server setup to provide both DNS and NTP servers, you
just relax and enjoy. Check DHCP_GETS_NTP = 1 in your lwipopts. Pay attention
that you won't have servers until DHCP gets them, so define a startup delay
(see sntp.c source) or let the code retry.
If you don't use DHCP, you have to manually add NTP server(s). You can do that
by adding an address or a name. Name resolution requires (really?) a DNS server,
so you'll have to add it too, and check SNTP_SERVER_DNS = 1 in your lwipopts
If you will use multiple servers, define NTP_MAX_SERVERS in your lwipopts
*/
int main()
{
static u32_t mytime_old = 0;

        lwip_initlwip(IwilluseDHCP);

#ifndef USE_DHCP
#if SNTP_SERVER_DNS
	{
	ip_addr_t dns_server;
	dns_init();
	ipaddr_aton("192.168.69.1", &dns_server);
	dns_setserver(0, &dns_server); // DNS_MAX_SERVERS
	}
	sntp_servermode(SNTP_SERVERMODE_NAMES);
	sntp_setservername(0,"pool.ntp.org");
#else // SNTP_SERVER_DNS
	{
	ip_addr_t sntp_server_address;
	ipaddr_aton("192.168.69.1", &sntp_server_address);
	sntp_servermode(SNTP_SERVERMODE_ADDRS);
	sntp_setserver(0,&sntp_server_address);
	}
#endif
#else // USE_DHCP
// check lwIP is configured to provide NTP servers via DHCP: DHCP_GETS_NTP = 1
	sntp_servermode(SNTP_SERVERMODE_DHCP);
#endif
	sntp_init();

// Manually change at runtime with sntp_servermode(mode);

	while(1){
                lwip_handler();
		if(mytime != mytime_old){
			mytime_old = mytime;
			printf("Current time: (%08X) %s",mytime,ctime((time_t *)&mytime));
		}
	}
	
 	sntp_stop();
}

