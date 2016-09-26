#include <stdlib.h>
#include <string.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/dns.h"

#if LWIP_DHCP
#include "lwip/dhcp.h"
#endif

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

/* Memory usage:
roughly DNS_TABLE_SIZE * DNS_MAX_NAME_LENGTH + DNS_MSG_SIZE (512 per RFC)
(plus some space for pointers and etc.; this is the big component)
*/

void found(const char *name, ip_addr_t *ipaddr, void *arg)
{
	if(ipaddr == NULL){
		printf("Name resolution failed for %s\n", name);
		// handle/signal error somehow
	} else {
		ip_addr_t *dest = arg;	// We used the extra argument to get a pointer to the destination
		printf("%s sucessfully resolved\n", name);
		*dest = *ipaddr;	// Update requested address
	}
}

enum myappstates_e { WAIT4LINKUP, NEEDIP, WAITING4RESOLVE };

int main()
{
ip_addr_t resolved;
int myappstate;

	resolved.addr = 0;
	lwip_initlwip(IwilluseDHCP);
	dns_init();
#if USE_DHCP
	// see DHCP example for starting it; DNS server is obtained from DHCP server
#else
	{
	ip_addr_t server; 	
	ipaddr_aton("192.168.69.1",&server);
	dns_setserver(0, &server); // DNS_MAX_SERVERS
	}
#endif
	myappstate = WAIT4LINKUP;	
	while(1){
		lwip_handler();
		switch(myappstate){
		case WAIT4LINKUP:
#if USE_DHCP
			// see DHCP example to check when you got yourself an IP
#else
			myappstate = NEEDIP;
#endif
			break;
		case NEEDIP:
			switch(dns_gethostbyname("www.yahoo.com", &resolved, found, &resolved)){
			case ERR_OK:
				// numeric or cached, returned in resolved
				printf("The IP I needed was cached: %u.%u.%u.%u\n",
				  ip4_addr1(&resolved), ip4_addr2(&resolved),ip4_addr3(&resolved), ip4_addr4(&resolved));
				exit(0);
			case ERR_INPROGRESS:
				// need to ask, will return data via callback
				myappstate = WAITING4RESOLVE;
				break;
			default:
				// bad arguments in function call
				printf("Oops, need to pay attention to function prototypes...\n");
				exit(0);
			}
			break;
		case WAITING4RESOLVE:
			if(resolved.addr){
				printf("The IP I needed has been resolved: %u.%u.%u.%u\n",
				ip4_addr1(&resolved), ip4_addr2(&resolved),ip4_addr3(&resolved), ip4_addr4(&resolved));
				exit(0);
			}
			break;
		}
	}
}

