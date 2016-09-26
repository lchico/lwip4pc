#include "lwip_unix.h"

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP	1
#else
 #define IwilluseDHCP	0
#endif

int main()
{
	lwip_initlwip(IwilluseDHCP);
	while(1){
		lwip_handler();
	}
}
