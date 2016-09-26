#include <stdlib.h>
#include <string.h>

#include "lwip_unix.h"

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "echo.h"

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

int main()
{

	lwip_initlwip(IwilluseDHCP);
	echo_init();
	while(1){
		lwip_handler();
	}
}

