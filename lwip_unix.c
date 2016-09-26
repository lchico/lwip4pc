#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "timer.h"
#include <signal.h>

#include "mintapif.h"

#include "lwip/init.h"
#include "netif/etharp.h"

#include "lwip/timers.h"
#include "lwip/dhcp.h"

/* (manual) host IP configuration */
static ip_addr_t ipaddr, netmask, gw;

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;


static struct netif netif;
static sigset_t mask, oldmask, empty;

static void printhost(void)
{
char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};

  strncpy(ip_str, ipaddr_ntoa(&ipaddr), sizeof(ip_str));
  strncpy(nm_str, ipaddr_ntoa(&netmask), sizeof(nm_str));
  strncpy(gw_str, ipaddr_ntoa(&gw), sizeof(gw_str));
  printf("Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);
}

static int dhcp;

void lwip_initlwip(int usedhcp)
{
  /* startup defaults (may be overridden by one or more opts) */
  IP4_ADDR(&gw, 192,168,0,1);
  IP4_ADDR(&ipaddr, 192,168,0,2);
  IP4_ADDR(&netmask, 255,255,255,0);

  /* use debug flags defined by debug.h */
  debug_flags = LWIP_DBG_OFF;

#ifdef PERF
  perf_init("/tmp/minimal.perf");
#endif /* PERF */

  lwip_init();

  printf("TCP/IP initialized.\n");

  netif_add(&netif, &ipaddr, &netmask, &gw, NULL, mintapif_init, ethernet_input);
  netif_set_default(&netif);


  timer_init();
  timer_set_interval(TIMER_EVT_ETHARPTMR, ARP_TMR_INTERVAL / 10);

  if(usedhcp){
	dhcp = 1;
	dhcp_start(&netif);
	printf("DHCP started\n");
  } else {
	dhcp = 0;
  	netif_set_up(&netif);
	printhost();
  }

  printf("Applications started.\n");
}

void lwip_handler()
{    
      /* poll for input packet and ensure
         select() or read() arn't interrupted */
      sigemptyset(&mask);
      sigaddset(&mask, SIGALRM);
      sigprocmask(SIG_BLOCK, &mask, &oldmask);

      /* start of critical section,
         poll netif, pass packet to lwIP */
      if (mintapif_select(&netif) > 0)
      {
        /* work, immediatly end critical section 
           hoping lwIP ended quickly ... */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
      }
      else
      {
        /* no work, wait a little (10 msec) for SIGALRM */
          sigemptyset(&empty);
          sigsuspend(&empty);
        /* ... end critical section */
          sigprocmask(SIG_SETMASK, &oldmask, NULL);
      }
    
      sys_check_timeouts();
      if((dhcp == 1) && (netif.dhcp->state == DHCP_BOUND)){
	dhcp = 2;
	ipaddr = netif.ip_addr;
	netmask = netif.netmask;
	gw = netif.gw;
	printhost();
      }
}

