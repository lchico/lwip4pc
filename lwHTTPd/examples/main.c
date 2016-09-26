#include <stdlib.h>
#include <string.h>

#include "lwip_unix.h"

#ifdef STATS
#include "lwip/stats.h"
#endif

extern void webstuff_init(void);


#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP	1
#else
 #define IwilluseDHCP	0
#endif

#ifdef PROFILE
#include <time.h>

double timeit(struct timespec *tsi,struct timespec *tsf)
{
double elapss=difftime(tsf->tv_sec,tsi->tv_sec);
long elapsns=tsf->tv_nsec-tsi->tv_nsec;

	return(elapss+(double)elapsns/1e9);
}
#endif

int main()
{
#ifdef PROFILE
static double time, min=1000000, max=0, avg;
static int ene=0;
struct timespec tsi,tsf;
#endif

	lwip_initlwip(IwilluseDHCP);
#ifdef STATS
	stats_init();
#endif
	webstuff_init();
	
	while(1){
#ifdef PROFILE
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&tsi);
#endif
		lwip_handler();
#ifdef PROFILE
	        clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&tsf);
	        time = 1e6*timeit(&tsi,&tsf);
	        if(time > max)
	        	max = time;
	        if(time < min)
	        	min = time;
	        avg += time;
	        if(++ene == 100){
	        	avg /= ene;
	        	ene = 0;
			printf("Min: %f us, Max: %f us, Average: %f us\n",min,max,avg);
			avg = 0;
			min = 1000000;
			max = 0;
		}
#endif
#ifdef STATS
		stats_display();
#endif
	}
}

