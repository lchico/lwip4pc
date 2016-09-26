#define LOCAL_PORT      7766

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

static err_t myconnected(void *arg, struct tcp_pcb* pcb, err_t err)
{
	if(err == ERR_OK){
		printf("Someone connected!\n");
		tcp_accepted((struct tcp_pcb_listen *)arg);
		tcp_err(pcb, myerr);
		tcp_recv(pcb, myrecv);
		tcp_sent(pcb, mysent);
		tcp_poll(pcb, mypoll, POLL_TIME);
		state = myJUSTCONNECTED;
		mysend(pcb);
		state = myOPEN;
	} else {
		printf("I should not be here... got: %s\n",lwip_strerr(err));
		/* ***	THIS WOULD HAPPEN in next release (or git head ?),
			and could (would?)
			include a null pcb, due to an abort during connection
		   *** */
		if(pcb)
			myclose(pcb);
	}
	return ERR_OK;
}

int main()
{
static struct tcp_pcb* mypcb;

        lwip_initlwip(IwilluseDHCP);

	if((mypcb = tcp_new()) == NULL){
		printf("Can't create pcb");
		exit(1);
	}
	if(tcp_bind(mypcb, IP_ADDR_ANY, LOCAL_PORT) != ERR_OK){
		printf("IP + port in use");
		tcp_close(mypcb);
		exit(1);
	}
	if((mypcb = tcp_listen(mypcb)) == NULL){
		printf("No memory");
		tcp_close(mypcb);
		exit(1);
	}

	tcp_arg(mypcb, mypcb);
	tcp_accept(mypcb, myconnected);

	state = myCONNECT;

	while(state != myCLOSED){
                lwip_handler();
	}
	return 0;
}

