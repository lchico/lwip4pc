#define DEST_IP(x)      IP4_ADDR((x),192,168,69,1)
#define DEST_PORT       6677
#define LOCAL_PORT      7766

#if USE_DHCP && LWIP_DHCP
 #define IwilluseDHCP   1
#else
 #define IwilluseDHCP   0
#endif

static err_t myconnected(void *arg, struct tcp_pcb* pcb, err_t err)
{
	if(err == ERR_OK){
		printf("Connected!\n");
		state = myJUSTCONNECTED;
	} else {
		printf("I should not be here... got: %s\n",lwip_strerr(err));
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
#if 0
	if(tcp_bind(mypcb, IP_ADDR_ANY, LOCAL_PORT) != ERR_OK){
		printf("IP + port in use");
		tcp_close(mypcb);
		exit(1);
	}
#endif
	tcp_err(mypcb, myerr);
	tcp_recv(mypcb, myrecv);
	tcp_sent(mypcb, mysent);
	tcp_poll(mypcb, mypoll, POLL_TIME);

	DEST_IP(&ipaddr);
	
	if(tcp_connect(mypcb, &ipaddr, DEST_PORT, myconnected) != ERR_OK){
		printf("Can't start connection (no memory ?)");
		tcp_close(mypcb);
		exit(1);
	}
	state = myCONNECT;

	while(state != myCLOSED){
                lwip_handler();
                if(state == myJUSTCONNECTED){
                	mysend(mypcb);
                	state = myOPEN;
        	}
	}
	return 0;
}

