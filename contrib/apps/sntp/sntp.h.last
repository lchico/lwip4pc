#ifndef LWIP_SNTP_H
#define LWIP_SNTP_H

#ifdef __cplusplus
extern "C" {
#endif

enum sntp_servermodes {
  SNTP_SERVERMODE_ADDRS = 0,
  SNTP_SERVERMODE_NAMES,
  SNTP_SERVERMODE_DHCP
};

void sntp_init(void);
void sntp_stop(void);

void sntp_servermode(int mode);
void sntp_setserver(u8_t num, ip_addr_t *server);
ip_addr_t sntp_getserver(u8_t num);

#ifdef SNTP_SERVER_DNS
void sntp_setservername(u8_t num, char *server);
char *sntp_getservername(u8_t num);
#endif /* SNTP_SERVER_DNS */

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SNTP_H */
