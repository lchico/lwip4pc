#ifndef _AUTH_H
#define _AUTH_H

#define AUTH_MAXUSERS 3

#define AUTH_NONE 0
#define AUTH_GROUP1RO (1<<0)
#define AUTH_GROUP2RO (1<<1)
#define AUTH_GROUP3RO (1<<2)
#define AUTH_GROUP4RO (1<<3)
#define AUTH_GROUP1RW ((1<<4)+(1<<0))
#define AUTH_GROUP2RW ((1<<5)+(1<<1))
#define AUTH_GROUP3RW ((1<<6)+(1<<2))
#define AUTH_GROUP4RW ((1<<7)+(1<<3))


void auth_init(void);

int auth_useradd(char *username, char *password, u8_t groupmap);
int auth_userdel(int uid);
int auth_userlogin(char *username, char *password);
int auth_userperm(int uid);
char *auth_username(int uid);

#define AUTH_RDGRANTED(a,b)	((a) & (b))
#define AUTH_WRGRANTED(a,b)	((a) & (b) & 0xF0)

#endif /* _AUTH_H */
