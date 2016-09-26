#include "arch/cc.h"
#include <string.h>

#include "auth.h"

extern char *strnstr(const char *buffer, const char *token, size_t n);

struct user_s {
  char *username;
  char *password;
  u8_t groupmap;
};

static struct user_s users[AUTH_MAXUSERS];

void auth_init()
{
  int i;

  for (i = 0; i < AUTH_MAXUSERS; ++i) {
    users[i].username = NULL;
  }
}

int auth_useradd(char *username, char *password, u8_t groupmap)
{
  int uid;

  if ((username == NULL) || (password == NULL))
    return -1;

  for (uid = 0; uid < AUTH_MAXUSERS; ++uid) {   /* find free entry */
    if (users[uid].username == NULL) {
      users[uid].username = username;
      users[uid].password = password;
      users[uid].groupmap = groupmap;
      return uid;
    }
  }
  return -1;
}

int auth_userdel(int uid)
{

  if ((uid < 0) || (uid >= AUTH_MAXUSERS))
    return (-1);
  users[uid].username = NULL;
  return 0;
}

int auth_userlogin(char *username, char *password)
{
  int uid;

  for (uid = 0; uid < AUTH_MAXUSERS; ++uid) {   /* find entry */
    if ((users[uid].username != NULL)
        && !strcmp(users[uid].username, username)
        && !strcmp(users[uid].password, password))
      return uid;
  }
  return -1;
}

int auth_userperm(int uid)
{
  if ((uid < 0) || (uid >= AUTH_MAXUSERS) || (users[uid].username == NULL))
    return -1;
  return users[uid].groupmap;
}

char *auth_username(int uid)
{
  if ((uid < 0) || (uid >= AUTH_MAXUSERS) || (users[uid].username == NULL))
    return NULL;
  return users[uid].username;
}

