/*
See license.h for licensing info and credits
See httpd.h for function usage
See httpdopts.h for user #defines
 */
#include "license.h"

#include "httpd.h"
#include "lwip/debug.h"
#include "lwip/stats.h"
#include "httpd_structs.h"
#include "lwip/tcp.h"
#include "fs.h"
#include "auth.h"

#include <string.h>
#include <stdlib.h>

#if LWIP_TCP

#define CRLF "\r\n"
#define HTTP11_CONNECTIONKEEPALIVE "Connection: keep-alive"

#define LWHTTPD_BOUNDARY_BUFFER_SIZE 71  /* Largest string = 70, as per RFC */

#if LWIP_HTTPD_SSI
#define LWIP_HTTPD_IS_SSI(hs) ((hs)->dh.ssi)
#else /* LWIP_HTTPD_SSI */
#define LWIP_HTTPD_IS_SSI(hs) 0
#endif /* LWIP_HTTPD_SSI */

/** These defines check whether tcp_write has to copy data or not 
@todo: make a portable macro to know if some stuff (e.g.: ptr in dynamic headers) comes from flash or RAM 
@todo: this info, for files, should come from the filesystem
*/
/** This was TI's check whether to let TCP copy data or not
#define HTTP_IS_DATA_VOLATILE(hs) ((hs->file < (char *)0x20000000) ? 0 : TCP_WRITE_FLAG_COPY)*/
#ifndef HTTP_IS_DATA_VOLATILE
#if LWIP_HTTPD_SSI
/* Copy for handled files (SSI, CGI, etc), no copy for static (HTML) files */
#define HTTP_IS_DATA_VOLATILE(hs)   ((hs)->dh.ssi ? TCP_WRITE_FLAG_COPY : 0)
#else /* LWIP_HTTPD_SSI */
/** Default: don't copy if the data is sent from file-system directly */
#define HTTP_IS_DATA_VOLATILE(hs) (((hs->file != NULL) && (hs->handle != NULL) && (hs->file == \
                                   (char*)hs->handle->data + hs->handle->len - hs->left)) \
                                   ? 0 : TCP_WRITE_FLAG_COPY)
#endif /* LWIP_HTTPD_SSI */
#endif

#if LWIP_HTTPD_SSI
/** Default: Tags are sent from struct http_state and are therefore volatile */
#ifndef HTTP_IS_TAG_VOLATILE
#define HTTP_IS_TAG_VOLATILE(ptr) TCP_WRITE_FLAG_COPY
#endif
#endif /* LWIP_HTTPD_SSI */


/* Return values for http_send_*() */
#define HTTP_DATA_SEND_TERMINATE   0xFF  /* used by http_cgi_data_handler(), http_send() subfunction */
#define HTTP_DATA_TO_SEND_BREAK    2
#define HTTP_DATA_TO_SEND_CONTINUE 1
#define HTTP_NO_DATA_TO_SEND       0

#if HTTPD_USE_MEM_POOL
#define HTTP_ALLOC_CGI_BOUNDARY() (char *)memp_malloc(MEMP_HTTPD_CGI_BOUNDARY)
#define HTTP_ALLOC_CGI_STATE()  (struct http_cgi_state *)memp_malloc(MEMP_HTTPD_CGI_STATE)
#define HTTP_ALLOC_SSI_STATE()  (struct http_ssi_state *)memp_malloc(MEMP_HTTPD_SSI_STATE)
#define HTTP_ALLOC_HTTP_STATE() (struct http_state *)memp_malloc(MEMP_HTTPD_STATE)
#else /* HTTPD_USE_MEM_POOL */
#define HTTP_ALLOC_CGI_BOUNDARY() (char *)mem_malloc(LWHTTPD_BOUNDARY_BUFFER_SIZE)
#define HTTP_ALLOC_CGI_STATE()  (struct http_cgi_state *)mem_malloc(sizeof(struct http_cgi_state))
#define HTTP_ALLOC_SSI_STATE()  (struct http_ssi_state *)mem_malloc(sizeof(struct http_ssi_state))
#define HTTP_ALLOC_HTTP_STATE() (struct http_state *)mem_malloc(sizeof(struct http_state))
#endif /* HTTPD_USE_MEM_POOL */

typedef struct
{
  const char *name;
  u8_t shtml;
} default_filename;

const default_filename g_psDefaultFilenames[] = {
  {"/index.shtml", 1 },
  {"/index.ssi",   1 },
  {"/index.shtm",  1 },
  {"/index.html",  0 },
  {"/index.htm",   0 }
};

#define NUM_DEFAULT_FILENAMES (sizeof(g_psDefaultFilenames) /   \
                               sizeof(default_filename))

/** HTTP request is copied here from pbufs for simple parsing */
static char uri_buf[LWIP_HTTPD_URI_BUFSIZE+1];

#if LWIP_HTTPD_DYNAMIC_HEADERS
/* The number of individual strings that comprise the headers sent before each
 * requested file.
 */
#define NUM_FILE_HDR_STRINGS 5
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

#if LWIP_HTTPD_SSI

#define TAGBUFFER_SIZE LWIP_HTTPD_MAX_TAG_INSERT_LEN

enum shtml_dh_states {
  SSI_NEXT,
  SSI_PROCESS_TAG,
  SSI_RUNFUNC,
  SSI_RESUME,
  SSI_DONE
};

struct http_ssi_state {
  char *from;
  u32_t left;
  u16_t state;
  char *tag_start;
  char *tag_end;
  char tagbuffer[TAGBUFFER_SIZE+1];
  const tSSIcmd *cmd; /* The command to call (again) */
  u16_t funcstate;
};
#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_CGI
enum cgi_handler_state {
  CGI_RECEIVING,       /* Serving the user CGI function, receiving POST content */
  CGI_SENDING,         /* Serving the user CGI function, generating content */
  CGI_STOP             /* User function stopped, closing */
};

struct http_cgi_state {
  tCGIHandler func;  /* The function to call (again) */
  u16_t state;
  struct cgi_state exposed; /* the user function structure */
};
#endif /* LWIP_HTTPD_CGI */


#if LWIP_HTTPD_SSI || LWIP_HTTPD_CGI
union datahandler {
#if LWIP_HTTPD_SSI
  struct http_ssi_state *ssi;
#endif /* LWIP_HTTPD_SSI */
#if LWIP_HTTPD_CGI
  struct http_cgi_state *cgi;
#endif /* LWIP_HTTPD_CGI */
};
#endif /* LWIP_HTTPD_SSI || LWIP_HTTPD_CGI */

enum handlertypes {
  HTTP_DHTYPE_HTML  = 0,
  HTTP_DHTYPE_SHTML,
  HTTP_DHTYPE_CGI
/* HTTP_DHTYPE_UBS, some other small script language, whatever */
};

#if LWIP_HTTPD_DYNAMIC_HEADERS
struct dynhdr {
  const char * hdr_from;
  u32_t hdr_left;   /* using u32_t here is way too much, but then a function can be reused and performance increased */
  u8_t hdrs[NUM_FILE_HDR_STRINGS]; /* HTTP headers to be sent. */
  u8_t hdr_index;   /* The index of the hdr string currently being sent. */
};
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

struct parsereq {
	u16_t offset;  /* where we are now in the pbuf chain */
#if LWIP_HTTPD_SUPPORT_POST
	u16_t contype;  /* where the content type string is in the pbuf chain */
	u16_t contlen;  /* where the content length string is in the pbuf chain */
#endif /* LWIP_HTTPD_SUPPORT_POST */
	u8_t state;
};

union shared {
#if LWIP_HTTPD_DYNAMIC_HEADERS
  struct dynhdr dyh;
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
  struct parsereq preq;
};

struct http_state {
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  struct http_state *next;
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  struct fs_file file_handle;
  struct fs_file *handle;
  char *file;       /* Pointer to first unsent byte in buf. */

  struct tcp_pcb *pcb;
  struct pbuf *req;

#if LWIP_HTTPD_DYNAMIC_FILE_READ
  char *buf;        /* File read buffer. */
  int buf_len;      /* Size of file read buffer, buf. */
#endif /* LWIP_HTTPD_DYNAMIC_FILE_READ */
  u32_t left;       /* Number of unsent bytes in buf. */
  u8_t retries;
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
  u8_t keepalive;
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
#if LWIP_HTTPD_SSI || LWIP_HTTPD_CGI
  u8_t handlertype;
  union datahandler dh;
#endif /* LWIP_HTTPD_SSI || LWIP_HTTPD_CGI */
  union shared sh;
#if LWIP_HTTPD_TIMING
  u32_t time_started;
#endif /* LWIP_HTTPD_TIMING */
  u8_t method;      /* HTTP method */
  u8_t version;     /* HTTP version */
#if LWIP_HTTPD_AUTH
  s8_t uid;         /* uid (when authenticated), -1 if none provided */
#endif /* LWIP_HTTPD_AUTH */
};

static err_t http_close_conn(struct tcp_pcb *pcb, struct http_state *hs);
static err_t http_close_or_abort_conn(struct tcp_pcb *pcb, struct http_state *hs, u8_t abort_conn);
static err_t http_find_file(struct http_state *hs, const char *uri);
static err_t http_init_file(struct http_state *hs, struct fs_file *file, const char *uri, u8_t tag_check);
static err_t http_poll(void *arg, struct tcp_pcb *pcb);
#if LWIP_HTTPD_FS_ASYNC_READ
static void http_continue(void *connection);
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
#if LWIP_HTTPD_AUTH
static int http_auth_process(struct pbuf *pb, u16_t offset, u16_t crlf);
#endif /* LWIP_HTTPD_AUTH */

#if LWIP_HTTPD_SSI
static const tSSIcmd *g_SSIexeccmds = NULL;
static int g_SSIexecNumCmds = 0;
static const tSSIvar *g_SSIechovars = NULL;
static int g_SSIechoNumVars = 0;
#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_CGI
/* CGI handler information */
const tCGI *g_pCGIs;
int g_iNumCGIs;
#endif /* LWIP_HTTPD_CGI */

#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
/** global list of active HTTP connections, use to kill the oldest when
    running out of memory */
static struct http_state *http_connections;
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */

#if LWIP_HTTPD_STRNSTR_PRIVATE
/** Like strstr but does not need 'buffer' to be NULL-terminated */
static char*
strnstr(const char* buffer, const char* token, size_t n)
{
  const char* p;
  int tokenlen = (int)strlen(token);
  if (tokenlen == 0) {
    return (char *)buffer;
  }
  for (p = buffer; *p && (p + tokenlen <= buffer + n); p++) {
    if ((*p == *token) && (strncmp(p, token, tokenlen) == 0)) {
      return (char *)p;
    }
  }
  return NULL;
} 
#endif /* LWIP_HTTPD_STRNSTR_PRIVATE */

#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
static void
http_kill_oldest_connection(u8_t ssi_required)
{
  struct http_state *hs = http_connections;
  struct http_state *hs_free_next = NULL;
  while(hs && hs->next) {
    if (ssi_required) {
      if (hs->next->ssi != NULL) {
        hs_free_next = hs;
      }
    } else {
      hs_free_next = hs;
    }
    hs = hs->next;
  }
  if (hs_free_next != NULL) {
    LWIP_ASSERT("hs_free_next->next != NULL", hs_free_next->next != NULL);
    LWIP_ASSERT("hs_free_next->next->pcb != NULL", hs_free_next->next->pcb != NULL);
    /* send RST when killing a connection because of memory shortage */
    http_close_or_abort_conn(hs_free_next->next->pcb, hs_free_next->next, 1); /* this also unlinks the http_state from the list */
  }
}
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */

#if LWIP_HTTPD_SSI
/** Allocate as struct http_ssi_state. */
static struct http_ssi_state*
http_ssi_state_alloc(void)
{
  struct http_ssi_state *ret = HTTP_ALLOC_SSI_STATE();
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  if (ret == NULL) {
    http_kill_oldest_connection(1);
    ret = HTTP_ALLOC_SSI_STATE();
  }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  if (ret != NULL) {
    memset(ret, 0, sizeof(struct http_ssi_state));
  }
  return ret;
}

/** Free a struct http_ssi_state. */
static void
http_ssi_state_free(struct http_ssi_state *ssi)
{
  if (ssi != NULL) {
#if HTTPD_USE_MEM_POOL
    memp_free(MEMP_HTTPD_SSI_STATE, ssi);
#else /* HTTPD_USE_MEM_POOL */
    mem_free(ssi);
#endif /* HTTPD_USE_MEM_POOL */
  }
}
#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_CGI
#if LWIP_HTTPD_SUPPORT_POST_MULTIPART
/** Allocate a buffer for boundary tag */
static char*
http_cgi_boundary_alloc(void)
{
  return HTTP_ALLOC_CGI_BOUNDARY();
}

/** Free boundary tag buffer */
static void
http_cgi_boundary_free(char *b)
{
  if (b != NULL) {
#if HTTPD_USE_MEM_POOL
    memp_free(MEMP_HTTPD_CGI_BOUNDARY, b);
#else /* HTTPD_USE_MEM_POOL */
    mem_free(b);
#endif /* HTTPD_USE_MEM_POOL */
  }
}
#endif /* LWIP_HTTPD_SUPPORT_POST_MULTIPART */

/** Allocate a struct http_cgi_state. */
static struct http_cgi_state*
http_cgi_state_alloc(void)
{
  struct http_cgi_state *ret = HTTP_ALLOC_CGI_STATE();
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  if (ret == NULL) {
    http_kill_oldest_connection(1);
    ret = HTTP_ALLOC_CGI_STATE();
  }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  if (ret != NULL) {
    memset(ret, 0, sizeof(struct http_cgi_state));
  }
  return ret;
}

/** Free a struct http_cgi_state. */
static void
http_cgi_state_free(struct http_cgi_state *cgi)
{
  if (cgi != NULL) {
#if HTTPD_USE_MEM_POOL
    memp_free(MEMP_HTTPD_CGI_STATE, cgi);
#else /* HTTPD_USE_MEM_POOL */
    mem_free(cgi);
#endif /* HTTPD_USE_MEM_POOL */
#if LWIP_HTTPD_SUPPORT_POST_MULTIPART
    http_cgi_boundary_free(cgi->exposed.boundary);  /* Function SHALL check if this has been allocated */
#endif /* LWIP_HTTPD_SUPPORT_POST_MULTIPART */
  }
}

#endif /* LWIP_HTTPD_CGI */

/** Initialize a struct http_state.
 */
static void
http_state_init(struct http_state* hs)
{
  /* Initialize the structure. */
  memset(hs, 0, sizeof(struct http_state));
#if LWIP_HTTPD_AUTH
  hs->uid = -1;
#endif /* LWIP_HTTPD_AUTH */
/* This has actually been done by memset to 0, as long as nobody messes with
the enum assigning 0 to the state
  preq->offset = 0;
  preq->state = HTTP_PARSEREQ_FIRSTLINE;
*/
}

/** Allocate a struct http_state. */
static struct http_state*
http_state_alloc(void)
{
  struct http_state *ret = HTTP_ALLOC_HTTP_STATE();
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
  if (ret == NULL) {
    http_kill_oldest_connection(0);
    ret = HTTP_ALLOC_HTTP_STATE();
  }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  if (ret != NULL) {
    http_state_init(ret);
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
    /* add the connection to the list */
    if (http_connections == NULL) {
      http_connections = ret;
    } else {
      struct http_state *last;
      for(last = http_connections; last->next != NULL; last = last->next);
      LWIP_ASSERT("last != NULL", last != NULL);
      last->next = ret;
    }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
  }
  return ret;
}

/** Free a struct http_state.
 * Also frees the file data if dynamic.
 */
static void
http_state_eof(struct http_state *hs)
{
  if(hs->handle) {
#if LWIP_HTTPD_TIMING
    u32_t ms_needed = sys_now() - hs->time_started;
    u32_t needed = LWIP_MAX(1, (ms_needed/100));
    LWIP_DEBUGF(HTTPD_DEBUG_TIMING, ("httpd: needed %"U32_F" ms to send file of %d bytes -> %"U32_F" bytes/sec\n",
      ms_needed, hs->handle->len, ((((u32_t)hs->handle->len) * 10) / needed)));
#endif /* LWIP_HTTPD_TIMING */
    fs_close(hs->handle);
    hs->handle = NULL;
  }
#if LWIP_HTTPD_DYNAMIC_FILE_READ
  if (hs->buf != NULL) {
    mem_free(hs->buf);
    hs->buf = NULL;
  }
#endif /* LWIP_HTTPD_DYNAMIC_FILE_READ */
#if LWIP_HTTPD_SSI || LWIP_HTTPD_CGI
  switch (hs->handlertype) {
#if LWIP_HTTPD_CGI
  case HTTP_DHTYPE_CGI:
    http_cgi_state_free(hs->dh.cgi);
    hs->dh.cgi = NULL;
    break;
#endif /* LWIP_HTTPD_CGI */
#if LWIP_HTTPD_SSI
  case HTTP_DHTYPE_SHTML:
    http_ssi_state_free(hs->dh.ssi);
    hs->dh.ssi = NULL;
    break;
#endif /* LWIP_HTTPD_SSI */
  }
#endif /* LWIP_HTTPD_SSI  || LWIP_HTTPD_CGI */
  if (hs->req) {
    pbuf_free(hs->req);
    hs->req = NULL;
  }
}

/** Free a struct http_state.
 * Also frees the file data if dynamic.
 */
static void
http_state_free(struct http_state *hs)
{
  if (hs != NULL) {
    http_state_eof(hs);
#if LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
    /* take the connection off the list */
    if (http_connections) {
      if (http_connections == hs) {
        http_connections = hs->next;
      } else {
        struct http_state *last;
        for(last = http_connections; last->next != NULL; last = last->next) {
          if (last->next == hs) {
            last->next = hs->next;
            break;
          }
        }
      }
    }
#endif /* LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED */
#if HTTPD_USE_MEM_POOL
    memp_free(MEMP_HTTPD_STATE, hs);
#else /* HTTPD_USE_MEM_POOL */
    mem_free(hs);
#endif /* HTTPD_USE_MEM_POOL */
  }
}

/** Call tcp_write() in a loop trying smaller and smaller length
 *
 * @param pcb tcp_pcb to send
 * @param ptr Data to send
 * @param length Length of data to send (in/out: on return, contains the
 *        amount of data sent)
 * @param apiflags directly passed to tcp_write
 * @return the return value of tcp_write
 */
static err_t
http_write(struct tcp_pcb *pcb, const void* ptr, u16_t *length, u8_t apiflags)
{
  u16_t len, max_len;
  err_t err;
  LWIP_ASSERT("length != NULL", length != NULL);
  len = *length;
  if (len == 0) {
    return ERR_OK;
  }
  /* We cannot send more data than space available in the send buffer. */
  max_len = tcp_sndbuf(pcb);
  if (max_len < len) {
    len = max_len;
  }
#ifdef HTTPD_MAX_WRITE_LEN
  /* Additional limitation: e.g. don't enqueue more than 2*mss at once */
  max_len = HTTPD_MAX_WRITE_LEN(pcb);
  if(len > max_len) {
    len = max_len;
  }
#endif /* HTTPD_MAX_WRITE_LEN */
  do {
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Trying to send %d bytes with flags: %u\n", len, apiflags));
    err = tcp_write(pcb, ptr, len, apiflags);
    if (err == ERR_MEM) {
      if ((tcp_sndbuf(pcb) == 0) ||
        (tcp_sndqueuelen(pcb) >= TCP_SND_QUEUELEN)) {
          /* no need to try smaller sizes */
          len = 1;
      } else {
        len /= 2;
      }
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, 
        ("Send failed, trying less (%d bytes)\n", len));
    }
  } while ((err == ERR_MEM) && (len > 1));

  if (err == ERR_OK) {
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Sent %d bytes\n", len));
    *length = len;
  } else {
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Send failed with err %d (\"%s\")\n", err, lwip_strerr(err)));
    *length = 0;
  }

  return err;
}

/**
 * The connection shall be actively closed (using RST to close from fault states).
 * Reset the sent- and recv-callbacks.
 *
 * @param pcb the tcp pcb to reset callbacks
 * @param hs connection state to free
 */
static err_t
http_close_or_abort_conn(struct tcp_pcb *pcb, struct http_state *hs, u8_t abort_conn)
{
  err_t err;
  LWIP_DEBUGF(HTTPD_DEBUG, ("Closing connection %p\n", (void*)pcb));

  tcp_arg(pcb, NULL);
  tcp_recv(pcb, NULL);
  tcp_err(pcb, NULL);
  tcp_poll(pcb, NULL, 0);
  tcp_sent(pcb, NULL);
  if (hs != NULL) {
    http_state_free(hs);
  }

  if (abort_conn) {
    tcp_abort(pcb);
    return ERR_OK;
  }
  err = tcp_close(pcb);
  if (err != ERR_OK) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("Error %d closing %p\n", err, (void*)pcb));
    /* error closing, try again later in poll */
    tcp_poll(pcb, http_poll, HTTPD_POLL_INTERVAL);
  }
  return err;
}

/**
 * The connection shall be actively closed.
 * Reset the sent- and recv-callbacks.
 *
 * @param pcb the tcp pcb to reset callbacks
 * @param hs connection state to free
 */
static err_t
http_close_conn(struct tcp_pcb *pcb, struct http_state *hs)
{
   return http_close_or_abort_conn(pcb, hs, 0);
}

/** End of file: either close the connection (Connection: close) or
 * close the file (Connection: keep-alive)
 */
static void
http_eof(struct tcp_pcb *pcb, struct http_state *hs)
{
  /* HTTP/1.1 persistent connection? (Not supported for SSI) */
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
  if (hs->keepalive && !LWIP_HTTPD_IS_SSI(hs)) {
    http_state_eof(hs);
    http_state_init(hs);
    hs->keepalive = 1;
  } else
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
  {
    http_close_conn(pcb, hs);
  }
}

#if LWIP_HTTPD_CGI
/**
 * \brief Extract URI parameters from the parameter-part of an URI in the form
 * "test.cgi?param1=value1&param2=value2"
 *
 * @param params pointer to the NULL-terminated parameter string from the URI
 * @param param_names pointer to an array where to store the pointer to the names
 * @param param_values pointer to an array where to store the pointer to the values
 * @return number of parameters extracted
 */
static int
__extract_parameters(char *params, char *param_names[], char *param_values[])
{
  char *pair;
  char *equals;
  int loop;

  /* If we have no parameters at all, return immediately. */
  if(!params || (params[0] == '\0')) {
      return(0);
  }

  /* Get a pointer to our first parameter */
  pair = params;

  /* Parse up to LWIP_HTTPD_MAX_CGI_PARAMETERS from the passed string and ignore the
   * remainder (if any) */
  for(loop = 0; (loop < LWIP_HTTPD_MAX_CGI_PARAMETERS) && pair; loop++) {

    /* Save the name of the parameter */
    param_names[loop] = pair;

    /* Remember the start of this name=value pair */
    equals = pair;

    /* Find the start of the next name=value pair and replace the delimiter
     * with a 0 to terminate the previous pair string. */
    pair = strchr(pair, '&');
    if(pair) {
      *pair = '\0';
      pair++;
    } else {
       /* We didn't find a new parameter so find the end of the string and
        * replace the space with a '\0' */
        char *sp = strchr(equals, ' ');		/* HTTP/1.x GET */
        char *eol = strchr(equals, '\r');	/* HTTP/0.9 GET, HTTP/1.x POST content */
        pair = LWIP_MIN(sp, eol);
        if(pair) {
            *pair = '\0';
        }

        /* Revert to NULL so that we exit the loop as expected. */
        pair = NULL;
    }

    /* Now find the '=' in the previous pair, replace it with '\0' and save
     * the parameter value string. */
    equals = strchr(equals, '=');
    if(equals) {
      *equals = '\0';
      param_values[loop] = equals + 1;
    } else {
      param_values[loop] = NULL;
    }
  }

  return loop;
}

int
cgi_extract_parameters(struct cgi_state *cgi, char *param_names[], char *param_values[])
{
#if LWIP_HTTPD_SUPPORT_POST
  if(cgi->http_method == HTTP_METHOD_POST)
    return __extract_parameters(cgi->buffer, param_names, param_values);
#endif /* LWIP_HTTPD_SUPPORT_POST */
  return __extract_parameters(*(char**)cgi->buffer, param_names, param_values);
}

#define TOUPPER(c) (((c>='a')&&(c<='z'))? (c-('a'-'A')):(c))
#define HEXNUMBER(c) ((((c)<'0')||((c)>'F')||(((c)>'9')&&((c)<'A')))? 0 :((c)>='A')?((c)-('0'+7)):((c)-'0'))

void cgi_urldecode(char *text)
{
char *ptr = text;
char c;
int val;

	while((c=*ptr)!= '\0'){
		if(c == '+'){
			*text = ' ';
		} else if(c == '%'){
			c = *(++ptr);
			c = TOUPPER(c);
			val = (HEXNUMBER(c)<<4);
			c = *(++ptr);
			c = TOUPPER(c);
			val += HEXNUMBER(c);
			*text = (char)val;
		} else {
			*text = *ptr;
		}
		++ptr;
		++text;
	}
	*text = '\0';
}


#endif /* LWIP_HTTPD_CGI */

#if LWIP_HTTPD_SSI
enum ssistdtags { SSITAGPRIVATE=0, SSITAGEXEC, SSITAGECHO };

static int parsetag(char *start, int count, char *buffer)
{
#define SSIEXECTAG "execcmd="
#define SSIECHOTAG "echovar="
#define SSIEXECTAGLEN 8
#define SSIECHOTAGLEN 8

char *pos = start;
char *buf = buffer;
int charcount = 0;

  do { /* skip spaces, ctrl chars, and '"' within the tag space */
    if((*pos > ' ') && (*pos != '"')){
      *(buf++) = *pos;
      if(++charcount >= TAGBUFFER_SIZE)
        break;
    }
    ++pos;
  }while(--count);
  *buf = '\0';
  /* now find known tag signatures (postprocessed) */
  if(strnstr(buffer, SSIEXECTAG, SSIEXECTAGLEN) != NULL) {
    charcount -= SSIEXECTAGLEN;
    memcpy(buffer, &buffer[SSIEXECTAGLEN],charcount);
    buffer[charcount] = '\0';
    return SSITAGEXEC;
  } else if(strnstr(buffer, SSIECHOTAG, SSIECHOTAGLEN) != NULL) {
    charcount -= SSIECHOTAGLEN;
    memcpy(buffer, &buffer[SSIECHOTAGLEN], charcount);
    buffer[charcount] = '\0';
    return SSITAGECHO;
  }
  return SSITAGPRIVATE;  
}
#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_DYNAMIC_HEADERS
/**
 * Generate the relevant HTTP headers for the given filename and write
 * them into the supplied buffer. Called only if HTTP version > 0.9
 */
static void
get_http_headers(struct http_state *pState, char *pszURI, int version)
{
  unsigned int iLoop;
  char *pszWork;
  char *pszExt;
  char *pszVars;
  struct dynhdr *h = &pState->sh.dyh;

  /* Ensure that we initialize the loop counter. */
  iLoop = 0;
  /* First header is split between version number and result code, uses placeholders 0,1 */
  h->hdrs[0] = (version == HTTP_VERSION_10)? HTTP_HDR_HTTP10 : HTTP_HDR_HTTP11;
  /* In all cases, the second header we send is the server identification
     so set it here. (placeholder 2)*/
  h->hdrs[2] = HTTP_HDR_SERVER;

  /* Content-type is split, using placeholders 3,4 
  setup an empty header (eoh) so we can preset the default
  error files, we'll change later if there is a real file */
  h->hdrs[3] = HTTP_HDR_EMPTY;
  /* We assume that any filename with "404" in it must be
     indicative of a 404 server error (and so on), whereas all
      other files require the 200 OK header. */
  if (strstr(pszURI, "404")) {
    h->hdrs[1] = HTTP_HDR_NOT_FOUND;
    h->hdrs[4] = DEFAULT_404_HTML;
  } else if (strstr(pszURI, "400")) {
    h->hdrs[1] = HTTP_HDR_BAD_REQUEST;
    h->hdrs[4] = DEFAULT_400_HTML;
  } else if (strstr(pszURI, "401")) {
    h->hdrs[1] = HTTP_HDR_NOT_AUTH;
    h->hdrs[4] = DEFAULT_401_HTML;
  } else if (strstr(pszURI, "501")) {
    h->hdrs[1] = HTTP_HDR_NOT_IMPL;
    h->hdrs[4] = DEFAULT_501_HTML;
  } else if (strstr(pszURI, "503")) {
    h->hdrs[1] = HTTP_HDR_UNAVAIL;
    h->hdrs[4] = DEFAULT_503_HTML;
  } else {
    h->hdrs[1] = HTTP_HDR_OK;
  }

  /* Determine if the URI has any variables and, if so, temporarily remove 
     them. */
  pszVars = strchr(pszURI, '?');
  if(pszVars) {
    *pszVars = '\0';
  }

  /* Get a pointer to the file extension.  We find this by looking for the
     last occurrence of "." in the filename passed. */
  pszExt = NULL;
  pszWork = strchr(pszURI, '.');
  while(pszWork) {
    pszExt = pszWork + 1;
    pszWork = strchr(pszExt, '.');
  }

  /* Now determine the content type and add the relevant header for that. */
  for(iLoop = 0; (iLoop < NUM_HTTP_HEADERS) && pszExt; iLoop++) {
    /* Have we found a matching extension? */
    if(!strcmp(g_psHTTPHeaders[iLoop].extension, pszExt)) {
      h->hdrs[4] = g_psHTTPHeaders[iLoop].headerIndex;
      break;
    }
  }

  /* Reinstate the parameter marker if there was one in the original URI. */
  if(pszVars) {
    *pszVars = '?';
  }

  /* Does the URL passed have any file extension?  If not, we assume it
     is a special-case URL used for control state notification and we 
     send back the default responses */
  if(pszExt) {
    h->hdrs[3] = HTTP_HDR_CONTENT_TYPE;
    /* Did we find a matching extension? */
    if(iLoop == NUM_HTTP_HEADERS) {
      /* No - use the default, plain text file type. */
      h->hdrs[4] = HTTP_HDR_DEFAULT_TYPE;
    }
  }
  /* Set up to send the first header string. */
  h->hdr_index = 0;
  h->hdr_left = 0;
}

#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

/** Sub-function of http_send(): end-of-file (or block) is reached,
 * either close the file or read the next block (if supported).
 *
 * @returns: 0 if the file is finished or no data has been read
 *           1 if the file is not finished and data has been read
 */
static u8_t
http_check_eof(struct tcp_pcb *pcb, struct http_state *hs)
{
#if LWIP_HTTPD_DYNAMIC_FILE_READ
  int count;
#endif /* LWIP_HTTPD_DYNAMIC_FILE_READ */

  /* Do we have a valid file handle? */
  if (hs->handle == NULL) {
    /* No - close the connection. */
    http_eof(pcb, hs);
    return 0;
  }
  if (fs_bytes_left(hs->handle) <= 0) {
    /* We reached the end of the file so this request is done. */
    LWIP_DEBUGF(HTTPD_DEBUG, ("End of file.\n"));
    http_eof(pcb, hs);
    return 0;
  }
#if LWIP_HTTPD_DYNAMIC_FILE_READ
  /* Do we already have a send buffer allocated? */
  if(hs->buf) {
    /* Yes - get the length of the buffer */
    count = hs->buf_len;
  } else {
    /* We don't have a send buffer so allocate one up to 2mss bytes long. */
#ifdef HTTPD_MAX_WRITE_LEN
    count = HTTPD_MAX_WRITE_LEN(pcb);
#else /* HTTPD_MAX_WRITE_LEN */
    count = 2 * tcp_mss(pcb);
#endif /* HTTPD_MAX_WRITE_LEN */
    do {
      hs->buf = (char*)mem_malloc((mem_size_t)count);
      if (hs->buf != NULL) {
        hs->buf_len = count;
        break;
      }
      count = count / 2;
    } while (count > 100);

    /* Did we get a send buffer? If not, return immediately. */
    if (hs->buf == NULL) {
      LWIP_DEBUGF(HTTPD_DEBUG, ("No buff\n"));
      return 0;
    }
  }

  /* Read a block of data from the file. */
  LWIP_DEBUGF(HTTPD_DEBUG, ("Trying to read %d bytes.\n", count));

#if LWIP_HTTPD_FS_ASYNC_READ
  count = fs_read_async(hs->handle, hs->buf, count, http_continue, hs);
#else /* LWIP_HTTPD_FS_ASYNC_READ */
  count = fs_read(hs->handle, hs->buf, count);
#endif /* LWIP_HTTPD_FS_ASYNC_READ */
  if (count < 0) {
    if (count == FS_READ_DELAYED) {
      /* Delayed read, wait for FS to unblock us */
      return 0;
    }
    /* We reached the end of the file so this request is done.
     * @todo: don't close here for HTTP/1.1? */
    LWIP_DEBUGF(HTTPD_DEBUG, ("End of file.\n"));
    http_eof(pcb, hs);
    return 0;
  }

  /* Set up to send the block of data we just read */
  LWIP_DEBUGF(HTTPD_DEBUG, ("Read %d bytes.\n", count));
  hs->left = count;
  hs->file = hs->buf;
#if LWIP_HTTPD_SSI
  if (hs->ssi) {
    hs->ssi->parse_left = count;
    hs->ssi->parsed = hs->buf;
  }
#endif /* LWIP_HTTPD_SSI */
#else /* LWIP_HTTPD_DYNAMIC_FILE_READ */
  LWIP_ASSERT("SSI and DYNAMIC_HEADERS turned off but eof not reached", 0);
#endif /* LWIP_HTTPD_SSI || LWIP_HTTPD_DYNAMIC_HEADERS */
  return 1;
}

#define ALLDATASENT  2
#define SOMEDATASENT 1

/** Elementary sub-function of all http_send() subfunctions
 * 
 * @returns: ALLDATASENT all data has been written
 *           SOMEDATASENT some data has been written
 *           0 no data has been written
 */
static u8_t
__http_send_data(struct tcp_pcb *pcb, char **from, u32_t *howmany, u8_t tcpflags)
{
  err_t err;
  u16_t len;

  len = (u16_t)LWIP_MIN(*howmany, 0xffff);
  
  err = http_write(pcb, *from, &len, tcpflags);
  if (err == ERR_OK) {
    *from += len;
    if((*howmany -= len) > 0)
      return SOMEDATASENT;
    return ALLDATASENT;
  }
  return 0;
}

#if LWIP_HTTPD_DYNAMIC_HEADERS
/** Sub-function of http_send(): send dynamic headers
 *
 * @returns: - HTTP_NO_DATA_TO_SEND: no new data has been enqueued
 *           - HTTP_DATA_TO_SEND_CONTINUE: continue with sending HTTP body
 *           - HTTP_DATA_TO_SEND_BREAK: data has been enqueued, headers pending,
 *                                      so don't send HTTP body yet
 * @note HTTP_IS_HDR_VOLATILE(hs, h->hdr_from) has been removed. We instruct TCP to copy,
 * in order to reduce overall memory and pbuf consumption. Headers are so short that the pbuf
 * overhead is comparable to the header length and the high number of chained pbufs messes
 * with the file sending operation.
 */
static u8_t
http_send_headers(struct tcp_pcb *pcb, struct http_state *hs)
{
  int ret;
  struct dynhdr *h = &hs->sh.dyh;

  /* resume any leftovers from prior memory constraints */
  if(h->hdr_left){
    if((ret=__http_send_data(pcb, (char **)&h->hdr_from, &h->hdr_left, TCP_WRITE_FLAG_COPY))
      != ALLDATASENT)
      return (ret)? HTTP_DATA_TO_SEND_BREAK : HTTP_NO_DATA_TO_SEND;
    ++(h->hdr_index);
  }
  /* now send the headers while there is memory */
  while(h->hdr_index < NUM_FILE_HDR_STRINGS){
    h->hdr_from = g_psHTTPHeaderStrings[h->hdrs[h->hdr_index]];
    h->hdr_left = strlen(h->hdr_from);
    if((ret=__http_send_data(pcb, (char **)&h->hdr_from, &h->hdr_left, TCP_WRITE_FLAG_COPY))
      != ALLDATASENT)
      return (ret)? HTTP_DATA_TO_SEND_BREAK : HTTP_NO_DATA_TO_SEND;
    ++(h->hdr_index);
  }
  /* headers done, flush and wait for file to be ready (if any) */
  if(!hs->file)
    return HTTP_DATA_TO_SEND_BREAK;
  return HTTP_DATA_TO_SEND_CONTINUE;
}
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

/** Sub-function of http_send(): This is the normal send-routine for non-ssi files
 * 
 * @returns: HTTP_DATA_TO_SEND_CONTINUE data has been written (so call tcp_ouput)
 *           HTTP_NO_DATA_TO_SEND no data has been written (no need to call tcp_output)
 */
static u8_t
http_send_data_nonssi(struct tcp_pcb *pcb, struct http_state *hs)
{
  /* We are not processing an SHTML file so no tag checking is necessary.
   * Just send the data as we received it from the file. */
  return (__http_send_data(pcb, &hs->file, &hs->left, HTTP_IS_DATA_VOLATILE(hs)))?
          HTTP_DATA_TO_SEND_CONTINUE : HTTP_NO_DATA_TO_SEND;
}


#if LWIP_HTTPD_SSI

#define SHTML_TAG_START "<!--#"
#define SHTML_TAG_START_LEN 5

#define SHTML_TAG_END "-->"
#define SHTML_TAG_END_LEN 3

static u16_t ssi_echo_var(int iIndex, char *pcInsert, int iInsertLen)
{
const tSSIvar *ssivar = &g_SSIechovars[iIndex];

  switch(ssivar->type){
  case INT8:
  default:
    return (u16_t) snprintf(pcInsert, iInsertLen, ssivar->format, *(u8_t *)(ssivar->var));
  case INT16:
    return (u16_t) snprintf(pcInsert, iInsertLen, ssivar->format, *(u16_t *)(ssivar->var));
  case INT32:
    return (u16_t) snprintf(pcInsert, iInsertLen, ssivar->format, *(u32_t *)(ssivar->var));
  case STRING:
    return (u16_t) snprintf(pcInsert, iInsertLen, ssivar->format, (char *)(ssivar->var));
  }
}

static u16_t ssi_exec_cmd(struct http_state *hs)
{
  struct http_ssi_state *ssi = hs->dh.ssi;
  LWIP_ASSERT("cmd != NULL", ssi->cmd != NULL);

  return ssi->cmd->func(ssi->tagbuffer, LWIP_HTTPD_MAX_TAG_INSERT_LEN
      ,ssi->funcstate, &ssi->funcstate
#if LWIP_HTTPD_FILE_STATE
      , hs->handle->state
#endif /* LWIP_HTTPD_FILE_STATE */
      );
}

/* HTTP_IS_DATA_VOLATILE(hs) is used as in the former handler, but in fact
SHTML files will be as static as HTML files as long as both come from a static
(in system flash) file system. So this should come from filesystem info...
tag generated content is server from a single RAM buffer and will be overwritten
as soon as it is queued, so must have a copy flag */
int http_shtml_data_handler(struct tcp_pcb *pcb, struct http_state *hs)
{
  struct http_ssi_state *ssi = hs->dh.ssi;
  int res = 0, ret;

  /* resume any leftovers from prior memory constraints */
  if(ssi->left){
    switch(res = __http_send_data(pcb, &ssi->from, &ssi->left, HTTP_IS_DATA_VOLATILE(hs))) {
	case SOMEDATASENT:
      return HTTP_DATA_TO_SEND_CONTINUE;
    case 0:
      return HTTP_NO_DATA_TO_SEND;
    }
  }
  ret = res;
  do {
    ret |= res;
    switch(ssi->state){
    case SSI_PROCESS_TAG:
      /* We found a tag and queued the file up to this point, parse the tag
      and do whatever it requires */
      if(parsetag(ssi->tag_start + SHTML_TAG_START_LEN,
             ssi->tag_end - ssi->tag_start - SHTML_TAG_START_LEN,
             ssi->tagbuffer) == SSITAGECHO){
	/* an 'echo var=' prints a variable and we resume parsing */
        ssi->from = "UNKNOWN VAR";
		ssi->left = 11;
    if(g_SSIechovars && g_SSIechoNumVars) {
	  int loop;
      for(loop = 0; loop < g_SSIechoNumVars; loop++) {
        if(strcmp(ssi->tagbuffer, g_SSIechovars[loop].varname) == 0) {
          ssi->left = ssi_echo_var(loop, ssi->tagbuffer, TAGBUFFER_SIZE);
          ssi->from = ssi->tagbuffer;
          break;
        }
      }
    }
        ssi->state = SSI_RESUME;
        break;
      } else { /* SSITAGEXEC or SSITAGPRIVATE */
        /* an 'exec cmd=' causes a function run */
        ssi->from = "UNKNOWN CMD";
		ssi->left = 11;
        ssi->state = SSI_RESUME;
        ssi->cmd = NULL;

    if(g_SSIexeccmds && g_SSIexecNumCmds) {
      int loop;
      for(loop = 0; loop < g_SSIexecNumCmds; loop++) {
        if(strcmp(ssi->tagbuffer, g_SSIexeccmds[loop].cmdname) == 0) {
          ssi->cmd = &g_SSIexeccmds[loop];
          ssi->state = SSI_RUNFUNC;
          break;
        }
      }
    }
      }
      if(ssi->cmd == NULL)  /* fallthrough on function hit, break on miss) */
        break;
      /*FALLTHROUGH*/
    case SSI_RUNFUNC:
      /* we call the function until it says 'don't call me anymore' */
      ssi->left = 0;
      if((ssi->left = ssi_exec_cmd(hs))>0){
        ssi->from = ssi->tagbuffer;
        break;
      }
      ssi->state = SSI_RESUME;
      /*FALLTHROUGH*/
    case SSI_RESUME:
      hs->file = &ssi->tag_end[SHTML_TAG_END_LEN];
      hs->left -= hs->file - ssi->tag_start;
      ssi->state = SSI_NEXT;
      /*FALLTHROUGH*/
    case SSI_NEXT:
      /* Find the occurrence of a tag start and a tag end; failure means
      there are no further tags, so we send the remaining piece of file.
      Otherwise, we send the file up to the tag start */
      if(((ssi->tag_start = strstr(hs->file, SHTML_TAG_START)) == NULL) ||
          ((ssi->tag_end = strstr(ssi->tag_start, SHTML_TAG_END)) == NULL)){
        ssi->left = hs->left;
        ssi->state = SSI_DONE;
      } else {
        ssi->left = ssi->tag_start - hs->file;
        hs->left -= ssi->left;  /* can't become 0 on a properly formatted file */
        ssi->state = SSI_PROCESS_TAG;
      }
      ssi->from = hs->file;
      break;
    case SSI_DONE:
      /* We've found the end of the file, when all data has been queued
      then signal http_data_send() to close the file */
      hs->left = ssi->left = 0;
      break;
    }
  } while (ssi->left &&
          ((res = __http_send_data(pcb, &ssi->from, &ssi->left, HTTP_IS_DATA_VOLATILE(hs))) == ALLDATASENT));
  return (ret)? HTTP_DATA_TO_SEND_CONTINUE : HTTP_NO_DATA_TO_SEND;
}
#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_CGI
#if LWIP_HTTPD_SUPPORT_POST
struct pcinfo {
	struct pbuf *p;
	struct parsereq *preq;
};
/* LWIP_HTTPD_CGI_BUFFER_SIZE must be big enough to hold this structure */

int cgi_post_content_info(struct cgi_state *cgi, u8_t *content_type, char *ctstring)
{

  struct pcinfo *c = (struct pcinfo *)cgi->buffer;
  struct parsereq *preq = c->preq;
  struct pbuf *p = c->p;

  if(ctstring == NULL) {
    if(!pbuf_memcmp(p, preq->contype, "application/x-www-form-urlencoded", 33)){
      *content_type = HTTP_CT_FORMU;      
      return 1;
#if LWIP_HTTPD_SUPPORT_POST_MULTIPART
    } else if(!pbuf_memcmp(p, preq->contype, "multipart/form-data", 19)){
      u16_t pos, crlf;
      *content_type = HTTP_CT_MFORMD;
      if(((pos = pbuf_memfind(p, "boundary=", 9, preq->contype)) < 0xFFF0) &&  /* Avoid possible overflows later */
        ((crlf = pbuf_memfind(p, CRLF, 2, preq->contype)) != 0xFFFF) &&
        ((pos += 9) < crlf)) {
        u16_t len = crlf - pos;
        char *ptr;
        if(len > LWHTTPD_BOUNDARY_BUFFER_SIZE) /* Oops, this violates the standard */
          return -1;
        if((ptr = http_cgi_boundary_alloc()) == NULL)
          return -1;
        cgi->boundary = ptr;
        cgi->bound_len = (u8_t) len;
        pbuf_copy_partial(p, ptr, len, pos);
        preq->offset -= 2;  /* re-write offset so it actually points to the first occurring boundary string */
        return 1;
      }
#endif /* LWIP_HTTPD_SUPPORT_POST_MULTIPART */
    } 
  } else {
    if(!pbuf_memcmp(p, preq->contype, ctstring, strlen(ctstring)))
      return 1;
  }
  LWIP_DEBUGF(HTTPD_DEBUG, ("Content-Type parse error\n"));
  return 0;
}
	/* 
    LWIP_ASSERT("LWIP_HTTPD_CGI_BUFFER_SIZE too small", LWIP_HTTPD_CGI_BUFFER_SIZE > sizeof(struct cdinfo));
	*/

#if LWIP_HTTPD_SUPPORT_POST_MULTIPART
/*
int cgi_multipart_next(struct cgi_state *cgi)
{
  struct pcinfo *c = (struct pcinfo *)cgi->buffer;
  struct parsereq *preq = c->preq;
  struct pbuf *p = c->p;

  if(pbuf_memcmp(p, preq->offset, "\r\n--", 4))
  if(pbuf_memcmp(p, preq->offset + 4, cgi->boundary, cgi->bound_len))
  if((start = pbuf_memfind(p, cgi->boundary, cgi->bound_len, prestart)) == 0xFFFF)
    if(!pbuf_memcmp(p, preq->contype, "application/x-www-form-urlencoded", 33)){
    } 
  LWIP_DEBUGF(HTTPD_DEBUG, ("Content-Type parse error\n"));
  return 0;
}
*/
#endif /* LWIP_HTTPD_SUPPORT_POST_MULTIPART */
	
	
static u8_t http_send(struct tcp_pcb *pcb, struct http_state *hs);

/**
 * This is the POST handler-routine for CGI "files"
 * As a sub-function of http_recv(), it passes received data to the user function until either:
 * - it pauses (returns cgi->length untouched), in which case you are responsible for resuming operation
 * later, as if no more data is coming, you won't be called again.
 * - it finishes handling content, indicated by setting content_len = 0
 * - it terminates (returns CGI_DONE)
 * @note the function may terminate early (return CGI_DONE while there is POST data being received),
 * in which case remaining content data will be ignored (not passed to the function) and any data
 * in the buffer passed to http_send().
 * Otherwise, the function must first get (and discard itself) the data content before sending any data.
 * @note You are responsible for memory/cpu usage, design your system accordingly.
 * @returns: 1 if done with the POST content, processing transferred to http_send()
 *           0 if still working but no more data is available or user function paused (didn't process any buffered data)
 *          -1 if data was received and user function won't handle it.
 */
static int
http_cgi_post_handler(struct tcp_pcb *pcb, struct http_state *hs, struct pbuf *p)
{
  struct http_cgi_state *cgi = hs->dh.cgi;
  struct parsereq *preq = &hs->sh.preq;
  int res;
  u32_t len;
  s32_t freed;
  
  LWIP_ASSERT("hs != NULL", hs != NULL);
  LWIP_ASSERT("cgi != NULL", cgi != NULL);
  LWIP_ASSERT("p != NULL", p != NULL);

  if(cgi->state != CGI_RECEIVING) { /* error condition, we moved out of this state and more data is coming */
    LWIP_DEBUGF(HTTPD_DEBUG, ("Received %"U16_F" bytes, but CGI function will ignore them\n", p->tot_len));
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return -1;
  }  
  LWIP_DEBUGF(HTTPD_DEBUG, ("Received %"U16_F" bytes\n", p->tot_len));
  /* chain pbufs */
  if (p == hs->req) {
    /* Call the user function with no data, just the request info. It may get it by calling
     * cgi_post_content_info() or ignore it */
    struct pcinfo *c = (struct pcinfo *)(cgi->exposed.buffer);
    c->p = hs->req;
    c->preq = preq;
    LWIP_DEBUGF(HTTPD_DEBUG, ("First pbuf, with request. Content-length: %u\nPassing to CGI function\n", cgi->exposed.content_len));
    cgi->exposed.length = 0;             /* Signal the buffer will be free (by omision) */
    res = cgi->func(&cgi->exposed);      /* Run the user function */
    tcp_recved(pcb, preq->offset);       /* Free request data, keep content len */
    freed = -1;		                 /* Signal this is the first run */
    goto cgipostfirstrun;
  } else {
    LWIP_DEBUGF(HTTPD_DEBUG, ("pbuf enqueued\n"));
    pbuf_cat(hs->req, p);
  }
  /* process content data */
  while((len = LWIP_MIN(hs->req->tot_len - preq->offset, sizeof(cgi->exposed.buffer) - cgi->exposed.length))>0){
    freed = len;
    LWIP_DEBUGF(HTTPD_DEBUG, ("Passing %d bytes to CGI function\n",len));
    pbuf_copy_partial(hs->req, cgi->exposed.buffer, len, preq->offset);
    cgi->exposed.length = len;
    res = cgi->func(&cgi->exposed);      /* Run the user function */
    freed -= cgi->exposed.length;        /* Calculate bytes processed */
    tcp_recved(pcb, freed);              /* Inform TCP that we have processed that amount of data. */
    preq->offset += freed;               /* Advance pointer */
cgipostfirstrun:
    if(res == CGI_DONE){                 /* Finished ? (Early termination) */
      cgi->state = CGI_STOP;
      break;
    }
    if (cgi->exposed.content_len == 0){	 /* All POST content processed ? */
      cgi->state = CGI_SENDING;
      break;
    }
    if(freed == 0)                       /* User paused ? */
      break;
    if(freed < sizeof(cgi->exposed.buffer)) /* If the user did not process the whole buffer, */
      memcpy(cgi->exposed.buffer,&cgi->exposed.buffer[freed], freed); /* move unprocessed content to start of buffer */
    if(preq->offset > hs->req->len){
      struct pbuf *q;
      preq->offset -= hs->req->len;
      q = hs->req->next; /* q can't be NULL since hs->req->len < processed data */
      pbuf_ref(q);
      pbuf_free(hs->req);
      hs->req = q;
    }
  }                                      /* If len evaluates to 0, all data in this pbuf chain has been processed */
  /* exit */
  if(cgi->state != CGI_RECEIVING) {
    tcp_recved(pcb, hs->req->tot_len - preq->offset); /* free remaining data */
    pbuf_free(hs->req);
    hs->req = NULL;
    hs->file = cgi->exposed.buffer;      /* pass control to cgi_data_handler() via http_send() */
    hs->left = cgi->exposed.length;
    http_send(pcb, hs);
    return 1;
  }
  /* to be called again when more data comes in */
  return 0;
}
#endif /* LWIP_HTTPD_SUPPORT_POST */

/**
 * This is the handler-routine for CGI "files", a sub-function of http_send()
 * This runs the user function until either:
 * - it pauses (returns cgi->length = 0)
 * - it terminates (returns CGI_DONE)
 * - memory is exhausted (by queing all generated data)
 * - tcp write limit is reached (see HTTPD_LIMIT_SENDING_TO_2MSS, HTTPD_MAX_WRITE_LEN)
 * @note You are responsible for memory/cpu usage, design your system accordingly.
 * CGIs are transient functions to serve user requests; if you know you'll be running
 * for too long, pause.
 * @todo Build some simple throttling mechanism so CGIs are simpler ? (like a small HTTPD_MAX_WRITE_LEN)
 *
 * @returns: HTTP_DATA_TO_SEND_CONTINUE data has been written (so call tcp_ouput)
 *           HTTP_NO_DATA_TO_SEND no data has been written (no need to call tcp_output)
 *           HTTP_DATA_SEND_TERMINATE CGI handling has finished
 */
static u8_t
http_cgi_data_handler(struct tcp_pcb *pcb, struct http_state *hs)
{
  struct http_cgi_state *cgi = hs->dh.cgi;
  int res = 0, ret;
  LWIP_ASSERT("hs != NULL", hs != NULL);
  LWIP_ASSERT("cgi != NULL", cgi != NULL);

  /* resume any leftovers from prior memory constraints */
  if(hs->left){
    switch(res = __http_send_data(pcb, &hs->file, &hs->left, TCP_WRITE_FLAG_COPY)) {
    case SOMEDATASENT:
      return HTTP_DATA_TO_SEND_CONTINUE;
    case 0:
      return HTTP_NO_DATA_TO_SEND;
    }
  }
  ret = res;
  /* all data on CGI buffer has been queued, resume CGI execution */
  if(cgi->state == CGI_SENDING){
    LWIP_DEBUGF(HTTPD_DEBUG, ("CGI run\n"));
    do {
  	  ret |= res;  /* remember if we once queued something to send */
      cgi->exposed.length = 0;
      if(cgi->func(&cgi->exposed) == CGI_DONE){
        cgi->state = CGI_STOP;
      }
      hs->file = cgi->exposed.buffer;  
      hs->left = cgi->exposed.length;
      LWIP_DEBUGF(HTTPD_DEBUG, ("CGI trying to send %u bytes\n", (unsigned int)hs->left));
    } while(hs->left && 
           ((res = __http_send_data(pcb, &hs->file, &hs->left, TCP_WRITE_FLAG_COPY)) == ALLDATASENT)
           && (cgi->state != CGI_STOP));
  }
  if((cgi->state != CGI_SENDING) && (ret != SOMEDATASENT)){
    LWIP_DEBUGF(HTTPD_DEBUG, ("CGI stop\n"));
    return HTTP_DATA_SEND_TERMINATE;
  }
  LWIP_DEBUGF(HTTPD_DEBUG, ("CGI pause"));
  return (ret)? HTTP_DATA_TO_SEND_CONTINUE : HTTP_NO_DATA_TO_SEND;
}

#endif /* LWIP_HTTPD_CGI */


/**
 * Try to send more data on this pcb.
 *
 * @param pcb the pcb to send data
 * @param hs connection state
 * @todo returns whatever its children (_headers, data_ssi, data_nonssi) return,
 * some of these return 0,1 instead of HTTP_NO_DATA_TO_SEND, HTTP_DATA_TO_SEND_CONTINUE.
 * There are also a couple of "return 0"s in this function 
 */
static u8_t
http_send(struct tcp_pcb *pcb, struct http_state *hs)
{
  u8_t data_to_send = HTTP_NO_DATA_TO_SEND;

  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_send: pcb=%p hs=%p left=%d\n", (void*)pcb,
    (void*)hs, hs != NULL ? (int)hs->left : 0));

/* If it is a CGI, go right away */
#if LWIP_HTTPD_CGI
  if(hs->handlertype == HTTP_DHTYPE_CGI){
    if((data_to_send = http_cgi_data_handler(pcb, hs)) == HTTP_DATA_SEND_TERMINATE){
      /* The CGI has finished execution.
       * This adds the FIN flag right into the last data segment. */
      LWIP_DEBUGF(HTTPD_DEBUG, ("End of CGI\n"));
      http_eof(pcb, hs);
      return HTTP_NO_DATA_TO_SEND;
    }
    return data_to_send;
  }
#endif /* LWIP_HTTPD_CGI */

  /* If we were passed a NULL state structure pointer, ignore the call. */
  if (hs == NULL) {
    return 0;
  }

#if LWIP_HTTPD_FS_ASYNC_READ
  /* Check if we are allowed to read from this file.
     (e.g. SSI might want to delay sending until data is available) */
  if (!fs_is_file_ready(hs->handle, http_continue, hs)) {
    return 0;
  }
#endif /* LWIP_HTTPD_FS_ASYNC_READ */

#if LWIP_HTTPD_DYNAMIC_HEADERS
  /* Do we have any more header data to send for this file? */
  if(hs->sh.dyh.hdr_index < NUM_FILE_HDR_STRINGS) {
    data_to_send = http_send_headers(pcb, hs);
    if (data_to_send != HTTP_DATA_TO_SEND_CONTINUE) {
      return data_to_send;
    }
  } 
  if(hs->method == HTTP_METHOD_HEAD){
    /* Just send headers if HEAD */
    http_eof(pcb, hs);
    return 0;
  }

#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
  
  /* Have we run out of file data to send? If so, we need to read the next
   * block from the file. */
  if (hs->left == 0) {
    if (!http_check_eof(pcb, hs)) {
      return 0;
    }
  }

#if LWIP_HTTPD_SSI
  if(hs->dh.ssi) {
    data_to_send = http_shtml_data_handler(pcb, hs);
  } else
#endif /* LWIP_HTTPD_SSI */
  {
    data_to_send = http_send_data_nonssi(pcb, hs);
  }

  if((hs->left == 0) && (fs_bytes_left(hs->handle) <= 0)) {
    /* We reached the end of the file so this request is done.
     * This adds the FIN flag right into the last data segment. */
    LWIP_DEBUGF(HTTPD_DEBUG, ("End of file\n"));
    http_eof(pcb, hs);
    return 0;
  }
  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_send: exit with code %u\n",data_to_send));
  return data_to_send;
}

#if LWIP_HTTPD_SUPPORT_EXTSTATUS
/** Initialize a http connection with a file to send for an error message
 *
 * @param hs http connection state
 * @param error_nr HTTP error number
 * @return ERR_OK if file was found and hs has been initialized correctly
 *         another err_t otherwise
 */
static err_t
http_find_error_file(struct http_state *hs, u16_t error_nr)
{
  const char *uri1, *uri2, *uri3;
  err_t err;

  switch(error_nr) {
  case 401:
    uri1 = "/401.html";
    uri2 = "/401.htm";
    uri3 = "/401.shtml";
    break;
  case 501:
    uri1 = "/501.html";
    uri2 = "/501.htm";
    uri3 = "/501.shtml";
    break;
  case 503:
    uri1 = "/503.html";
    uri2 = "/503.htm";
    uri3 = "/503.shtml";
    break;
  default:
    /* 400 (bad request is the default) */
    uri1 = "/400.html";
    uri2 = "/400.htm";
    uri3 = "/400.shtml";
    break;
  }
  err = fs_open(&hs->file_handle, uri1);
  if (err != ERR_OK) {
    err = fs_open(&hs->file_handle, uri2);
    if (err != ERR_OK) {
      err = fs_open(&hs->file_handle, uri3);
      if (err != ERR_OK) {
        LWIP_DEBUGF(HTTPD_DEBUG, ("Error page for error %"U16_F" not found\n",
          error_nr));
        return http_init_file(hs, NULL, uri1, 0);
      }
    }
  }
  return http_init_file(hs, &hs->file_handle, NULL, 0);
}
#else /* LWIP_HTTPD_SUPPORT_EXTSTATUS */
static err_t
http_find_error_file(struct http_state *hs, u16_t error_nr)
{
  const char *uri;
	
  switch(error_nr) {
  case 401:
    uri = "401";
    break;
  case 501:
    uri = "501";
    break;
  case 503:
    uri = "503";
    break;
  default:
    uri = "400";
    break;
  }
  return http_init_file(hs, NULL, uri, 0);
}
#endif /* LWIP_HTTPD_SUPPORT_EXTSTATUS */

/**
 * Get the file struct for a 404 error page.
 * Tries some file names and returns NULL if none found.
 *
 * @param uri pointer that receives the actual file name URI
 * @return file struct for the error page or NULL no matching file was found
 */
static struct fs_file *
http_get_404_file(struct http_state *hs, const char **uri)
{
  err_t err;

  *uri = "/404.html";
  err = fs_open(&hs->file_handle, *uri);
  if (err != ERR_OK) {
    /* 404.html doesn't exist. Try 404.htm instead. */
    *uri = "/404.htm";
    err = fs_open(&hs->file_handle, *uri);
    if (err != ERR_OK) {
      /* 404.htm doesn't exist either. Try 404.shtml instead. */
      *uri = "/404.shtml";
      err = fs_open(&hs->file_handle, *uri);
      if (err != ERR_OK) {
        /* 404.htm doesn't exist either. Indicate to the caller that it should
         * send back a default 404 page.
         */
        *uri = "404";
        return NULL;
      }
    }
  }

  return &hs->file_handle;
}

#if LWIP_HTTPD_FS_ASYNC_READ
/** Try to send more data if file has been blocked before
 * This is a callback function passed to fs_read_async().
 */
static void
http_continue(void *connection)
{
  struct http_state *hs = (struct http_state*)connection;
  if (hs && (hs->pcb) && (hs->handle)) {
    LWIP_ASSERT("hs->pcb != NULL", hs->pcb != NULL);
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("httpd_continue: try to send more data\n"));
    if (http_send(hs->pcb, hs)) {
      /* If we wrote anything to be sent, go ahead and send it now. */
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("tcp_output\n"));
      tcp_output(hs->pcb);
    }
  }
}
#endif /* LWIP_HTTPD_FS_ASYNC_READ */


enum hrstates {HTTP_PARSEREQ_FIRSTLINE=0, HTTP_PARSEREQ_LINES};
/**
 * When data has been received in the correct state, try to parse it
 * as a HTTP request.
 *
 * @param p the received pbuf
 * @param hs the connection state
 * @param pcb the tcp_pcb which received this packet
 * @return ERR_OK if request was OK and hs has been initialized correctly
 *         ERR_INPROGRESS if request was OK so far but not fully received
 *         another err_t otherwise
 */
u16_t
pbuf_memnfind(struct pbuf* p, const void* mem, u16_t mem_len, u16_t start_offset, u16_t end_offset);

static err_t
http_parse_request(struct pbuf *p, struct http_state *hs)
{
  int data;
  u16_t crlf, data_len;
  u16_t sp1, sp2;
  int err=0;
  struct parsereq *preq = &hs->sh.preq;
  
  LWIP_ASSERT("p != NULL", p != NULL);
  LWIP_ASSERT("hs != NULL", hs != NULL);

  if ((hs->handle != NULL) || (hs->file != NULL)) {	/* @todo: hs->handle condition was already tested in http_recv() */
    LWIP_DEBUGF(HTTPD_DEBUG, ("Received data while sending a file\n"));
    /* already sending a file */
    /* @todo: abort? */
    return ERR_USE;
  }
  LWIP_DEBUGF(HTTPD_DEBUG, ("Received %"U16_F" bytes\n", p->tot_len));

  /* enqueue the pbuf */
  if (hs->req == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("First pbuf\n"));
    hs->req = p;
  } else {
    LWIP_DEBUGF(HTTPD_DEBUG, ("pbuf enqueued\n"));
    pbuf_cat(hs->req, p);
  }
  do {
    /* check for CRLF (wait for a line) */
    if((crlf = pbuf_memfind(hs->req, CRLF, 2, preq->offset)) == 0xFFFF){
      u16_t clen;
      clen = pbuf_clen(hs->req);
      if (clen <= LWIP_HTTPD_REQ_QUEUELEN) {
        /* line/request not fully received (too short or CRLF is missing) */
        return ERR_INPROGRESS;
      } else {
  	  /* request is too long, exceding line buffer or max number of pbufs
        do I care about the number of pbufs or just the amount of memory in them ?
          Actually both...
  	  */
        LWIP_DEBUGF(HTTPD_DEBUG, ("Too many pbufs in use (%u), reached LWIP_HTTPD_REQ_QUEUELEN limit\n", clen));
badrequest:
        LWIP_DEBUGF(HTTPD_DEBUG, ("bad request\n"));
        /* could not parse request */
        return http_find_error_file(hs, 400);
      }
    }
  
    data_len = crlf - preq->offset;
    data = preq->offset;
    preq->offset = crlf + 2;
  
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("CRLF received, parsing request\n"));
    switch(preq->state){
    case HTTP_PARSEREQ_FIRSTLINE:
      /* parse method, there can be more than one line in the pbuf, so limit the scope */
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("parsing first line for method\n"));
      if ((sp1=pbuf_memnfind(hs->req, "GET ", 4, data, crlf)) != 0xFFFF) {
        hs->method = HTTP_METHOD_GET;
        sp1 += 3;
        LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Received GET request\n"));
#if LWIP_HTTPD_SUPPORT_POST
      } else if ((sp1=pbuf_memnfind(hs->req, "POST ", 5, data, crlf)) != 0xFFFF) {
        hs->method = HTTP_METHOD_POST;
        sp1 += 4;
        preq->contype = preq->contlen = 0xFFFF;
        LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Received POST request\n"));
#endif /* LWIP_HTTPD_SUPPORT_POST */
#if LWIP_HTTPD_DYNAMIC_HEADERS
      } else if ((sp1=pbuf_memnfind(hs->req, "HEAD ", 5, data, crlf)) != 0xFFFF) {
        hs->method = HTTP_METHOD_HEAD;
        sp1 += 4;
        LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Received HEAD request\n"));
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
      } else {
        /* unsupported method! */
        LWIP_DEBUGF(HTTPD_DEBUG, ("Unsupported request method (not implemented)\n"));
        err = 1;
      }
      /* parse version, even if method is not OK */
      sp2 = pbuf_memnfind(hs->req, "HTTP/1.", 7, sp1+1, crlf);
      if (sp2 == 0xFFFF) {
        sp2 = crlf;
        hs->version = HTTP_VERSION_09;
#if LWIP_HTTPD_SUPPORT_POST
        if (hs->method == HTTP_METHOD_POST) {
          /* HTTP/0.9 does not support POST */
          goto badrequest;
        }
#endif /* LWIP_HTTPD_SUPPORT_POST */
      } else {
        if(pbuf_get_at(hs->req, sp2 + 7) == '0')
          hs->version = HTTP_VERSION_10;
        else
          hs->version = HTTP_VERSION_11;
        sp2 -= 1;
      }
      if(err) /* exit if method is not OK */
        return http_find_error_file(hs, 501);
      /* parse URI */
      if((sp2 - sp1) > 1){
        int uri_len = LWIP_MIN(sp2 - sp1 - 1, LWIP_HTTPD_URI_BUFSIZE);
        pbuf_copy_partial(hs->req, uri_buf, uri_len, sp1+1);
        uri_buf[uri_len] = 0;
        LWIP_DEBUGF(HTTPD_DEBUG, ("Received request for URI: \"%s\"\n", uri_buf));
      } else {
        LWIP_DEBUGF(HTTPD_DEBUG, ("invalid URI\n"));
        goto badrequest;
      }
      ++(preq->state);
      break;
    case HTTP_PARSEREQ_LINES:
      /* end of HTTP headers is indicated by an empty line */
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("parsing succesive lines\n"));
      if(data_len){
#if LWIP_HTTPD_AUTH
        u16_t authdata = pbuf_memnfind(hs->req, "uthorization: ", 14, data, crlf);
        if (authdata < crlf) {
          authdata += 14;
          LWIP_DEBUGF(HTTPD_DEBUG, ("Authorization provided\r\n"));
          hs->uid = http_auth_process(hs->req, authdata, crlf);
        }
#endif /* LWIP_HTTPD_AUTH */
#if LWIP_HTTPD_SUPPORT_11_KEEPALIVE
        if ((hs->version == HTTP_VERSION_11) &&
         (pbuf_memnfind(hs->req, HTTP11_CONNECTIONKEEPALIVE, ?, data, crlf) != 0xFFFF) {
          hs->keepalive = 1;
        }
#endif /* LWIP_HTTPD_SUPPORT_11_KEEPALIVE */
#if LWIP_HTTPD_SUPPORT_POST
         if (hs->method == HTTP_METHOD_POST) {
           char *txt = (char *)g_psHTTPHeaderStrings[HTTP_HDR_CONTENT_TYPE];
           u16_t pos = pbuf_memnfind(hs->req, txt, 14, data, crlf);  /* Find "Content-Type" string */
           if ((pos < crlf) && ((pos += 14) < crlf)){
             preq->contype = pos;
           } else {
             txt = (char *)g_psHTTPHeaderStrings[HTTP_HDR_CONTENT_LENGTH];
             pos = pbuf_memnfind(hs->req, txt, 16, data, crlf);    /* Find "Content-Length" string */
             if ((pos < crlf) && ((pos += 16) < crlf))
               preq->contlen = pos;
           }
         }
#endif /* LWIP_HTTPD_SUPPORT_POST */
         break;
      }
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("end of headers\n"));
#if LWIP_HTTPD_SUPPORT_POST
      if ((hs->method == HTTP_METHOD_POST) && 
         ((preq->contlen == 0xFFFF) || (preq->contype == 0xFFFF)))
        goto badrequest;
#endif /* LWIP_HTTPD_SUPPORT_POST */
      {
        int ret=http_find_file(hs, uri_buf);
#if LWIP_HTTPD_AUTH
        if(ret == 1){
          LWIP_DEBUGF(HTTPD_DEBUG, ("Authorization failed\n"));
          return http_find_error_file(hs, 401);
        } else
#endif /* LWIP_HTTPD_AUTH */
        {
          return ret;
        }
      }
    }
  } while(hs->req->tot_len > preq->offset);
  /* we didn't get the end of headers so far */
  return ERR_INPROGRESS;
}


#if LWIP_HTTPD_CGI
/** Initialize structures so this http connection is handled by a CGI handler
 * Called by http_find_file.
 *
 * @param idx the index in the CGI table (to pickup the function)
 * @param hs http connection state
 * @param params pointer to parameters in HTTP request (recv buffer)
 * @return ERR_OK if memory is available and hs has been initialized correctly
 *         another err_t otherwise
 */
static err_t
http_init_cgi(int idx, struct http_state *hs, char *params)
{
  struct http_cgi_state *cgi = http_cgi_state_alloc();
  if (cgi == NULL) {
    /* We don't have enough memory to run the CGI, so return
       503 Service Unavailable */    
    return http_find_error_file(hs, 503);
  }
  cgi->func = g_pCGIs[idx].pfnCGIHandler;
  cgi->exposed.state = 0;
  hs->dh.cgi = cgi;
  hs->handlertype = HTTP_DHTYPE_CGI;
  cgi->exposed.length = 0;
  hs->file = cgi->exposed.buffer;  
  hs->left = 0;
  hs->retries = 0;
  cgi->exposed.http_version = hs->version;
  cgi->exposed.http_method = hs->method;
#if LWIP_HTTPD_AUTH
  cgi->exposed.uid = hs->uid;
#endif /* LWIP_HTTPD_AUTH */
#if LWIP_HTTPD_TIMING
  hs->time_started = sys_now();
#endif /* LWIP_HTTPD_TIMING */
  hs->handle = NULL;
#if LWIP_HTTPD_SUPPORT_POST
  if (hs->method == HTTP_METHOD_POST) {
#define HTTP_HDR_CONTENT_LEN_DIGIT_MAX_LEN  10
    char ctnumstring[HTTP_HDR_CONTENT_LEN_DIGIT_MAX_LEN];
    struct parsereq *preq = &hs->sh.preq;
    pbuf_copy_partial(hs->req, ctnumstring, HTTP_HDR_CONTENT_LEN_DIGIT_MAX_LEN, preq->contlen);
    cgi->exposed.content_len = atoi(ctnumstring);
    cgi->state = CGI_RECEIVING;
  } else
#endif /* LWIP_HTTPD_SUPPORT_POST */
  {
    *(char **)cgi->exposed.buffer = params;  /* pointer to the text after the URI in the input buffer */
    cgi->state = CGI_SENDING;
  }
  return ERR_OK;
}
#endif /* LWIP_HTTPD_CGI */


/** Try to find the file specified by uri and, if found, initialize hs
 * accordingly.
 *
 * @param hs the connection state
 * @param uri the HTTP header URI
 * @param permissions the authentication information (-1: none, u8_t otherwise)
 * @return ERR_OK if file was found and hs has been initialized correctly
 *         >0 if authorization required and not matching provided
 *         another err_t (< 0) otherwise
 */
static err_t
http_find_file(struct http_state *hs, const char *uri)
{
  size_t loop;
  struct fs_file *file = NULL;
  char *params;
  err_t err;
#if LWIP_HTTPD_CGI
  int i;
#endif /* LWIP_HTTPD_CGI */
#if !LWIP_HTTPD_SSI
  const
#endif /* !LWIP_HTTPD_SSI */
  /* By default, assume we will not be processing server-side-includes tags */
  u8_t tag_check = 0;

  /* Have we been asked for the default root file? */
  if((uri[0] == '/') &&  (uri[1] == 0)) {
    /* Try each of the configured default filenames until we find one
       that exists. */
    for (loop = 0; loop < NUM_DEFAULT_FILENAMES; loop++) {
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Looking for %s...\n", g_psDefaultFilenames[loop].name));
      err = fs_open(&hs->file_handle, (char *)g_psDefaultFilenames[loop].name);
      uri = (char *)g_psDefaultFilenames[loop].name;
      if(err == ERR_OK) {
        file = &hs->file_handle;
        LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Opened.\n"));
#if LWIP_HTTPD_SSI
        tag_check = g_psDefaultFilenames[loop].shtml;
#endif /* LWIP_HTTPD_SSI */
        break;
      }
    }
    if (file == NULL) {
      /* None of the default filenames exist so send back a 404 page */
      file = http_get_404_file(hs, &uri);
#if LWIP_HTTPD_SSI
      tag_check = 0;
#endif /* LWIP_HTTPD_SSI */
    }
  } else {
    /* No - we've been asked for a specific file. */
    /* First, isolate the base URI (without any parameters) */
    params = (char *)strchr(uri, '?');
    if (params != NULL) {
      /* URI contains parameters. NULL-terminate the base URI */
      *params = '\0';
      params++;
    }
    hs->handlertype = HTTP_DHTYPE_HTML; /* Assume a basic plain static standard HTML file */
#if LWIP_HTTPD_CGI
    /* Does the base URI we have isolated correspond to a CGI handler? */
    if (g_iNumCGIs && g_pCGIs) {
      for (i = 0; i < g_iNumCGIs; i++) {
        if (strcmp(uri, g_pCGIs[i].pcCGIName) == 0) {
          /* We found a CGI that handles this URI */
#if LWIP_HTTPD_AUTH
          if(g_pCGIs[i].permissions) { 
            if(hs->uid == -1) {    /* no authorization provided */
              return 1;
            }else {                /* authorization included in request */
              u8_t fperm = g_pCGIs[i].permissions;
              u8_t uperm = (u8_t) auth_userperm(hs->uid);
              if(hs->method != HTTP_METHOD_POST){ /* CGI needs AUTH_RDGRANTED for GET/HEAD */
              	if(!AUTH_RDGRANTED(fperm, uperm))
                	return 1;
              } else {                           /* and AUTH_WRGRANTED for POST */
              	if(!AUTH_WRGRANTED(fperm, uperm))
                	return 1;
              }
            }
          }
#endif /* LWIP_HTTPD_AUTH */
          return http_init_cgi(i, hs, params);
        }
      }
    }
#endif /* LWIP_HTTPD_CGI */

    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Opening %s\n", uri));

    err = fs_open(&hs->file_handle, uri);
    if (err == ERR_OK) {
      file = &hs->file_handle;
#if LWIP_HTTPD_AUTH
      if(hs->file_handle.permissions) { /* file needs auth */
        if(hs->uid == -1) {       /* no authorization provided */
          return 1;
        } else {                  /* authorization included in request */
          if(!AUTH_RDGRANTED(hs->file_handle.permissions, (u8_t) auth_userperm(hs->uid)))
            return 1;
        }
      }
#endif /* LWIP_HTTPD_AUTH */
    } else {
      file = http_get_404_file(hs, &uri);
    }
#if LWIP_HTTPD_SSI
    if (file != NULL) {
      /* See if we have been asked for an shtml file and, if so,
         enable tag checking. */
      tag_check = 0;
      for (loop = 0; loop < NUM_SHTML_EXTENSIONS; loop++) {
        if (strstr(uri, g_pcSSIExtensions[loop])) {
          tag_check = 1;
          break;
        }
      }
    }
#endif /* LWIP_HTTPD_SSI */
  }
  return http_init_file(hs, file, uri, tag_check);
}

/** Initialize a http connection with a file to send (if found).
 * Called by http_find_file and http_find_error_file.
 *
 * @param hs http connection state
 * @param file file structure to send (or NULL if not found)
 * @param uri the HTTP header URI
 * @param tag_check enable SSI tag checking
 * @return ERR_OK if file was found and hs has been initialized correctly
 *         another err_t otherwise
 */
static err_t
http_init_file(struct http_state *hs, struct fs_file *file, const char *uri, u8_t tag_check)
{
  if (file != NULL) {
    /* file opened, initialise struct http_state */
#if LWIP_HTTPD_SSI
    if (tag_check) {
      struct http_ssi_state *ssi = http_ssi_state_alloc();
      if (ssi != NULL) {
        ssi->cmd = NULL;
        hs->dh.ssi = ssi;
        hs->handlertype = HTTP_DHTYPE_SHTML;
       	ssi->left = 0;
	ssi->state = SSI_NEXT;
      }
    }
#else /* LWIP_HTTPD_SSI */
    LWIP_UNUSED_ARG(tag_check);
#endif /* LWIP_HTTPD_SSI */
    hs->handle = file;
    hs->file = (char*)file->data;
    LWIP_ASSERT("File length must be positive!", (file->len >= 0));
    hs->left = file->len;
    hs->retries = 0;
#if LWIP_HTTPD_TIMING
    hs->time_started = sys_now();
#endif /* LWIP_HTTPD_TIMING */
#if !LWIP_HTTPD_DYNAMIC_HEADERS
    LWIP_ASSERT("HTTP headers not included in file system", hs->handle->http_header_included);
#endif /* !LWIP_HTTPD_DYNAMIC_HEADERS */
#if LWIP_HTTPD_SUPPORT_V09
    if ((hs->handle->http_header_included) && (hs->version == HTTP_VERSION_09)) {
      /* HTTP/0.9 responses are sent without HTTP header,
         search for the end of the header. */
      char *file_start = strnstr(hs->file, CRLF CRLF, hs->left);
      if (file_start != NULL) {
        size_t diff = file_start + 4 - hs->file;
        hs->file += diff;
        hs->left -= (u32_t)diff;
      }
    }
#endif /* LWIP_HTTPD_SUPPORT_V09*/
  } else {
    hs->handle = NULL;
    hs->file = NULL;
    hs->left = 0;
    hs->retries = 0;
  }
  /* Indicate that the headers are not yet valid */
  hs->sh.dyh.hdr_index = NUM_FILE_HDR_STRINGS;
#if LWIP_HTTPD_DYNAMIC_HEADERS
   /* Determine the HTTP headers to send based on the file extension of
   * the requested URI. */
  if (((hs->handle == NULL) || !hs->handle->http_header_included) && (hs->version != HTTP_VERSION_09)) {
    get_http_headers(hs, (char*)uri, hs->version);
  }
#else /* LWIP_HTTPD_DYNAMIC_HEADERS */
  LWIP_UNUSED_ARG(uri);
#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */
  return ERR_OK;
}


/**
 * The pcb had an error and is already deallocated.
 * The argument might still be valid (if != NULL).
 */
static void
http_err(void *arg, err_t err)
{
  struct http_state *hs = (struct http_state *)arg;
  LWIP_UNUSED_ARG(err);

  LWIP_DEBUGF(HTTPD_DEBUG, ("http_err: %s", lwip_strerr(err)));

  if (hs != NULL) {
    http_state_free(hs);
  }
}

/**
 * Data has been sent and acknowledged by the remote host.
 * This means that more data can be sent.
 */
static err_t
http_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
  struct http_state *hs = (struct http_state *)arg;

  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_sent %p\n", (void*)pcb));

  LWIP_UNUSED_ARG(len);

  if (hs == NULL) {
    return ERR_OK;
  }

  hs->retries = 0;

  http_send(pcb, hs);

  return ERR_OK;
}

/**
 * The poll function is called every 2nd second.
 * If there has been no data sent (which resets the retries) in 8 seconds, close.
 * If the last portion of a file has not been sent in 2 seconds, close.
 *
 * This could be increased, but we don't want to waste resources for bad connections.
 */
static err_t
http_poll(void *arg, struct tcp_pcb *pcb)
{
  struct http_state *hs = (struct http_state *)arg;
  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_poll: pcb=%p hs=%p pcb_state=%s\n",
    (void*)pcb, (void*)hs, tcp_debug_state_str(pcb->state)));

  if (hs == NULL) {
    err_t closed;
    /* arg is null, close. */
    LWIP_DEBUGF(HTTPD_DEBUG, ("http_poll: arg is NULL, close\n"));
    closed = http_close_conn(pcb, NULL);
    LWIP_UNUSED_ARG(closed);
#if LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR
    if (closed == ERR_MEM) {
       tcp_abort(pcb);
       return ERR_ABRT;
    }
#endif /* LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR */
    return ERR_OK;
  } else {
    hs->retries++;
    if (hs->retries == HTTPD_MAX_RETRIES) {
      LWIP_DEBUGF(HTTPD_DEBUG, ("http_poll: too many retries, close\n"));
      http_close_conn(pcb, hs);
      return ERR_OK;
    }

    /* If this connection has a file open (or it is a CGI), try to send some more data. If
     * it has not yet received a GET request, don't do this since it will
     * cause the connection to close immediately. */
    if(hs && ((hs->handle)
#if LWIP_HTTPD_CGI
             || (hs->handlertype == HTTP_DHTYPE_CGI)
#endif /* LWIP_HTTPD_CGI */
             )) {
      LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_poll: try to send more data\n"));
      if(http_send(pcb, hs)) {
        /* If we wrote anything to be sent, go ahead and send it now. */
        LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("tcp_output\n"));
        tcp_output(pcb);
      }
    }
  }

  return ERR_OK;
}

/**
 * Data has been received on this pcb.
 * For HTTP 1.0 GET, this would normally only happen once (if the request fits in one packet).
 * For POSTs, the request is more likely to not fit in one packet, so this function will be called
 * more times.
 */
static err_t
http_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  err_t parsed = ERR_ABRT;
  struct http_state *hs = (struct http_state *)arg;
  LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("http_recv: pcb=%p pbuf=%p err=%s\n", (void*)pcb,
    (void*)p, lwip_strerr(err)));

  if ((err != ERR_OK) || (p == NULL) || (hs == NULL)) {
    /* error or closed by other side? */
    if (p != NULL) {
      /* Inform TCP that we have taken the data. */
      tcp_recved(pcb, p->tot_len);
      pbuf_free(p);
    }
    if (hs == NULL) {
      /* this should not happen, only to be robust */
      LWIP_DEBUGF(HTTPD_DEBUG, ("Error, http_recv: hs is NULL, close\n"));
    }
    http_close_conn(pcb, hs);
    return ERR_OK;
  }

  if (hs->handle != NULL){
  /* There is a handle, we are sending data, this is an error condition or an attempt to
   * do a persistent connection request, which we don't support (yet?) */
    printf("http_recv: already sending GET file data\n");
    LWIP_DEBUGF(HTTPD_DEBUG, ("http_recv: already sending GET file data\n"));
  } else {
  /* There is no handle, this is a request unless we are serving a CGI */
#if LWIP_HTTPD_CGI
    if (hs->handlertype == HTTP_DHTYPE_CGI){
      /* We are serving a CGI, so unless this is POST data, this is an error condition */
      if(hs->method != HTTP_METHOD_POST){
        LWIP_DEBUGF(HTTPD_DEBUG, ("http_recv: already serving CGI GET\n"));
      } else {
#if LWIP_HTTPD_SUPPORT_POST
        /* A POST request has been parsed and we are now receiving content data.
         * We will call the proper data handler with content data in pbuf, and forget
         * about the pbuf, it is now the responsibility of the data handler
         */
        LWIP_DEBUGF(HTTPD_DEBUG, ("POST on CGI, receiving data beyond first packet\n"));
        http_cgi_post_handler(pcb, hs, p);
        return ERR_OK;
#endif /* LWIP_HTTPD_SUPPORT_POST */
      }
    } else
#endif /* LWIP_HTTPD_CGI */
    { /* This is a request, parse it */
    tcp_recved(pcb, p->tot_len);    /* Inform TCP that we have taken the data. */
    parsed = http_parse_request(p, hs);
    LWIP_ASSERT("http_parse_request: unexpected return value", parsed == ERR_OK
      || parsed == ERR_INPROGRESS ||parsed == ERR_ARG || parsed == ERR_USE);
    }
  }
  if (parsed == ERR_INPROGRESS) /* request not yet fully parsed */
    return ERR_OK;
  if (parsed == ERR_OK) {
    LWIP_DEBUGF(HTTPD_DEBUG | LWIP_DBG_TRACE, ("Request successfully parsed, about to leave http_recv()\n"));
#if LWIP_HTTPD_CGI
    if ((hs->handlertype == HTTP_DHTYPE_CGI) && (hs->method == HTTP_METHOD_POST)) {
#if LWIP_HTTPD_SUPPORT_POST
      /* A POST request for a CGI has been parsed, we need to call the handler ourselves
       * for the first time to pass the header and any remaining content data in the
       * request pbuf(s) and forget about it, it is now the data handler's responsibility
       */
      http_cgi_post_handler(pcb, hs, hs->req);
      LWIP_DEBUGF(HTTPD_DEBUG, ("POST on CGI, passing header (and content data) in first packet\n"));
      return ERR_OK;
#endif /* LWIP_HTTPD_SUPPORT_POST */
    } else
#endif /* LWIP_HTTPD_CGI */
    {
      /* A GET request has been successfully parsed.(or a POST for a non-CGI file, which we'll treat as a GET)
       * http_parse_request() has been concatenating all succesive pbufs until the header was complete
       * (or error), so we must free them
       */
      if (hs->req != NULL) {
        pbuf_free(hs->req);
        hs->req = NULL;
      }
      http_send(pcb, hs);
    }
  } else {
    /* parse error, 
     * http_parse_request() has been concatenating all succesive pbufs until the header was complete
     * (or error), so we must free them at the end; unless it is a POST request
     */
    if (hs->req != NULL) {
      pbuf_free(hs->req);
      hs->req = NULL;
    }
    if (parsed == ERR_ARG) {
      /* @todo: close on ERR_USE? */
      http_close_conn(pcb, hs);
    }
  }
  return ERR_OK;
}

/**
 * A new incoming connection has been accepted.
 */
static err_t
http_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct http_state *hs;
  struct tcp_pcb_listen *lpcb = (struct tcp_pcb_listen*)arg;
  LWIP_UNUSED_ARG(err);
  LWIP_DEBUGF(HTTPD_DEBUG, ("http_accept %p / %p\n", (void*)pcb, arg));

  /* Decrease the listen backlog counter */
  tcp_accepted(lpcb);
  /* Set priority */
  tcp_setprio(pcb, HTTPD_TCP_PRIO);

  /* Allocate memory for the structure that holds the state of the
     connection - initialized by that function. */
  hs = http_state_alloc();
  if (hs == NULL) {
    LWIP_DEBUGF(HTTPD_DEBUG, ("http_accept: Out of memory, RST\n"));
    return ERR_MEM;
  }
  hs->pcb = pcb;

  /* Tell TCP that this is the structure we wish to be passed for our
     callbacks. */
  tcp_arg(pcb, hs);

  /* Set up the various callback functions */
  tcp_recv(pcb, http_recv);
  tcp_err(pcb, http_err);
  tcp_poll(pcb, http_poll, HTTPD_POLL_INTERVAL);
  tcp_sent(pcb, http_sent);

  return ERR_OK;
}

/**
 * Initialize the httpd with the specified local address.
 */
static void
httpd_init_addr(ip_addr_t *local_addr)
{
  struct tcp_pcb *pcb;
  err_t err;

  pcb = tcp_new();
  LWIP_ASSERT("httpd_init: tcp_new failed", pcb != NULL);
  tcp_setprio(pcb, HTTPD_TCP_PRIO);
  /* set SOF_REUSEADDR here to explicitly bind httpd to multiple interfaces */
  err = tcp_bind(pcb, local_addr, HTTPD_SERVER_PORT);
  LWIP_ASSERT("httpd_init: tcp_bind failed", err == ERR_OK);
  pcb = tcp_listen(pcb);
  LWIP_ASSERT("httpd_init: tcp_listen failed", pcb != NULL);
  /* initialize callback arg and accept callback */
  tcp_arg(pcb, pcb);
  tcp_accept(pcb, http_accept);
}

/**
 * Initialize the httpd: set up a listening PCB and bind it to the defined port
 */
void
httpd_init(void)
{
#if HTTPD_USE_MEM_POOL
  LWIP_ASSERT("memp_sizes[MEMP_HTTPD_STATE] >= sizeof(http_state)",
     memp_sizes[MEMP_HTTPD_STATE] >= sizeof(http_state));
  LWIP_ASSERT("memp_sizes[MEMP_HTTPD_SSI_STATE] >= sizeof(http_ssi_state)",
     memp_sizes[MEMP_HTTPD_SSI_STATE] >= sizeof(http_ssi_state));
  LWIP_ASSERT("memp_sizes[MEMP_HTTPD_CGI_STATE] >= sizeof(http_cgi_state)",
     memp_sizes[MEMP_HTTPD_CGI_STATE] >= sizeof(http_cgi_state));
  LWIP_ASSERT("memp_sizes[MEMP_HTTPD_CGI_BOUNDARY] >= LWHTTPD_BOUNDARY_BUFFER_SIZE",
     memp_sizes[MEMP_HTTPD_CGI_BOUNDARY] >= LWHTTPD_BOUNDARY_BUFFER_SIZE);
#endif
  LWIP_DEBUGF(HTTPD_DEBUG, ("httpd_init\n"));

  httpd_init_addr(IP_ADDR_ANY);
#if LWIP_HTTPD_AUTH
  auth_init();
#endif /* LWIP_HTTPD_AUTH */
}

#if LWIP_HTTPD_SSI

/**
 * Set the SSI exec handler table of functions.
 *
 * @param ssi_cmds the table address
 * @param num_cmds number of entries in the table
 */
void http_set_ssi_execfuncs(const tSSIcmd *ssi_cmds, int num_cmds)
{
  LWIP_DEBUGF(HTTPD_DEBUG, ("http_set_ssi_execfuncs\n"));

  LWIP_ASSERT("no table address given", ssi_cmds != NULL);
  LWIP_ASSERT("invalid table length", num_cmds > 0);

  g_SSIexeccmds = ssi_cmds;
  g_SSIexecNumCmds = num_cmds;
}

/**
 * Set the SSI exec handler table of functions.
 *
 * @param ssi_cmds the table address
 * @param num_cmds number of entries in the table
 */
void http_set_ssi_echovars(const tSSIvar *ssi_vars, int num_vars)
{
  LWIP_DEBUGF(HTTPD_DEBUG, ("http_set_ssi_echovars\n"));

  LWIP_ASSERT("no table address given", ssi_vars != NULL);
  LWIP_ASSERT("invalid table length", num_vars > 0);

  g_SSIechovars = ssi_vars;
  g_SSIechoNumVars = num_vars;
}

#endif /* LWIP_HTTPD_SSI */

#if LWIP_HTTPD_CGI
/*#include <stddef.h>
#define CGI_PARENT(x) ((struct http_cgi_state *)((u32_t)(x) \
                          - offsetof(struct http_cgi_state, exposed)))
*/
/**
 * Set an array of CGI filenames/handler functions
 *
 * @param cgis an array of CGI filenames/handler functions
 * @param num_handlers number of elements in the 'cgis' array
 */
void
http_set_cgi_handlers(const tCGI *cgis, int num_handlers)
{
  LWIP_ASSERT("no cgis given", cgis != NULL);
  LWIP_ASSERT("invalid number of handlers", num_handlers > 0);
  
  g_pCGIs = cgis;
  g_iNumCGIs = num_handlers;
}

void cgi_redirect(struct cgi_state *cgi, char *url)
{
  cgi->length =
    snprintf(cgi->buffer, LWIP_HTTPD_CGI_BUFFER_SIZE, "%s%s%s\r\n\r\n",
      (char *)g_psHTTPHeaderStrings[
        (cgi->http_version == HTTP_VERSION_10)? HTTP_HDR_HTTP10 : HTTP_HDR_HTTP11
      ], 
      (char *)g_psHTTPHeaderStrings[HTTP_HDR_FOUND], url
    );
}

/*
void cgi_unavailable(struct cgi_state *cgi)
{
  h->hdrs[0] = (version == HTTP_VERSION_10)? HTTP_HDR_HTTP10 : HTTP_HDR_HTTP11;
    h->hdrs[1] = HTTP_HDR_UNAVAIL;
  h->hdrs[2] = HTTP_HDR_SERVER;
  h->hdrs[3] = HTTP_HDR_EMPTY;
    h->hdrs[4] = DEFAULT_503_HTML;
  cgi->length =
    snprintf(cgi->buffer, LWIP_HTTPD_CGI_BUFFER_SIZE, "%s%s%s\r\n\r\n",
      (char *)g_psHTTPHeaderStrings[
        (cgi->http_version == HTTP_VERSION_10)? HTTP_HDR_HTTP10 : HTTP_HDR_HTTP11
      ], 
      (char *)g_psHTTPHeaderStrings[HTTP_HDR_FOUND], url
    );
}
*/
#endif /* LWIP_HTTPD_CGI */

#if LWIP_HTTPD_AUTH
/** This is a small function as a trade-off for decoding passwords.
For a fast solution to process lots of chars, go for a table look-up */
static u8_t base64code(u8_t c)
{
	if((c >= 'A') && (c <= 'Z'))
		return c-'A';
	else if((c >= 'a') && (c <= 'z'))
		return c - ('a'-26);
	else if((c >='0') && (c <= '9'))
		return c - ('0'-52);
	else if(c == '+')
		return 62;
	else if(c == '/')
		return 63;
	return 0;
}

/** Decode either 'len' characters or a null-terminated string
Use a negative 'len' for this */
static int base64_decode (char *bfr, int len)
{
int c1, c2, c3, count=0;
char *ptr;

	ptr = bfr;
	do {
		if((c1 = base64code(*(bfr++)))=='\0')
			break;
		c2 = base64code(*(bfr++));
		*(ptr++) = (u8_t)((c1 << 2) + (c2 >> 4));
		if (*bfr == '=')
			return count + 1;
		c3 = base64code(*(bfr++));
		*(ptr++) = (u8_t)(((c2 & 0xF) << 4) + (c3 >> 2));
		if(*bfr == '=')
			return count + 2;
		*(ptr++) = (u8_t)(((c3 & 0x3) << 6) + base64code(*(bfr++)));
		count += 3;
		len -= 4;
	} while(len);
	return count;
}

static int http_auth_process(struct pbuf *p, u16_t offset, u16_t crlf)
{
char *pw, authstring[LWIP_HTTPD_MAX_AUTHDATA];
u16_t o, len;
int ret;

  if((o=pbuf_memnfind(p, "Basic", 5, offset, crlf)) == 0xFFFF)
  	return -1;
  o += 6;
  len = crlf - o;
  if(len > LWIP_HTTPD_MAX_AUTHDATA)
  	return -1;
  pbuf_copy_partial(p, authstring, len, o);
  len = base64_decode(authstring, len);
  authstring[len] = '\0';
  if((pw=strchr(authstring, ':')) == NULL)
  	return -1;
  *(pw++) = '\0';
  LWIP_DEBUGF(HTTPD_DEBUG, ("User: %s, Password: %s\n",authstring,pw));
  ret = auth_userlogin(authstring, pw);
  return ret;
}

#endif /* LWIP_HTTPD_AUTH */


/** Find occurrence of mem (with length mem_len) in pbuf p, starting at offset
 * start_offset, and ending at offset end_offset
 *
 * @param p pbuf to search, maximum length is 0xFFFE since 0xFFFF is used as
 *        return value 'not found'
 * @param mem search for the contents of this buffer
 * @param mem_len length of 'mem'
 * @param start_offset offset into p at which to start searching
 * @param end_offset offset into p at which to stop searching
 * @return 0xFFFF if substr was not found in p or the index where it was found
 */
u16_t
pbuf_memnfind(struct pbuf* p, const void* mem, u16_t mem_len, u16_t start_offset, u16_t end_offset)
{
  u16_t i;
  u16_t max = end_offset - mem_len;
  if (end_offset >= mem_len + start_offset) {
    for(i = start_offset; i <= max; ) {
      u16_t plus = pbuf_memcmp(p, i, mem, mem_len);
      if (plus == 0) {
        return i;
      } else {
        i += plus;
      }
    }
  }
  return 0xFFFF;
}

#endif /* LWIP_TCP */
