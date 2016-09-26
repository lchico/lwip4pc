#ifndef __LWHTTPDOPTS_H__
#define __LWHTTPDOPTS_H__

/** Set this to 1 to support CGI functions */
#ifndef LWIP_HTTPD_CGI
#define LWIP_HTTPD_CGI            0
#endif

/** Set this to 1 to support SSI (Server-Side-Includes) */
#ifndef LWIP_HTTPD_SSI
#define LWIP_HTTPD_SSI            0
#endif

/** Set this to 1 to support HTTP POST */
#ifndef LWIP_HTTPD_SUPPORT_POST
#define LWIP_HTTPD_SUPPORT_POST   0
#endif


#ifndef HTTPD_DEBUG
#define HTTPD_DEBUG         LWIP_DBG_OFF
#endif

/** Set this to 1 and add the next line to lwippools.h to use a memp pool
 * for allocating struct http_state instead of the heap:
 *
 * LWIP_MEMPOOL(HTTPD_STATE, 20, 100, "HTTPD_STATE")
 */
#ifndef HTTPD_USE_MEM_POOL
#define HTTPD_USE_MEM_POOL  0
#endif

/** The server port for HTTPD to use */
#ifndef HTTPD_SERVER_PORT
#define HTTPD_SERVER_PORT                   80
#endif

/** Maximum retries before the connection is aborted/closed.
 * - number of times pcb->poll is called -> default is 4*500ms = 2s;
 * - reset when pcb->sent is called
 */
#ifndef HTTPD_MAX_RETRIES
#define HTTPD_MAX_RETRIES                   4
#endif

/** The poll delay is X*500ms */
#ifndef HTTPD_POLL_INTERVAL
#define HTTPD_POLL_INTERVAL                 4
#endif

/** Priority for tcp pcbs created by HTTPD (very low by default).
 *  Lower priorities get killed first when running out of memory.
 */
#ifndef HTTPD_TCP_PRIO
#define HTTPD_TCP_PRIO                      TCP_PRIO_MIN
#endif

/** Set this to 1 to enable timing each file sent */
#ifndef LWIP_HTTPD_TIMING
#define LWIP_HTTPD_TIMING                   0
#endif
#ifndef HTTPD_DEBUG_TIMING
#define HTTPD_DEBUG_TIMING                  LWIP_DBG_OFF
#endif

/** Set this to 1 on platforms where strnstr is not available */
#ifndef LWIP_HTTPD_STRNSTR_PRIVATE
#define LWIP_HTTPD_STRNSTR_PRIVATE          1
#endif

/** Set this to one to show error pages when parsing a request fails instead
    of simply closing the connection. */
#ifndef LWIP_HTTPD_SUPPORT_EXTSTATUS
#define LWIP_HTTPD_SUPPORT_EXTSTATUS        0
#endif

/** Set this to 0 to drop support for HTTP/0.9 clients (to save some bytes) */
#ifndef LWIP_HTTPD_SUPPORT_V09
#define LWIP_HTTPD_SUPPORT_V09              1
#endif

/** Set this to 1 to enable HTTP/1.1 persistent connections.
 * ATTENTION: If the generated file system includes HTTP headers, these must
 * include the "Connection: keep-alive" header (pass argument "-11" to makefsdata).
 */
#ifndef LWIP_HTTPD_SUPPORT_11_KEEPALIVE
#define LWIP_HTTPD_SUPPORT_11_KEEPALIVE     0
#endif

/** Number of rx pbufs to enqueue to parse an incoming request
 (up to the end of headers) */
#ifndef LWIP_HTTPD_REQ_QUEUELEN
#define LWIP_HTTPD_REQ_QUEUELEN             5
#endif

/** Defines the maximum length of a URI (including parameters),
    copied from pbuf into this global buffer */
#ifndef LWIP_HTTPD_URI_BUFSIZE
#define LWIP_HTTPD_URI_BUFSIZE              128
#endif

/** Set this to 1 to call tcp_abort when tcp_close fails with memory error.
 * This can be used to prevent consuming all memory in situations where the
 * HTTP server has low priority compared to other communication. */
#ifndef LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR
#define LWIP_HTTPD_ABORT_ON_CLOSE_MEM_ERROR  0
#endif

/** Set this to 1 to kill the oldest connection when running out of
 * memory for 'struct http_state' or 'struct http_ssi_state'.
 * ATTENTION: This puts all connections on a linked list, so may be kind of slow.
 */
#ifndef LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED
#define LWIP_HTTPD_KILL_OLD_ON_CONNECTIONS_EXCEEDED 0
#endif

/* By default, the httpd is limited to send 2*pcb->mss to keep resource usage low
   when http is not an important protocol in the device. */
#ifndef HTTPD_LIMIT_SENDING_TO_2MSS
#define HTTPD_LIMIT_SENDING_TO_2MSS 1
#endif

/* Define this to a function that returns the maximum amount of data to enqueue.
   The function have this signature: u16_t fn(struct tcp_pcb* pcb); */
#ifndef HTTPD_MAX_WRITE_LEN
#if HTTPD_LIMIT_SENDING_TO_2MSS
#define HTTPD_MAX_WRITE_LEN(pcb)    (2 * tcp_mss(pcb))
#endif
#endif

/** Amount of memory (from the stack) to evaluate the authorization string
 * (user:password in base64) (8 + 8)x 4/3 => 22 for 8 chars usr and pwd.
 */
#ifndef LWIP_HTTPD_MAX_AUTHDATA
#define LWIP_HTTPD_MAX_AUTHDATA              80
#endif


#if LWIP_HTTPD_CGI

#ifndef LWIP_HTTPD_CGI_BUFFER_SIZE
#define LWIP_HTTPD_CGI_BUFFER_SIZE 256
#endif /* LWIP_HTTPD_CGI_BUFFER_SIZE */

/* The maximum number of parameters that the CGI handler can be sent. */
#ifndef LWIP_HTTPD_MAX_CGI_PARAMETERS
#define LWIP_HTTPD_MAX_CGI_PARAMETERS 16
#endif

#endif /* LWIP_HTTPD_CGI */

#if LWIP_HTTPD_SSI

/* The maximum length of the string comprising the tag name
 * Please take into account that you must consider the extra space occupied by
 * the standard tag format itself, ~8 chars, check source */
#ifndef LWIP_HTTPD_MAX_TAG_NAME_LEN
#define LWIP_HTTPD_MAX_TAG_NAME_LEN 17
#endif

/* The maximum length of string that can be returned to replace any given tag */
#ifndef LWIP_HTTPD_MAX_TAG_INSERT_LEN
#define LWIP_HTTPD_MAX_TAG_INSERT_LEN 192
#endif

#endif /* LWIP_HTTPD_SSI */

/** This string is passed in the HTTP header as "Server: " */
#ifndef HTTPD_SERVER_AGENT
#define HTTPD_SERVER_AGENT "lwHTTPd/lwIP"
#endif

/** This string is passed in the HTTP header (for authentication) as "realm= " */
#ifndef HTTPD_SERVER_REALM
#define HTTPD_SERVER_REALM "this device"
#endif

/** Set this to 1 if you want to include code that creates HTTP headers
 * at runtime. Static headers mean smaller code size, but
 * the (readonly) fsdata will grow a bit as every file includes the HTTP
 * header. This rules out many interesting functions of this server, so... don't disable it */
#ifndef LWIP_HTTPD_DYNAMIC_HEADERS
#define LWIP_HTTPD_DYNAMIC_HEADERS 1
#endif

#endif /* __LWHTTPDOPTS_H__ */
