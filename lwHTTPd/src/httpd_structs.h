#ifndef __HTTPD_STRUCTS_H__
#define __HTTPD_STRUCTS_H__

#include "httpd.h"

#if LWIP_HTTPD_DYNAMIC_HEADERS
/** This struct is used for a list of HTTP header strings for various
 * filename extensions. */
typedef struct
{
  const char *extension;
  int headerIndex;
} tHTTPHeader;

/** A list of strings used in HTTP headers */
static const char * const g_psHTTPHeaderStrings[] =
{
 "text/html\r\n\r\n",
 "text/html\r\nExpires: Fri, 10 Apr 2008 14:00:00 GMT\r\nPragma: no-cache\r\n\r\n",
 "image/gif\r\n\r\n",
 "image/png\r\n\r\n",
 "image/jpeg\r\n\r\n",
 "image/bmp\r\n\r\n",
 "image/x-icon\r\n\r\n",
 "application/octet-stream\r\n\r\n",
 "application/x-javascript\r\n\r\n",
 "text/css\r\n\r\n",
 "application/x-shockwave-flash\r\n\r\n",
 "text/xml\r\n\r\n",
 "application/xml\r\n\r\n",
 "text/csv\r\n\r\n",
 "text/plain\r\n\r\n",
 "200 OK\r\n",
 "302 Found\r\nLocation: ",
 "400 Bad Request\r\n",
#if LWIP_HTTPD_AUTH
 "401 Unauthorized\r\nWWW-Authenticate: Basic realm=\""HTTPD_SERVER_REALM"\"\r\n",
#endif /* LWIP_HTTPD_AUTH */
 "404 File not found\r\n",
 "501 Not Implemented\r\n",
 "503 Service Unavailable\r\n",
 "HTTP/1.0 ",
 "HTTP/1.1 ",
 "Content-Type: ",
 "Content-Length: ",
 "Connection: Close\r\n",
 "Connection: keep-alive\r\n",
 "Server: "HTTPD_SERVER_AGENT"\r\n",
 "\r\n",
 "<html><body><h2>400: Bad Request</h2></body></html>\r\n",
 "<html><body><h2>401: Authorization required</h2></body></html>\r\n",
 "<html><body><h2>404: The requested file cannot be found.</h2></body></html>\r\n",
 "<html><body><h2>501: Not Implemented</h2></body></html>\r\n",
 "<html><body><h2>503: Service Unavailable</h2></body></html>\r\n",
 "Content-disposition: inline; filename="
};

/* Indexes into the g_psHTTPHeaderStrings array */
enum http_hdr_e {
  HTTP_HDR_HTML = 0,       /* text/html */
  HTTP_HDR_SSI,            /* text/html Expires... */
  HTTP_HDR_GIF,            /* image/gif */
  HTTP_HDR_PNG,            /* image/png */
  HTTP_HDR_JPG,            /* image/jpeg */
  HTTP_HDR_BMP,            /* image/bmp */
  HTTP_HDR_ICO,            /* image/x-icon */
  HTTP_HDR_APP,            /* application/octet-stream */
  HTTP_HDR_JS,             /* application/x-javascript */
  HTTP_HDR_CSS,            /* text/css */
  HTTP_HDR_SWF,            /* application/x-shockwave-flash */
  HTTP_HDR_XML,            /* text/xml */
  HTTP_HDR_AXML,           /* application/xml , dynamically generated XML */
  HTTP_HDR_CSV,            /* text/csv */
  HTTP_HDR_DEFAULT_TYPE,   /* text/plain */
  HTTP_HDR_OK,             /* 200 OK */
  HTTP_HDR_FOUND,          /* 302 Found */
  HTTP_HDR_BAD_REQUEST,    /* 400 Bad request */
#if LWIP_HTTPD_AUTH
  HTTP_HDR_NOT_AUTH,       /* 401 Not Authorized */
#endif /* LWIP_HTTPD_AUTH */
  HTTP_HDR_NOT_FOUND,      /* 404 File not found */
  HTTP_HDR_NOT_IMPL,       /* 501 Not Implemented */
  HTTP_HDR_UNAVAIL,        /* 503 Service unavailable */
  HTTP_HDR_HTTP10,         /* HTTP/1.0 */
  HTTP_HDR_HTTP11,         /* HTTP/1.1 */
  HTTP_HDR_CONTENT_TYPE,   /* Content-type: */
  HTTP_HDR_CONTENT_LENGTH, /* Content-Length: (HTTP 1.1)*/
  HTTP_HDR_CONN_CLOSE,     /* Connection: Close (HTTP 1.1) */
  HTTP_HDR_CONN_KEEPALIVE, /* Connection: keep-alive (HTTP 1.1) */
  HTTP_HDR_SERVER,         /* Server: HTTPD_SERVER_AGENT */
  HTTP_HDR_EMPTY,          /* Just CRLF */
  DEFAULT_400_HTML,        /* default 400 body */
  DEFAULT_401_HTML,        /* default 401 body */
  DEFAULT_404_HTML,        /* default 404 body */
  DEFAULT_501_HTML,        /* default 501 body */
  DEFAULT_503_HTML,        /* default 503 body */
  HTTP_HDR_CONTDISPO
};

/** A list of extension-to-HTTP header strings */
const static tHTTPHeader g_psHTTPHeaders[] =
{
 { "html", HTTP_HDR_HTML},
 { "htm",  HTTP_HDR_HTML},
 { "shtml",HTTP_HDR_SSI},
 { "shtm", HTTP_HDR_SSI},
 { "ssi",  HTTP_HDR_SSI},
 { "gif",  HTTP_HDR_GIF},
 { "png",  HTTP_HDR_PNG},
 { "jpg",  HTTP_HDR_JPG},
 { "bmp",  HTTP_HDR_BMP},
 { "ico",  HTTP_HDR_ICO},
 { "class",HTTP_HDR_APP},
 { "cls",  HTTP_HDR_APP},
 { "js",   HTTP_HDR_JS},
 { "ram",  HTTP_HDR_JS},
 { "css",  HTTP_HDR_CSS},
 { "swf",  HTTP_HDR_SWF},
 { "xml",  HTTP_HDR_XML},
 { "xsl",  HTTP_HDR_XML},
 { "csv",  HTTP_HDR_CSV}
};

#define NUM_HTTP_HEADERS (sizeof(g_psHTTPHeaders) / sizeof(tHTTPHeader))

#endif /* LWIP_HTTPD_DYNAMIC_HEADERS */

#if LWIP_HTTPD_SSI
static const char * const g_pcSSIExtensions[] = {
  ".shtml", ".shtm", ".ssi", ".xml"
};
#define NUM_SHTML_EXTENSIONS (sizeof(g_pcSSIExtensions) / sizeof(const char *))
#endif /* LWIP_HTTPD_SSI */

#endif /* __HTTPD_STRUCTS_H__ */
