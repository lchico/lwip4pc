/*
See license.h for licensing info and credits
 */
#include "license.h"

#ifndef __HTTPD_H__
#define __HTTPD_H__

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "httpdopts.h"

#if LWIP_HTTPD_CGI

void cgi_urldecode(char *text);

struct cgi_state {
  u16_t state;
  u16_t length; /* Length of content in buffer (GET: to be sent, POST: just received, 0 means done receiving) */
#if LWIP_HTTPD_SUPPORT_POST
  u32_t content_len; /* Length of content in POST request buffer */
#if LWIP_HTTPD_SUPPORT_POST_MULTIPART
  char *boundary;
  u8_t bound_len;
#endif /* LWIP_HTTPD_SUPPORT_POST_MULTIPART */
#endif /* LWIP_HTTPD_SUPPORT_POST */
  char buffer[LWIP_HTTPD_CGI_BUFFER_SIZE]; /* buffer for CGI generated content */
  u8_t http_method;      /* HTTP method */
  u8_t http_version;     /* HTTP version */
#if LWIP_HTTPD_AUTH
  s8_t uid;         /* uid (when authenticated), -1 if none provided */
#endif /* LWIP_HTTPD_AUTH */
#ifdef LWIP_HTTPD_CGI_USER_SIZE
  u8_t user[LWIP_HTTPD_CGI_USER_SIZE];
#endif /* LWIP_HTTPD_CGI_USER_SIZE */
};

int cgi_gethttpversion(struct cgi_state *cgi);
int cgi_gethttpmethod(struct cgi_state *cgi);
#if LWIP_HTTPD_AUTH
int cgi_getuid(struct cgi_state *cgi);
#endif /* LWIP_HTTPD_AUTH */

enum cgi_retvals_e {
	CGI_DONE = 0,
	CGI_WORKING
};

/** 
 * Function pointer for a CGI script handler.
 *
 * This function is called each time the HTTPD server is asked for a file
 * whose name was previously registered as a CGI function using a call to
 * http_set_cgi_handler.
 * It receives a struct cgi_state, and a buffer to write data, 
 * must return CGI_WORKING to be called again and CGI_DONE when
 * it has finished processing. As this web server tries to fill TCP buffers with
 * data, your function will be repeatedly called until that happens; so if you 
 * know you'll be taking too long to serve your request, pause once in a while
 * by writing length=0 to avoid hogging system resources

 * returns CGI_WORKING "as call me again", CGI_DONE as "I'm done"
 * For POST requests, this function will be called with content data in the buffer
 * @todo EXTEND !!!
 */
typedef int (*tCGIHandler)(struct cgi_state *cgi);

/**
 * Extract calling parameters
 * GET: from the parameter-part of an URI in the form "test.cgi?param1=value1&param2=value2"
 * POST: from content data
 * This CGI auxiliary function knows where that data is on either method
 * After running this function on the example string
 * *param_names[0] is the address of the string param1,
 * *param_values[0] is the address of the string value1, and so on
 * The modification is done in place, so return data is valid as long as the
 * buffer containing the URI is not freed, you must extract parameters at first call
 * (if you need them)
 *
 * @param params pointer to the NULL-terminated parameter string from the URI
 * @param param_names pointer to an array where to store the pointer to the names
 * @param param_values pointer to an array where to store the pointer to the values
 * @return number of parameters extracted
 *
 * The maximum number of parameters that will be passed to this function via
 * iNumParams is defined by LWIP_HTTPD_MAX_CGI_PARAMETERS. Any parameters in the incoming
 * HTTP request above this number will be discarded.
 */
int cgi_extract_parameters(struct cgi_state *cgi, char *param_names[], char *param_values[]);

int cgi_post_content_info(struct cgi_state *cgi, u8_t *content_type, char *ctstring);

/**
 * Helper to generate the necessary headers for HTTP redirection, so a CGI can
 avoid generating response text and instruct the browser to request a response
 document
 * @param cgi this is the cgi_state structure in your calling parameters
 * @param url the URL you are redirecting to, does NOT need to be full http://...
 */
void cgi_redirect(struct cgi_state *cgi, char *url);

/*
 * Structure defining the base filename (URL) of a CGI and the associated
 * function which is to be called when that URL is requested.
 */
typedef struct
{
  const char *pcCGIName;
  tCGIHandler pfnCGIHandler;
#if LWIP_HTTPD_AUTH
  u8_t permissions;
#endif /* LWIP_HTTPD_AUTH */
} tCGI;

void http_set_cgi_handlers(const tCGI *pCGIs, int iNumHandlers);

enum http_post_content_type_e {
  HTTP_CT_FORMU,                          /* application/x-www-form-urlencoded */
  HTTP_CT_MFORMD                          /* multipart/form-data */
};

#endif /* LWIP_HTTPD_CGI */

#if LWIP_HTTPD_SSI

/*
 * Function pointer for the SSI tag handler callback.
 *
 * This function will be called each time the HTTPD server detects a tag
 * It must return the number of characters written, excluding
 * any terminating NULL.
 *
 * Tags take the standard SSI form (for compatibility with standards and ease of
 * web page development, that can be done on an Apache system, for example)
 * Use <!--#exec cmd=name--> for an executable function. There is a built-in
 * dispatcher that will call functions based on the described prototype.
 * 'funcname' is taken from a tSSIcmd structure
 * of the form: {"tagname", (tSSIxcHandler) &funcname}. 
 * Use <!--#echo var=name--> to print variables. There is a built-in function to
 * do this, which will call snprintf(pcInsert, iInsertLen, format, varname);
 * where 'format' and 'varname' are taken from a tSSIvar structure of the form:
 * {"tagname","format",(void *)&varname} (that is, the variable address is stored)
 *
 */

typedef u16_t (*tSSIxcHandler)(char *pcInsert, int iInsertLen
                             , u16_t current_tag_part, u16_t *next_tag_part
#if LWIP_HTTPD_FILE_STATE
                             , void *connection_state
#endif /* LWIP_HTTPD_FILE_STATE */
                             );

enum echovartypes {
	INT8=0, INT16, INT32, STRING
};

typedef struct tSSIvars_s {
  const char *varname;
  const char *format;
  void *var;
  u8_t type;
} tSSIvar;

typedef struct tSSIcmds_s {
  const char *cmdname;
  tSSIxcHandler func;
} tSSIcmd;

void http_set_ssi_execfuncs(const tSSIcmd *pfnSSIcmd, int iNumCmds);

void http_set_ssi_echovars(const tSSIvar *pfnSSIvar, int iNumVars);

#endif /* LWIP_HTTPD_SSI */

void httpd_init(void);

enum http_methods { HTTP_METHOD_GET = 0, HTTP_METHOD_POST, HTTP_METHOD_HEAD };
enum http_versions { HTTP_VERSION_09 = 0, HTTP_VERSION_10, HTTP_VERSION_11 };

#endif /* __HTTPD_H__ */
