#include <stdlib.h>
#include <string.h>

#include "httpd.h"
#include "auth.h"
#ifdef STATS
#include "lwip/stats.h"
#endif

static int8_t mycounter=123, var8=123;
static int16_t var16=12345;
static int32_t var32=1234567890;
static char text[]="This is a string";

#define LINEAS 1000

u16_t list(char *buffer, int len, u16_t current_tag_part, u16_t *next_tag_part)
{
	if(current_tag_part >= LINEAS)
		return 0;

	snprintf(buffer, len, "L&iacute;nea #%2d<br>\r\n",current_tag_part);
	*next_tag_part = current_tag_part+1;
	return (u16_t) strlen(buffer);
}

const tSSIcmd mycmds[1]={
	{"listar",list}
};

static const tSSIvar myvars[5]={
	{"counter","%d",&mycounter,INT8},
	{"var8","%d",&var8,INT8},
	{"var16","%d",&var16,INT16},
	{"var32","%d",&var32,INT32},	/* these will actually depend on how your printf handles 16/32 */
	{"text","%s",text,STRING}
};

/* This is a POST CGI, we don't use content-type nor content-length, so it is small and we
can save some bytes in the control structure */
int myinc(struct cgi_state *cgi)
{
	mycounter++;	
	cgi_redirect(cgi,"/index.shtml");	/* Terminate early */
	return CGI_DONE;
}

int myreset(struct cgi_state *cgi)
{
	mycounter=0;
	cgi_redirect(cgi,"/index.shtml");	
	return CGI_DONE;
}

int listcgi(struct cgi_state *cgi)
{
	if(cgi->state >= LINEAS)
		return CGI_DONE;

	sprintf(cgi->buffer,"Line #%2d\r\n",cgi->state);
	cgi->length = strlen(cgi->buffer);
	++cgi->state;
	return CGI_WORKING;
}

struct mystatevarsstruct {
	int lines;
};

int listfullcgi(struct cgi_state *cgi)	/* GET */
{
struct mystatevarsstruct *s = (struct mystatevarsstruct *)cgi->user;

	if(cgi->state == 0){	/* First call, extract parameters and setup state variables */
		char *names[LWIP_HTTPD_MAX_CGI_PARAMETERS],*values[LWIP_HTTPD_MAX_CGI_PARAMETERS];
		int j, i = cgi_extract_parameters(cgi, names, values);
		LWIP_ASSERT ("Need to set LWIP_HTTPD_CGI_USER_SIZE to some value with enough room for your state variables",
			LWIP_HTTPD_CGI_USER_SIZE >= sizeof(struct mystatevarsstruct));
		s->lines = 0;
		for(j=0;j<i;j++){
			if(!strcmp(names[j],"title")){
				cgi_urldecode(values[j]);
				cgi->length = sprintf(cgi->buffer,"<H1>%s</H1><hr>",values[j]);
			} else if(!strcmp(names[j],"count")){
				s->lines = atoi(values[j]);
			}
		}
	} else {	/* CGI normal life */
		if(cgi->state > s->lines)
			return CGI_DONE;

		cgi->length = sprintf(cgi->buffer,"Line #%2d<br>",cgi->state);
	}
	++cgi->state;
	return CGI_WORKING;
}

int varspostcgi(struct cgi_state *cgi)
{
	switch(cgi->state){
	case 0:	/* First call: check content-length, extract content-type */
		{
		u8_t content_type;
		if(!cgi_post_content_info(cgi, &content_type, NULL) ||
		   (content_type != HTTP_CT_FORMU)){
			/* handle error */
			return CGI_DONE;
		}
		if(LWIP_HTTPD_CGI_BUFFER_SIZE < cgi->content_len){
			/* Data won't fit, handle error (see below, this is just for this case)*/
			return CGI_DONE;
		}
		}
		break;
	case 1:	/* We are now receiving content data. As we are going to parse the post parameters,
		 * we need to wait until we have the whole data available before calling the standard
		 * extraction routine.
		 * We will use the CGI buffer, so we need a buffer big enough to hold that data, so the
		 * check and assertion before.
		 * You might prefer to get some piece of memory and copy buffer contents to that
		 * memory until done, your call (see next CGI for an example)
		 */
		if(cgi->length == cgi->content_len){	/* Wait until all data arrives and is in buffer */
			char *names[LWIP_HTTPD_MAX_CGI_PARAMETERS],*values[LWIP_HTTPD_MAX_CGI_PARAMETERS];
			int j, i = cgi_extract_parameters(cgi, names, values);
			for(j=0;j<i;j++){
				if(!strcmp(names[j],"var8")){
					var8 = (u8_t)atoi(values[j]);
				} else if(!strcmp(names[j],"var16")){
					var16 = (u16_t)atoi(values[j]);
				} else if(!strcmp(names[j],"var32")){
					var32 = (u32_t)atoi(values[j]);
				} else if(!strcmp(names[j],"text")){
					cgi_urldecode(values[j]);
					strncpy(text,values[j],sizeof(text));
				}
			}
			cgi_redirect(cgi,"/echovar.shtml");	/* Terminate early */
			return CGI_DONE;
		}
		break;
	}
	++cgi->state;
	return CGI_WORKING;
}

int fileuploadcgi(struct cgi_state *cgi)
{
u32_t *contentsofar = (u32_t *)cgi->user;

	switch(cgi->state){
	case 0:	/* First call: extract content-type and boundary */
		{
		u8_t content_type;
		LWIP_ASSERT ("Need to set LWIP_HTTPD_CGI_USER_SIZE to some value with enough room for your static variables",
			LWIP_HTTPD_CGI_USER_SIZE >= sizeof(u32_t));
		if((cgi_post_content_info(cgi, &content_type, NULL) <= 0) ||
		   (content_type != HTTP_CT_MFORMD)){
			/* handle error, cgi_post_content_info() will return < 0 if it can't 
			 * allocate memory for the boundary buffer, so we should return 503
			 * in this case to instruct the caller to try again later */
			return CGI_DONE;
		}
		cgi->boundary[cgi->bound_len]='\0';
		printf("My boundary:\n%s\nMy content:\n",cgi->boundary);
		*contentsofar = 0;
		++cgi->state;
		}
		break;
	case 1:	/* We are now receiving content data.
		 * We just discard data, a real life application will store it somewhere...
		 */
		#define PROCESSEDLEN cgi->length
		/* memcpy(somewhere, cgi->buffer, PROCESSEDLEN); */
		if(*contentsofar < 500)
			printf(cgi->buffer);
		*contentsofar += PROCESSEDLEN;
		cgi->length -= PROCESSEDLEN;	
		if(*contentsofar >= cgi->content_len){	/* Wait until all data arrives */
			++cgi->state;
			cgi->content_len = 0;		/* Signal we've got it all and will start sending */
		}
		break;
	case 2:	/* We have just received content data. We generate our own content for response */
		cgi->length = sprintf(cgi->buffer, "<H1>Finished uploading a %u bytes file</H1>",*contentsofar);
		return CGI_DONE;		
	}
	return CGI_WORKING;
}

static const tCGI mycgis[6]={
	{"/inc.cgi", &myinc,0},
	{"/reset.cgi", &myreset,0},
	{"/list.cgi", &listcgi,0},
	{"/list2.cgi", &listfullcgi,0},
	{"/setvars.cgi", &varspostcgi,0},
	{"/fileupload.cgi", &fileuploadcgi, AUTH_GROUP1RW}	/* Only select people can write */
};

#ifdef PROFILE
#include <time.h>

double timeit(struct timespec *tsi,struct timespec *tsf)
{
double elapss=difftime(tsf->tv_sec,tsi->tv_sec);
long elapsns=tsf->tv_nsec-tsi->tv_nsec;

	return(elapss+(double)elapsns/1e9);
}
#endif

void webstuff_init(void)
{
	httpd_init();
	auth_useradd("topdog","topsecret",AUTH_GROUP1RW);
	http_set_ssi_echovars(myvars, (sizeof(myvars)/sizeof(tSSIvar)));
	http_set_ssi_execfuncs(mycmds, (sizeof(myvars)/sizeof(tSSIcmd)));
	http_set_cgi_handlers(mycgis, (sizeof(mycgis)/sizeof(tCGI)));
}

