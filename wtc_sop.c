#include <stdio.h>
#include <string.h>

#include <iconv.h>
#include <errno.h>

#include<pthread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "api.h"
#include "trans_type.h"
#include "ret_code.h"
#include "wtc_sop.h"


typedef struct {
    char *ptr;
    size_t size;
} ByteBuf;


typedef struct {
    ByteBuf request_data;
    ByteBuf reply_data;
} wrt_wtc_sop_session_t;

typedef struct {
    wrt_module_api_t *api;
    wrt_module_config_t *config;
    wrt_api_log_handle_t log;

    FILE *fp;
    FILE *fp1;

    /* pthread_mutex */
    pthread_mutex_t mutex;

    /* input */
    wrt_context_descriptor_t *ctxid_tcpsrcport;
    wrt_context_descriptor_t *ctxid_tcpdstport;
    wrt_context_descriptor_t *ctxid_ipv4srcaddr;
    wrt_context_descriptor_t *ctxid_ipv4dstaddr;
    wrt_context_descriptor_t *ctxid_ipv4origsrcaddr;
    wrt_context_descriptor_t *ctxid_ipv4origdstaddr;


    wrt_metric_descriptor_t *ctxid_tcpresponse_timetotal;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timeserver;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timenetwork;
    wrt_metric_descriptor_t *ctxid_tcpresponse_timeload;


    /* output */
    wrt_context_descriptor_t *ctxid_transactionname;
    wrt_context_descriptor_t *ctxid_statuscode;
    wrt_context_descriptor_t *ctxid_statusisbad;

} wrt_wtc_sop_module_instance_t;


static size_t
BB_cpy(ByteBuf *buf, void *src, size_t size)
{
    if(size <= 0 || !src || !buf)
        return -1;

    char *ptr = (char *)malloc( sizeof(char)*(size+1) );
    if(!ptr)
    {
        return -2;
    }

    memcpy((void *)ptr, src, size);
    *(ptr+size) = '\0';

    buf->ptr = ptr;
    buf->size = size+1;

    return size+1;
}

static size_t
BB_size(ByteBuf *buf)
{
    if(NULL != buf)
        return buf->size;

    return -1;
}


static void
BB_free(ByteBuf *buf)
{
    if(NULL != buf)
        if(NULL != buf->ptr)
            free(buf->ptr);
    return;
}


static int
convert_encoding(char *fromencoding,
                 char *toencoding,
                 char *inbuf,
                 size_t inlen,
                 char *outbuf,
                 size_t outlen,
                 wrt_module_instance_t instance)
{
    wrt_wtc_sop_module_instance_t *wtc_sop_instance =  (wrt_wtc_sop_module_instance_t *)instance;
    wrt_module_api_t *api =  wtc_sop_instance->api;
    wrt_api_log_handle_t log = wtc_sop_instance->log;
   
    
    if(!inbuf || !outbuf) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "iconv_error: buffers not exist.");
        return -1;
    }

    /*convert data*/
    iconv_t cd = iconv_open(toencoding, fromencoding);
    if ( cd == (iconv_t)(-1) ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__,
                         __LINE__, "iconv_error: iconv_open(%s,%s) fail. err[%s].",
                         toencoding, fromencoding, strerror(errno));
        return -1;
    }

    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: start convert %s to %s.",
                     fromencoding, toencoding);

		char **pin = &inbuf, **pout = &outbuf;
    size_t cs = iconv(cd, pin, &inlen, pout, &outlen);
    if ( cs  == (size_t)(-1) ) {
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                         "iconv_error: converting %s to %s fail. errno[%d],errstr[%s],buf[%*s]",
                         fromencoding, toencoding,
                         errno,strerror(errno),
                         inlen, *pin);                       
        return -1;
    } 
 
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: convert %s to %s finish. the number of characters converted in a non-reversible way is [%d].",
                     fromencoding, toencoding, cs);


    iconv_close(cd);
    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__,
                     "iconv_info: close convert %s to %s success.",
                     fromencoding, toencoding);

    return cs;

}


static void
free_session(wrt_api_session_t session, void *data)
{
    wrt_wtc_sop_session_t *wtc_sop_session = (wrt_wtc_sop_session_t*)data;

    BB_free(&wtc_sop_session->request_data);
    BB_free(&wtc_sop_session->reply_data);
    free(wtc_sop_session);

    return;
}

wrt_context_descriptor_t*
find_context_descriptor(wrt_context_descriptor_t *d,
                        const char *name,
                        wrt_context_type_t type)
{
    for (; d; d = d->next)
    {
        if (strcmp(d->name, name) == 0)
            return d->type == type ? d : NULL;
    }
    return NULL;
}


wrt_metric_descriptor_t*
find_metric_descriptor(wrt_metric_descriptor_t *d,
                       const char *name,
                       wrt_metric_type_t type)
{
    for (; d; d = d->next)
    {
        if (strcmp(d->name, name) == 0)
            return d->type == type ? d : NULL;
    }
    return NULL;
}


wrt_api_status_t
wtc_sop_init( wrt_module_api_t *api,
           wrt_module_config_t *config,
           wrt_module_instance_t *instance)
{
    wrt_wtc_sop_module_instance_t *wtc_sop_instance;
    wtc_sop_instance  = (wrt_wtc_sop_module_instance_t *)malloc(sizeof(wrt_wtc_sop_module_instance_t));
    if(!wtc_sop_instance)
    {
        return  WRT_API_STATUS_NOMEM;
    }

    memset(wtc_sop_instance,0x00,sizeof(wrt_wtc_sop_module_instance_t));

    /*init a log*/
    api->init_log(__FILE__,&wtc_sop_instance->log);

    /* output */
    /* 1 */
    wtc_sop_instance->ctxid_transactionname = find_context_descriptor(
            config->output_context, "transaction.name", WRT_CONTEXT_STRING);
    if (!wtc_sop_instance->ctxid_transactionname)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for transaction.name.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 2 */
    wtc_sop_instance->ctxid_statuscode = find_context_descriptor(
                                          config->output_context, "status.code", WRT_CONTEXT_INT16);
    if (!wtc_sop_instance->ctxid_statuscode)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for status.code.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 3 */
    wtc_sop_instance->ctxid_statusisbad = find_context_descriptor(
                                           config->output_context, "status.isbad", WRT_CONTEXT_INT16);
    if (!wtc_sop_instance->ctxid_statusisbad)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for status.isbad.");
        return WRT_API_STATUS_BADCFG;
    }



    /* input */
    /* 1 */
    wtc_sop_instance->ctxid_tcpsrcport = find_context_descriptor(
                                          config->input_context, "tcp.srcport", WRT_CONTEXT_UINT16);
    if (!wtc_sop_instance->ctxid_tcpsrcport)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.srcport.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 2 */
    wtc_sop_instance->ctxid_tcpdstport = find_context_descriptor(
                                          config->input_context, "tcp.dstport", WRT_CONTEXT_UINT16);
    if (!wtc_sop_instance->ctxid_tcpdstport)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.dstport.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 3 */
    wtc_sop_instance->ctxid_ipv4srcaddr = find_context_descriptor(
                                           config->input_context, "ipv4.srcaddr", WRT_CONTEXT_IPV4);
    if (!wtc_sop_instance->ctxid_ipv4srcaddr)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.srcaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 4*/
    wtc_sop_instance->ctxid_ipv4dstaddr = find_context_descriptor(
                                           config->input_context, "ipv4.dstaddr", WRT_CONTEXT_IPV4);
    if (!wtc_sop_instance->ctxid_ipv4dstaddr)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.dstaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 5 */
    wtc_sop_instance->ctxid_ipv4origsrcaddr = find_context_descriptor(
            config->input_context, "ipv4.origsrcaddr", WRT_CONTEXT_IPV4);
    if (!wtc_sop_instance->ctxid_ipv4origsrcaddr)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.origsrcaddr.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 6 */
    wtc_sop_instance->ctxid_ipv4origdstaddr = find_context_descriptor(
            config->input_context, "ipv4.origdstaddr", WRT_CONTEXT_IPV4);
    if (!wtc_sop_instance->ctxid_ipv4origdstaddr)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for ipv4.origdstaddr.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 7 */
    wtc_sop_instance->ctxid_tcpresponse_timetotal = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.total", WRT_METRIC_UINT64);
    if (!wtc_sop_instance->ctxid_tcpresponse_timetotal)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.total.");
        return WRT_API_STATUS_BADCFG;
    }


    /* 8 */
    wtc_sop_instance->ctxid_tcpresponse_timeserver = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.server", WRT_METRIC_UINT64);
    if (!wtc_sop_instance->ctxid_tcpresponse_timeserver)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.server.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 9 */
    wtc_sop_instance->ctxid_tcpresponse_timenetwork = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.network", WRT_METRIC_UINT64);
    if (!wtc_sop_instance->ctxid_tcpresponse_timenetwork)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.network.");
        return WRT_API_STATUS_BADCFG;
    }

    /* 10 */
    wtc_sop_instance->ctxid_tcpresponse_timeload = find_metric_descriptor(
                config->input_metrics, "tcp.response_time.load", WRT_METRIC_UINT64);
    if (!wtc_sop_instance->ctxid_tcpresponse_timeload)
    {
        api->log_message(wtc_sop_instance->log, WRT_API_LOG_ERROR,
                         __func__, __LINE__,
                         "Failed to locate context ID for tcp.response_time.load.");
        return WRT_API_STATUS_BADCFG;
    }


    wtc_sop_instance->api = api;
    wtc_sop_instance->config = config;

    FILE *fp = fopen("/opt/itump/ITM/tmaitm6/wrm/linux/wtc_sop_payload_error.txt","a+");
    setbuf(fp, NULL);
    wtc_sop_instance->fp = fp;

    FILE *fp1 = fopen("/opt/itump/ITM/tmaitm6/wrm/linux/wtc_sop_payload_ok.txt","a+");
    setbuf(fp1, NULL);
    wtc_sop_instance->fp1 = fp1;


    pthread_mutex_t aa = PTHREAD_MUTEX_INITIALIZER ;
    wtc_sop_instance->mutex = aa;

    *instance = wtc_sop_instance;

    return 	WRT_API_STATUS_OK;

}


wrt_api_status_t
wtc_sop_terminate(wrt_module_instance_t instance)
{
    wrt_wtc_sop_module_instance_t *wtc_sop_instance =  (wrt_wtc_sop_module_instance_t *)instance;
    if(wtc_sop_instance->fp != NULL)
        fclose(wtc_sop_instance->fp);

    if(wtc_sop_instance->fp1 != NULL)
        fclose(wtc_sop_instance->fp1);

    free(instance);
    return WRT_API_STATUS_OK;
}


wrt_api_status_t
wtc_sop_process(wrt_module_instance_t instance,
             wrt_api_session_t session,
             wrt_api_data_t data)
{
    wrt_wtc_sop_module_instance_t *wtc_sop_instance =  (wrt_wtc_sop_module_instance_t *)instance;
    wrt_module_api_t *api =  wtc_sop_instance->api;
    wrt_api_log_handle_t log = wtc_sop_instance->log;

    FILE *fp = wtc_sop_instance->fp;
    FILE *fp1 = wtc_sop_instance->fp1;

    pthread_mutex_t mutex = wtc_sop_instance->mutex;

    wrt_api_status_t status =  WRT_API_STATUS_OK;

    wrt_wtc_sop_session_t *wtc_sop_session = NULL;

    const void *request_data_part = NULL;
    const void *reply_data_part = NULL;
    size_t request_data_part_size = 0;
    size_t reply_data_part_size = 0;

    api->log_message(log, WRT_API_LOG_INFO, __func__,
                     __LINE__, "start wtc sop.");
                     
    /* Store wtc_sop session data in userdata. */
    if (api->get_userdata(session, (void**)&wtc_sop_session) != WRT_API_STATUS_OK)
    {
        wtc_sop_session = malloc(sizeof(wrt_wtc_sop_session_t));
        if (!wtc_sop_session)
        {
            return WRT_API_STATUS_NOMEM;
        }
        memset(wtc_sop_session, 0, sizeof(wrt_wtc_sop_session_t));
        api->set_userdata(session, wtc_sop_session, free_session);
    }

    /* get the current request/reply data. */
    api->get_request_data(data, &request_data_part, &request_data_part_size);
    api->get_reply_data(data, &reply_data_part, &reply_data_part_size);


    /* save request/reply data in session */
    BB_cpy(&wtc_sop_session->request_data, request_data_part, request_data_part_size);
    BB_cpy(&wtc_sop_session->reply_data, reply_data_part, reply_data_part_size);

    
    if( request_data_part_size == 0 || reply_data_part_size == 0){
    	    api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, " wtc_sop_pq_empty");
					return -1;
    }
    
    /*
    api->log_message(log, WRT_API_LOG_INFO, "wtc_sop_process", __LINE__, "request_data_buff=[%*s]", (int)request_data_part_size, (char *)request_data_part);
    api->log_message(log, WRT_API_LOG_INFO, "wtc_sop_process", __LINE__, "replay_data_buff=[%*s]", (int)reply_data_part_size, (char *)reply_data_part);
    */

	  char *carray_req = NULL, *carray_ans = NULL, *sop_ptr = NULL;
	  char base[7] = "CARRAY";


    carray_req = (char *)(request_data_part+72);
    carray_ans = (char *)(reply_data_part + 72);
 
 
    char req_transcode[5];
    char req_journo[13];
    char req_termdate[9];
  
    char reply_transcode[5];
    char reply_journo[13];
    char reply_termdate[9];
    char reply_termtime[5];
    char reply_errcode[8];
    
    
    memset(req_transcode, 0x00, sizeof(req_transcode));
    memset(req_journo, 0x00, sizeof(req_journo));
    memset(req_termdate, 0x00, sizeof(req_termdate));    
    memset(reply_transcode, 0x00, sizeof(reply_transcode));
    memset(reply_journo, 0x00, sizeof(reply_journo));
    memset(reply_termdate, 0x00, sizeof(reply_termdate));
    memset(reply_termtime, 0x00, sizeof(reply_termtime));
    memset(reply_errcode, 0x00, sizeof(reply_errcode));
         
           	
	  sop_ptr = carray_req ;
	  memcpy(req_transcode, sop_ptr + 128, 4);
	  req_transcode[4] = '\0';  
	  memcpy(req_journo, sop_ptr + 145, 12);
	  req_journo[12] = '\0';       	  
	  memcpy(req_termdate, sop_ptr + 157, 8);
	  req_termdate[8] = '\0';   
    	  
    	  
    int ii,jj,mm,nn,xx = -1;
    for(ii=0,mm=wtc_sop_type_max-1; ii<mm; ii++) {
        if( memcmp( req_transcode , wtc_sop_type[ii][0], 4) == 0 )
        {
            xx = ii;
            break;
        }
    }

	  sop_ptr = carray_ans ;   
		memcpy(reply_transcode, sop_ptr + 107, 4);
	  reply_transcode[4] = '\0';  
	  memcpy(reply_journo, sop_ptr + 127, 12);
	  reply_journo[12] = '\0';       	  
	  memcpy(reply_termdate, sop_ptr + 115, 8);
	  reply_termdate[8] = '\0';  
	  memcpy(reply_termtime, sop_ptr + 123, 4);
	  reply_termtime[4] = '\0';  
	  memcpy(reply_errcode, sop_ptr + 141, 7);
	  reply_errcode[7] = '\0';  
	

    int iii,jjj,mmm,nnn,xxx = -1;
    for(iii=0,mmm=wtc_sop_type_max-1; iii<mmm; iii++) {
        if( memcmp( reply_transcode , wtc_sop_type[iii][0], 4) == 0 )
        {
            xxx = iii;
            break;
        }
    }


		if(xx == -1 || xxx == -1){
			
				pthread_mutex_lock(&mutex);       
				if(fp != NULL) {
							fprintf(fp, "error format:req_transcode=%s,reply_transcode=%s\n", req_transcode, reply_transcode);
			        fprintf(fp,"request_data_buff=[");
			        fwrite(request_data_part, request_data_part_size, 1, fp);
			        fprintf(fp, "]\n");
			
			        fprintf(fp,"replay_data_buff=[");
			        fwrite(reply_data_part, reply_data_part_size, 1, fp);
			        fprintf(fp, "]\n");
			        fprintf(fp, "\n");;          
			            			     			   
			  }
     		pthread_mutex_unlock(&mutex);    
			
		}else{
			
				pthread_mutex_lock(&mutex);       
				if(fp1 != NULL) {
							fprintf(fp1, "ok format:req_transcode=%s,reply_transcode=%s\n", req_transcode, reply_transcode);
			        fprintf(fp1,"request_data_buff=[");
			        fwrite(request_data_part, request_data_part_size, 1, fp1);
			        fprintf(fp1, "]\n");
			
			        fprintf(fp1,"replay_data_buff=[");
			        fwrite(reply_data_part, reply_data_part_size, 1, fp1);
			        fprintf(fp1, "]\n");
			        fprintf(fp1, "\n");;          
			            			     			   
			  }
     		pthread_mutex_unlock(&mutex);    
			
		}    
 

    int rc = 1;
    /* While there are more requests to process, decode and process them. */
    while( rc == 1 && BB_size(&wtc_sop_session->request_data) != 0)
    {

        wrt_api_data_t out_data = NULL;
        status = api->clone_data(data, &out_data);
        if (status != WRT_API_STATUS_OK)
        {
            /* Break out of loop. */
            break;
        }
        else
        {
        	  wrt_context_descriptor_t *ctx_dsc;
            wrt_context_type_t ctx_type;
            wrt_uint16_t  ctx_value;
            const void  *raw_ctx_value;
            size_t ctx_size = 0;
        	
        	 int kkkk = 1234;
        	 if( memcmp(reply_errcode,"AAAAAAA",7) == 0){
    			 		kkkk = 0;
    			 }else{
    			 		kkkk = 1;	
    			 }
       
          api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "kkkk=%d",kkkk);
          
           
            ctx_dsc = wtc_sop_instance->ctxid_statusisbad;
            api->set_context(out_data, ctx_dsc->id,
                             WRT_CONTEXT_INT16,
                             &kkkk,
                             sizeof(kkkk));



            /* custom output */
            api->set_context(out_data, wtc_sop_instance->ctxid_transactionname->id,
                             WRT_CONTEXT_STRING,
                             xx != -1 ?  wtc_sop_type[xx][1] : "empty" ,
                             xx != -1 ?  strlen(wtc_sop_type[xx][1])+1 :sizeof("empty") );

           
                             	       	
            /* Send the request/response transaction to  the next module in the chain. */
            api->send_data(session, out_data);
            api->destroy_data(out_data);
        }
        rc = 0;
        api->log_message(log, WRT_API_LOG_INFO, __func__, __LINE__, "sent wtc sop");
    }

    return status;
}


WRT_MODULE_DEFINE(wtc_sop) = {
    WRT_MODULE_VERSION,
    "wtc_sop",
    &wtc_sop_init,
    &wtc_sop_terminate,
    &wtc_sop_process
};