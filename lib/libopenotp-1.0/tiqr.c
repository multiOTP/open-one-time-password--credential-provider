/*
 RCDevs OpenOTP Development Library
 Copyright (c) 2010-2011 RCDevs SA, All rights reserved.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
  
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include "tiqr.h"
#include "libcsoap/soap-client.h"
#include "nanohttp/nanohttp-client.h"
#ifdef HAVE_SSL
#include "nanohttp/nanohttp-ssl.h"
#endif

char *__tiqr_url1 = NULL;
char *__tiqr_url2 = NULL;

int tiqr_initialize (char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)()) {
   herror_t err = H_OK;
   
   if (__tiqr_url1 != NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR already initialized");
      return 0;
   }
   
   if (url == NULL) {
      if (log_handler != NULL) (*log_handler)("missing TiQR server URL");
      return 0;
   }
   
   char *ptr = strchr(url, ',');
   if (ptr != NULL) {
      __tiqr_url1 = url;
      __tiqr_url2 = ptr+1;
      *ptr = 0;
   } else {
      __tiqr_url1 = url;
      __tiqr_url2 = NULL;
   }
   
   #ifdef HAVE_SSL
   if ((__tiqr_url1 != NULL && strncmp(__tiqr_url1, "https://", 8) == 0) ||
       (__tiqr_url2 != NULL && strncmp(__tiqr_url2, "https://", 8) == 0)) {
      hssl_enable();
      if (cert != NULL) hssl_set_certificate(cert);
      if (pass != NULL) hssl_set_certpass(pass);
      if (ca != NULL) hssl_set_ca(ca);
      
      err = hssl_module_init(0, NULL);
      if (err != H_OK) {
	 if (log_handler != NULL) (*log_handler)(herror_message(err));
	 herror_release(err);
	 return 0;
      }
   }
   #endif
   
   err = soap_client_init_args(0, NULL);
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
      return 0;
      }
   
   if (timeout != 0) httpd_set_timeout(timeout);
   return 1;
}

int tiqr_terminate (void(*log_handler)()) {
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return 0;
   }
   __tiqr_url1 = NULL;
   __tiqr_url2 = NULL;
   #ifdef HAVE_SSL
   if ((__tiqr_url1 != NULL && strncmp(__tiqr_url1, "https://", 8) == 0) ||
       (__tiqr_url2 != NULL && strncmp(__tiqr_url2, "https://", 8) == 0)) {
      hssl_module_destroy();
   }
   #endif
   soap_client_destroy();
   return 1;
}

tiqr_start_rep_t *tiqr_start(tiqr_start_req_t *request, void(*log_handler)()) {
   tiqr_start_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_START_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (request->client != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "client", request->client) == NULL) goto error;
   }
   if (request->source != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "source", request->source) == NULL) goto error;
   }
   if (request->settings != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "settings", request->settings) == NULL) goto error;
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_START_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_start_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->session = NULL;
   response->QR_data = NULL;
   response->QR_length = 0;
   response->URI = NULL;
   response->message = NULL;
   response->timeout = 0;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "code") == 0) {
	    response->code = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "timeout") == 0) {
	    response->timeout = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "session") == 0) response->session = value;
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else if (strcasecmp(name, "URI") == 0) response->URI = value;
	 else if (strcasecmp(name, "QR") == 0) {
	    response->QR_data = (void*)malloc(strlen(value));
	    if (response->QR_data == NULL) {
	       if (log_handler != NULL) (*log_handler)("memory allocation failed");
	       xmlFree(value);
	       goto error;
	    }
	    response->QR_length = base64_decode(response->QR_data, value);
	    if (!response->QR_length) {
	       if (log_handler != NULL) (*log_handler)("base64_decode failed failed");
	       xmlFree(value);
	       goto error;
	    }
	    xmlFree(value);
	 }
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_start_rep_free(response);
   return NULL;
}

tiqr_check_rep_t *tiqr_check(tiqr_check_req_t *request, void(*log_handler)()) {
   tiqr_check_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->session == NULL) return NULL;
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_CHECK_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   if (request->ldapPassword != NULL) { 
      if (soap_env_add_item(soap_request->env, "xsd:string", "ldapPassword", request->ldapPassword) == NULL) goto error;
   }
     
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_CHECK_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_check_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
   response->username = NULL;
   response->domain = NULL;
   response->data = NULL;
   response->timeout = 0;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "code") == 0) {
	    response->code = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "timeout") == 0) {
	    response->timeout = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else if (strcasecmp(name, "username") == 0) response->username = value;
	 else if (strcasecmp(name, "domain") == 0) response->domain = value;
	 else if (strcasecmp(name, "data") == 0) response->data = value;
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_check_rep_free(response);
   return NULL;
}

tiqr_offline_check_rep_t *tiqr_offline_check(tiqr_offline_check_req_t *request, void(*log_handler)()) {
   tiqr_offline_check_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->username == NULL || request->session == NULL || request->tiqrPassword == NULL) return NULL;
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_OFFLINE_CHECK_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "username", request->username) == NULL) goto error;
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   if (soap_env_add_item(soap_request->env, "xsd:string", "tiqrPassword", request->tiqrPassword) == NULL) goto error;
   if (request->domain != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "domain", request->domain) == NULL) goto error;
   }
   if (request->ldapPassword != NULL) { 
      if (soap_env_add_item(soap_request->env, "xsd:string", "ldapPassword", request->ldapPassword) == NULL) goto error;
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_OFFLINE_CHECK_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_check_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
   response->data = NULL;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "code") == 0) {
	    response->code = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else if (strcasecmp(name, "data") == 0) response->data = value;
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_offline_check_rep_free(response);
   return NULL;
}

tiqr_cancel_rep_t *tiqr_cancel(tiqr_cancel_req_t *request, void(*log_handler)()) {
   tiqr_cancel_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->session == NULL) return NULL;
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_CANCEL_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_CANCEL_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_cancel_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "code") == 0) {
	    response->code = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_cancel_rep_free(response);
   return NULL;
}

tiqr_session_qr_rep_t *tiqr_session_qr(tiqr_session_qr_req_t *request, void(*log_handler)()) {
   tiqr_session_qr_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->session == NULL) return NULL;
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_SESSION_QR_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_SESSION_QR_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_session_qr_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->QR_data = NULL;
   response->QR_length = 0;
   response->URI = NULL;
   response->message = NULL;
   response->timeout = 0;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "code") == 0) {
	    response->code = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "timeout") == 0) {
	    response->timeout = atoi(value);
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else if (strcasecmp(name, "URI") == 0) response->URI = value;
	 else if (strcasecmp(name, "QR") == 0) {
	    response->QR_data = (void*)malloc(strlen(value));
	    if (response->QR_data == NULL) {
	       if (log_handler != NULL) (*log_handler)("memory allocation failed");
	       xmlFree(value);
	       goto error;
	    }
	    response->QR_length = base64_decode(response->QR_data, value);
	    if (!response->QR_length) {
	       if (log_handler != NULL) (*log_handler)("base64_decode failed failed");
	       xmlFree(value);
	       goto error;
	    }
	    xmlFree(value);
	 }
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_session_qr_rep_free(response);
   return NULL;
}

tiqr_status_rep_t *tiqr_status(void(*log_handler)()) {
   tiqr_status_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__tiqr_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("TiQR not initialized");
      return NULL;
   }
   
   err = soap_ctx_new_with_method(TIQR_URN, TIQR_STATUS_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __tiqr_url1, "");
   if (err != H_OK && __tiqr_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __tiqr_url2, "");
   if (err != H_OK) goto error;
   
   if (soap_env_get_fault(soap_response->env)) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (strcasecmp((char*)method->name, TIQR_STATUS_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(tiqr_status_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->status = 0;
   response->message = NULL;
   
   node = soap_xml_get_children(method);
   while (node != NULL) {
      name = (char*)node->name;
      value = soap_xml_get_text(node);
      if (value != NULL) {
	 if (strcasecmp(name, "status") == 0) {
	    if (strcasecmp(value, "1") == 0 || strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "ok") == 0) response->status = 1;
	    else response->status = 0;
	    xmlFree(value);
	 }
	 else if (strcasecmp(name, "message") == 0) response->message = value;
	 else xmlFree(value);
      }
      node = soap_xml_get_next(node);
   }
   
   soap_ctx_free(soap_request);
   soap_ctx_free(soap_response);
   return response;
   
   error:
   if (err != H_OK) {
      if (log_handler != NULL) (*log_handler)(herror_message(err));
      herror_release(err);
   }
   if (soap_request != NULL) soap_ctx_free(soap_request);
   if (soap_response != NULL) soap_ctx_free(soap_response);
   if (response != NULL) tiqr_status_rep_free(response);
   return NULL;
}

tiqr_start_req_t *tiqr_start_req_new(void) {
   tiqr_start_req_t *request = malloc(sizeof(tiqr_start_req_t));
   if (request == NULL) return NULL;
   request->client = NULL;
   request->source = NULL;
   request->settings = NULL;
   return request;
}

void tiqr_start_req_free(tiqr_start_req_t *request) {
   if (request == NULL) return;
   if (request->client != NULL) free(request->client);
   if (request->source != NULL) free(request->source);
   if (request->settings != NULL) free(request->settings);
   free(request);
}

void tiqr_start_rep_free(tiqr_start_rep_t *response) {
   if (response == NULL) return;
   if (response->session != NULL) free(response->session);
   if (response->QR_data != NULL) free(response->QR_data);
   if (response->URI != NULL) free(response->URI);
   if (response->message != NULL) free(response->message);
   free(response);
}

tiqr_check_req_t *tiqr_check_req_new(void) {
   tiqr_check_req_t *request = malloc(sizeof(tiqr_check_req_t));
   if (request == NULL) return NULL;
   request->session = NULL;
   request->ldapPassword = NULL;
   return request;
}

void tiqr_check_req_free(tiqr_check_req_t *request) {
   if (request == NULL) return;
   if (request->session != NULL) free(request->session);
   if (request->ldapPassword != NULL) free(request->ldapPassword);
   free(request);
}

void tiqr_check_rep_free(tiqr_check_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->username != NULL) free(response->username);
   if (response->domain != NULL) free(response->domain);
   if (response->data != NULL) free(response->data);
   free(response);
}

tiqr_offline_check_req_t *tiqr_offline_check_req_new(void) {
   tiqr_offline_check_req_t *request = malloc(sizeof(tiqr_offline_check_req_t));
   if (request == NULL) return NULL;
   request->username = NULL;
   request->domain = NULL;
   request->session = NULL;
   request->ldapPassword = NULL;
   request->tiqrPassword = NULL;
   return request;
}

void tiqr_offline_check_req_free(tiqr_offline_check_req_t *request) {
   if (request == NULL) return;
   if (request->username != NULL) free(request->username);
   if (request->domain != NULL) free(request->domain);
   if (request->session != NULL) free(request->session);
   if (request->ldapPassword != NULL) free(request->ldapPassword);
   if (request->tiqrPassword != NULL) free(request->tiqrPassword);
   free(request);
}

void tiqr_offline_check_rep_free(tiqr_offline_check_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->data != NULL) free(response->data);
   free(response);
}

tiqr_cancel_req_t *tiqr_cancel_req_new(void) {
   tiqr_cancel_req_t *request = malloc(sizeof(tiqr_cancel_req_t));
   if (request == NULL) return NULL;
   request->session = NULL;
   return request;
}

void tiqr_cancel_req_free(tiqr_cancel_req_t *request) {
   if (request == NULL) return;
   if (request->session != NULL) free(request->session);
   free(request);
}

void tiqr_cancel_rep_free(tiqr_cancel_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   free(response);
}

tiqr_session_qr_req_t *tiqr_session_qr_req_new(void) {
   tiqr_session_qr_req_t *request = malloc(sizeof(tiqr_session_qr_req_t));
   if (request == NULL) return NULL;
   request->session = NULL;
   return request;
}

void tiqr_session_qr_req_free(tiqr_session_qr_req_t *request) {
   if (request == NULL) return;
   if (request->session != NULL) free(request->session);
   free(request);
}

void tiqr_session_qr_rep_free(tiqr_session_qr_rep_t *response) {
   if (response == NULL) return;
   if (response->QR_data != NULL) free(response->QR_data);
   if (response->URI != NULL) free(response->URI);
   if (response->message != NULL) free(response->message);
   free(response);
}

void tiqr_status_rep_free(tiqr_status_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   free(response);
}
