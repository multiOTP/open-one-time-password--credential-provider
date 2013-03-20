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

#include "opensso.h"
#include "libcsoap/soap-client.h"
#include "nanohttp/nanohttp-client.h"
#ifdef HAVE_SSL
#include "nanohttp/nanohttp-ssl.h"
#endif

char *__opensso_url1 = NULL;
char *__opensso_url2 = NULL;

int opensso_initialize (char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)()) {
   herror_t err = H_OK;
   
   if (__opensso_url1 != NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO already initialized");
      return 0;
   }
   
   if (url == NULL) {
      if (log_handler != NULL) (*log_handler)("missing OpenSSO server URL");
      return 0;
   }
   
   char *ptr = strchr(url, ',');
   if (ptr != NULL) {
      __opensso_url1 = url;
      __opensso_url2 = ptr+1;
      *ptr = 0;
   } else {
      __opensso_url1 = url;
      __opensso_url2 = NULL;
   }
   
   #ifdef HAVE_SSL
   if ((__opensso_url1 != NULL && strncmp(__opensso_url1, "https://", 8) == 0) ||
       (__opensso_url2 != NULL && strncmp(__opensso_url2, "https://", 8) == 0)) {
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

int opensso_terminate (void(*log_handler)()) {
   if (__opensso_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO not initialized");
      return 0;
   }
   __opensso_url1 = NULL;
   __opensso_url2 = NULL;
   #ifdef HAVE_SSL
   if ((__opensso_url1 != NULL && strncmp(__opensso_url1, "https://", 8) == 0) ||
       (__opensso_url2 != NULL && strncmp(__opensso_url2, "https://", 8) == 0)) {
      hssl_module_destroy();
   }
   #endif
   soap_client_destroy();
   return 1;
}

opensso_start_rep_t *opensso_start(opensso_start_req_t *request, void(*log_handler)()) {
   opensso_start_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__opensso_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->username == NULL) return NULL;
   
   err = soap_ctx_new_with_method(OPENSSO_URN, OPENSSO_START_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "username", request->username) == NULL) goto error;
   if (request->domain != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "domain", request->domain) == NULL) goto error;
   }
   if (request->data != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "data", request->data) == NULL) goto error;
   }
   if (request->client != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "client", request->client) == NULL) goto error;
   }
   if (request->source != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "source", request->source) == NULL) goto error;
   }
   if (request->settings != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "settings", request->settings) == NULL) goto error;
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __opensso_url1, "");
   if (err != H_OK && __opensso_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __opensso_url2, "");
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
   if (strcasecmp((char*)method->name, OPENSSO_START_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(opensso_start_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
   response->session = NULL;
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
	 else if (strcasecmp(name, "session") == 0) response->session = value;
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
   if (response != NULL) opensso_start_rep_free(response);
   return NULL;
}

opensso_stop_rep_t *opensso_stop(opensso_stop_req_t *request, void(*log_handler)()) {
   opensso_stop_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__opensso_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->session == NULL) return NULL;
   
   err = soap_ctx_new_with_method(OPENSSO_URN, OPENSSO_STOP_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __opensso_url1, "");
   if (err != H_OK && __opensso_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __opensso_url2, "");
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
   if (strcasecmp((char*)method->name, OPENSSO_STOP_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(opensso_stop_rep_t));
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
   if (response != NULL) opensso_stop_rep_free(response);
   return NULL;
}

opensso_check_rep_t *opensso_check(opensso_check_req_t *request, void(*log_handler)()) {
   opensso_check_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__opensso_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->session == NULL) return NULL;
   
   err = soap_ctx_new_with_method(OPENSSO_URN, OPENSSO_CHECK_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   if (request->data != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "data", request->data) == NULL) goto error;
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __opensso_url1, "");
   if (err != H_OK && __opensso_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __opensso_url2, "");
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
   if (strcasecmp((char*)method->name, OPENSSO_CHECK_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(opensso_check_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
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
   if (response != NULL) opensso_check_rep_free(response);
   return NULL;
}

opensso_status_rep_t *opensso_status(void(*log_handler)()) {
   opensso_status_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__opensso_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenSSO not initialized");
      return NULL;
   }
   
   err = soap_ctx_new_with_method(OPENSSO_URN, OPENSSO_STATUS_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __opensso_url1, "");
   if (err != H_OK && __opensso_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __opensso_url2, "");
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
   if (strcasecmp((char*)method->name, OPENSSO_STATUS_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(opensso_status_rep_t));
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
   if (response != NULL) opensso_status_rep_free(response);
   return NULL;
}

opensso_start_req_t *opensso_start_req_new(void) {
   opensso_start_req_t *request = malloc(sizeof(opensso_start_req_t));
   if (request == NULL) return NULL;
   request->username = NULL;
   request->domain = NULL;
   request->data = NULL;
   request->client = NULL;
   request->source = NULL;
   request->settings = NULL;
   return request;
}

void opensso_start_req_free(opensso_start_req_t *request) {
   if (request == NULL) return;
   if (request->username != NULL) free(request->username);
   if (request->domain != NULL) free(request->domain);
   if (request->data != NULL) free(request->data);
   if (request->client != NULL) free(request->client);
   if (request->source != NULL) free(request->source);
   if (request->settings != NULL) free(request->settings);
   free(request);
}

void opensso_start_rep_free(opensso_start_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->session != NULL) free(response->session);
   free(response);
}

opensso_stop_req_t *opensso_stop_req_new(void) {
   opensso_stop_req_t *request = malloc(sizeof(opensso_stop_req_t));
   if (request == NULL) return NULL;
   request->session = NULL;
   return request;
}

void opensso_stop_req_free(opensso_stop_req_t *request) {
   if (request == NULL) return;
   if (request->session != NULL) free(request->session);
   free(request);
}

void opensso_stop_rep_free(opensso_stop_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   free(response);
}

opensso_check_req_t *opensso_check_req_new(void) {
   opensso_check_req_t *request = malloc(sizeof(opensso_check_req_t));
   if (request == NULL) return NULL;
   request->session = NULL;
   request->data = NULL;
   return request;
}

void opensso_check_req_free(opensso_check_req_t *request) {
   if (request == NULL) return;
   if (request->session != NULL) free(request->session);
   if (request->data != NULL) free(request->data);
   free(request);
}

void opensso_check_rep_free(opensso_check_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->data != NULL) free(response->data);
   free(response);
}

void opensso_status_rep_free(opensso_status_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   free(response);
}
