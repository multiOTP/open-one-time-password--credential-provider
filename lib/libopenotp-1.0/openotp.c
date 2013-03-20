/*
 OpenOTP Development Library
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

#include "openotp.h"
#include "libcsoap/soap-client.h"
#include "nanohttp/nanohttp-client.h"
#ifdef HAVE_SSL
#include "nanohttp/nanohttp-ssl.h"
#endif

#define OPENOTP_SIMPLE_LOGIN 1
#define OPENOTP_NORMAL_LOGIN 2
#define OPENOTP_COMPAT_LOGIN 3

char *__openotp_url1 = NULL;
char *__openotp_url2 = NULL;

int openotp_initialize (char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)()) {
   herror_t err = H_OK;
   
   if (__openotp_url1 != NULL) {
      if (log_handler != NULL) (*log_handler)("OpenOTP already initialized");
      return 0;
   }
   
   if (url == NULL) {
      if (log_handler != NULL) (*log_handler)("missing OpenOTP server URL");
      return 0;
   }
   
   char *ptr = strchr(url, ',');
   if (ptr != NULL) {
      __openotp_url1 = url;
      __openotp_url2 = ptr+1;
      *ptr = 0;
   } else {
      __openotp_url1 = url;
      __openotp_url2 = NULL;
   }
   
   #ifdef HAVE_SSL
   if ((__openotp_url1 != NULL && strncmp(__openotp_url1, "https://", 8) == 0) ||
       (__openotp_url2 != NULL && strncmp(__openotp_url2, "https://", 8) == 0)) {
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

int openotp_terminate (void(*log_handler)()) {
   if (__openotp_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenOTP not initialized");
      return 0;
   }
   __openotp_url1 = NULL;
   __openotp_url2 = NULL;
   #ifdef HAVE_SSL
   if ((__openotp_url1 != NULL && strncmp(__openotp_url1, "https://", 8) == 0) ||
       (__openotp_url2 != NULL && strncmp(__openotp_url2, "https://", 8) == 0)) {
      hssl_module_destroy();
   }
   #endif
   soap_client_destroy();
   return 1;
}

openotp_login_rep_t *openotp_login_wrapper(int type, void *request, void(*log_handler)()) {
   openotp_login_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__openotp_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenOTP not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   
   switch (type) {
    case OPENOTP_SIMPLE_LOGIN: {
       openotp_simple_login_req_t *simple_request = request;
       
       if (simple_request->username == NULL) return NULL;
      
       err = soap_ctx_new_with_method(OPENOTP_URN, OPENOTP_SIMPLE_LOGIN_METHOD, &soap_request);
       if (err != H_OK) goto error;
       
       if (soap_env_add_item(soap_request->env, "xsd:string", "username", simple_request->username) == NULL) goto error;
       if (simple_request->domain != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "domain", simple_request->domain) == NULL) goto error;
       }
       if (simple_request->anyPassword != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "anyPassword", simple_request->anyPassword) == NULL) goto error;
       }
       if (simple_request->client != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "client", simple_request->client) == NULL) goto error;
       }
       if (simple_request->source != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "source", simple_request->source) == NULL) goto error;
       }
       if (simple_request->settings != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "settings", simple_request->settings) == NULL) goto error;
       }
       break;
    }
    case OPENOTP_NORMAL_LOGIN:
    case OPENOTP_COMPAT_LOGIN: {
       openotp_normal_login_req_t *normal_request = request;
       
       if (normal_request->username == NULL) return NULL;
       
       if (type == OPENOTP_NORMAL_LOGIN) err = soap_ctx_new_with_method(OPENOTP_URN, OPENOTP_NORMAL_LOGIN_METHOD, &soap_request);
       else err = soap_ctx_new_with_method(OPENOTP_URN, OPENOTP_COMPAT_LOGIN_METHOD, &soap_request);
       if (err != H_OK) goto error;
       
       if (soap_env_add_item(soap_request->env, "xsd:string", "username", normal_request->username) == NULL) goto error;
       if (normal_request->domain != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "domain", normal_request->domain) == NULL) goto error;
       }
       if (normal_request->ldapPassword != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "ldapPassword", normal_request->ldapPassword) == NULL) goto error;
       }
       if (normal_request->otpPassword != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "otpPassword", normal_request->otpPassword) == NULL) goto error;
       }
       if (normal_request->client != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "client", normal_request->client) == NULL) goto error;
       }
       if (normal_request->source != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "source", normal_request->source) == NULL) goto error;
       }
       if (normal_request->settings != NULL) {
	  if (soap_env_add_item(soap_request->env, "xsd:string", "settings", normal_request->settings) == NULL) goto error;
       }
       break;
    }
    default: {
       return NULL;
       break;
    }
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __openotp_url1, "");
   if (err != H_OK && __openotp_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __openotp_url2, "");
   if (err != H_OK) goto error;
   
   node = soap_env_get_fault(soap_response->env);
   if (node != NULL) {
      if (log_handler != NULL) (*log_handler)("received SOAP fault");
      goto error;
   }
   
   method = soap_env_get_method(soap_response->env);
   if (method == NULL) {
      if (log_handler != NULL) (*log_handler)("missing response method");
      goto error;
   }
   if (type == OPENOTP_SIMPLE_LOGIN && strcasecmp((char*)method->name, OPENOTP_SIMPLE_LOGIN_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   else if (type == OPENOTP_NORMAL_LOGIN && strcasecmp((char*)method->name, OPENOTP_NORMAL_LOGIN_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   else if (type == OPENOTP_COMPAT_LOGIN && strcasecmp((char*)method->name, OPENOTP_COMPAT_LOGIN_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(openotp_login_rep_t));
   if (response == NULL) {
      if (log_handler != NULL) (*log_handler)("memory allocation failed");
      goto error;
   }
   response->code = 0;
   response->message = NULL;
   response->session = NULL;
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
	 else if (strcasecmp(name, "session") == 0) response->session = value;
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
   if (response != NULL) openotp_login_rep_free(response);
   return NULL;
}

openotp_login_rep_t *openotp_simple_login(openotp_simple_login_req_t *request, void(*log_handler)()) {
   return openotp_login_wrapper(OPENOTP_SIMPLE_LOGIN, (void*)request, log_handler);
}

openotp_login_rep_t *openotp_normal_login(openotp_normal_login_req_t *request, void(*log_handler)()) {
   return openotp_login_wrapper(OPENOTP_NORMAL_LOGIN, (void*)request, log_handler);
}

openotp_login_rep_t *openotp_login(openotp_login_req_t *request, void(*log_handler)()) {
   return openotp_login_wrapper(OPENOTP_COMPAT_LOGIN, (void*)request, log_handler);
}

openotp_challenge_rep_t *openotp_challenge(openotp_challenge_req_t *request, void(*log_handler)()) {
   openotp_challenge_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;

   if (__openotp_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenOTP not initialized");
      return NULL;
   }
   
   if (request == NULL) return NULL;
   if (request->username == NULL || request->session == NULL || request->otpPassword == NULL)  return NULL;
   
   err = soap_ctx_new_with_method(OPENOTP_URN, OPENOTP_CHALLENGE_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   if (soap_env_add_item(soap_request->env, "xsd:string", "username", request->username) == NULL) goto error;
   if (soap_env_add_item(soap_request->env, "xsd:string", "session", request->session) == NULL) goto error;
   if (soap_env_add_item(soap_request->env, "xsd:string", "otpPassword", request->otpPassword) == NULL) goto error;
   if (request->domain != NULL) {
      if (soap_env_add_item(soap_request->env, "xsd:string", "domain", request->domain) == NULL) goto error;
   }
   
   err = soap_client_invoke(soap_request, &soap_response, __openotp_url1, "");
   if (err != H_OK && __openotp_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __openotp_url2, "");
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
   if (strcasecmp((char*)method->name, OPENOTP_CHALLENGE_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(openotp_challenge_rep_t));
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
   if (response != NULL) openotp_challenge_rep_free(response);
   return NULL;
}

openotp_status_rep_t *openotp_status(void(*log_handler)()) {
   openotp_status_rep_t *response = NULL;
   SoapCtx *soap_request = NULL;
   SoapCtx *soap_response = NULL;
   herror_t err = H_OK;
   xmlNodePtr method, node;
   char *value, *name;
   
   if (__openotp_url1 == NULL) {
      if (log_handler != NULL) (*log_handler)("OpenOTP not initialized");
      return NULL;
   }
      
   err = soap_ctx_new_with_method(OPENOTP_URN, OPENOTP_STATUS_METHOD, &soap_request);
   if (err != H_OK) goto error;
   
   err = soap_client_invoke(soap_request, &soap_response, __openotp_url1, "");
   if (err != H_OK && __openotp_url2 != NULL) err = soap_client_invoke(soap_request, &soap_response, __openotp_url2, "");
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
   if (strcasecmp((char*)method->name, OPENOTP_STATUS_RESPONSE) != 0) {
      if (log_handler != NULL) (*log_handler)("invalid response method");
      goto error;
   }
   
   response = malloc(sizeof(openotp_status_rep_t));
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
   if (response != NULL) openotp_status_rep_free(response);
   return NULL;
}

openotp_simple_login_req_t *openotp_simple_login_req_new(void) {
   openotp_simple_login_req_t *request = malloc(sizeof(openotp_simple_login_req_t));
   if (request == NULL) return NULL;
   request->username = NULL;
   request->domain = NULL;
   request->anyPassword = NULL;
   request->client = NULL;
   request->source = NULL;
   request->settings = NULL;
   return request;
}

openotp_normal_login_req_t *openotp_normal_login_req_new(void) {
   openotp_normal_login_req_t *request = malloc(sizeof(openotp_normal_login_req_t));
   if (request == NULL) return NULL;
   request->username = NULL;
   request->domain = NULL;
   request->ldapPassword = NULL;
   request->otpPassword = NULL;
   request->client = NULL;
   request->source = NULL;
   request->settings = NULL;
   return request;
}

openotp_login_req_t *openotp_login_req_new(void) {
   return openotp_normal_login_req_new();
}

void openotp_simple_login_req_free(openotp_simple_login_req_t *request) {
   if (request == NULL) return;
   if (request->username != NULL) free(request->username);
   if (request->domain != NULL) free(request->domain);
   if (request->anyPassword != NULL) free(request->anyPassword);
   if (request->client != NULL) free(request->client);
   if (request->source != NULL) free(request->source);
   if (request->settings != NULL) free(request->settings);
   free(request);
}

void openotp_normal_login_req_free(openotp_normal_login_req_t *request) {
   if (request == NULL) return;
   if (request->username != NULL) free(request->username);
   if (request->domain != NULL) free(request->domain);
   if (request->ldapPassword != NULL) free(request->ldapPassword);
   if (request->otpPassword != NULL) free(request->otpPassword);
   if (request->client != NULL) free(request->client);
   if (request->source != NULL) free(request->source);
   if (request->settings != NULL) free(request->settings);
   free(request);
}

void openotp_login_req_free(openotp_login_req_t *request) {
   return openotp_normal_login_req_free(request);
}

void openotp_login_rep_free(openotp_login_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->session != NULL) free(response->session);
   if (response->data != NULL) free(response->data);
   free(response);
}

openotp_challenge_req_t *openotp_challenge_req_new(void) {
   openotp_challenge_req_t *request = malloc(sizeof(openotp_challenge_req_t));
   if (request == NULL) return NULL;
   request->username = NULL;
   request->domain = NULL;
   request->session = NULL;
   request->otpPassword = NULL;
   return request;
}

void openotp_challenge_req_free(openotp_challenge_req_t *request) {
   if (request == NULL) return;
   if (request->username != NULL) free(request->username);
   if (request->domain != NULL) free(request->domain);
   if (request->session != NULL) free(request->session);
   if (request->otpPassword != NULL) free(request->otpPassword);
   free(request);
}

void openotp_challenge_rep_free(openotp_challenge_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   if (response->data != NULL) free(response->data);
   free(response);
}

void openotp_status_rep_free(openotp_status_rep_t *response) {
   if (response == NULL) return;
   if (response->message != NULL) free(response->message);
   free(response);
}
