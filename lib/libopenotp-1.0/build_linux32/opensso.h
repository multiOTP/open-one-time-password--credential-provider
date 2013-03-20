/*
 RCDevs OpenOTP/TiQR Development Library
 Copyright (c) 2010-2013 RCDevs SA, All rights reserved.
 
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

#ifndef _OPENSSO_H
#define _OPENSSO_H 1

// OpenSSO definitions

#define OPENSSO_URN "urn:opensso"
#define OPENSSO_START_METHOD "openssoStart"
#define OPENSSO_STOP_METHOD "openssoStop"
#define OPENSSO_CHECK_METHOD "openssoCheck"
#define OPENSSO_STATUS_METHOD "openssoStatus"

#define OPENSSO_START_REQUEST "openssoStartRequest"
#define OPENSSO_START_RESPONSE "openssoStartResponse"
#define OPENSSO_STOP_REQUEST "openssoStopRequest"
#define OPENSSO_STOP_RESPONSE "openssoStopResponse"
#define OPENSSO_CHECK_REQUEST "openssoCheckRequest"
#define OPENSSO_CHECK_RESPONSE "openssoCheckResponse"
#define OPENSSO_STATUS_REQUEST "openssoStatusRequest"
#define OPENSSO_STATUS_RESPONSE "openssoStatusResponse"

// OpenSSO response codes

#define OPENSSO_FAILURE 0
#define OPENSSO_SUCCESS 1

// OpenSSO structures

typedef struct opensso_start_req_t {
   char *username;
   char *domain;
   char *data;
   char *client;
   char *source;
   char *settings;
} opensso_start_req_t;

typedef struct opensso_start_rep_t {
   int  code;
   char *message;
   char *session;
   int timeout;
} opensso_start_rep_t;

typedef struct opensso_stop_req_t {
   char *session;
} opensso_stop_req_t;

typedef struct opensso_stop_rep_t {
   int  code;
   char *message;
} opensso_stop_rep_t;

typedef struct opensso_check_req_t {
   char *session;
   char *data;
} opensso_check_req_t;

typedef struct opensso_check_rep_t {
   int  code;
   char *message;
   char *data;
   int timeout;
} opensso_check_rep_t;

typedef struct opensso_status_rep_t {
   int status;
   char *message;
} opensso_status_rep_t;


#if defined(WINDOWS) || defined(WIN32) || defined(WIN64)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT extern
#endif

/* 
 * opensso_initialize() parameters:
 * - url: OpenSSO SOAP server URL (mandatory)
 * - cert: client certificate in PEM format (set NULL to disable)
 * - pass: client certificate password if encrypted (set NULL to disable)
 * - ca: server certificate in PEM format (set NULL to disable)
 * - timeout: soap request timeout in seconds (set 0 for default)
 * - log_handler: log handler function (set NULL to disable)
 */
EXPORT int opensso_initialize(char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)());
EXPORT int opensso_terminate(void(*log_handler)());

// OpenSSO functions

EXPORT opensso_start_rep_t *opensso_start(opensso_start_req_t *request, void(*log_handler)());
EXPORT opensso_stop_rep_t *opensso_stop(opensso_stop_req_t *request, void(*log_handler)());
EXPORT opensso_check_rep_t *opensso_check(opensso_check_req_t *request, void(*log_handler)());
EXPORT opensso_status_rep_t *opensso_status(void(*log_handler)());

EXPORT opensso_start_req_t *opensso_start_req_new(void);
EXPORT void opensso_start_req_free(opensso_start_req_t *request);
EXPORT void opensso_start_rep_free(opensso_start_rep_t *response);

EXPORT opensso_stop_req_t *opensso_stop_req_new(void);
EXPORT void opensso_stop_req_free(opensso_stop_req_t *request);
EXPORT void opensso_stop_rep_free(opensso_stop_rep_t *response);

EXPORT opensso_check_req_t *opensso_check_req_new(void);
EXPORT void opensso_check_req_free(opensso_check_req_t *request);
EXPORT void opensso_check_rep_free(opensso_check_rep_t *response);

EXPORT void opensso_status_rep_free(opensso_status_rep_t *response); 

#endif
