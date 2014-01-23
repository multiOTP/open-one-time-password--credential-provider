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

#ifndef _TIQR_H                                                                                                  
#define _TIQR_H 1

// TiQR definitions

#define TIQR_URN "urn:tiqr"
#define TIQR_START_METHOD "tiqrStart"
#define TIQR_STOP_METHOD "tiqrStop"
#define TIQR_CHECK_METHOD "tiqrCheck"
#define TIQR_OFFLINE_CHECK_METHOD "tiqrOfflineCheck"
#define TIQR_CANCEL_METHOD "tiqrCancel"
#define TIQR_SESSION_QR_METHOD "tiqrSessionQR"
#define TIQR_STATUS_METHOD "tiqrStatus"

#define TIQR_START_REQUEST "tiqrStartRequest"
#define TIQR_START_RESPONSE "tiqrStartResponse"
#define TIQR_CHECK_REQUEST "tiqrCheckRequest"
#define TIQR_CHECK_RESPONSE "tiqrCheckResponse"
#define TIQR_OFFLINE_CHECK_REQUEST "tiqrOfflineCheckRequest"
#define TIQR_OFFLINE_CHECK_RESPONSE "tiqrOfflineCheckResponse"
#define TIQR_CANCEL_REQUEST "tiqrCancelRequest"
#define TIQR_CANCEL_RESPONSE "tiqrCancelResponse"
#define TIQR_SESSION_QR_REQUEST "tiqrSessionQRRequest"
#define TIQR_SESSION_QR_RESPONSE "tiqrSessionQRResponse"
#define TIQR_STATUS_REQUEST "tiqrStatusRequest"
#define TIQR_STATUS_RESPONSE "tiqrStatusResponse"

// TiQR response codes

#define TIQR_FAILURE 0
#define TIQR_SUCCESS 1
#define TIQR_PENDING 2

// TiQR structures

typedef struct tiqr_start_req_t {
   char *client;
   char *source;
   char *settings;
} tiqr_start_req_t;

typedef struct tiqr_start_rep_t {
   int  code;
   char *session;
   void *QR_data;
   int QR_length;
   char *URI;
   char *message;
   int timeout;
} tiqr_start_rep_t;

typedef struct tiqr_check_req_t {
   char *session;
   char *ldapPassword;
} tiqr_check_req_t;

typedef struct tiqr_check_rep_t {
   int  code;
   char *message;
   char *username;
   char *domain;
   char *data;
   int timeout;
} tiqr_check_rep_t;

typedef struct tiqr_offline_check_req_t {
   char *username;
   char *domain;
   char *session;
   char *ldapPassword;
   char *tiqrPassword;
} tiqr_offline_check_req_t;

typedef struct tiqr_offline_check_rep_t {
   int  code;
   char *message;
   char *data;
} tiqr_offline_check_rep_t;

typedef struct tiqr_cancel_req_t {
   char *session;
} tiqr_cancel_req_t;

typedef struct tiqr_cancel_rep_t {
   int  code;
   char *message;
} tiqr_cancel_rep_t;

typedef struct tiqr_session_qr_req_t {
   char *session;
} tiqr_session_qr_req_t;

typedef struct tiqr_session_qr_rep_t {
   int  code;
   void *QR_data;
   int QR_length;
   char *URI;
   char *message;
   int timeout;
} tiqr_session_qr_rep_t;

typedef struct tiqr_status_rep_t {
   int status;
   char *message;
} tiqr_status_rep_t;


#if defined(WINDOWS) || defined(WIN32) || defined(WIN64)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT extern
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/* 
 * tiqr_initialize() parameters:
 * - url: TiQR SOAP server URL (mandatory)
 * - cert: client certificate in PEM format (set NULL to disable)
 * - pass: client certificate password if encrypted (set NULL to disable)
 * - ca: server certificate in PEM format (set NULL to disable)
 * - timeout: soap request timeout in seconds (set 0 for default)
 * - log_handler: log handler function (set NULL to disable)
 */
EXPORT int tiqr_initialize(char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)());
EXPORT int tiqr_terminate(void(*log_handler)());

// tiqr functions

EXPORT tiqr_start_rep_t *tiqr_start(tiqr_start_req_t *request, void(*log_handler)());
EXPORT tiqr_check_rep_t *tiqr_check(tiqr_check_req_t *request, void(*log_handler)());
EXPORT tiqr_offline_check_rep_t *tiqr_offline_check(tiqr_offline_check_req_t *request, void(*log_handler)());
EXPORT tiqr_cancel_rep_t *tiqr_cancel(tiqr_cancel_req_t *request, void(*log_handler)());
EXPORT tiqr_session_qr_rep_t *tiqr_session_qr(tiqr_session_qr_req_t *request, void(*log_handler)());
EXPORT tiqr_status_rep_t *tiqr_status(void(*log_handler)());

EXPORT tiqr_start_req_t *tiqr_start_req_new(void);
EXPORT void tiqr_start_req_free(tiqr_start_req_t *request);
EXPORT void tiqr_start_rep_free(tiqr_start_rep_t *response);

EXPORT tiqr_check_req_t *tiqr_check_req_new(void);
EXPORT void tiqr_check_req_free(tiqr_check_req_t *request);
EXPORT void tiqr_check_rep_free(tiqr_check_rep_t *response);

EXPORT tiqr_offline_check_req_t *tiqr_offline_check_req_new(void);
EXPORT void tiqr_offline_check_req_free(tiqr_offline_check_req_t *request);
EXPORT void tiqr_offline_check_rep_free(tiqr_offline_check_rep_t *response);

EXPORT tiqr_cancel_req_t *tiqr_cancel_req_new(void);
EXPORT void tiqr_cancel_req_free(tiqr_cancel_req_t *request);
EXPORT void tiqr_cancel_rep_free(tiqr_cancel_rep_t *response);

EXPORT tiqr_session_qr_req_t *tiqr_session_qr_req_new(void);
EXPORT void tiqr_session_qr_req_free(tiqr_session_qr_req_t *request);
EXPORT void tiqr_session_qr_rep_free(tiqr_session_qr_rep_t *response);

EXPORT void tiqr_status_rep_free(tiqr_status_rep_t *response); 

#ifdef __cplusplus
}
#endif

#endif
