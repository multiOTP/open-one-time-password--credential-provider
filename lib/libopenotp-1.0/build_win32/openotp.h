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

#ifndef _OPENOTP_H                                                                                                  
#define _OPENOTP_H 1

// OpenOTP definitions

#define OPENOTP_URN "urn:openotp"
#define OPENOTP_SIMPLE_LOGIN_METHOD "openotpSimpleLogin"
#define OPENOTP_NORMAL_LOGIN_METHOD "openotpNormalLogin"
#define OPENOTP_COMPAT_LOGIN_METHOD "openotpLogin"
#define OPENOTP_CHALLENGE_METHOD "openotpChallenge"
#define OPENOTP_STATUS_METHOD "openotpStatus"

#define OPENOTP_SIMPLE_LOGIN_REQUEST "openotpSimpleLoginRequest"
#define OPENOTP_SIMPLE_LOGIN_RESPONSE "openotpSimpleLoginResponse"
#define OPENOTP_NORMAL_LOGIN_REQUEST "openotpNormalLoginRequest"
#define OPENOTP_NORMAL_LOGIN_RESPONSE "openotpNormalLoginResponse"
#define OPENOTP_COMPAT_LOGIN_REQUEST "openotpLoginRequest"
#define OPENOTP_COMPAT_LOGIN_RESPONSE "openotpLoginResponse"
#define OPENOTP_CHALLENGE_REQUEST "openotpChallengeRequest"
#define OPENOTP_CHALLENGE_RESPONSE "openotpChallengeResponse"
#define OPENOTP_STATUS_REQUEST "openotpStatusRequest"
#define OPENOTP_STATUS_RESPONSE "openotpStatusResponse"

// OpenOTP response codes

#define OPENOTP_FAILURE 0
#define OPENOTP_SUCCESS 1
#define OPENOTP_CHALLENGE 2

// OpenOTP structures

typedef struct openotp_simple_login_req_t {
   char *username;
   char *domain;
   char *anyPassword;
   char *client;
   char *source;
   char *settings;
} openotp_simple_login_req_t;

typedef struct openotp_normal_login_req_t {
   char *username;
   char *domain;
   char *ldapPassword;
   char *otpPassword;
   char *client;
   char *source;
   char *settings;
} openotp_normal_login_req_t;

// openotp_login_req_t is an alias of openotp_normal_login_req_t
#define openotp_login_req_t openotp_normal_login_req_t

typedef struct openotp_login_rep_t {
   int  code;
   char *message;
   char *session;
   char *data;
   int timeout;
} openotp_login_rep_t;

typedef struct openotp_challenge_req_t {
   char *username;
   char *domain;
   char *session;
   char *otpPassword;
} openotp_challenge_req_t;

typedef struct openotp_challenge_rep_t {
   int  code;
   char *message;
   char *data;
} openotp_challenge_rep_t;

typedef struct openotp_status_rep_t {
   int status;
   char *message;
} openotp_status_rep_t;


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
 * openotp_initialize() parameters:
 * - url: OpenOTP SOAP server URL(s) (mandatory)
 * - cert: client certificate file in PEM format (set NULL to disable)
 * - pass: client certificate password if encrypted (set NULL to disable)
 * - ca: server certificate file in PEM format (set NULL to disable)
 * - timeout: soap request timeout in seconds (set 0 for default)
 * - log_handler: log handler function (set NULL to disable)
 */
EXPORT int openotp_initialize(char *url, char *cert, char *pass, char *ca, int timeout, void(*log_handler)());
EXPORT int openotp_terminate(void(*log_handler)());

// OpenOTP functions

EXPORT openotp_login_rep_t *openotp_simple_login(openotp_simple_login_req_t *request, void(*log_handler)());
EXPORT openotp_simple_login_req_t *openotp_simple_login_req_new(void);
EXPORT void openotp_simple_login_req_free(openotp_simple_login_req_t *request);
EXPORT void openotp_login_rep_free(openotp_login_rep_t *response);

EXPORT openotp_login_rep_t *openotp_normal_login(openotp_normal_login_req_t *request, void(*log_handler)());
EXPORT openotp_normal_login_req_t *openotp_normal_login_req_new(void);
EXPORT void openotp_normal_login_req_free(openotp_normal_login_req_t *request);

// openotp_login(), openotp_login_req_new() and openotp_login_req_free() are aliases functions for 
// openotp_normal_login(), openotp_login_req_new() and openotp_login_req_free().
EXPORT openotp_login_rep_t *openotp_login(openotp_login_req_t *request, void(*log_handler)());
EXPORT openotp_login_req_t *openotp_login_req_new(void);
EXPORT void openotp_login_req_free(openotp_login_req_t *request);

EXPORT openotp_challenge_rep_t *openotp_challenge(openotp_challenge_req_t *request, void(*log_handler)());
EXPORT openotp_challenge_req_t *openotp_challenge_req_new(void);
EXPORT void openotp_challenge_req_free(openotp_challenge_req_t *request);
EXPORT void openotp_challenge_rep_free(openotp_challenge_rep_t *response);

EXPORT openotp_status_rep_t *openotp_status(void(*log_handler)());
EXPORT void openotp_status_rep_free(openotp_status_rep_t *response); 

#ifdef __cplusplus
}
#endif

#endif
