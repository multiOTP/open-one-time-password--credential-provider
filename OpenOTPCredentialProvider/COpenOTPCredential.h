/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
** 
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
** 
**        http://www.apache.org/licenses/LICENSE-2.0
** 
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#pragma once

#include <helpers.h>
#include "common.h"
#include "dll.h"
#include "resource.h"

#include <openotp.h>
#include "registry.h"

//#include "CMultiOneTimePassword.h"

#define OOTP_CHALLENGE	((HRESULT)0x88809001)
#define OOTP_FAILURE	((HRESULT)0x88809002)
#define OOTP_SUCCESS	((HRESULT)0x88809101)

#define OPENOTP_DEFAULT_LOGIN_TEXT "OpenOTP Login"
#define OPENOTP_TIMEOUT_TEXT L"Timeout: %i secs."
#define WORKSTATION_LOCKED _user_name

enum FIELD_SCENARIO
{
	SCENARIO_NO_CHANGE			= 0,
	SCENARIO_LOGON_BASE			= 1,
	SCENARIO_UNLOCK_BASE		= 2,
	SCENARIO_LOGON_CHALLENGE	= 3,	
	SCENARIO_UNLOCK_CHALLENGE	= 4,
};

class COpenOTPCredential : public ICredentialProviderCredential
{
    public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }
    
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(COpenOTPCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(__in DWORD dwFieldID,
                                 __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(<,*pcItems) DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
                                    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
                                    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
                                    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(__in NTSTATUS ntsStatus, 
                                __in NTSTATUS ntsSubstatus,
                                __deref_out_opt PWSTR* ppwszOptionalStatusText, 
                                __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

  public:
    HRESULT Initialize(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
					   __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       __in const FIELD_STATE_PAIR* rgfsp,
					   __in_opt PWSTR user_name,
					   __in_opt PWSTR domain_name);

    COpenOTPCredential();

    virtual ~COpenOTPCredential();

  private:
	HRESULT COpenOTPCredential::_DoKerberosLogon(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__in PWSTR username,
		__in PWSTR password
		);

	void COpenOTPCredential::_SetFieldScenario(
		__in FIELD_SCENARIO scenario,
		__in_opt PWSTR large_text,
		__in_opt PWSTR small_text
		);

	void COpenOTPCredential::_SetFieldScenario(
		__in FIELD_SCENARIO scenario
		);

	void COpenOTPCredential::_ClearOpenOTPChallengeReqRep(
		__in openotp_challenge_req_t *creq,
		__in openotp_challenge_rep_t *crep
		);

	void COpenOTPCredential::_ClearOpenOTPLoginReqRep(
		__out_opt openotp_login_req_t *lreq,
		__out_opt openotp_login_rep_t *lrep
		);

	void COpenOTPCredential::_SeparateUserAndDomainName(
		__in wchar_t *domain_slash_username,
		__out wchar_t *username,
		__in int sizeUsername,
		__out_opt wchar_t *domain,
		__in_opt int sizeDomain
		);

	int COpenOTPCredential::_GetFirstActiveIPAddress(
		__deref_out_opt char *ip_addr
		);

  private:
    LONG                                  _cRef;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus; // The usage scenario for which we were enumerated.

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[SFI_NUM_FIELDS]; // An array holding the type and 
                                                                                       // name of each field in the tile.

    FIELD_STATE_PAIR                      _rgFieldStatePairs[SFI_NUM_FIELDS];          // An array holding the state of 
                                                                                       // each field in the tile.
    
    PWSTR                                 _rgFieldStrings[SFI_NUM_FIELDS];             // An array holding the string 
                                                                                       // value of each field. This is 
                                                                                       // different from the name of 
                                                                                       // the field held in 
                                                                                       // _rgCredProvFieldDescriptors.
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;

	// OpenOTP
	HRESULT COpenOTPCredential::_OpenOTPCheck(
		__deref_in PWSTR user, 
		__deref_in PWSTR domain, 
		__deref_in PWSTR ldapPass, 
		__deref_in PWSTR otpPass
	);

	HRESULT COpenOTPCredential::_OpenOTPChallenge(
		__deref_in PWSTR challenge
	);

	openotp_login_req_t					 _openotp_login_request;
	openotp_login_rep_t					 _openotp_login_response;

	bool								 _openotp_is_challenge_request;
	openotp_challenge_rep_t				 _openotp_challenge_response;	

	char								 _openotp_server_url[1024];
	char								 _openotp_cert_file[512];
	char								 _openotp_cert_password[64];
	char								 _openotp_ca_file[512];
	char								 _openotp_client_id[64];
	char								 _openotp_default_domain[64];
	char								 _openotp_user_settings[1024];
	char								 _openotp_login_text[64];

	int									 _openotp_soap_timeout;	

	// END OpenOTP

	void COpenOTPCredential::_WideCharToChar(
		__in PWSTR data,
		__in int buffSize,
		__out char *pc
	);

	PWSTR								 _user_name;
	PWSTR								 _domain_name;
};
