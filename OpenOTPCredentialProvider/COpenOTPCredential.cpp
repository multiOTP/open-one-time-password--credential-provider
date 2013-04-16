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

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "COpenOTPCredential.h"
#include "guid.h"

// COpenOTPCredential ////////////////////////////////////////////////////////

COpenOTPCredential::COpenOTPCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL),
	_openotp_is_challenge_request(false),
	_user_name(NULL),
	_domain_name(NULL)
{
    DllAddRef();

    ZERO(_rgCredProvFieldDescriptors);
    ZERO(_rgFieldStatePairs);
    ZERO(_rgFieldStrings);

	ZERO(_openotp_server_url);
	ZERO(_openotp_cert_file);
	ZERO(_openotp_cert_password);
	ZERO(_openotp_ca_file);
	ZERO(_openotp_client_id);
	ZERO(_openotp_default_domain);
	ZERO(_openotp_user_settings);
	ZERO(_openotp_login_text);

	_openotp_login_request = *openotp_login_req_new();

	_openotp_login_response.code    = 0;
	_openotp_login_response.timeout = 0;
	_openotp_login_response.data    = NULL;
	_openotp_login_response.message = NULL;
	_openotp_login_response.session = NULL;

	_openotp_challenge_response.code    = 0;
	_openotp_challenge_response.data    = NULL;
	_openotp_challenge_response.message = NULL;

	// Read OpenOTP config
	readRegistryValueString(CONF_SERVER_URL, sizeof(_openotp_server_url), _openotp_server_url);
	readRegistryValueString(CONF_CERT_FILE, sizeof(_openotp_cert_file), _openotp_cert_file);
	readRegistryValueString(CONF_CERT_PASSWORD, sizeof(_openotp_cert_password), _openotp_cert_password);
	readRegistryValueString(CONF_CA_FILE, sizeof(_openotp_ca_file), _openotp_ca_file);
	readRegistryValueString(CONF_CLIENT_ID, sizeof(_openotp_client_id), _openotp_client_id);	
	readRegistryValueString(CONF_DEFAULT_DOMAIN, sizeof(_openotp_default_domain), _openotp_default_domain);
	readRegistryValueString(CONF_USER_SETTINGS, sizeof(_openotp_user_settings), _openotp_user_settings);

	//readRegistryValueString(CONF_LOGIN_TEXT, sizeof(_openotp_login_text), _openotp_login_text);
	if (readRegistryValueString(CONF_LOGIN_TEXT, sizeof(_openotp_login_text), _openotp_login_text) <= 2) // 2 = size of a wchar_t NULL-terminator in byte
		strcpy_s(_openotp_login_text, sizeof(_openotp_login_text), OPENOTP_DEFAULT_LOGIN_TEXT);

	readRegistryValueInteger(CONF_SOAP_TIMEOUT, &_openotp_soap_timeout);
	// END Read OpenOTP config
}

COpenOTPCredential::~COpenOTPCredential()
{
	if (_rgFieldStrings[SFI_OTP_USERNAME])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenUsername = lstrlen(_rgFieldStrings[SFI_OTP_USERNAME]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_USERNAME], lenUsername * sizeof(*_rgFieldStrings[SFI_OTP_USERNAME]));
    }
    if (_rgFieldStrings[SFI_OTP_LDAP_PASS])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS]));
    }
	if (_rgFieldStrings[SFI_OTP_PASS])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_PASS]));
    }
	if (_rgFieldStrings[SFI_OTP_CHALLENGE])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_CHALLENGE]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_CHALLENGE], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_CHALLENGE]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

	/// Make sure _openotp-runtime is clean
	ZERO(_openotp_server_url);
	ZERO(_openotp_cert_file);
	ZERO(_openotp_ca_file);
	ZERO(_openotp_client_id);
	ZERO(_openotp_default_domain);
	ZERO(_openotp_user_settings);
	ZERO(_openotp_login_text);

	SecureZeroMemory(_openotp_cert_password, sizeof(_openotp_cert_password));

	_ClearOpenOTPLoginReqRep(&_openotp_login_request, &_openotp_login_response);
	_ClearOpenOTPChallengeReqRep(NULL, &_openotp_challenge_response);

	// DISABLE OPENOTP IN EVERY CASE
	_openotp_is_challenge_request = false;
	openotp_terminate(NULL);
	///
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT COpenOTPCredential::Initialize(
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, 
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    __in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name
    )
{
    HRESULT hr = S_OK;

	_cpus = cpus;

	if (user_name)
		_user_name = user_name;

	if (domain_name)
		_domain_name = domain_name;

    // Copy the field descriptors for each field. This is useful if you want to vary the 
    // field descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String values of all the fields.
	if (SUCCEEDED(hr))
    {
		//if (_openotp_login_text[0] == NULL)
		//	hr = SHStrDupW(OPENOTP_DEFAULT_LOGIN_TEXT, &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
		//else
		//{
			wchar_t large_text[sizeof(_openotp_login_text)];

			int size = MultiByteToWideChar(CP_ACP, 0, _openotp_login_text, -1, large_text, 0);
			MultiByteToWideChar(CP_ACP, 0, _openotp_login_text, -1, large_text, size);

			hr = SHStrDupW(large_text, &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
		//}

		//hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
    {
		if (_cpus == CPUS_UNLOCK_WORKSTATION)
			hr = SHStrDupW(WORKSTATION_LOCKED, &_rgFieldStrings[SFI_OTP_SMALL_TEXT]);
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_SMALL_TEXT]);
	}
    if (SUCCEEDED(hr))
    {
		if (_cpus == CPUS_UNLOCK_WORKSTATION && _user_name)
		{
			hr = SHStrDupW(_user_name, &_rgFieldStrings[SFI_OTP_USERNAME]);
		}
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_PASS]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_CHALLENGE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_OTP_SUBMIT_BUTTON]);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT COpenOTPCredential::Advise(
    __in ICredentialProviderCredentialEvents* pcpce
    )
{
    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT COpenOTPCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT COpenOTPCredential::SetSelected(__out BOOL* pbAutoLogon)  
{
    *pbAutoLogon = FALSE;  

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT COpenOTPCredential::SetDeselected()
{
    HRESULT hr = S_OK;
	if (_cpus != CPUS_UNLOCK_WORKSTATION && _rgFieldStrings[SFI_OTP_USERNAME])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_USERNAME]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_USERNAME], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_USERNAME]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_USERNAME]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_USERNAME]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_USERNAME, _rgFieldStrings[SFI_OTP_USERNAME]);
        }
    }
	if (_rgFieldStrings[SFI_OTP_LDAP_PASS])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS, _rgFieldStrings[SFI_OTP_LDAP_PASS]);
        }
    }
    if (_rgFieldStrings[SFI_OTP_PASS])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_PASS]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_PASS]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_PASS]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_PASS, _rgFieldStrings[SFI_OTP_PASS]);
        }
    }
	if (_rgFieldStrings[SFI_OTP_CHALLENGE])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_CHALLENGE]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_CHALLENGE], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_CHALLENGE]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_CHALLENGE]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_CHALLENGE]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_CHALLENGE, _rgFieldStrings[SFI_OTP_CHALLENGE]);
        }
    }

	if (_cpus == CPUS_UNLOCK_WORKSTATION)
		_SetFieldScenario(SCENARIO_UNLOCK_BASE);
	else
	{
		_SetFieldScenario(SCENARIO_LOGON_BASE);
	}

	// DISABLE OPENOTP IN EVERY CASE
	_openotp_is_challenge_request = false;
	openotp_terminate(NULL);

    return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT COpenOTPCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;

    // Validate paramters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT COpenOTPCredential::GetStringValue(
    __in DWORD dwFieldID, 
    __deref_out PWSTR* ppwsz
    )
{
    HRESULT hr;

    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Gets the image to show in the user tile.
HRESULT COpenOTPCredential::GetBitmapValue(
    __in DWORD dwFieldID, 
    __out HBITMAP* phbmp
    )
{
    HRESULT hr;
    if ((SFI_OTP_LOGO == dwFieldID) && phbmp)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != NULL)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT COpenOTPCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo
    )
{
    HRESULT hr;

    // Validate parameters.
    if ((SFI_OTP_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
        *pdwAdjacentTo = SFI_OTP_PASS;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT COpenOTPCredential::SetStringValue(
    __in DWORD dwFieldID, 
    __in PCWSTR pwz      
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT COpenOTPCredential::GetCheckboxValue(
    __in DWORD dwFieldID, 
    __out BOOL* pbChecked,
    __deref_out PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT COpenOTPCredential::GetComboBoxValueCount(
    __in DWORD dwFieldID, 
    __out DWORD* pcItems, 
    __out_range(<,*pcItems) DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT COpenOTPCredential::GetComboBoxValueAt(
    __in DWORD dwFieldID, 
    __in DWORD dwItem,
    __deref_out PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT COpenOTPCredential::SetCheckboxValue(
    __in DWORD dwFieldID, 
    __in BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT COpenOTPCredential::SetComboBoxSelectedValue(
    __in DWORD dwFieldId,
    __in DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT COpenOTPCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT COpenOTPCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
	UNREFERENCED_PARAMETER(pcpcs);
    //UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    //UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	HRESULT hrOpenOtp, hr = E_FAIL;
	BOOL error = false;

	INIT_ZERO_WCHAR(username, 64);
	INIT_ZERO_WCHAR(domain, 64);

	_SeparateUserAndDomainName(_rgFieldStrings[SFI_OTP_USERNAME], username, sizeof(username), domain, sizeof(domain));

	// Set domain name:
	if (domain[0])
		// ... user typed DOMAIN\USERNAME, so we set it to DOMAIN
		_domain_name = _wcsdup(domain);
	else
	{
		if ((!_domain_name || !_domain_name[0]) && _openotp_default_domain && _openotp_default_domain[0])
		{
			// ... _domain_name is not set (logon scenario is most likely NOT unlock) and a default domain exists, so we set it to the default openotp domain

			// TODO: Preset arguments using a macro (even for the vice versa function) and NOT using a function
			int size = MultiByteToWideChar(CP_ACP, 0, _openotp_default_domain, -1, domain, 0);
			MultiByteToWideChar(CP_ACP, 0, _openotp_default_domain, -1, domain, size);

			_domain_name = _wcsdup(domain);
		}

		// ... _domain_name already set or no default domain, nothing to do
	}

	/* DEBUG:
	wcscpy_s(domain, sizeof(domain), L"DEMOS");
	_domain_name = _wcsdup(domain);
	//*/

	if (!_openotp_is_challenge_request)
	{   
		//hrOpenOtp = _OpenOTPCheck(username, domain, _rgFieldStrings[SFI_OTP_LDAP_PASS], _rgFieldStrings[SFI_OTP_PASS]);
		hrOpenOtp = _OpenOTPCheck(username, _domain_name, _rgFieldStrings[SFI_OTP_LDAP_PASS], _rgFieldStrings[SFI_OTP_PASS]);
	}
	else
		hrOpenOtp = _OpenOTPChallenge(_rgFieldStrings[SFI_OTP_CHALLENGE]);

	if (SUCCEEDED(hrOpenOtp)) 
	{
		hr = _DoKerberosLogon(pcpgsr, pcpcs, username, _rgFieldStrings[SFI_OTP_LDAP_PASS]);		
		goto CleanUpAndReturn;
	}

	if (!_openotp_is_challenge_request) 
	{
		if (hrOpenOtp == OOTP_CHALLENGE)
		{
			//**/SHStrDupW(L"Your one-time password was sent to you, please enter it on the next screen.", ppwszOptionalStatusText);
			*pcpsiOptionalStatusIcon = CPSI_NONE;
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

			_openotp_is_challenge_request = true;

			wchar_t large_text[100], small_text[100];
			MultiByteToWideChar(CP_ACP, 0, _openotp_login_response.message, -1, large_text, sizeof(large_text) / sizeof(large_text[0]));

			swprintf_s(small_text, sizeof(small_text), OPENOTP_TIMEOUT_TEXT, _openotp_login_response.timeout);

			if (_cpus == CPUS_UNLOCK_WORKSTATION)
				_SetFieldScenario(SCENARIO_UNLOCK_CHALLENGE, large_text, small_text);
			else
			{
				_SetFieldScenario(SCENARIO_LOGON_CHALLENGE, large_text, small_text);
			}
		}
		else
		{
			if (_pCredProvCredentialEvents)
			{
				//wchar_t *large_text = NULL;
				//if (_openotp_login_response.message) 
				//{
				//	int size = MultiByteToWideChar(CP_ACP, 0, _openotp_login_response.message, -1, large_text, 0);
				//	MultiByteToWideChar(CP_ACP, 0, _openotp_login_response.message, -1, large_text, size);
				//}

				// TODO: Show default fail message if .message is NULL

				if (_cpus == CPUS_UNLOCK_WORKSTATION)
					_SetFieldScenario(SCENARIO_UNLOCK_BASE/*, large_text, NULL*/);
				else
				{
					_SetFieldScenario(SCENARIO_LOGON_BASE/*, large_text, NULL*/);
					_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_USERNAME, L"");
				}

				_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS,	   L"");
				_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_PASS,         L"");
				_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_CHALLENGE,    L"");
			}

			//**/SHStrDupW(I18N_RESYNC_FAILED, ppwszOptionalStatusText);
			if (_openotp_login_response.message)
			{
				wchar_t error_msg[100];
				MultiByteToWideChar(CP_ACP, 0, _openotp_login_response.message, -1, error_msg, sizeof(error_msg) / sizeof(error_msg[0]));

				SHStrDupW(error_msg, ppwszOptionalStatusText);
			}
			else
			{
				SHStrDupW(L"An error occured.", ppwszOptionalStatusText);
			}
			*pcpsiOptionalStatusIcon = CPSI_ERROR;
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;

			error = true; 
			//_ClearOpenOTPLoginReqRep(&_openotp_login_request, &_openotp_login_response);
		}
	}
	else 
	{
		if (_pCredProvCredentialEvents)
		{
			wchar_t *large_text = NULL;
			if (_openotp_challenge_response.message) 
			{
				int size = MultiByteToWideChar(CP_ACP, 0, _openotp_challenge_response.message, -1, large_text, 0);
				MultiByteToWideChar(CP_ACP, 0, _openotp_challenge_response.message, -1, large_text, size);
			}

			if (_cpus == CPUS_UNLOCK_WORKSTATION)
				_SetFieldScenario(SCENARIO_UNLOCK_BASE/*, large_text, NULL*/);
			else
			{
				_SetFieldScenario(SCENARIO_LOGON_BASE/*, large_text, NULL*/);
				_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_USERNAME,  L"");
			}
			
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS,		L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_PASS,			L"");
			_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_CHALLENGE,     L"");
		}

		_openotp_is_challenge_request = false;

		//**/SHStrDupW(I18N_RESYNC_FAILED, ppwszOptionalStatusText);
		if (_openotp_challenge_response.message)
		{
			wchar_t error_msg[100];
			MultiByteToWideChar(CP_ACP, 0, _openotp_challenge_response.message, -1, error_msg, sizeof(error_msg) / sizeof(error_msg[0]));

			SHStrDupW(error_msg, ppwszOptionalStatusText);
		}
		else
		{
			SHStrDupW(L"An error occured.", ppwszOptionalStatusText);
		}
		*pcpsiOptionalStatusIcon = CPSI_ERROR;
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

		error = true;
		//_ClearOpenOTPLoginReqRep(&_openotp_login_request, &_openotp_login_response);
		//_ClearOpenOTPChallengeReqRep(NULL, &_openotp_challenge_response);
	}

CleanUpAndReturn:
	ZERO(username);
	ZERO(domain);

	if (error)
	{
		_ClearOpenOTPLoginReqRep(&_openotp_login_request, &_openotp_login_response);
		_ClearOpenOTPChallengeReqRep(NULL, &_openotp_challenge_response);
	}

    //return hr;
	return S_OK;
}

HRESULT COpenOTPCredential::_DoKerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in PWSTR username,
	__in PWSTR password
	)
{
	HRESULT hr;

	WCHAR wsz[sizeof(_openotp_default_domain)];
    DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (_domain_name && _domain_name[0])
		wcscpy_s(wsz, ARRAYSIZE(wsz), _domain_name);
	else
		bGetCompName = GetComputerNameW(wsz, &cch);

    if ((_domain_name && _domain_name[0]) || bGetCompName)
    {
        PWSTR pwzProtectedPassword;

        hr = ProtectIfNecessaryAndCopyPassword(password, _cpus, &pwzProtectedPassword);

        if (SUCCEEDED(hr))
        {
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;

            // Initialize kiul with weak references to our credential.
            hr = KerbInteractiveUnlockLogonInit(wsz, username, pwzProtectedPassword, _cpus, &kiul);

            if (SUCCEEDED(hr))
            {
                // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                // as necessary.
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
 
                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the 
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
            }

            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
    }

	return hr;
}

int COpenOTPCredential::_GetFirstActiveIPAddress(
	__out_opt char *ip_addr
	)
{
	const int MAX_IP_LENGTH = 16; // Maximum length including trailing zero
	WSAData wsaData;

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        return 1;
    }

	char hostname[80];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        return 2;
    }

	struct hostent *phe = gethostbyname(hostname);

    if (phe == 0) {
        return 3;
    }

    //for (int i = 0; phe->h_addr_list[i] != 0; i++) {
	if (phe->h_addr_list[0] != 0)
	{
        struct in_addr addr;
        memcpy(&addr, phe->h_addr_list[0/*i*/], sizeof(struct in_addr));

		//ip_addr = _strdup(inet_ntoa(addr));
		strcpy_s(ip_addr, MAX_IP_LENGTH, inet_ntoa(addr));
    }

	return 0;
}

HRESULT COpenOTPCredential::_OpenOTPCheck(
	__deref_in PWSTR user,
	__deref_in PWSTR domain,
	__deref_in PWSTR ldapPass, 
	__deref_in PWSTR otpPass
	)
{
	const int MAX_IP_LENGTH = 16;

	HRESULT hr = E_FAIL;

	openotp_login_rep_t *lrep = NULL;
	openotp_login_req_t *lreq = NULL;

	INIT_ZERO_CHAR(c_user, 64);
	INIT_ZERO_CHAR(c_domain, 64);
	INIT_ZERO_CHAR(c_ldapPass, 64);
	INIT_ZERO_CHAR(c_otpPass, 64);
	INIT_ZERO_CHAR(c_ip_addr, MAX_IP_LENGTH);

	//// INITIALIZE OPENOTP
	if (!openotp_initialize(
		(_openotp_server_url[0]    == NULL) ? NULL : _openotp_server_url, 
		(_openotp_cert_file[0]     == NULL) ? NULL : _openotp_cert_file, 
		(_openotp_cert_password[0] == NULL) ? NULL : _openotp_cert_password, 
		(_openotp_ca_file[0]       == NULL) ? NULL : _openotp_ca_file, 
		_openotp_soap_timeout, 
		NULL)) goto CleanUpAndReturn;

	_WideCharToChar(user, sizeof(c_user), c_user);
	_WideCharToChar(domain, sizeof(c_domain), c_domain);
	_WideCharToChar(ldapPass, sizeof(c_ldapPass), c_ldapPass);
	_WideCharToChar(otpPass, sizeof(c_ldapPass), c_otpPass);

	//// FORM REQUEST
	_GetFirstActiveIPAddress(c_ip_addr);

	lreq = openotp_login_req_new();
	lreq->username		= _strdup(c_user);
	lreq->ldapPassword	= _strdup(c_ldapPass);
	lreq->otpPassword	= _strdup(c_otpPass);

	lreq->client	= _strdup(_openotp_client_id);
	lreq->domain	= (c_domain[0]!=NULL) ? _strdup(c_domain) : _strdup(_openotp_default_domain);
	lreq->settings	= _strdup(_openotp_user_settings);

	lreq->source    = _strdup(c_ip_addr);

	//// SEND REQUEST
	lrep = openotp_login(lreq, NULL);

	//// CHECK RESPONSE
	if (!lrep)
		goto CleanUpAndReturn;

	//// SAVING RESPONSE AND REQUEST FOR LATER REUSE
	_openotp_login_request.client       = _strdup(lreq->client);
	_openotp_login_request.domain       = _strdup(lreq->domain);
	_openotp_login_request.ldapPassword = _strdup(lreq->ldapPassword);
	_openotp_login_request.otpPassword  = _strdup(lreq->otpPassword);
	_openotp_login_request.settings     = _strdup(lreq->settings);	
	_openotp_login_request.username     = _strdup(lreq->username);
	_openotp_login_request.source		= _strdup(lreq->source);

	_openotp_login_response.code		= lrep->code;
	_openotp_login_response.timeout		= lrep->timeout;
	_openotp_login_response.data		= _strdup(lrep->data);
	_openotp_login_response.message		= _strdup(lrep->message);
	_openotp_login_response.session		= _strdup(lrep->session);

	if (lrep->code == OPENOTP_FAILURE)
		goto CleanUpAndReturn;

	if (lrep->code == OPENOTP_CHALLENGE) {
		hr = OOTP_CHALLENGE;
		goto CleanUpAndReturn;
	}

	// lrep->code == OPENOTP_SUCCESS
	hr = S_OK;

CleanUpAndReturn:
	ZERO(c_user);
	ZERO(c_domain);
	ZERO(c_ldapPass);
	ZERO(c_otpPass);
	ZERO(c_ip_addr);

	_ClearOpenOTPLoginReqRep(lreq, lrep);
	openotp_terminate(NULL);

	return hr;
}

HRESULT COpenOTPCredential::_OpenOTPChallenge(
	__deref_in PWSTR challenge
	)
{
	HRESULT hr = E_FAIL;

	openotp_challenge_rep_t *crep = NULL;
	openotp_challenge_req_t *creq = NULL;

	INIT_ZERO_CHAR(c_challenge, 64);

	//// INITIALIZE OPENOTP
	if (!openotp_initialize(
		(_openotp_server_url[0]    == NULL) ? NULL : _openotp_server_url, 
		(_openotp_cert_file[0]     == NULL) ? NULL : _openotp_cert_file, 
		(_openotp_cert_password[0] == NULL) ? NULL : _openotp_cert_password, 
		(_openotp_ca_file[0]       == NULL) ? NULL : _openotp_ca_file, 
		_openotp_soap_timeout, 
		NULL)) goto CleanUpAndReturn;

	_WideCharToChar(challenge, sizeof(c_challenge), c_challenge);

	//// FORM REQUEST
	creq = openotp_challenge_req_new();
    creq->otpPassword = _strdup(c_challenge);

	creq->session  = _strdup(_openotp_login_response.session);
	creq->username = _strdup(_openotp_login_request.username);
	if (_openotp_login_request.domain) creq->domain = _strdup(_openotp_login_request.domain);
	//if (_openotp_login_request.client) creq->client = _strdup(_openotp_login_request.client);

	//// SEND REQUEST
	crep = openotp_challenge(creq, NULL);

	//// CHECK RESPONSE
	if (!crep) goto CleanUpAndReturn;

	//// SAVING RESPONSE FOR LATER REUSE
	_openotp_challenge_response.code    = crep->code;
	_openotp_challenge_response.data	= _strdup(crep->data);
	_openotp_challenge_response.message	= _strdup(crep->message);

	if (crep->code == OPENOTP_FAILURE)
		goto CleanUpAndReturn;

	if (crep->code == OPENOTP_SUCCESS)
		hr = S_OK;

CleanUpAndReturn:
	//openotp_challenge_req_free(creq);
	//openotp_challenge_rep_free(crep);
	ZERO(c_challenge);

	_ClearOpenOTPChallengeReqRep(creq, crep);	
	openotp_terminate(NULL);

	return hr;
}

void COpenOTPCredential::_SeparateUserAndDomainName(
	__in wchar_t *domain_slash_username,
	__out wchar_t *username,
	__in int sizeUsername,
	__out_opt wchar_t *domain,
	__in_opt int sizeDomain
	)
{
	int pos;
	for(pos=0;domain_slash_username[pos]!=L'\\' && domain_slash_username[pos]!=NULL;pos++);

	if (domain_slash_username[pos]!=NULL)
	{
		int i;
		for (i=0;i<pos && i<sizeDomain;i++)
			domain[i] = domain_slash_username[i];
		domain[i]=L'\0';

		for (i=0;domain_slash_username[pos+i+1]!=NULL && i<sizeUsername;i++)
			username[i] = domain_slash_username[pos+i+1];
		username[i]=L'\0';
	}
	else
	{
		int i;
		for (i=0;i<pos && i<sizeUsername;i++)
			username[i] = domain_slash_username[i];
		username[i]=L'\0';
	}
}

void COpenOTPCredential::_ClearOpenOTPChallengeReqRep(
		__out_opt openotp_challenge_req_t *creq,
		__out_opt openotp_challenge_rep_t *crep
		)
{
	if (creq)
	{
		/*
		if (creq->client)
			for(int i=0;creq->client[i]!=NULL;i++)
				creq->client[i] = NULL;
		*/
		if (creq->domain)
			for(int i=0;creq->domain[i]!=NULL;i++)
				creq->domain[i] = NULL;
		if (creq->otpPassword)
			for(int i=0;creq->otpPassword[i]!=NULL;i++)
				creq->otpPassword[i] = NULL;
		if (creq->session)
			for(int i=0;creq->session[i]!=NULL;i++)
				creq->session[i] = NULL;
		if (creq->username)
			for(int i=0;creq->username[i]!=NULL;i++)
				creq->username[i] = NULL;
	}

	if (crep)
	{
		crep->code = 0;
		if (crep->data)
			for(int i=0;crep->data[i]!=NULL;i++)
				crep->data[i] = NULL;
		if (crep->message)
			for(int i=0;crep->message[i]!=NULL;i++)
				crep->message[i] = NULL;
	}
}

void COpenOTPCredential::_ClearOpenOTPLoginReqRep(
		__out_opt openotp_login_req_t *lreq,
		__out_opt openotp_login_rep_t *lrep
		)
{
	if (lreq)
	{
		if (lreq->client)
			for(int i=0;lreq->client[i]!=NULL;i++)
				lreq->client[i] = NULL;
		if (lreq->domain)
			for(int i=0;lreq->domain[i]!=NULL;i++)
				lreq->domain[i] = NULL;
		if (lreq->ldapPassword)
			for(int i=0;lreq->ldapPassword[i]!=NULL;i++)
				lreq->ldapPassword[i] = NULL;
		if (lreq->otpPassword)
			for(int i=0;lreq->otpPassword[i]!=NULL;i++)
				lreq->otpPassword[i] = NULL;
		if (lreq->settings)
			for(int i=0;lreq->settings[i]!=NULL;i++)
				lreq->settings[i] = NULL;
		if (lreq->source)
			for(int i=0;lreq->source[i]!=NULL;i++)
				lreq->source[i] = NULL;
		if (lreq->username)
			for(int i=0;lreq->username[i]!=NULL;i++)
				lreq->username[i] = NULL;
	}

	if (lrep)
	{
		lrep->code = 0;
		lrep->timeout = 0;
		if (lrep->data)
			for(int i=0;lrep->data[i]!=NULL;i++)
				lrep->data[i] = NULL;
		if (lrep->message)
			for(int i=0;lrep->message[i]!=NULL;i++)
				lrep->message[i] = NULL;
		if (lrep->session)
			for(int i=0;lrep->session[i]!=NULL;i++)
				lrep->session[i] = NULL;
	}
}

void COpenOTPCredential::_SetFieldScenario(
	__in FIELD_SCENARIO scenario
	)
{
	_SetFieldScenario(scenario, NULL, NULL);
}

void COpenOTPCredential::_SetFieldScenario(
	__in FIELD_SCENARIO scenario,
	__in_opt PWSTR large_text,
	__in_opt PWSTR small_text
	)
{
	switch (scenario)
	{
	case SCENARIO_LOGON_BASE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,	CPFIS_FOCUSED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_CHALLENGE,	CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,	CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,	CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,		CPFS_DISPLAY_IN_SELECTED_TILE);	
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_CHALLENGE,	CPFS_HIDDEN);
		break;

	case SCENARIO_UNLOCK_BASE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,	CPFIS_FOCUSED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_CHALLENGE,	CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_DISPLAY_IN_BOTH);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,	CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,		CPFS_DISPLAY_IN_SELECTED_TILE);	
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_CHALLENGE,	CPFS_HIDDEN);
		break;

	case SCENARIO_LOGON_CHALLENGE:
	case SCENARIO_UNLOCK_CHALLENGE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_CHALLENGE,	CPFIS_FOCUSED);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,		CPFS_HIDDEN);	
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_CHALLENGE,	CPFS_DISPLAY_IN_SELECTED_TILE);
		break;

	case SCENARIO_NO_CHANGE:
	default:
		break;
	}

	if (large_text)
		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LARGE_TEXT, large_text);
	else
	{
		wchar_t text[sizeof(_openotp_login_text)];

		int size = MultiByteToWideChar(CP_ACP, 0, _openotp_login_text, -1, text, 0);
		MultiByteToWideChar(CP_ACP, 0, _openotp_login_text, -1, text, size);

		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LARGE_TEXT, text);
	}

	if (small_text)
	{
		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, small_text);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
	}
	else
	{		
		 if (_cpus == CPUS_UNLOCK_WORKSTATION)
			 _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, WORKSTATION_LOCKED);
		 else
		 {
			 _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, L"");

			_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_HIDDEN);
		 }
	}
}

void COpenOTPCredential::_WideCharToChar(
	__in PWSTR data,
	__in int buffSize,
	__out char *pc
	)
{
	WideCharToMultiByte(
		CP_ACP,
		0,
		data,
		-1,
		pc,
		buffSize, 
		NULL,
		NULL);
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT COpenOTPCredential::ReportResult(
    __in NTSTATUS ntsStatus, 
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
	UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
	return E_NOTIMPL;
}

