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

#include <credentialprovider.h>
#include "COpenOTPProvider.h"
//#include "COpenOTPCredential.h"
#include "guid.h"

// COpenOTPProvider ////////////////////////////////////////////////////////

COpenOTPProvider::COpenOTPProvider():
    _cRef(1),
    _pkiulSetSerialization(NULL),
    //_dwNumCreds(0),
    _bAutoSubmitSetSerializationCred(false),
    _dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT)
{
    DllAddRef();

    ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));
}

COpenOTPProvider::~COpenOTPProvider()
{
	/*
    for (size_t i = 0; i < _dwNumCreds; i++)
    {
        if (_rgpCredentials[i] != NULL)
        {
            _rgpCredentials[i]->Release();
        }
    }
	*/

	if (_rgpCredentials[0] != NULL)
    {
        _rgpCredentials[0]->Release();
    }

    DllRelease();
}

void COpenOTPProvider::_CleanupSetSerialization()
{
    if (_pkiulSetSerialization)
    {
        KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
        SecureZeroMemory(_pkiulSetSerialization,
                         sizeof(*_pkiulSetSerialization) +
                         pkil->LogonDomainName.MaximumLength +
                         pkil->UserName.MaximumLength +
                         pkil->Password.MaximumLength);
        HeapFree(GetProcessHeap(),0, _pkiulSetSerialization);
    }
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.  
//
// This sample only handles the logon and unlock scenarios as those are the most common.
HRESULT COpenOTPProvider::SetUsageScenario(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in DWORD dwFlags
    )
{
    UNREFERENCED_PARAMETER(dwFlags);
    HRESULT hr;

    static bool s_bCredsEnumeratedLogon  = false;
	static bool s_bCredsEnumeratedUnlock = false;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
		if (!s_bCredsEnumeratedLogon)
        {
			_cpus = cpus;

			hr = this->_EnumerateCredentials(NULL, NULL);

			s_bCredsEnumeratedLogon  = true;
			s_bCredsEnumeratedUnlock = false;
		}
		else
			hr = S_OK;
		break;

	case CPUS_UNLOCK_WORKSTATION:
        if (!s_bCredsEnumeratedUnlock)
        {
			_cpus = cpus;

			PWSTR szUserName = NULL;
			PWSTR szDomainName = NULL;
			DWORD dwLen;

			if ( ! WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
						WTS_CURRENT_SESSION,
						WTSUserName,
						&szUserName,
						&dwLen)) szUserName = NULL;

			if ( ! WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
						WTS_CURRENT_SESSION,
						WTSDomainName,
						&szDomainName,
						&dwLen)) szDomainName = NULL;

			hr = this->_EnumerateCredentials(szUserName, szDomainName);     

            s_bCredsEnumeratedUnlock = true;
			s_bCredsEnumeratedLogon  = false;
        }
        else
            hr = S_OK;
        break;

    case CPUS_CREDUI:
    case CPUS_CHANGE_PASSWORD:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a credential.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// Since this sample doesn't support CPUS_CREDUI, we have not implemented the credui specific
// pieces of this function.  For information on that, please see the credUI sample.
HRESULT COpenOTPProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
	UNREFERENCED_PARAMETER(pcpcs);
	return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated
HRESULT COpenOTPProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    __in UINT_PTR upAdviseContext
    )
{
    UNREFERENCED_PARAMETER(pcpe);
    UNREFERENCED_PARAMETER(upAdviseContext);

    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT COpenOTPProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired 
// using the field descriptors.
HRESULT COpenOTPProvider::GetFieldDescriptorCount(
    __out DWORD* pdwCount
    )
{
    *pdwCount = SFI_NUM_FIELDS;

    return S_OK;
}

// Gets the field descriptor for a particular field
HRESULT COpenOTPProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex, 
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{    
    HRESULT hr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    { 
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
//
// The default tile is the tile which will be shown in the zoomed view by default. If 
// more than one provider specifies a default tile the behavior is the last used cred
// prov gets to specify the default tile to be displayed
//
// If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call GetSerialization
// on the credential you've specified as the default and will submit that credential
// for authentication without showing any further UI.
HRESULT COpenOTPProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out_range(<,*pdwCount) DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault
    )
{
    HRESULT hr = S_OK;
    
    *pdwCount = 1; //_dwNumCreds;
	*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    return hr;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT COpenOTPProvider::GetCredentialAt(
    __in DWORD dwIndex, 
    __deref_out ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr;

    // Validate parameters.
    //if((dwIndex < _dwNumCreds) && ppcpc)
	if((dwIndex == 0) && ppcpc)
    {
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }
        
    return hr;
}

// Sets up all the credentials for this provider. Since we always show the same tiles, 
// we just set it up once.
HRESULT COpenOTPProvider::_EnumerateCredentials(
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name
	)
{
	HRESULT hr;

    // Allocate memory for the new credential.
    COpenOTPCredential* ppc = new COpenOTPCredential();

	if (ppc)
    {
        // Set the Field State Pair and Field Descriptors for ppc's fields
        // to the defaults (s_rgCredProvFieldDescriptors, and s_rgFieldStatePairs).
		if (_cpus == CPUS_UNLOCK_WORKSTATION)
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsUnlock, user_name, domain_name);
		else
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, user_name, domain_name);
        
        if (SUCCEEDED(hr))
        {
            _rgpCredentials[0] = ppc;
            //_dwNumCreds++;
        }
        else
        {
            // Release the pointer to account for the local reference.
            ppc->Release();
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

	return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;

    COpenOTPProvider* pProvider = new COpenOTPProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

// This enumerates a tile for the info in _pkiulSetSerialization.  See the SetSerialization function comment for
// more information.
HRESULT COpenOTPProvider::_EnumerateSetSerialization()
{
	return E_NOTIMPL;
}

