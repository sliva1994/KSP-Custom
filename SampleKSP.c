// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.

/*++

Abstract:
    Implementation of the sample CNG RSA key storage provider
--*/


///////////////////////////////////////////////////////////////////////////////
//
// Headers
//
///////////////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "../inc/SampleKSP.h"
#include "../inc/Logger.h"


///////////////////////////////////////////////////////////////////////////////
//
// Ncrypt key storage provider function table
//
///////////////////////////////////////////////////////////////////////////////
NCRYPT_KEY_STORAGE_FUNCTION_TABLE SampleKSPFunctionTable =
{
    SAMPLEKSP_INTERFACE_VERSION,
    SampleKSPOpenProvider,
    SampleKSPOpenKey,
    SampleKSPCreatePersistedKey,
    SampleKSPGetProviderProperty,
    SampleKSPGetKeyProperty,
    SampleKSPSetProviderProperty,
    SampleKSPSetKeyProperty,
    SampleKSPFinalizeKey,
    SampleKSPDeleteKey,
    SampleKSPFreeProvider,
    SampleKSPFreeKey,
    SampleKSPFreeBuffer,
    SampleKSPEncrypt,
    SampleKSPDecrypt,
    SampleKSPIsAlgSupported,
    SampleKSPEnumAlgorithms,
    SampleKSPEnumKeys,
    SampleKSPImportKey,
    SampleKSPExportKey,
    SampleKSPSignHash,
    SampleKSPVerifySignature,
    SampleKSPPromptUser,
    SampleKSPNotifyChangeKey,
    SampleKSPSecretAgreement,
    SampleKSPDeriveKey,
    SampleKSPFreeSecret
};

///////////////////////////////////////////////////////////////////////////////
//
// Variables
//
///////////////////////////////////////////////////////////////////////////////
HINSTANCE g_hInstance;
//List of keys/providers
LIST_ENTRY g_SampleKspEnumStateList;

///////////////////////////////////////////////////////////////////////////////
//
// Dll entry
//
///////////////////////////////////////////////////////////////////////////////

BOOL
WINAPI
DllMain(
    HMODULE hInstDLL,
    DWORD dwReason,
    LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(lpvReserved);
    g_hInstance = (HINSTANCE)hInstDLL;
    DebugPrint("Call function ");
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        InitializeListHead(&g_SampleKspEnumStateList);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        if (g_hRSAProvider)
        {
            BCryptCloseAlgorithmProvider(g_hRSAProvider, 0);
        }
    }
    return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION :     Get the sample KSP key storage Interface function
*                   dispatch table
*
* INPUTS :
*            LPCWSTR pszProviderName        Name of the provider (unused)
*            DWORD   dwFlags                Flags (unused)
* OUTPUTS :
*            char    **ppFunctionTable      The key storage interface function
*                                           dispatch table
* RETURN :
*            ERROR_SUCCESS                  The function was successful.
*/
NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    __in   DWORD dwFlags)
{
    DebugPrint("Call function ");
    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);

    *ppFunctionTable = &SampleKSPFunctionTable;

    return ERROR_SUCCESS;
}

/*******************************************************************
* Verify the signature
*/
BOOL VerifySign(
    __in_bcount(cbSignaturee) PBYTE pbSignature,
    __in    DWORD   cbSignaturee)
{
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT aCertContext = NULL;
    LPBYTE pbData = NULL;
    DWORD cbData = 0;
    DWORD dwKeySpec;
    PBYTE pbOutput = NULL;
    PBYTE   vHashData;
    DWORD   vHashDataSize;
    NTSTATUS status;
    BCRYPT_PKCS1_PADDING_INFO padding_PKCS1;
    padding_PKCS1.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    
    DebugPrint("Start VerifySign");
    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY");

    if (hMyCertStore == NULL)
    {
        DebugPrint("Call function -> hMyCertStore is NULL");
        return FALSE;
    }
    aCertContext = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        L"test01", // use appropriate subject name 
        NULL
    );
    if (aCertContext == NULL)
    {
        DebugPrint("Call function -> Error: aCertContext is NULL");
        return FALSE;
    }

    PCCERT_CONTEXT pcCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, aCertContext->pbCertEncoded, aCertContext->cbCertEncoded);
    if (!pcCertContext)
    {
        DebugPrint("ERROR: pcCertContext");
        return FALSE;
    }
    BCRYPT_KEY_HANDLE publicKeyHandle = NULL;
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pcCertContext->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &publicKeyHandle))
    {
        DebugPrint("CryptImportPublicKeyInfoEx2 failed");
        return FALSE;
    }
    pbOutput = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, aCertContext->cbCertEncoded);
    CopyMemory(pbOutput, aCertContext->pbCertEncoded, aCertContext->cbCertEncoded);

    if (!GetHashData((LPBYTE)pbOutput, aCertContext->cbCertEncoded, &vHashData, &vHashDataSize)) {
        DebugPrint("GetHashData failed.");
        return FALSE;
    }

    status = BCryptVerifySignature(publicKeyHandle, &padding_PKCS1, vHashData, vHashDataSize, pbSignature, cbSignaturee, BCRYPT_PAD_PKCS1);
    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptSignHash= %X", status);
        return FALSE;
    }
    DebugPrint("Verify Sign OK");
    return TRUE;
}

/*******************************************************************
* GetHashData
*/
BOOL GetHashData(PBYTE lpData, DWORD dwDataSize, PBYTE* lplpHashData, LPDWORD lpdwHashDataSize)
{
    BCRYPT_ALG_HANDLE  hAlg;
    BCRYPT_HASH_HANDLE hHash;
    DWORD              dwResult;
    DWORD              dwHashObjectSize;
    PBYTE             lpHashObject;
    NTSTATUS           status;

    DebugPrint("Call function ");
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptOpenAlgorithmProvider 0x%.8X\n", GetLastError());
        return FALSE;
    }
    DebugPrint("Call function ");
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHashObjectSize, sizeof(DWORD), &dwResult, 0);
    lpHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwHashObjectSize);
    status = BCryptCreateHash(hAlg, &hHash, lpHashObject, dwHashObjectSize, NULL, 0, 0);

    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptCreateHash 0x%.8X\n", GetLastError());
        DebugPrint("Error: status= %X\n", status);
        HeapFree(GetProcessHeap(), 0, lpHashObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    DebugPrint("Call function ");
    BCryptHashData(hHash, lpData, dwDataSize, 0);

    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)lpdwHashDataSize, sizeof(DWORD), &dwResult, 0);
    *lplpHashData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *lpdwHashDataSize);
    BCryptFinishHash(hHash, *lplpHashData, *lpdwHashDataSize, 0);

    HeapFree(GetProcessHeap(), 0, lpHashObject);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    DebugPrint("Call function ");
    return TRUE;
}


/*******************************************************************
* DESCRIPTION :     Load and initialize the Sample KSP provider
*
* INPUTS :
*            LPCWSTR pszProviderName         Name of the provider
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS :
*            NCRYPT_PROV_HANDLE *phProvider  The provider handle
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
SampleKSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE* phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    DWORD cbLength = 0;
    size_t cbProviderName = 0;
    UNREFERENCED_PARAMETER(dwFlags);

    DebugPrint("Call function ");
    // Validate input parameters.
    if (phProvider == NULL)
    {
        DebugPrint("Call function ");
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    if (pszProviderName == NULL)
    {
        DebugPrint("Call function ");
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //The size of the provider name should be limited.
    cbProviderName = (wcslen(pszProviderName) + 1) * sizeof(WCHAR);
    if (cbProviderName > MAXUSHORT)
    {
        DebugPrint("Call function ");
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Allocate memory for provider object.
    cbLength = sizeof(SAMPLEKSP_PROVIDER) + (DWORD)cbProviderName;
    pProvider = (SAMPLEKSP_PROVIDER*)HeapAlloc(GetProcessHeap(), 0, cbLength);;
    if (NULL == pProvider)
    {
        DebugPrint("Call function ");
        status = NTE_NO_MEMORY;
        goto cleanup;
    }
    DebugPrint("Call function ");
    //Assign values to fields of the provider handle.
    pProvider->cbLength = cbLength;
    pProvider->dwMagic = SAMPLEKSP_PROVIDER_MAGIC;
    pProvider->dwFlags = 0;
    pProvider->pszName = (LPWSTR)(pProvider + 1);
    CopyMemory(pProvider->pszName, pszProviderName, cbProviderName);
    pProvider->pszContext = NULL;
    //Assign the output value.
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    pProvider = NULL;
    status = ERROR_SUCCESS;
cleanup:
    if (pProvider)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pProvider);
    }
    DebugPrint("Call function ");
    return status;
}



/******************************************************************************
* DESCRIPTION :     Release a handle to the sample KSP provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*/
SECURITY_STATUS
WINAPI
SampleKSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
    DebugPrint("Call function ");
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    // Free context.
    if (pProvider->pszContext)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pProvider->pszContext);
        pProvider->pszContext = NULL;
    }
    DebugPrint("Call function ");
    ZeroMemory(pProvider, pProvider->cbLength);
    HeapFree(GetProcessHeap(), 0, pProvider);

    Status = ERROR_SUCCESS;
cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :     Open a key in the SAMPLE key storage provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszKeyName              Name of the key
             DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
SampleKSPOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE* phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;

    //
    // Validate input parameters.
    //
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);
    DebugPrint("Call function ");
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((phKey == NULL) || (pszKeyName == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    //Initialize the key object.
    Status = CreateNewKeyObject(pszKeyName, &pKey);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }

    DebugPrint("Call function - Start workround");

    //Start workround
    //The purpose to pass this funtion is to handle SampleKSPGetKeyProperty
    //To restore the original code switch #if 0 -> #if 1
#if 0
    //Get path to user's key file.
    Status = GetSampleKeyStorageArea(&pKey->pszKeyFilePath);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }
    DebugPrint("Call function -> pszKeyName: %ls", pszKeyName);
    //Read and validate key file header from the key file.
    Status = ReadKeyFile(pKey);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }

    //Parse key file.
    Status = ParseKeyFile(pKey);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }
#endif
    //End workround

    DebugPrint("Call function ");
    pKey->fFinished = TRUE;
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;
    DebugPrint("Call function ");
cleanup:

    if (pKey)
    {
        DebugPrint("Call function ");
        DeleteKeyObject(pKey);
    }

    return Status;
}


/******************************************************************************
* DESCRIPTION :     Create a new key and stored it into the user profile
*                   key storage area
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszAlgId                Cryptographic algorithm to create the key
*            LPCWSTR pszKeyName              Name of the key
*            DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 0|NCRYPT_OVERWRITE_KEY_FLAG
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_EXISTS                      The key already exists.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_NOT_SUPPORTED               The algorithm is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE* phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS       Status = NTE_INTERNAL_ERROR;
    NTSTATUS              ntStatus = STATUS_INTERNAL_ERROR;
    DWORD                 dwBitLength = 0;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;
    DebugPrint("Call function ");
    //
    // Validate input parameters.
    //
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);

    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((phKey == NULL) || (pszAlgId == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_SILENT_FLAG | NCRYPT_OVERWRITE_KEY_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    //Create the key object.
    Status = CreateNewKeyObject(pszKeyName,
        &pKey);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }

    // If the overwrite flag is not set then check to
    // make sure the key doesn't already exist.
    if ((pszKeyName != NULL) && (dwFlags & NCRYPT_OVERWRITE_KEY_FLAG) == 0)
    {
        DebugPrint("Call function ");
        Status = ValidateKeyFileExistence(pKey);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }

    //Set the key length to the default length.
    dwBitLength = SAMPLEKSP_DEFAULT_KEY_LENGTH;
    pKey->dwKeyBitLength = dwBitLength;

    //Set the key blob type to BCRYPT_RSAPRIVATE_BLOB.
    pKey->pszKeyBlobType = BCRYPT_RSAPRIVATE_BLOB;

    //Generate the key handle.
    ntStatus = BCryptGenerateKeyPair(
        pKey->hProvider,
        &pKey->hPrivateKey,
        SAMPLEKSP_DEFAULT_KEY_LENGTH,
        0);
    if (!NT_SUCCESS(ntStatus))
    {
        DebugPrint("Call function ");
        Status = NormalizeNteStatus(ntStatus);
        goto cleanup;
    }

    //Get path to user's key file storage area.
    Status = GetSampleKeyStorageArea(&pKey->pszKeyFilePath);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }

    //
    // Set return values.
    //
    DebugPrint("Call function ");
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;

    Status = ERROR_SUCCESS;

cleanup:
    if (pKey)
    {
        DebugPrint("Call function ");
        DeleteKeyObject(pKey);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    DebugPrint("Call function ");
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    DWORD cbResult = 0;
    DWORD dwProperty = 0;

    //
    // Validate input parameters.
    //

    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((pszProperty == NULL) || (pcbResult == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    DebugPrint("Call function ");
    if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //
    //Determine the size of the properties.
    //
    DebugPrint("Call function ");
    if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_IMPL_TYPE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_MAX_NAME_LENGTH_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_MAX_NAME_LEN_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_NAME_PROPERTY;
        cbResult = (DWORD)((wcslen(pProvider->pszName) + 1) * sizeof(WCHAR));
    }
    else if (wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_VERSION_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_USE_CONTEXT_PROPERTY;
        cbResult = 0;

        if (pProvider->pszContext)
        {
            DebugPrint("Call function ");
            cbResult =
                (DWORD)(wcslen(pProvider->pszContext) + 1) * sizeof(WCHAR);
        }

        if (cbResult == 0)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }
    else if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_SECURITY_DESCR_SUPPORT_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    *pcbResult = cbResult;

    //Output buffer is empty, this is a property length query, and we can exit early.
    if (pbOutput == NULL)
    {
        DebugPrint("Call function ");
        Status = ERROR_SUCCESS;
        goto cleanup;
    }

    //Otherwise, validate the size.
    if (cbOutput < *pcbResult)
    {
        DebugPrint("Call function ");
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    //
    //Retrieve the requested property data
    //if the property is not supported, we have already returned NTE_NOT_SUPPORTED.
    //
    switch (dwProperty)
    {
        DebugPrint("Call function ");
    case SAMPLEKSP_IMPL_TYPE_PROPERTY:
        *(DWORD*)pbOutput = NCRYPT_IMPL_SOFTWARE_FLAG;
        break;

    case SAMPLEKSP_MAX_NAME_LEN_PROPERTY:
        *(DWORD*)pbOutput = MAX_PATH;
        break;

    case SAMPLEKSP_NAME_PROPERTY:
        CopyMemory(pbOutput, pProvider->pszName, cbResult);
        break;

    case SAMPLEKSP_VERSION_PROPERTY:
        *(DWORD*)pbOutput = SAMPLEKSP_VERSION;
        break;

    case SAMPLEKSP_USE_CONTEXT_PROPERTY:
        CopyMemory(pbOutput, pProvider->pszContext, cbResult);
        break;

    case SAMPLEKSP_SECURITY_DESCR_SUPPORT_PROPERTY:
        *(DWORD*)pbOutput = SAMPLEKSP_SUPPORT_SECURITY_DESCRIPTOR;
        break;
    }
    DebugPrint("Call function ");
    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    DebugPrint("Call function : pszProperty= %ls", pszProperty);
    DebugPrint("Call function : cbOutput= %ld", cbOutput);
    DebugPrint("Call function : dwFlags= %ld", dwFlags);
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;
    SAMPLEKSP_PROPERTY* pProperty = NULL;
    DWORD dwProperty = 0;
    DWORD cbResult = 0;
    LPWSTR pszAlgorithm = NULL;
    LPWSTR pszAlgorithmGroup = NULL;
    PBYTE pbSecurityInfo = NULL;
    DWORD cbSecurityInfo = 0;
    DWORD cbTmp = 0;

    //
    // Validate input parameters.
    //

    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    pKey = SampleKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((pszProperty == NULL) ||
        (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
        (pcbResult == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    DebugPrint("Call function ");
    //NCRYPT_SILENT_FLAG is ignored in this sample KSP.
    dwFlags &= ~NCRYPT_SILENT_FLAG;

    //If this is to get the security descriptor, the flags
    //must be one of the OWNER_SECURITY_INFORMATION |GROUP_SECURITY_INFORMATION |
    //DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION.
    if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {

        if ((dwFlags == 0) || ((dwFlags & ~(OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION)) != 0))
        {
            DebugPrint("Call function ");
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    else
    {
        //Otherwise,Only NCRYPT_PERSIST_ONLY_FLAG is a valid flag.
        if (dwFlags & ~NCRYPT_PERSIST_ONLY_FLAG)
        {
            DebugPrint("Call function ");
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    DebugPrint("Call function ");
    //If NCRYPT_PERSIST_ONLY_FLAG is supported, properties must
    //be read from the property list.
    if (dwFlags & NCRYPT_PERSIST_ONLY_FLAG)
    {   //@@Critical section code would need to be added here for
        //multi-threaded support@@.
        // Lookup property.
        Status = LookupExistingKeyProperty(
            pKey,
            pszProperty,
            &pProperty);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }

        // Validate the size of the output buffer.
        cbResult = pProperty->cbPropertyData;

        *pcbResult = cbResult;
        if (pbOutput == NULL)
        {
            DebugPrint("Call function ");
            Status = ERROR_SUCCESS;
            goto cleanup;
        }
        if (cbOutput < *pcbResult)
        {
            DebugPrint("Call function ");
            Status = NTE_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        // Copy the property data to the output buffer.
        CopyMemory(pbOutput, (PBYTE)(pProperty + 1), cbResult);

        Status = ERROR_SUCCESS;
        goto cleanup;

    }
    DebugPrint("Call function : pszProperty= %ls", pszProperty);

    //Start add
    //Load the certificate that was installed earlier in the store store.
    //This certificate was previously issued by the AD server.
    //To restore the original code then switch #if 1 -> #if 0
#if 1
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT aCertContext = NULL;
    LPBYTE pbData = NULL;
    DWORD cbData = 0;
    DWORD dwKeySpec;
    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY");

    if (hMyCertStore == NULL)
    {
        DebugPrint("Call function -> hMyCertStore is NULL");
    }
    aCertContext = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        L"test01", // use appropriate subject name (発行先 )
        NULL
    );
    if (aCertContext == NULL)
    {
        DebugPrint("Call function -> Error: aCertContext is NULL");
    }

#endif
    //End add
        //
        //Determine length of requested property.
        //
    if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_ALGORITHM_PROPERTY;
        pszAlgorithm = BCRYPT_RSA_ALGORITHM;
        cbResult = (DWORD)(wcslen(pszAlgorithm) + 1) * sizeof(WCHAR);
    }

    //Start add by
    //Continue Load the certificate that was installed earlier in the store store
    //To restore the original code then switch #if 1 -> #if 0

#if 1
    else if (wcscmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0)
    {
        if (aCertContext->dwCertEncodingType == X509_ASN_ENCODING)
        {
            DebugPrint("INFO ENCODING: X509_ASN_ENCODING"); // this line gets logged
        }
        if (aCertContext->dwCertEncodingType == PKCS_7_ASN_ENCODING)
        {
            DebugPrint("INFO ENCODING: PKCS_7_ASN_ENCODING");
        }

        if (pbOutput == NULL) // get the certificate size
        {
            DebugPrint("INFO Reporting Buffer Size: %ld", aCertContext->cbCertEncoded);
            *pcbResult = aCertContext->cbCertEncoded;
        }
        else
        {
            if (aCertContext->cbCertEncoded < *pcbResult)
            {
                DebugPrint("ERROR", "Buffer too small!");
                Status = NTE_BUFFER_TOO_SMALL;
                goto cleanup;
            }

            DebugPrint("INFO Returning certificate payload...");
            *pcbResult = aCertContext->cbCertEncoded;
            CopyMemory(pbOutput, aCertContext->pbCertEncoded, aCertContext->cbCertEncoded);

            //Debug print the output certEncoded
            char text[4096];
            for (int i = 0; i < aCertContext->cbCertEncoded; i++)
            {
                sprintf((char*)text + (i * 2), "%02X", pbOutput[i]);
            }
            DebugPrint("Call function -> pbOutput: %s", text);

            // There should handle hashdata directly here?
           //PBYTE pbSignature = NULL;
           //DWORD cbSignaturee = 0;
           //SampleKSPSignHash(hProvider,hKey,NULL, pbOutput, aCertContext->cbCertEncoded, pbSignature, pbSignature,0,0);
           //DebugPrint("Call function ");
        }
    }
    //End add
#endif
    else if (wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_BLOCK_LENGTH_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        dwProperty = SAMPLEKSP_EXPORT_POLICY_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_KEY_USAGE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_KEY_TYPE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_LENGTH_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if (wcscmp(pszProperty, NCRYPT_LENGTHS_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_LENGTHS_PROPERTY;
        cbResult = sizeof(NCRYPT_SUPPORTED_LENGTHS);
    }
    else if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_NAME_PROPERTY;
        if (pKey->pszKeyName == NULL)
        {
            // This should only happen if this is an ephemeral key.
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }
        cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
    }
    else if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        //@@Synchronization schemes would need to be added here for
        //multi-threaded support@@.
        dwProperty = SAMPLEKSP_SECURITY_DESCR_PROPERTY;
        Status = GetSecurityOnKeyFile(
            pKey,
            dwFlags,
            (PSECURITY_DESCRIPTOR*)&pbSecurityInfo,
            &cbSecurityInfo);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }

        cbResult = cbSecurityInfo;
    }
    else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        dwProperty = SAMPLEKSP_ALGORITHM_GROUP_PROPERTY;
        pszAlgorithmGroup = NCRYPT_RSA_ALGORITHM_GROUP;
        cbResult = (DWORD)(wcslen(pszAlgorithmGroup) + 1) * sizeof(WCHAR);
    }
    else if (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        //For this sample, the unique name property and the name property are
        //the same, which is the name of the key file.
        dwProperty = SAMPLEKSP_UNIQUE_NAME_PROPERTY;

        if (pKey->pszKeyName == NULL)
        {
            DebugPrint("Call function ");
            // This should only happen if this is a public key object.
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
    }
    else
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    //
    // Validate the size of the output buffer.
    //
# if 0
    DebugPrint("Call function ");
    *pcbResult = cbResult;

    if (pbOutput == NULL)
    {
        DebugPrint("Call function ");
        Status = ERROR_SUCCESS;
        goto cleanup;
    }

    if (cbOutput < *pcbResult)
    {
        DebugPrint("Call function ");
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }
#endif
    DebugPrint("Call function ");

    //
    // Retrieve the requested property data.
    //
    switch (dwProperty)
    {
    case SAMPLEKSP_ALGORITHM_PROPERTY:
        DebugPrint("Call function ");
        CopyMemory(pbOutput, pszAlgorithm, cbResult);
        break;

    case SAMPLEKSP_BLOCK_LENGTH_PROPERTY:
        DebugPrint("Call function ");
        *(DWORD*)pbOutput = (pKey->dwKeyBitLength + 7) / 8;
        break;

    case SAMPLEKSP_EXPORT_POLICY_PROPERTY:
        DebugPrint("Call function ");
        *(DWORD*)pbOutput = pKey->dwExportPolicy;
        break;

    case SAMPLEKSP_KEY_USAGE_PROPERTY:
        DebugPrint("Call function ");
        *(DWORD*)pbOutput = pKey->dwKeyUsagePolicy;
        break;

    case SAMPLEKSP_KEY_TYPE_PROPERTY:
        DebugPrint("Call function ");
        //This sample KSP does not support machine keys.
        *(DWORD*)pbOutput = 0;
        break;

    case SAMPLEKSP_LENGTH_PROPERTY:
        DebugPrint("Call function ");
        *(DWORD*)pbOutput = pKey->dwKeyBitLength;
        break;

    case SAMPLEKSP_LENGTHS_PROPERTY:
    {
        DebugPrint("Call function ");
        NCRYPT_SUPPORTED_LENGTHS UNALIGNED* pLengths = (NCRYPT_SUPPORTED_LENGTHS*)pbOutput;

        Status = BCryptGetProperty(pKey->hProvider,
            BCRYPT_KEY_LENGTHS,
            pbOutput,
            cbOutput,
            &cbTmp,
            0);
        if (ERROR_SUCCESS != Status)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
        DebugPrint("Call function ");
        pLengths->dwDefaultLength = SAMPLEKSP_DEFAULT_KEY_LENGTH;
        break;
    }

    case SAMPLEKSP_NAME_PROPERTY:
        DebugPrint("Call function ");
        CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
        break;

    case SAMPLEKSP_UNIQUE_NAME_PROPERTY:
        DebugPrint("Call function ");
        CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
        break;

    case SAMPLEKSP_SECURITY_DESCR_PROPERTY:
        DebugPrint("Call function ");
        CopyMemory(pbOutput, pbSecurityInfo, cbResult);
        break;

    case SAMPLEKSP_ALGORITHM_GROUP_PROPERTY:
        DebugPrint("Call function ");
        CopyMemory(pbOutput, pszAlgorithmGroup, cbResult);
        break;

    }
    Status = ERROR_SUCCESS;

cleanup:
    DebugPrint("Call function ");
    if (pbSecurityInfo)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pbSecurityInfo);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Sets the value for a named property for a CNG key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
SampleKSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    DebugPrint("Call function ");

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((pszProperty == NULL) ||
        (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
        (pbInput == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //Update the property.
    if (wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
    {

        if (pProvider->pszContext)
        {
            DebugPrint("Call function ");
            HeapFree(GetProcessHeap(), 0, pProvider->pszContext);
        }

        pProvider->pszContext = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbInput);
        if (pProvider->pszContext == NULL)
        {
            DebugPrint("Call function ");
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }

        CopyMemory(pProvider->pszContext, pbInput, cbInput);

    }
    else
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Set the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle or a valid key handle
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
SampleKSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
    //Start Debug print out the value
    DebugPrint("Call function - cbInput: %ld", cbInput);
    DebugPrint("Call function - dwFlags: %ld", dwFlags);
    char text[4096];
    for (int i = 0; i < cbInput; i++) {
        sprintf((char*)text + (i * 2), "%02X", pbInput[i]);
    }
    DebugPrint("Call function - pbInput: %s", text);
    //End debug

    SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;
    SAMPLEKSP_PROPERTY* pProperty = NULL;
    SAMPLEKSP_PROPERTY* pExistingProperty = NULL;
    DWORD                   dwTempFlags = dwFlags;
    DebugPrint("Call function ");
    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);
    DebugPrint("Call function ");
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    pKey = SampleKspValidateKeyHandle(hKey);
    DebugPrint("Call function ");
    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if ((pszProperty == NULL) ||
        (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
        (pbInput == NULL))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    DebugPrint("Call function ");
    // Ignore the silent flag if it is turned on.
    dwTempFlags &= ~NCRYPT_SILENT_FLAG;
    if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {
        DebugPrint("Call function ");
        // At least one flag must be set.
        if (dwTempFlags == 0)
        {
            DebugPrint("Call function ");
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }

        // Reject flags *not* in the list below.
        if ((dwTempFlags & ~(OWNER_SECURITY_INFORMATION |
            GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION |
            SACL_SECURITY_INFORMATION |
            NCRYPT_PERSIST_FLAG)) != 0)
        {
            DebugPrint("Call function ");
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    else
    {
        DebugPrint("Call function ");
        if ((dwTempFlags & ~(NCRYPT_PERSIST_FLAG |
            NCRYPT_PERSIST_ONLY_FLAG)) != 0)
        {
            DebugPrint("Call function ");
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }

    if ((dwTempFlags & NCRYPT_PERSIST_ONLY_FLAG) == 0)
    {
        DebugPrint("Call function ");
        //The property is one of the built-in key properties.
        Status = SetBuildinKeyProperty(pKey,
            pszProperty,
            pbInput,
            cbInput,
            &dwTempFlags);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }

        if ((dwTempFlags & NCRYPT_PERSIST_FLAG) == 0)
        {
            DebugPrint("Call function ");
            //we are done here.
            goto cleanup;
        }
    }
    DebugPrint("Call function ");
    //Remove the existing property
    Status = LookupExistingKeyProperty(pKey,
        pszProperty,
        &pExistingProperty);
    DebugPrint("Call function ");
    if (Status != NTE_NOT_FOUND)
    {
        DebugPrint("Call function ");
        RemoveEntryList(&pExistingProperty->ListEntry);
        HeapFree(GetProcessHeap(), 0, pExistingProperty);
    }
    DebugPrint("Call function ");
    //Create a new property and attach it to the key object.
    Status = CreateNewProperty(
        pszProperty,
        pbInput,
        cbInput,
        dwTempFlags,
        &pProperty);
    if (Status != ERROR_SUCCESS)
    {
        DebugPrint("Call function ");
        goto cleanup;
    }
    InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);

    //Write the new properties to the file system
    //if it should be persisted.
    if (pProperty->fPersisted && pKey->fFinished)
    {
        DebugPrint("Call function ");
        Status = WriteKeyToStore(pKey);

        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }
    DebugPrint("Call function ");
    Status = ERROR_SUCCESS;
    DebugPrint("Call function ");
cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :     Completes a sample key storage key. The key cannot be used
*                   until this function has been called.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*/
SECURITY_STATUS
WINAPI
SampleKSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;

    //
    // Validate input parameters.
    //
    DebugPrint("Call function ");
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = SampleKspValidateKeyHandle(hKey);
    DebugPrint("Call function ");
    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->fFinished == TRUE)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_NO_KEY_VALIDATION |
        NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG |
        NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if (dwFlags & NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    if (pKey->pbPrivateKey)
    {
        DebugPrint("Call function ");
        //Private key is provisioned by NCryptSetProperty
        //or NCryptImportKey.
        //Once the key blob is imported as a BCrypt key handle,
        //the key is finalized.
        Status = ImportRsaKeyPair(pKey);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }
    else
    {
        //
        //Finalize the key.
        //
        Status = FinalizeKey(pKey);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }

    //
    //Write key to the file system, if the key is persisted.
    //
    //
    if (pKey->pszKeyName != NULL)
    {
        DebugPrint("Call function ");
        Status = WriteKeyToStore(pKey);
        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }

    pKey->fFinished = TRUE;
    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :     Deletes a CNG sample KSP key
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          Handle to a sample KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*            NTE_INTERNAL_ERROR              Key file deletion failed.
*/
SECURITY_STATUS
WINAPI
SampleKSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS Status = ERROR_SUCCESS;
    SAMPLEKSP_PROVIDER* pProvider;
    SAMPLEKSP_KEY* pKey = NULL;

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    pKey = SampleKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //Delete the key if it is already stored in the file system
    if (pKey->fFinished == TRUE);
    {  DebugPrint("Call function ");
    Status = RemoveKeyFromStore(pKey);
    }

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :     Free a CNG sample KSP key object
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the sample KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*/
SECURITY_STATUS
WINAPI
SampleKSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{
    SECURITY_STATUS Status;
    SAMPLEKSP_PROVIDER* pProvider;
    SAMPLEKSP_KEY* pKey = NULL;

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = SampleKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }


    //
    // Free key object.
    //
    Status = DeleteKeyObject(pKey);
    DebugPrint("Call function ");
cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :     free a CNG sample KSP memory buffer object
*
* INPUTS :
*            PVOID   pvInput                 The buffer to free.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*/
SECURITY_STATUS
WINAPI
SampleKSPFreeBuffer(
    __deref PVOID   pvInput)
{
    SAMPLEKSP_MEMORY_BUFFER* pBuffer;
    SAMPLEKSP_ENUM_STATE* pEnumState;

    //
    // Is this one of the enumeration buffers, that needs to be
    // freed?
    //

    pBuffer = RemoveMemoryBuffer(&g_SampleKspEnumStateList, pvInput);

    if (pBuffer)
    {
        DebugPrint("Call function ");
        pEnumState = (SAMPLEKSP_ENUM_STATE*)pBuffer->pvBuffer;

        FindClose(pEnumState->hFind);

        HeapFree(GetProcessHeap(), 0, pEnumState);
        HeapFree(GetProcessHeap(), 0, pBuffer);

        goto cleanup;
    }
    DebugPrint("Call function ");
    //
    // Free the buffer from the heap.
    //

    HeapFree(GetProcessHeap(), 0, pvInput);

cleanup:

    return ERROR_SUCCESS;
}


/******************************************************************************
* DESCRIPTION :  encrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object.
*            PBYTE   pbInput                 Plain text data to be encrypted.
*            DWORD   cbInput                 Size of the plain text data.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing encrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID* pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    SAMPLEKSP_KEY* pKey = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    NTSTATUS        ntStatus = STATUS_INTERNAL_ERROR;
    UNREFERENCED_PARAMETER(hProvider);
    DebugPrint("Call function ");
    // Validate input parameters.
    pKey = SampleKspValidateKeyHandle(hKey);

    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    if (!pKey->fFinished)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_KEY_STATE;
        goto cleanup;
    }

    if (pbInput == NULL || cbInput == 0 ||
        pcbResult == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_NO_PADDING_FLAG |
        NCRYPT_PAD_PKCS1_FLAG |
        NCRYPT_PAD_OAEP_FLAG |
        NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    // Encrypt input buffer.
    ntStatus = BCryptEncrypt(pKey->hPublicKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        NULL,
        0,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
    if (!NT_SUCCESS(ntStatus))
    {
        DebugPrint("Call function ");
        Status = NormalizeNteStatus(ntStatus);
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
    DebugPrint("Call function ");
cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Decrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object.
*            PBYTE   pbInput                 Encrypted data blob.
*            DWORD   cbInput                 Size of the encrypted data blob.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing decrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/

SECURITY_STATUS
WINAPI
SampleKSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID* pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    SAMPLEKSP_KEY* pKey;
    DWORD BlockLength = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    NTSTATUS    ntStatus = ERROR_SUCCESS;
    UNREFERENCED_PARAMETER(hProvider);

    // Validate input parameters.
    pKey = SampleKspValidateKeyHandle(hKey);
    DebugPrint("Call function ");
    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pbInput == NULL || cbInput == 0 ||
        pcbResult == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_NO_PADDING_FLAG |
        NCRYPT_PAD_PKCS1_FLAG |
        NCRYPT_PAD_OAEP_FLAG |
        NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }


    //
    // Verify that this key is allowed to decrypt.
    //

    if ((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_DECRYPT_FLAG) == 0)
    {
        DebugPrint("Call function ");
        Status = (DWORD)NTE_PERM;
        goto cleanup;
    }

    BlockLength = (pKey->dwKeyBitLength + 7) / 8;

    if (cbInput != BlockLength)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Decrypt input buffer.
    ntStatus = BCryptDecrypt(pKey->hPrivateKey,
        pbInput,
        cbInput,
        pPaddingInfo,
        NULL,
        0,
        pbOutput,
        cbOutput,
        pcbResult,
        dwFlags);
    if (!NT_SUCCESS(ntStatus))
    {
        DebugPrint("Call function ");
        Status = NormalizeNteStatus(ntStatus);
        goto cleanup;
    }
    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Determines if a sample key storage provider supports a
*                specific cryptographic algorithm.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            LPCWSTR pszAlgId                Name of the cryptographic
*                                            Algorithm in question
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The algorithm is supported.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               This algorithm is not supported.
*/
SECURITY_STATUS
WINAPI
SampleKSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags)
{
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);
    DebugPrint("Call function ");
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pszAlgId == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    // This KSP only supports the RSA algorithm.
    if (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the algorithms that are supported by
*                the sample key storage provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            DWORD   dwAlgOperations         The crypto operations that are to
*                                            be enumerated.
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            DWORD * pdwAlgCount             Number of supported algorithms.
*            NCryptAlgorithmName **ppAlgList List of supported algorithms.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The crypto operations are not supported.
*/
SECURITY_STATUS
WINAPI
SampleKSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations,
    __out   DWORD* pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName** ppAlgList,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    NCryptAlgorithmName* pCurrentAlg = NULL;
    PBYTE pbCurrent = NULL;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;

    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);
    DebugPrint("Call function ");
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pdwAlgCount == NULL || ppAlgList == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }


    if (dwAlgOperations == 0 ||
        ((dwAlgOperations & NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION) != 0) ||
        ((dwAlgOperations & NCRYPT_SIGNATURE_OPERATION)) != 0)
    {
        DebugPrint("Call function ");
        cbOutput += sizeof(NCryptAlgorithmName) +
            sizeof(BCRYPT_RSA_ALGORITHM);
    }
    else
    {
        DebugPrint("Call function ");
        //Sample KSP only supports RSA.
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    //Allocate the output buffer.
    pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutput);
    if (pbOutput == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    DebugPrint("Call function ");
    pCurrentAlg = (NCryptAlgorithmName*)pbOutput;
    pbCurrent = pbOutput + sizeof(NCryptAlgorithmName);

    pCurrentAlg->dwFlags = 0;
    pCurrentAlg->dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
    pCurrentAlg->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
        NCRYPT_SIGNATURE_OPERATION;

    pCurrentAlg->pszName = (LPWSTR)pbCurrent;
    CopyMemory(pbCurrent,
        BCRYPT_RSA_ALGORITHM,
        sizeof(BCRYPT_RSA_ALGORITHM));
    pbCurrent += sizeof(BCRYPT_RSA_ALGORITHM);

    *pdwAlgCount = 1;
    *ppAlgList = (NCryptAlgorithmName*)pbOutput;

    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the keys that are stored by the provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            LPCWSTR pszScope                Unused
*            NCryptKeyName **ppKeyName       Name of the retrieved key
*            PVOID * ppEnumState             Enumeration state information
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            PVOID * ppEnumState             Enumeration state information that
*                                            is used in subsequent calls to
*                                            this function.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               NCRYPT_MACHINE_KEY_FLAG is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
SampleKSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName** ppKeyName,
    __inout PVOID* ppEnumState,
    __in    DWORD   dwFlags)
{
    DebugPrint("Call function ");
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    NCryptKeyName* pKeyName = NULL;
    SAMPLEKSP_MEMORY_BUFFER* pBuffer = NULL;
    PVOID pEnumState = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    UNREFERENCED_PARAMETER(pszScope);
    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if (ppKeyName == NULL || ppEnumState == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if (dwFlags & NCRYPT_MACHINE_KEY_FLAG)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    // Enumerate key files.
    if (dwFlags & NCRYPT_MACHINE_KEY_FLAG)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    pEnumState = *ppEnumState;
    if (pEnumState == NULL)
    {
        DebugPrint("Call function ");
        // Find the first key file.
        Status = FindFirstKeyFile(
            &pEnumState,
            &pKeyName);

        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }

        // Allocate structure to hold the returned pEnumState buffer.
        pBuffer = (SAMPLEKSP_MEMORY_BUFFER*)HeapAlloc(
            GetProcessHeap(),
            0,
            sizeof(SAMPLEKSP_MEMORY_BUFFER));
        if (pBuffer == NULL)
        {
            DebugPrint("Call function ");
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }
        ZeroMemory(pBuffer, sizeof(SAMPLEKSP_MEMORY_BUFFER));

        // Add the returned pEnumState buffer to a global list, so that
        // the sample KSP will know the correct way to free the buffer.
        pBuffer->pvBuffer = pEnumState;
        //@@Critical section code would need to be added here for multi-threaded support.@@
        InsertTailList(
            &g_SampleKspEnumStateList,
            &pBuffer->List);
        pBuffer = NULL;
    }
    else
    {
        DebugPrint("Call function ");
        // Make sure that the passed in pEnumState buffer is one
        // that we recognize.
        if (LookupMemoryBuffer(
            &g_SampleKspEnumStateList,
            pEnumState) == NULL)
        {
            DebugPrint("Call function ");
            Status = NTE_INVALID_PARAMETER;
            goto cleanup;
        }
        DebugPrint("Call function ");
        Status = FindNextKeyFile(
            pEnumState,
            &pKeyName);

        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }

    DebugPrint("Call function ");
    // Build output data.
    *ppKeyName = pKeyName;
    pKeyName = NULL;
    *ppEnumState = pEnumState;
    pEnumState = NULL;

    Status = ERROR_SUCCESS;
cleanup:
    if (pKeyName)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pKeyName);
    }

    if (pBuffer)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    if (pEnumState)
    {
        DebugPrint("Call function ");
        HeapFree(GetProcessHeap(), 0, pEnumState);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Imports a key into the sample KSP from a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a sample KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hImportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            PBYTE   pbData                   Key blob.
*            DWORD   cbData                   Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            NCRYPT_KEY_HANDLE *phKey        Sample KSP key object imported
*                                            from the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Decoding failed.
*/
SECURITY_STATUS
WINAPI
SampleKSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc* pParameterList,
    __out   NCRYPT_KEY_HANDLE* phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags)
{
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;
    DWORD                   cbResult = 0;
    BOOL                    fPkcs7Blob = FALSE;
    BOOL                    fPkcs8Blob = FALSE;
    BOOL                    fPrivateKeyBlob = FALSE;
    LPCWSTR                 pszTmpBlobType = pszBlobType;
    LPWSTR                  pszKeyName = NULL;
    SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
    NTSTATUS                ntStatus = STATUS_INTERNAL_ERROR;
    DebugPrint("Call function ");
    UNREFERENCED_PARAMETER(hImportKey);

    //
    //Validate input parameters.
    //
    pProvider = SampleKspValidateProvHandle(hProvider);
    DebugPrint("Call function ");
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if ((phKey == NULL) || (pbData == NULL) || (cbData == 0))
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if ((dwFlags & ~(NCRYPT_MACHINE_KEY_FLAG | BCRYPT_NO_KEY_VALIDATION |
        NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG | NCRYPT_DO_NOT_FINALIZE_FLAG |
        NCRYPT_SILENT_FLAG | NCRYPT_OVERWRITE_KEY_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if (dwFlags & (NCRYPT_MACHINE_KEY_FLAG |
        NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG))
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    if (wcscmp(pszTmpBlobType, BCRYPT_PUBLIC_KEY_BLOB) == 0 ||
        wcscmp(pszTmpBlobType, BCRYPT_PRIVATE_KEY_BLOB) == 0)
    {
        if (cbData < sizeof(BCRYPT_KEY_BLOB))
        {
            DebugPrint("Call function ");
            Status = NTE_INVALID_PARAMETER;
            goto cleanup;
        }

        if (wcscmp(pszTmpBlobType, BCRYPT_PRIVATE_KEY_BLOB) == 0)
        {
            DebugPrint("Call function ");
            fPrivateKeyBlob = TRUE;
        }
    }
    else if (wcscmp(pszTmpBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPrivateKeyBlob = FALSE;

    }
    else if (wcscmp(pszTmpBlobType, BCRYPT_RSAPRIVATE_BLOB) == 0 ||
        wcscmp(pszTmpBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPrivateKeyBlob = TRUE;
    }
    else if (wcscmp(pszTmpBlobType, NCRYPT_PKCS7_ENVELOPE_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPkcs7Blob = TRUE;
    }
    else if (wcscmp(pszTmpBlobType, NCRYPT_PKCS8_PRIVATE_KEY_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPkcs8Blob = TRUE;
    }
    else
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    if (fPkcs7Blob)
    {
        DebugPrint("Call function ");
        Status = SampleKspImportPKCS7Blob(pProvider,
            &pKey,
            pParameterList,
            pbData,
            cbData,
            dwFlags);

        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }
    else if (fPkcs8Blob)
    {
        DebugPrint("Call function ");
        // PKCS#8 private key blob
        Status = SampleKspImportPKCS8Blob(
            hProvider,
            &pKey,
            pParameterList,
            pbData,
            cbData,
            dwFlags);

        if (Status != ERROR_SUCCESS)
        {
            DebugPrint("Call function ");
            goto cleanup;
        }
    }
    else
    {
        if (fPrivateKeyBlob)
        {
            DebugPrint("Call function ");
            //Get the name of the key if it is passed in.
            Status = ReadKeyNameFromParams(
                pParameterList,
                &pszKeyName);
            if (Status != ERROR_SUCCESS)
            {
                goto cleanup;
            }
        }

        //Create the key object.
        Status = CreateNewKeyObject(
            pszKeyName,
            &pKey);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        if (fPrivateKeyBlob)
        {
            DebugPrint("Call function ");
            //If the key to import is to be persisted, and
            //the flags do not allow overwriting an existing key,
            //we error out if the key already exists.
            if ((pszKeyName != NULL) && (dwFlags & NCRYPT_OVERWRITE_KEY_FLAG) == 0)
            {
                Status = ValidateKeyFileExistence(pKey);
                if (Status != ERROR_SUCCESS)
                {
                    DebugPrint("Call function ");
                    goto cleanup;
                }
            }

            // Set the private key blob, key length and key type.
            Status = ProtectAndSetPrivateKey(
                pszTmpBlobType,
                pbData,
                cbData,
                pKey);
            if (Status != ERROR_SUCCESS)
            {
                DebugPrint("Call function ");
                Status = NTE_NOT_SUPPORTED;
                goto cleanup;
            }

        }
        else
        {
            if ((dwFlags & (NCRYPT_MACHINE_KEY_FLAG |
                NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG |
                NCRYPT_DO_NOT_FINALIZE_FLAG |
                NCRYPT_OVERWRITE_KEY_FLAG)) != 0)
            {
                DebugPrint("Call function ");
                Status = NTE_BAD_FLAGS;
                goto cleanup;
            }

            //Create the primitive public key
            ntStatus = BCryptImportKeyPair(
                pKey->hProvider,
                NULL,
                pszTmpBlobType,
                &pKey->hPublicKey,
                pbData,
                cbData,
                dwFlags & NCRYPT_NO_KEY_VALIDATION);
            DebugPrint("Call function ");
            if (!NT_SUCCESS(ntStatus))
            {
                DebugPrint("Call function ");
                Status = NormalizeNteStatus(ntStatus);
                goto cleanup;
            }

            // Obtain the bit length.
            ntStatus = BCryptGetProperty(
                pKey->hPublicKey,
                BCRYPT_KEY_STRENGTH,
                (PBYTE)&pKey->dwKeyBitLength,
                sizeof(DWORD),
                &cbResult,
                0);
            if (!NT_SUCCESS(ntStatus))
            {
                DebugPrint("Call function ");
                Status = NormalizeNteStatus(ntStatus);
                goto cleanup;
            }

        }
    }
    DebugPrint("Call function ");
    //Finalize key: pkcs7 or pkcs8 keys is already finalized in
    //SampleKspImportPKCS7Blob or SampleKspImportPKCS8Blob,
    //depending on dwFlags values passed to the KspImportPKCS7Blob function.
    if (!fPkcs7Blob && !fPkcs8Blob)
    {
        DebugPrint("Call function ");
        if ((fPrivateKeyBlob) && ((dwFlags & NCRYPT_DO_NOT_FINALIZE_FLAG) == 0))
        {
            //Create the private key handle and the public key handle.
            Status = ImportRsaKeyPair(pKey);
            if (Status != ERROR_SUCCESS)
            {
                DebugPrint("Call function ");
                goto cleanup;
            }

            //Write the persistent key to the key store.
            if (pKey->pszKeyName != NULL)
            {
                DebugPrint("Call function ");
                Status = WriteKeyToStore(pKey);

                if (Status != ERROR_SUCCESS)
                {
                    DebugPrint("Call function ");
                    goto cleanup;
                }
            }

            pKey->fFinished = TRUE;

        }

    }
    DebugPrint("Call function ");
    Status = ERROR_SUCCESS;
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;
cleanup:
    if (pKey)
    {
        DebugPrint("Call function ");
        DeleteKeyObject(pKey);
        pKey = NULL;
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Exports a sample key storage key into a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a sample KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hKey           A handle to the sample KSP key
*                                             object to export.
*            NCRYPT_KEY_HANDLE hExportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            DWORD   cbOutput                 Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            PBYTE pbOutput                  Key blob.
*            DWORD * pcbResult               Required size of the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Encoding failed.
*/
SECURITY_STATUS
WINAPI
SampleKSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc* pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    SAMPLEKSP_PROVIDER* pProvider = NULL;
    SAMPLEKSP_KEY* pKey = NULL;
    PBYTE               pbTemp = NULL;
    BOOL                fPkcs7Blob = FALSE;
    BOOL                fPkcs8Blob = FALSE;
    BOOL                fPublicKeyBlob = FALSE;
    BOOL                fPrivateKeyBlob = FALSE;
    NTSTATUS            ntStatus = STATUS_INTERNAL_ERROR;
    SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;
    UNREFERENCED_PARAMETER(hExportKey);
    DebugPrint("Call function ");
    // Validate input parameters.
    pProvider = SampleKspValidateProvHandle(hProvider);
    if (pProvider == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    pKey = SampleKspValidateKeyHandle(hKey);
    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    if (pcbResult == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    if ((dwFlags & ~(NCRYPT_SILENT_FLAG | NCRYPT_EXPORT_LEGACY_FLAG)) != 0)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }
    if (dwFlags & NCRYPT_EXPORT_LEGACY_FLAG)
    {
        DebugPrint("Call function ");
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }
    DebugPrint("Call function ");
    //
    // Export key.
    //
    if (wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPublicKeyBlob = TRUE;
    }
    else if (wcscmp(pszBlobType, BCRYPT_PRIVATE_KEY_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPrivateKeyBlob = TRUE;
    }
    else if (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPublicKeyBlob = TRUE;
    }
    else if (wcscmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB) == 0 ||
        wcscmp(pszBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPrivateKeyBlob = TRUE;
    }
    else if (wcscmp(pszBlobType, NCRYPT_PKCS7_ENVELOPE_BLOB) == 0)
    {
        fPrivateKeyBlob = TRUE;
        fPkcs7Blob = TRUE;
    }
    else if (wcscmp(pszBlobType, NCRYPT_PKCS8_PRIVATE_KEY_BLOB) == 0)
    {
        DebugPrint("Call function ");
        fPrivateKeyBlob = TRUE;
        fPkcs8Blob = TRUE;
    }
    else
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //Export the public key blob.
    if (fPublicKeyBlob)
    {
        DebugPrint("Call function ");
        // Obtain the key blob from the primitive layer.
        ntStatus = BCryptExportKey(
            pKey->hPublicKey,
            NULL,
            pszBlobType,
            pbOutput,
            cbOutput,
            pcbResult,
            0);
        if (!NT_SUCCESS(ntStatus))
        {
            DebugPrint("Call function ");
            Status = NormalizeNteStatus(ntStatus);
            goto cleanup;
        }
    }

    if (fPrivateKeyBlob)
    {
        // Check to see if plaintext exports are permitted.
        if (!fPkcs7Blob && ((pKey->dwExportPolicy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) == 0) &&
            !(fPkcs8Blob && IsPkcs8KeyExportable(pKey, pParameterList)))
        {
            DebugPrint("Call function ");
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        if (fPkcs7Blob)
        {
            Status = SampleKspExportPKCS7Blob(pKey,
                pParameterList,
                pbOutput,
                cbOutput,
                pcbResult);
            if (Status != ERROR_SUCCESS)
            {
                DebugPrint("Call function ");
                goto cleanup;
            }
        }
        else if (fPkcs8Blob)
        {
            Status = SampleKspExportPKCS8Blob(
                pKey,
                pParameterList,
                pbOutput,
                cbOutput,
                pcbResult);
            if (Status != ERROR_SUCCESS)
            {
                DebugPrint("Call function ");
                goto cleanup;
            }
        }
        else
        {
            Status = AllocAndGetRsaPrivateKeyBlob(
                pKey,
                pszBlobType,
                &pbTemp,
                pcbResult);
            if (Status != ERROR_SUCCESS)
            {
                DebugPrint("Call function ");
                goto cleanup;
            }
            if (pbOutput != NULL)
            {
                if (cbOutput < *pcbResult)
                {
                    DebugPrint("Call function ");
                    Status = NTE_BUFFER_TOO_SMALL;
                    goto cleanup;
                }
                CopyMemory(pbOutput, pbTemp, *pcbResult);
            }
        }


    }

    Status = ERROR_SUCCESS;
cleanup:
    if (pbTemp)
    {
        DebugPrint("Call function ");
        SecureZeroMemory(pbTemp, *pcbResult);
        HeapFree(GetProcessHeap(), 0, pbTemp);
    }
    return Status;
}
/******************************************************************************
* DESCRIPTION :  creates a signature of a hash value.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used
*            PBYTE  pbHashValue              Hash to sign.
*            DWORD  cbHashValue              Size of the hash.
*            DWORD  cbSignature              Size of the signature
*            DWORD  dwFlags                  Flags
* OUTPUTS:
*            PBYTE  pbSignature              Output buffer containing signature.
*                                            If pbOutput is NULL, required buffer
*                                            size will return in *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID* pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignaturee, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignaturee,
    __out   DWORD* pcbResult,
    __in    DWORD   dwFlags)
{
    SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;
    NTSTATUS            ntStatus = STATUS_INTERNAL_ERROR;
    SAMPLEKSP_KEY* pKey = NULL;
    DWORD               cbTmpSig = 0;
    DWORD               cbTmp = 0;
    UNREFERENCED_PARAMETER(hProvider);
    DebugPrint("Call function ");

    //Start workround
    //Add handling to hash data and sign certificate with private key.
    //To restore the original code switch #if 1 -> #if 0
    char text[4096];
    DWORD dwBufferLen = 0, cbKeyBlob = 0;
    PBYTE pbBuffer = NULL, pbKeyBlob = NULL;
    LPBYTE   lpHashData;
    DWORD    dwHashDataSize;
    NTSTATUS status;
    BCRYPT_ALG_HANDLE  hAlg;
    DWORD    dwSignatureSize;
    PBYTE   lpSignature;
    BCRYPT_PKCS1_PADDING_INFO padding_PKCS1;
    padding_PKCS1.pszAlgId = BCRYPT_SHA1_ALGORITHM;

    //Start Regardless of which calls to take, force always signs with the current certificate
    //Alway force input pbHashValue = aCertContext->pbCertEncoded
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT aCertContext = NULL;
    LPBYTE pbData = NULL;
    DWORD cbData = 0;
    DWORD dwKeySpec;
    hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        X509_ASN_ENCODING,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY");

    if (hMyCertStore == NULL)
    {
        DebugPrint("Call function -> hMyCertStore is NULL");
    }
    aCertContext = CertFindCertificateInStore(hMyCertStore,
        X509_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        L"test01", // use appropriate subject name
        NULL
    );
    if (aCertContext == NULL)
    {
        DebugPrint("Call function -> Error: aCertContext is NULL");
    }

    pbHashValue = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, aCertContext->cbCertEncoded);
    CopyMemory(pbHashValue, aCertContext->pbCertEncoded, aCertContext->cbCertEncoded);
    cbHashValue = aCertContext->cbCertEncoded;

    // End force

    //Debug printout
    DebugPrint("Call function - cbHashValue= %ld", cbHashValue);
    DebugPrint("Call function - cbSignaturee= %ld", cbSignaturee);
    DebugPrint("Call function - dwFlags= %ld", dwFlags);
    for (int i = 0; i < cbHashValue; i++)
    {
        sprintf((char*)text + (i * 2), "%02X", pbHashValue[i]);
    }
    DebugPrint("Call function -> pbHashValue: %s", text);

    // ------- HARCODE PRIVATE KEY ------ //
    //Import the previously exported private key using the pfx file.Use the command below to export the private key.
    //Command :#openssl pkcs12 -in sample.pfx -nocerts -nodes -out sample.key
    //         #openssl rsa -in sample.key -out sample_private.key
        const char* szPemPrivKeyPass =
        "-----BEGIN RSA PRIVATE KEY-----"
        "MIIEowIBAAKCAQEA1MtKkDL5RuY7lYwCZy38x1w9kisJLhyb7VkIlodJPLyqkQUZ"
        "nLKmC/ZFtzi4aHvlivpoflel+V7Pmcl0nM3JLdWi/1ZOiNc+hRCMQsbVNvCcJTpe"
        "g3m/EiAErt5Uo3moMWUAHIOv1lenkxRR8RCVtsrDXCAROlziDQ85AdXNj1zp+DyN"
        "15jegcam42I659I5lwkoUfDkAxIrt3cUn24TKwSo8w5dXBRKqIn+4ecF8sXLKpKG"
        "kxgvAzmD78Mg77VsHn70qkhPzAX6ymKdHOl09OtryJ132ow36VM8xdtSGmpYFicA"
        "5CxIgvqAHSWWzd6BsEx5GJJfOYHDQcFCdkKnHQIDAQABAoIBAEY31yECURO+QYc1"
        "rk1R9YnrvD2RifP3aNTHfnf9qIMsVrSIFE2K/hQQbizpwKBp0fMscnLOhWxmhube"
        "fWaI2YwQZTsQxdWOAYlzTnVym0UH3N7EBhAoio52llUF9LQFHyU9iO3f3pRCVH/K"
        "QsfjiyPIgPLTehviLo3UqiEa5jwZ+Mg+EeCZqqp2FBn98xad+cAS2lVtY+wWS2J8"
        "MWMydUDN0Jyqx2bshPk7Tr6YymlKqh7dRR3m2wd223QqE5xjpv171XZOsDeS2SXQ"
        "gKiMb8FMYnEcFReSokcqCHN+SJt5C81TZHZx51EjAGa5DZhTlx/DWi00LaJTtLWz"
        "+Cgh71kCgYEA8ywJhXzFMA5wJIzCrijhwl7gIaN1ebT/vidvAdCAVc2TJPHmVxu4"
        "C/3NNEt5ZQvYH4gcTwtOM8k8QiYynpaYuQhfhaJgeBXUl81yJH1r0jB6iWUJyLf8"
        "eDjEvSyKl75ucgB4gzyO4MyYbH/lrttXH2sR830gG40MKz6EnsxyzCsCgYEA4AUC"
        "fz5l+q7lW9Fm+hhM9duDFO5EME6RDJp6MIEWH9C0khv2wWhNJCdWNPwwlPgCWIpL"
        "7ueaVfhErJkJLzH8V8gIPpb5Hot4YUycTNvZffSeS+RE5AF9kWgzlxcd31fGHgZZ"
        "f9W0xn7ieQS3fFnVWlK900drOQ+qkQ8jMKvxDdcCgYEAtUJnGoSFq6undecimpVI"
        "qwzzfr+MKpt7Ym+cdDrJ3qts+kYCD35O80lNM6TqqSJqCB76EwV3VmyzKQ+1/bZ9"
        "wrb2FPOTew+ytzDh20dOHpAaVt3krCRQ4gBWzjgsWq4NP5cQParfSbvYBlBTkcJX"
        "r8isydXEICVEI9vnGUOGcp8CgYBUsXAtPSD+8mpiGTvuZ4uJE9Ft81qyTLHH6wsx"
        "FUyRAK2T46CZpF4twfV0mLehSlZQtRBaJROTVwZXno/7WNGHOmfridZrNt1vI7Cf"
        "2ipS1U2XcZid/vZDJ/sBL0sq6htLtKjXjKsItGXYzPC1wZzIxilgHEssSoD40JlE"
        "SG0dBwKBgCohRx4Rb5ftlT6unv+FO61Z4A/6PDmkNzFNcEmKQRzQ3Ii3v8w8GqK+"
        "BdYVwZjU02Lk1S7tVHdyJ6bs+orsxL9n2hxwxUlGqitrSItTRcm53x39cLMeax/c"
        "3/rmIEUzkH2i7NKcZLFRtnhpsiWhTKNb2n7LtzJ+vr9CHL1tSvcO"
        "-----END RSA PRIVATE KEY-----";

    DebugPrint("Process Start import private key");
    if (!CryptStringToBinaryA(szPemPrivKeyPass, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen, NULL, NULL))
    {
        DebugPrint("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());

    }
    pbBuffer = (PBYTE)LocalAlloc(0, dwBufferLen);
    if (!CryptStringToBinaryA(szPemPrivKeyPass, 0, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwBufferLen, NULL, NULL))
    {
        DebugPrint("Failed to convert BASE64 private key. Error 0x%.8X\n", GetLastError());
    }
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, NULL, &cbKeyBlob))
    {
        DebugPrint("Failed to parse private key. Error 0x%.8X\n", GetLastError());
    }
    pbKeyBlob = (PBYTE)LocalAlloc(0, cbKeyBlob);
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbBuffer, dwBufferLen, 0, NULL, pbKeyBlob, &cbKeyBlob))
    {
        DebugPrint("Failed to parse private key. Error 0x%.8X\n", GetLastError());
    }
    // ---------START  HASH DATA ------------//
    DebugPrint("Start Hash the data");
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptOpenAlgorithmProvider");
        return 0;
    }

    //Import key pair
    status = BCryptImportKeyPair(hAlg, NULL, LEGACY_RSAPRIVATE_BLOB, &hKey, (PUCHAR)pbKeyBlob, cbKeyBlob, 0);

    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptImportKeyPair : 0x%.8X\n", GetLastError());
        return FALSE;
    }
    // Hash Data certificate 
    if (!GetHashData((LPBYTE)pbHashValue, cbHashValue, &lpHashData, &dwHashDataSize)) {
        DebugPrint("Error: GetHashData");
        return FALSE;
    }
    
    //Sign hash certificate
    BCryptSignHash(hKey, &padding_PKCS1, (LPBYTE)lpHashData, dwHashDataSize, NULL, 0, &dwSignatureSize, BCRYPT_PAD_PKCS1);

    pbSignature = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwSignatureSize);
    status = BCryptSignHash(hKey, &padding_PKCS1, (LPBYTE)lpHashData, dwHashDataSize, pbSignature, dwSignatureSize, pcbResult, BCRYPT_PAD_PKCS1);
    
    //Debug print 
    DebugPrint("Call function - dwHashDataSize= %ld", dwHashDataSize);
    DebugPrint("Call function - pcbResult= %ld", *pcbResult);
    DebugPrint("Call function - dwSignatureSize= %ld", dwSignatureSize);

    if (!NT_SUCCESS(status)) {
        DebugPrint("Error: BCryptSignHash= %X", status);
        HeapFree(GetProcessHeap(), 0, lpHashData);
        HeapFree(GetProcessHeap(), 0, pbSignature);
        return FALSE;
    }

    // Print the Signature data.
    char textPn[4096];
    for (int i = 0; i < dwSignatureSize; i++){
        sprintf((char*)textPn + (i * 2), "%02X", pbSignature[i]);
    }
    DebugPrint("pbSignature: %s", textPn);

    // Verify the signature with the public key
    if (!VerifySign(pbSignature, dwSignatureSize)) {
        DebugPrint("Error signature");
        return FALSE;
    }
    DebugPrint("Verify the signature success", );
    Status = ERROR_SUCCESS;
    //End workround
cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Verifies that the specified signature matches the specified hash
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a sample KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a sample KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used.
*            PBYTE  pbHashValue              Hash data
*            DWORD  cbHashValue              Size of the hash
*            PBYTE  pbSignature              Signature data
*            DWORD  cbSignaturee             Size of the signature
*            DWORD  dwFlags                  Flags
*
* RETURN :
*            ERROR_SUCCESS                   The signature is a valid signature.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid sample KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
SampleKSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID* pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignaturee) PBYTE pbSignature,
    __in    DWORD   cbSignaturee,
    __in    DWORD   dwFlags)
{
    NTSTATUS    ntStatus = STATUS_INTERNAL_ERROR;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    SAMPLEKSP_KEY* pKey;
    UNREFERENCED_PARAMETER(hProvider);
    DebugPrint("Call function ");
    // Validate input parameters.
    pKey = SampleKspValidateKeyHandle(hKey);
    if (pKey == NULL)
    {
        DebugPrint("Call function ");
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->fFinished == FALSE)
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_KEY_STATE;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if (pbHashValue == NULL || cbHashValue == 0)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    DebugPrint("Call function ");
    if (dwFlags & ~(BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG))
    {
        DebugPrint("Call function ");
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }


    //Verify the signature.
    ntStatus = BCryptVerifySignature(
        pKey->hPublicKey,
        pPaddingInfo,
        pbHashValue,
        cbHashValue,
        pbSignature,
        cbSignaturee,
        dwFlags);

    if (!NT_SUCCESS(ntStatus))
    {
        DebugPrint("Call function ");
        Status = NormalizeNteStatus(Status);
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:

    return Status;
}

SECURITY_STATUS
WINAPI
SampleKSPPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
SampleKSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE* phEvent,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phEvent);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
SampleKSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE* phAgreedSecret,
    __in    DWORD   dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hPrivKey);
    UNREFERENCED_PARAMETER(hPubKey);
    UNREFERENCED_PARAMETER(phAgreedSecret);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
SampleKSPDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc* pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD* pcbResult,
    __in        ULONG                dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    UNREFERENCED_PARAMETER(pwszKDF);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbDerivedKey);
    UNREFERENCED_PARAMETER(cbDerivedKey);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
SampleKSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    return NTE_NOT_SUPPORTED;
}
