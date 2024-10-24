#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#include <AccCtrl.h>
#include <AclAPI.h>
#include <cassert>
#include <strsafe.h>

namespace {
DWORD security_size_  = 0;
char* psecurity_data_ = nullptr;

bool InitSecurityDescriptor()
{
    PSECURITY_DESCRIPTOR psecurity_descriptor = nullptr;
    EXPLICIT_ACCESS      explicit_access[2];
    PACL                 pACL         = nullptr;
    PSID                 pEveryoneSID = nullptr;
    PSID                 pAdminSID    = nullptr;
    bool                 rv;

    SECURITY_ATTRIBUTES sa;

    static SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    static SID_IDENTIFIER_AUTHORITY SIDAuthNT    = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
            SECURITY_WORLD_RID, //SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &pEveryoneSID)) {
        rv = false;
        goto Cleanup;
    }

    if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &pAdminSID)) {
        rv = false;
        goto Cleanup;
    }

    //ZeroMemory(&explicit_access_, 1 * sizeof(EXPLICIT_ACCESS));
    memset(explicit_access, 0, 2 * sizeof(EXPLICIT_ACCESS));

    explicit_access[0].grfAccessPermissions = KEY_ALL_ACCESS; //KEY_READ;
    explicit_access[0].grfAccessMode        = SET_ACCESS;
    explicit_access[0].grfInheritance       = NO_INHERITANCE;
    explicit_access[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    explicit_access[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    explicit_access[0].Trustee.ptstrName    = (LPTSTR)pEveryoneSID;

    // Initialize an EXPLICIT_ACCESS structure for an ACE.
    // The ACE will allow the Administrators group full access to
    // the key.
    explicit_access[1].grfAccessPermissions = KEY_ALL_ACCESS;
    explicit_access[1].grfAccessMode        = SET_ACCESS;
    explicit_access[1].grfInheritance       = NO_INHERITANCE;
    explicit_access[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    explicit_access[1].Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
    explicit_access[1].Trustee.ptstrName    = (LPTSTR)pAdminSID;

    if (ERROR_SUCCESS != SetEntriesInAcl(2, explicit_access, NULL, &pACL)) {
        rv = false;
        goto Cleanup;
    }

    psecurity_descriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (nullptr == psecurity_descriptor) {
        rv = false;
        goto Cleanup;
    }

    if (!InitializeSecurityDescriptor(psecurity_descriptor, SECURITY_DESCRIPTOR_REVISION)) {
        rv = false;
        goto Cleanup;
    }

    // Add the ACL to the security descriptor.
    if (!SetSecurityDescriptorDacl(psecurity_descriptor,
            TRUE, // bDaclPresent flag
            pACL,
            FALSE)) // not a default DACL
    {
        rv = false;
        goto Cleanup;
    }

    //solid_check(SetSecurityDescriptorOwner(psecurity_descriptor_, pAdminSID_, FALSE));
    //solid_check(SetSecurityDescriptorGroup(psecurity_descriptor_, pAdminSID_, FALSE));
    security_size_  = GetSecurityDescriptorLength(psecurity_descriptor);
    psecurity_data_ = new char[security_size_];
    memcpy(psecurity_data_, psecurity_descriptor, security_size_);
    rv = true;

    //sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    //sa.lpSecurityDescriptor = psecurity_descriptor;
    //sa.bInheritHandle       = FALSE;

    //HANDLE hFile = CreateFile(L"test.log", FILE_APPEND_DATA, FILE_SHARE_WRITE, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
    //wprintf(L"CreateFile Error: %u\n", GetLastError());
    //assert(hFile != INVALID_HANDLE_VALUE);
Cleanup:
    if (pEveryoneSID)
        FreeSid(pEveryoneSID);
    if (pACL)
        LocalFree(pACL);
    if (psecurity_descriptor)
        LocalFree(psecurity_descriptor);
    return rv;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (1) {

        InitSecurityDescriptor();
        SECURITY_ATTRIBUTES sa;
        sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)psecurity_data_;
        sa.bInheritHandle       = FALSE;

        HANDLE hFile = CreateFile(L"test.log", FILE_APPEND_DATA, FILE_SHARE_WRITE, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
        wprintf(L"CreateFile Error: %u\n", GetLastError());
        assert(hFile != INVALID_HANDLE_VALUE);
    } else {
        DWORD                    dwRes;
        PSID                     pSystemSID = NULL, pAdminSID = NULL;
        PACL                     pACL = NULL;
        PSECURITY_DESCRIPTOR     pSD  = NULL;
        EXPLICIT_ACCESS          ea[2];
        SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
        SECURITY_ATTRIBUTES      sa;

        // Create a SID for the LOCAL SYSTEM account.
        if (!AllocateAndInitializeSid(&SIDAuthNT, 1,
                SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0,
                &pSystemSID)) {
            wprintf(L"AllocateAndInitializeSid Error: %u", GetLastError());
            goto Cleanup;
        }

        // Initialize an EXPLICIT_ACCESS structure for an ACE.
        // The ACE will allow Everyone read access to the key.
        ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));
        ea[0].grfAccessPermissions = TRUSTEE_ACCESS_ALL;
        ea[0].grfAccessMode        = SET_ACCESS;
        ea[0].grfInheritance       = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[0].Trustee.ptstrName    = (LPTSTR)pSystemSID;

        // Create a SID for the BUILTIN\Administrators group.
        if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0,
                &pAdminSID)) {
            wprintf(L"AllocateAndInitializeSid Error: %u", GetLastError());
            goto Cleanup;
        }

        // Initialize an EXPLICIT_ACCESS structure for an ACE.
        // The ACE will allow the Administrators group full access to
        // the key.
        ea[1].grfAccessPermissions = TRUSTEE_ACCESS_ALL;
        ea[1].grfAccessMode        = SET_ACCESS;
        ea[1].grfInheritance       = NO_INHERITANCE;
        ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
        ea[1].Trustee.ptstrName    = (LPTSTR)pAdminSID;

        // Create a new ACL that contains the new ACEs.
        dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);
        if (ERROR_SUCCESS != dwRes) {
            wprintf(L"SetEntriesInAcl Error: %u", GetLastError());
            goto Cleanup;
        }

        // Initialize a security descriptor.
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (NULL == pSD) {
            wprintf(L"LocalAlloc Error: %u", GetLastError());
            goto Cleanup;
        }

        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
            wprintf(L"InitializeSecurityDescriptor Error: %u", GetLastError());
            goto Cleanup;
        }

        // Add the ACL to the security descriptor.
        if (!SetSecurityDescriptorDacl(pSD,
                TRUE, // bDaclPresent flag
                pACL,
                FALSE)) // not a default DACL
        {
            wprintf(L"SetSecurityDescriptorDacl Error: %u", GetLastError());
            goto Cleanup;
        }

        // Initialize a security attributes structure.
        sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle       = FALSE;
        {
            HANDLE hFile = CreateFile(L"test.log", FILE_APPEND_DATA, FILE_SHARE_WRITE, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
            wprintf(L"CreateFile Error: %u\n", GetLastError());
            assert(hFile != INVALID_HANDLE_VALUE);
        }
    Cleanup:
        wprintf(L"fail\n");
    }

    return 0;
}