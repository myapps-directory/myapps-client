#include <fstream>
#include <string>
#include <vector>

#include <windows.h>

#include <msi.h>
#include <msiquery.h>

using namespace std;
namespace {

std::wstring get_property(MSIHANDLE msi_handle, std::wstring const& name)
{
    DWORD size = 0;

    WCHAR value_buffer[] = L"";
    UINT  status         = MsiGetPropertyW(msi_handle, name.c_str(), value_buffer, &size);

    if (status == ERROR_MORE_DATA) {
        std::vector<wchar_t> buffer(size + 1);
        MsiGetPropertyW(msi_handle, name.c_str(), &buffer[0], &size);
        return std::wstring(&buffer[0]);
    } else {
        return std::wstring();
    }
}

void set_property(MSIHANDLE msi_handle, std::wstring const& name,
    std::wstring const& value)
{
    MsiSetPropertyW(msi_handle, name.c_str(), value.c_str());
}

string env_config_path_prefix()
{
    const char* v = getenv("APPDATA");
    if (v == nullptr) {
        v = getenv("LOCALAPPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\MyApps.dir";
    return r;
}

string env_path_prefix()
{
    const char* v = getenv("LOCALAPPDATA");
    if (v == nullptr) {
        v = getenv("APPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\MyApps.dir";
    return r;
}

int silently_remove_directory(LPCTSTR dir) // Fully qualified name of the directory being   deleted,   without trailing backslash
{
    int   len     = strlen(dir) + 2; // required to set 2 nulls at end of argument to SHFileOperation.
    char* tempdir = (char*)malloc(len);
    memset(tempdir, 0, len);
    strcpy(tempdir, dir);

    SHFILEOPSTRUCT file_op = {
        NULL,
        FO_DELETE,
        tempdir,
        NULL,
        FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT,
        false,
        0,
        ""};
    int ret = SHFileOperation(&file_op);
    free(tempdir);
    return ret; // returns 0 on success, non zero on failure.
}

} // namespace
extern "C" UINT __stdcall UninstallCleanup(MSIHANDLE msi_handle)
{

    silently_remove_directory(env_config_path_prefix().c_str());
    silently_remove_directory(env_path_prefix().c_str());

    return ERROR_SUCCESS;
}