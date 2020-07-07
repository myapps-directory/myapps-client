#include <string>
#include <vector>
#include <fstream>

#include <windows.h>

#include <msi.h>
#include <msiquery.h>
#include "boost/filesystem.hpp"

using namespace std;
namespace{

std::wstring get_property(MSIHANDLE msi_handle, std::wstring const& name)
{
    DWORD size = 0;

    WCHAR value_buffer[] = L"";
    UINT status = MsiGetPropertyW(msi_handle, name.c_str(), value_buffer, &size);

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
    r += "\\MyApps.space";
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
    r += "\\MyApps.space";
    return r;
}


}
extern "C" UINT __stdcall UninstallCleanup(MSIHANDLE msi_handle)
{
#if 1
    boost::system::error_code err;

    boost::filesystem::remove_all(env_config_path_prefix(), err);
    boost::filesystem::remove_all(env_path_prefix(), err);
#endif
    ofstream ofs(env_path_prefix() + "\\myapps.space.uninstall.txt");
    if(ofs){
        ofs << "Deleted: " << env_config_path_prefix() << " and " << env_path_prefix()<< endl;
    }
    return ERROR_SUCCESS;
}