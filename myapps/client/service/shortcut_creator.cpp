#include "shortcut_creator.hpp"
#include "boost/filesystem.hpp"
#include "solid/system/common.hpp"
#include <fstream>
#include <sstream>
#include <thread>
#ifdef SOLID_ON_WINDOWS

#include "objbase.h"
#include "objidl.h"
#include "shlguid.h"
#include "shobjidl.h"
#include "windows.h"
#include "winnls.h"

#else
#endif

using namespace solid;
using namespace std;
namespace fs = boost::filesystem;

namespace myapps {
namespace client {
namespace service {

struct ShortcutCreator::Implementation {
    string temp_folder_;

    Implementation(const string& _temp_folder)
        : temp_folder_(_temp_folder)
    {
    }

    string tempLinkFile()
    {
        ostringstream oss;
        oss << temp_folder_ << "\\ola_" << this_thread::get_id() << ".lnk";
        return oss.str();
    }
};

ShortcutCreator::ShortcutCreator(const string& _temp_folder)
    : pimpl_{make_pimpl<Implementation>(_temp_folder)}
{
}

ShortcutCreator::~ShortcutCreator()
{
}

size_t ShortcutCreator::create(
    std::ostream&      _ros,
    const std::string& _command,
    const std::string& _arguments,
    const std::string& _run_folder,
    const std::string& _icon,
    const std::string& _description)
{
    HRESULT     hres;
    IShellLink* psl;
    string      path = pimpl_->tempLinkFile();

    CoInitialize(nullptr);
    // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
    // has already been called.
    hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
    if (SUCCEEDED(hres)) {
        IPersistFile* ppf;

        // Set the path to the shortcut target and add the description.
        psl->SetPath(_command.c_str());
        psl->SetArguments(_arguments.c_str());
        psl->SetDescription(_description.c_str());
        psl->SetWorkingDirectory(_run_folder.c_str());
        if (!_icon.empty()) {
            psl->SetIconLocation(_icon.c_str(), 0);
        }

        // Query IShellLink for the IPersistFile interface, used for saving the
        // shortcut in persistent storage.
        hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

        if (SUCCEEDED(hres)) {
            WCHAR wsz[MAX_PATH];

            // Ensure that the string is Unicode.
            MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wsz, MAX_PATH);

            // Save the link by calling IPersistFile::Save.
            hres = ppf->Save(wsz, TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    CoUninitialize();

    string lnk;
    size_t read_count = 0;

    if (SUCCEEDED(hres)) {
        ifstream         ifs{path, ios::binary};
        constexpr size_t buffer_capacity = 4096;
        char             buffer[buffer_capacity];
        if (ifs) {
            while (ifs.read(buffer, buffer_capacity)) {
                read_count += buffer_capacity;
                _ros.write(buffer, buffer_capacity);
            }
            size_t cnt = ifs.gcount();
            _ros.write(buffer, cnt);
            read_count += cnt;
        }
        ifs.close();
        fs::remove(path);
    }
    return read_count;
}

} //namespace service
} //namespace client
} //namespace myapps