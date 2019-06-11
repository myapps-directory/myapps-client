#include "shortcut_creator.hpp"
#include "solid/system/common.hpp"
#include <sstream>
#include <fstream>
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

namespace ola {
namespace client {
namespace service {

struct ShortcutCreator::Implementation {
    string temp_folder_;

    Implementation(const string& _temp_folder)
        : temp_folder_(_temp_folder)
    {
    }

    string tempLinkFile() {
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

string ShortcutCreator::create(
    const std::string& _name,
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

	if (SUCCEEDED(hres)) {
        ifstream ifs{path, ios::binary};
        ifs.seekg(0, std::ios_base::end);
        std::streamoff sz = ifs.tellg();
        ifs.seekg(0);

        lnk.resize(sz);
        ifs.read(&lnk[0], sz); 
    }
    return lnk;
}

} //namespace service
} //namespace client
} //namespace ola