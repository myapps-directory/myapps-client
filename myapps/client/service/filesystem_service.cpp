#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <strsafe.h>
#include <winfsp/winfsp.hpp>

#include "solid/system/log.hpp"

#include "myapps/common/utility/encode.hpp"
#include "myapps/common/utility/version.hpp"

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#include "myapps/client/service/engine.hpp"
#include "myapps/client/utility/app_list_file.hpp"
#include "myapps/client/utility/auth_file.hpp"
#include "myapps/client/utility/file_monitor.hpp"
#include "myapps/client/utility/locale.hpp"

#include <future>
#include <iostream>
#include <sstream>
#include <thread>

#include "solid/system/log.hpp"

#include <Shlobj.h>

#include <aclapi.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

#define PROGNAME "myapps_service_filesystem"

#define ALLOCATION_UNIT 4096
#define FULLPATH_SIZE (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define log_info(format, ...) Service::Log(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define log_warn(format, ...) Service::Log(EVENTLOG_WARNING_TYPE, format, __VA_ARGS__)
#define log_fail(format, ...) Service::Log(EVENTLOG_ERROR_TYPE, format, __VA_ARGS__)

#define ConcatPath(FN, FP) (0 == StringCbPrintfW(FP, sizeof FP, L"%s%s", _Path, FN))
#define HandleFromFileDesc(FD) ((FileDesc*)(FD))->Handle

using namespace Fsp;
using namespace std;
using namespace myapps::client;

namespace fs = boost::filesystem;

namespace {

constexpr string_view service_name("myapps_service_filesystem");

const solid::LoggerT logger("myapps::client::service");

struct Parameters {
    wstring        debug_log_file_;
    uint32_t       debug_flags_;
    wstring        mount_point_;
    vector<string> debug_modules_;
    string         debug_addr_;
    string         debug_port_;
    bool           debug_console_;
    bool           debug_buffered_;
    bool           secure_;
    bool           compress_;
    string         secure_prefix_;
    string         path_prefix_;

    string configPath(const string& _path_prefix) const;

    bool                                  parse(ULONG argc, PWSTR* argv);
    boost::program_options::variables_map bootstrapCommandLine(ULONG argc, PWSTR* argv);
    void                                  writeConfigurationFile(string _path, const boost::program_options::options_description& _od, const boost::program_options::variables_map& _vm) const;
};

class FileSystem final : public FileSystemBase {
    myapps::client::service::Engine& rengine_;
    DWORD                            security_size_  = 0;
    char*                            psecurity_data_ = nullptr;
    int64_t                          base_time_      = 0;

public:
    FileSystem(myapps::client::service::Engine& _rengine);
    ~FileSystem();

private:
    myapps::client::service::Engine& engine() const
    {
        return rengine_;
    }

    NTSTATUS InitSecurityDescriptor();

    NTSTATUS Init(PVOID Host) override;
    NTSTATUS GetVolumeInfo(
        VolumeInfo* VolumeInfo) override;
    NTSTATUS GetSecurityByName(
        PWSTR                FileName,
        PUINT32              PFileAttributes /* or ReparsePointIndex */,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        SIZE_T*              PSecurityDescriptorSize) override;
    NTSTATUS Create(
        PWSTR                FileName,
        UINT32               CreateOptions,
        UINT32               GrantedAccess,
        UINT32               FileAttributes,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        UINT64               AllocationSize,
        PVOID*               PFileNode,
        PVOID*               PFileDesc,
        OpenFileInfo*        OpenFileInfo) override;
    NTSTATUS Open(
        PWSTR         FileName,
        UINT32        CreateOptions,
        UINT32        GrantedAccess,
        PVOID*        PFileNode,
        PVOID*        PFileDesc,
        OpenFileInfo* OpenFileInfo) override;
    NTSTATUS Overwrite(
        PVOID     FileNode,
        PVOID     FileDesc,
        UINT32    FileAttributes,
        BOOLEAN   ReplaceFileAttributes,
        UINT64    AllocationSize,
        FileInfo* FileInfo) override;
    VOID Cleanup(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR FileName,
        ULONG Flags) override;
    VOID Close(
        PVOID FileNode,
        PVOID FileDesc) override;
    NTSTATUS Read(
        PVOID  FileNode,
        PVOID  FileDesc,
        PVOID  Buffer,
        UINT64 Offset,
        ULONG  Length,
        PULONG PBytesTransferred) override;
    NTSTATUS Write(
        PVOID     FileNode,
        PVOID     FileDesc,
        PVOID     Buffer,
        UINT64    Offset,
        ULONG     Length,
        BOOLEAN   WriteToEndOfFile,
        BOOLEAN   ConstrainedIo,
        PULONG    PBytesTransferred,
        FileInfo* FileInfo) override;
    NTSTATUS Flush(
        PVOID     FileNode,
        PVOID     FileDesc,
        FileInfo* FileInfo) override;
    NTSTATUS GetFileInfo(
        PVOID     FileNode,
        PVOID     FileDesc,
        FileInfo* FileInfo) override;
    NTSTATUS SetBasicInfo(
        PVOID     FileNode,
        PVOID     FileDesc,
        UINT32    FileAttributes,
        UINT64    CreationTime,
        UINT64    LastAccessTime,
        UINT64    LastWriteTime,
        UINT64    ChangeTime,
        FileInfo* FileInfo) override;
    NTSTATUS SetFileSize(
        PVOID     FileNode,
        PVOID     FileDesc,
        UINT64    NewSize,
        BOOLEAN   SetAllocationSize,
        FileInfo* FileInfo) override;
    NTSTATUS CanDelete(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR FileName) override;
    NTSTATUS Rename(
        PVOID   FileNode,
        PVOID   FileDesc,
        PWSTR   FileName,
        PWSTR   NewFileName,
        BOOLEAN ReplaceIfExists) override;
    NTSTATUS GetSecurity(
        PVOID                FileNode,
        PVOID                FileDesc,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        SIZE_T*              PSecurityDescriptorSize) override;
    NTSTATUS SetSecurity(
        PVOID                FileNode,
        PVOID                FileDesc,
        SECURITY_INFORMATION SecurityInformation,
        PSECURITY_DESCRIPTOR ModificationDescriptor) override;
    NTSTATUS ReadDirectory(
        PVOID  FileNode,
        PVOID  FileDesc,
        PWSTR  Pattern,
        PWSTR  Marker,
        PVOID  Buffer,
        ULONG  Length,
        PULONG PBytesTransferred) override;
    NTSTATUS ReadDirectoryEntry(
        PVOID    FileNode,
        PVOID    FileDesc,
        PWSTR    Pattern,
        PWSTR    Marker,
        PVOID*   PContext,
        DirInfo* DirInfo) override;
};

class FileSystemService final : public Service {
    enum struct WaitStatusE {
        NoWait,
        Wait,
        Done,
        Restart,
    };

    myapps::client::service::Engine      engine_;
    FileSystem                           fs_;
    FileSystemHost                       host_;
    Parameters                           params_;
    mutex                                mutex_;
    condition_variable                   condition_;
    chrono::system_clock::time_point     auth_file_time_point_;
    string                               auth_endpoint_;
    string                               auth_user_;
    string                               auth_token_;
    WaitStatusE                          wait_status_ = WaitStatusE::NoWait;
    myapps::client::utility::FileMonitor file_monitor_;

    fs::path configDirectoryPath() const
    {
        fs::path p = params_.path_prefix_;
        p /= "config";
        return p;
    }

    fs::path authDataFilePath() const
    {
        return configDirectoryPath() / "auth.data";
    }

    fs::path appListDataFilePath() const
    {
        return configDirectoryPath() / "app_list.data";
    }

public:
    FileSystemService();

    bool waitAuthentication();
    void onAuthFileChange(const chrono::system_clock::time_point& _time_point);
    void onAppListFileChange(const chrono::system_clock::time_point& _time_point);

protected:
    NTSTATUS OnStart(ULONG Argc, PWSTR* Argv) override;
    NTSTATUS OnStop() override;

private:
    void guiStart();
    void meStart();
#if 0
    void onGuiFail();
#endif
};
} // namespace

#ifdef SOLID_ON_WINDOWS
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow)
{
    int        argc;
    LPWSTR*    argv                  = CommandLineToArgvW(GetCommandLineW(), &argc);
    const auto m_singleInstanceMutex = CreateMutex(NULL, TRUE, L"MYAPPS_SERVICE_SHARED_MUTEX");
    if (m_singleInstanceMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        return -1; // Exit the app. For MFC, return false from InitInstance.
    }

#else
int wmain(int argc, wchar_t** argv)
{
    const HANDLE m_singleInstanceMutex = INVALID_HANDLE_VALUE;
#endif

    FileSystemService service;
    const auto        rv = service.Run();
    if (!service.waitAuthentication()) {
    } else {
        // we need to restart the service
        TCHAR          szFileName[MAX_PATH];
        vector<WCHAR*> arg_vec;
        for (int i = 0; i < argc; ++i) {
            arg_vec.emplace_back(argv[i]);
        }
        arg_vec.emplace_back(nullptr);
        GetModuleFileName(NULL, szFileName, MAX_PATH);
        if (m_singleInstanceMutex != INVALID_HANDLE_VALUE) {
            ReleaseMutex(m_singleInstanceMutex);
            CloseHandle(m_singleInstanceMutex);
        }
        _wexecv(szFileName, arg_vec.data());
    }
    return rv;
}

namespace std {
std::ostream& operator<<(std::ostream& os, const std::vector<string>& vec)
{
    for (auto item : vec) {
        os << item << ",";
    }
    return os;
}
} // namespace std

namespace {
// TODO: find a better name
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

string env_app_data_path()
{
    const char* v = getenv("APPDATA");
    if (v == nullptr) {
        v = getenv("LOCALAPPDATA");
        if (v == nullptr) {
            v = "c:\\";
        }
    }
    return v;
}

// TODO: find a better name
string env_log_path_prefix()
{
    const char* v = getenv("LOCALAPPDATA");
    if (v == nullptr) {
        v = getenv("APPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\MyApps.dir\\client";
    return r;
}

string env_temp_prefix()
{
    const char* v = getenv("TEMP");
    if (v == nullptr) {
        v = getenv("TMP");
        if (v == nullptr) {
            v = "c:";
        }
    }

    return v;
}

string env_mount_point(){
    const char* home_drive = getenv("HOMEDRIVE");
    const char* home_path  = getenv("HOMEPATH");
    if (home_drive) {
        if (home_path) {
            return string(home_drive)+ "\\" + string(home_path) + "\\MyApps.dir";
        } else {
            return string(home_drive) + "\\MyApps.dir";
        }
    } else {
        return "C:\\MyApps.dir";
    }
}

// -- FileSystemService -------------------------------------------------------

static NTSTATUS EnableBackupRestorePrivileges(VOID)
{
    union {
        TOKEN_PRIVILEGES P;
        UINT8            B[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
    } Privileges;
    HANDLE Token;

    Privileges.P.PrivilegeCount           = 2;
    Privileges.P.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Privileges.P.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(0, SE_BACKUP_NAME, &Privileges.P.Privileges[0].Luid) || !LookupPrivilegeValueW(0, SE_RESTORE_NAME, &Privileges.P.Privileges[1].Luid))
        return FspNtStatusFromWin32(GetLastError());

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FspNtStatusFromWin32(GetLastError());

    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges.P, 0, 0, 0)) {
        CloseHandle(Token);

        return FspNtStatusFromWin32(GetLastError());
    }

    CloseHandle(Token);

    return STATUS_SUCCESS;
}

static ULONG wcstol_deflt(wchar_t* w, ULONG deflt)
{
    wchar_t* endp;
    ULONG    ul = wcstol(w, &endp, 0);
    return L'\0' != w[0] && L'\0' == *endp ? ul : deflt;
}
//-----------------------------------------------------------------------------
// Parameters
//-----------------------------------------------------------------------------
string Parameters::configPath(const std::string& _path_prefix) const
{
    return _path_prefix + "\\config\\" + string(service_name) + ".config";
}
//-----------------------------------------------------------------------------
boost::program_options::variables_map Parameters::bootstrapCommandLine(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;
    boost::program_options::options_description desc{"Bootstrap Options"};
    // clang-format off
    desc.add_options()
        ("version,v", "Version string")
        ("help,h", "Help Message")
        ("config,c", value<string>(), "Configuration File Path")
        ("generate-config", value<bool>()->implicit_value(true)->default_value(false), "Write configuration file and exit")
        ;
    // clang-format off
    variables_map vm;
    store(basic_command_line_parser(argc, argv).options(desc).allow_unregistered().run(), vm);
    notify(vm);
    return vm;
}

bool Parameters::parse(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;
    try {
        string              config_file_path;
        bool                generate_config_file;
        options_description generic(string(service_name) + " generic options");
        // clang-format off
        generic.add_options()
            ("version,v", "Version string")
            ("help,h", "Help Message")
            ("config,c", value<string>(&config_file_path), "Configuration File Path")
            ("generate-config", value<bool>(&generate_config_file)->implicit_value(true)->default_value(false), "Write configuration file and exit")
            ;
        // clang-format on
        options_description config(string(service_name) + " configuration options");
        // clang-format off
        config.add_options()
            ("debug-modules,M", value<std::vector<std::string>>(&this->debug_modules_)->default_value(std::vector<std::string>{"myapps::.*:VIEW", ".*:EWX", "\\*:VIEWX"}), "Debug logging modules")
            ("debug-address,A", value<string>(&debug_addr_)->default_value(""), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&debug_port_)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&debug_console_)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-buffered,S", value<bool>(&this->debug_buffered_)->implicit_value(true)->default_value(true), "Debug unbuffered")
            ("mount-point,m", wvalue<wstring>(&mount_point_)->default_value(myapps::client::utility::widen(env_mount_point()), env_mount_point()), "Mount point")
            ("secure,s", value<bool>(&secure_)->implicit_value(true)->default_value(true), "Use SSL to secure communication")
            ("compress", value<bool>(&compress_)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("secure-prefix", value<std::string>(&secure_prefix_)->default_value("certs"), "Secure Path prefix")
            ("path-prefix", value<std::string>(&path_prefix_)->default_value(env_config_path_prefix()), "Path prefix")
            ;
        // clang-format off
            
        options_description cmdline_options;
        cmdline_options.add(generic).add(config);

        options_description config_file_options;
        config_file_options.add(config);

        options_description visible("Allowed options");
        visible.add(generic).add(config);

        variables_map vm;
        store(basic_command_line_parser(argc, argv).options(cmdline_options).run(), vm);
        
        auto bootstrap = bootstrapCommandLine(argc, argv);
        
        if (bootstrap.count("help") != 0u) {
            cout << visible << endl;
            return false;
        }

        if (bootstrap.count("version") != 0u) {
            cout << myapps::utility::version_full() << endl;
            cout << "SolidFrame: " << solid::version_full() << endl;
            return false;
        }
        
        string cfg_path;
        
        if(bootstrap.count("config")){
            cfg_path = bootstrap["config"].as<std::string>();
        }

        if (cfg_path.empty()) {
            string prefix;
            if (bootstrap.count("path-prefix")) {
                prefix = bootstrap["path-prefix"].as<std::string>();
            }
            else {
                prefix = env_config_path_prefix();
            }
            cfg_path = configPath(prefix);
        }
        
        generate_config_file = bootstrap["generate-config"].as<bool>();
        
        if (generate_config_file) {
            writeConfigurationFile(cfg_path, config_file_options, vm);
            return false;
        }
        
        if (!cfg_path.empty()) {
            ifstream ifs(cfg_path);
            if (!ifs) {
                cout << "cannot open config file: " << cfg_path << endl;
                if (bootstrap.count("config")) {
                    //exit only if the config path was explicitly given
                    return false;
                }
            } else {
                store(parse_config_file(ifs, config_file_options), vm);
            }
        }
        
        notify(vm);
    } catch (exception& e) {
        cout << e.what() << "\n";
        return false;
    }
    return true;
}
//-----------------------------------------------------------------------------
void write_value(std::ostream& _ros, const string& _name, const boost::any& _rav)
{
    if (_rav.type() == typeid(bool)) {
        _ros << _name << '=' << boost::any_cast<bool>(_rav) << endl;
    } else if (_rav.type() == typeid(uint16_t)) {
        _ros << _name << '=' << boost::any_cast<uint16_t>(_rav) << endl;
    } else if (_rav.type() == typeid(uint32_t)) {
        _ros << _name << '=' << boost::any_cast<uint32_t>(_rav) << endl;
    } else if (_rav.type() == typeid(uint64_t)) {
        _ros << _name << '=' << boost::any_cast<uint64_t>(_rav) << endl;
    } else if (_rav.type() == typeid(std::string)) {
        _ros << _name << '=' << boost::any_cast<std::string>(_rav) << endl;
    } else if (_rav.type() == typeid(std::wstring)) {
        _ros << _name << '=' << myapps::client::utility::narrow(boost::any_cast<std::wstring>(_rav)) << endl;
    } else if (_rav.type() == typeid(std::vector<std::string>)) {
        const auto& v = boost::any_cast<const std::vector<std::string>&>(_rav);
        for (const auto& val : v) {
            _ros << _name << '=' << val << endl;
        }
        if (v.empty()) {
            _ros << '#' << _name << '=' << endl;
        }
    } else {
        _ros << _name << '=' << "<UNKNOWN-TYPE>" << endl;
    }
}
//-----------------------------------------------------------------------------
void Parameters::writeConfigurationFile(string _path, const boost::program_options::options_description& _od, const boost::program_options::variables_map& _vm)const
{
    if (boost::filesystem::exists(_path)) {
        
        cout << "File \"" << _path << "\" already exists - renamed to: " << _path << ".old" << endl;
        
        boost::filesystem::rename(_path, _path + ".old");
    }

    ofstream ofs(_path);

    if (!ofs) {
        cout << "Could not open file \"" << _path << "\" for writing" << endl;
        return;
    }
    if (!_od.options().empty()) {
        ofs << '#' << " "<<service_name<<" configuration file" << endl;
        ofs << endl;

        for (auto& opt : _od.options()) {
            ofs << '#' << ' ' << opt->description() << endl;
            const auto& val = _vm[opt->long_name()];
            write_value(ofs, opt->long_name(), val.value());
            ofs << endl;
        }
    }
    ofs.flush();
    ofs.close();
    cout<<service_name<<" configuration file writen: "<<_path<<endl;
}
//-----------------------------------------------------------------------------
// FileSystemService
//-----------------------------------------------------------------------------
FileSystemService::FileSystemService() : Service(L"" PROGNAME), fs_(engine_), host_(fs_)
{
}

string printOpenFlags(const uint32_t _flags)
{
    string str;
    if (_flags & FILE_DIRECTORY_FILE) {
        str += "FILE_DIRECTORY_FILE ";
    }
   
    if (_flags & FILE_WRITE_THROUGH) {
        str += "FILE_WRITE_THROUGH ";
    }
 
    if (_flags & FILE_SEQUENTIAL_ONLY) {
        str += "FILE_SEQUENTIAL_ONLY ";
    }
 
    if (_flags & FILE_NO_INTERMEDIATE_BUFFERING) {
        str += "FILE_NO_INTERMEDIATE_BUFFERING ";
    }
 
    if (_flags & FILE_SYNCHRONOUS_IO_ALERT) {
        str += "FILE_SYNCHRONOUS_IO_ALERT ";
    }
 
    if (_flags & FILE_SYNCHRONOUS_IO_NONALERT) {
        str += "FILE_SYNCHRONOUS_IO_NONALERT ";
    }
   
    if (_flags & FILE_NON_DIRECTORY_FILE) {
        str += "FILE_NON_DIRECTORY_FILE ";
    }
 
    if (_flags & FILE_CREATE_TREE_CONNECTION) {
        str += "FILE_CREATE_TREE_CONNECTION ";
    }
    if (_flags & FILE_COMPLETE_IF_OPLOCKED) {
        str += "FILE_COMPLETE_IF_OPLOCKED ";
    }
    if (_flags & FILE_NO_EA_KNOWLEDGE) {
        str += "FILE_NO_EA_KNOWLEDGE ";
    }
    if (_flags & FILE_OPEN_REMOTE_INSTANCE) {
        str += "FILE_OPEN_REMOTE_INSTANCE ";
    }
    if (_flags & FILE_RANDOM_ACCESS) {
        str += "FILE_RANDOM_ACCESS ";
    }
    if (_flags & FILE_DELETE_ON_CLOSE) {
        str += "FILE_DELETE_ON_CLOSE ";
    }
    if (_flags & FILE_OPEN_BY_FILE_ID) {
        str += "FILE_OPEN_BY_FILE_ID ";
    }
    if (_flags & FILE_OPEN_FOR_BACKUP_INTENT) {
        str += "FILE_OPEN_FOR_BACKUP_INTENT ";
    }
    if (_flags & FILE_NO_COMPRESSION) {
        str += "FILE_NO_COMPRESSION ";
    }
    if (_flags & FILE_OPEN_REQUIRING_OPLOCK) {
        str += "FILE_OPEN_REQUIRING_OPLOCK ";
    }
    if (_flags & FILE_RESERVE_OPFILTER) {
        str += "FILE_RESERVE_OPFILTER ";
    }
    if (_flags & FILE_OPEN_REPARSE_POINT) {
        str += "FILE_OPEN_REPARSE_POINT ";
    }
    if (_flags & FILE_OPEN_NO_RECALL) {
        str += "FILE_OPEN_NO_RECALL ";
    }
    if (_flags & FILE_OPEN_FOR_FREE_SPACE_QUERY) {
        str += "FILE_OPEN_FOR_FREE_SPACE_QUERY ";
    }
    return str;
}

string printFileAttributes(const uint32_t _flags)
{
    string str;
    if (_flags & FILE_ATTRIBUTE_READONLY) {
        str += "FILE_ATTRIBUTE_READONLY ";
    }
    if (_flags & FILE_ATTRIBUTE_SYSTEM) {
        str += "FILE_ATTRIBUTE_SYSTEM ";
    }
    if (_flags & FILE_ATTRIBUTE_DIRECTORY) {
        str += "FILE_ATTRIBUTE_DIRECTORY ";
    }
    if (_flags & FILE_ATTRIBUTE_ARCHIVE) {
        str += "FILE_ATTRIBUTE_ARCHIVE ";
    }
    if (_flags & FILE_ATTRIBUTE_DEVICE) {
        str += "FILE_ATTRIBUTE_DEVICE ";
    }
    if (_flags & FILE_ATTRIBUTE_NORMAL) {
        str += "FILE_ATTRIBUTE_NORMAL ";
    }
    if (_flags & FILE_ATTRIBUTE_TEMPORARY) {
        str += "FILE_ATTRIBUTE_TEMPORARY ";
    }
    if (_flags & FILE_ATTRIBUTE_SPARSE_FILE) {
        str += "FILE_ATTRIBUTE_SPARSE_FILE ";
    }
    if (_flags & FILE_ATTRIBUTE_REPARSE_POINT) {
        str += "FILE_ATTRIBUTE_REPARSE_POINT ";
    }
    if (_flags & FILE_ATTRIBUTE_COMPRESSED) {
        str += "FILE_ATTRIBUTE_COMPRESSED ";
    }
    if (_flags & FILE_ATTRIBUTE_OFFLINE) {
        str += "FILE_ATTRIBUTE_OFFLINE ";
    }
    if (_flags & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) {
        str += "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED ";
    }
    if (_flags & FILE_ATTRIBUTE_ENCRYPTED) {
        str += "FILE_ATTRIBUTE_ENCRYPTED ";
    }
    if (_flags & FILE_ATTRIBUTE_INTEGRITY_STREAM) {
        str += "FILE_ATTRIBUTE_INTEGRITY_STREAM ";
    }
    if (_flags & FILE_ATTRIBUTE_VIRTUAL) {
        str += "FILE_ATTRIBUTE_VIRTUAL ";
    }
    if (_flags & FILE_ATTRIBUTE_NO_SCRUB_DATA) {
        str += "FILE_ATTRIBUTE_NO_SCRUB_DATA ";
    }
    if (_flags & FILE_ATTRIBUTE_EA) {
        str += "FILE_ATTRIBUTE_EA ";
    }
    if (_flags & FILE_ATTRIBUTE_PINNED) {
        str += "FILE_ATTRIBUTE_PINNED ";
    }
    if (_flags & FILE_ATTRIBUTE_UNPINNED) {
        str += "FILE_ATTRIBUTE_UNPINNED ";
    }
    if (_flags & FILE_ATTRIBUTE_RECALL_ON_OPEN) {
        str += "FILE_ATTRIBUTE_RECALL_ON_OPEN ";
    }
    if (_flags & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) {
        str += "FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS ";
    }
    return str;
}


DWORD GetSessionIdOfUser(PCWSTR pszUserName,  
                         PCWSTR pszDomain) 
{ 
    DWORD dwSessionId = 0xFFFFFFFF; 
     
    if (pszUserName == NULL) 
    { 
        // If the user name is not provided, try to get the session attached  
        // to the physical console. The physical console is the monitor,  
        // keyboard, and mouse. 
        dwSessionId = WTSGetActiveConsoleSessionId(); 
    } 
    else 
    { 
        // If the user name is provided, get the session of the provided user.  
        // The same user could have more than one session, this sample just  
        // retrieves the first one found. You can add more sophisticated  
        // checks by requesting different types of information from  
        // WTSQuerySessionInformation. 
 
        PWTS_SESSION_INFO *pSessionsBuffer = NULL; 
        DWORD dwSessionCount = 0; 
 
        // Enumerate the sessions on the current server. 
        if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1,  
            pSessionsBuffer, &dwSessionCount)) 
        { 
            for (DWORD i = 0; (dwSessionId == -1) && (i < dwSessionCount); i++) 
            { 
                DWORD sid = pSessionsBuffer[i]->SessionId; 
 
                // Get the user name from the session ID. 
                PWSTR pszSessionUserName = NULL; 
                DWORD dwSize; 
                if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sid,  
                    WTSUserName, &pszSessionUserName, &dwSize)) 
                { 
                    // Compare with the provided user name (case insensitive). 
                    if (_wcsicmp(pszUserName, pszSessionUserName) == 0) 
                    { 
                        // Get the domain from the session ID. 
                        PWSTR pszSessionDomain = NULL; 
                        if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,  
                            sid, WTSDomainName, &pszSessionDomain, &dwSize)) 
                        { 
                            // Compare with the provided domain (case insensitive). 
                            if (_wcsicmp(pszDomain, pszSessionDomain) == 0) 
                            { 
                                // The session of the provided user is found. 
                                dwSessionId = sid; 
                            } 
                            WTSFreeMemory(pszSessionDomain); 
                        } 
                    } 
                    WTSFreeMemory(pszSessionUserName); 
                } 
            } 
 
            WTSFreeMemory(pSessionsBuffer); 
            pSessionsBuffer = NULL; 
            dwSessionCount = 0; 
 
            // Cannot find the session of the provided user. 
            if (dwSessionId == 0xFFFFFFFF) 
            { 
                SetLastError(ERROR_INVALID_PARAMETER); 
            } 
        } 
    } 
 
    return dwSessionId; 
} 
 
 
BOOL DisplayInteractiveMessage(DWORD dwSessionId, 
                               PWSTR pszTitle,  
                               PWSTR pszMessage, 
                               DWORD dwStyle,  
                               BOOL fWait,  
                               DWORD dwTimeoutSeconds,  
                               DWORD *pResponse) 
{ 
    DWORD cbTitle = wcslen(pszTitle) * sizeof(*pszTitle); 
    DWORD cbMessage = wcslen(pszMessage) * sizeof(*pszMessage); 
 
    return WTSSendMessage( 
        WTS_CURRENT_SERVER_HANDLE,  // The current server 
        dwSessionId,                // Identify the session to display message 
        pszTitle,                   // Title bar of the message box 
        cbTitle,                    // Length, in bytes, of the title 
        pszMessage,                 // Message to display 
        cbMessage,                  // Length, in bytes, of the message 
        dwStyle,                    // Contents and behavior of the message 
        dwTimeoutSeconds,           // Timeout of the message in seconds 
        pResponse,                  // Receive the user's response 
        fWait                       // Whether wait for user's response or not 
        ); 
}

bool CreateInteractiveProcess(const wstring &_cmd_line, 
                              BOOL fWait, 
                              DWORD dwTimeout, 
                              DWORD *pExitCode)
{
	STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
	LPWSTR p;
    // Start the child process. 
    if( !CreateProcess( NULL,   // No module name (use command line)
        const_cast<wchar_t*>(_cmd_line.c_str()),        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf( "CreateProcess failed (%d).\n", GetLastError() );
        return false;
    }

	return true;
}

void WriteEventLogEntry(PWSTR pszMessage, WORD wType) 
{ 
	const PWSTR m_name = L"myapps_service_filesystem"; 
    HANDLE hEventSource = NULL; 
    LPCWSTR lpszStrings[2] = { NULL, NULL }; 
 
    hEventSource = RegisterEventSource(NULL, m_name); 
    if (hEventSource) 
    { 
        lpszStrings[0] = m_name; 
        lpszStrings[1] = pszMessage; 
 
        ReportEvent(hEventSource,  // Event log handle 
            wType,                 // Event type 
            0,                     // Event category 
            0,                     // Event identifier 
            NULL,                  // No security identifier 
            2,                     // Size of lpszStrings array 
            0,                     // No binary data 
            lpszStrings,           // Array of strings 
            NULL                   // No binary data 
            ); 
 
        DeregisterEventSource(hEventSource); 
    } 
}
void WriteErrorLogEntry(PWSTR pszFunction, DWORD dwError) 
{ 
    wchar_t szMessage[260]; 
    StringCchPrintf(szMessage, ARRAYSIZE(szMessage),  
        L"%s failed w/err 0x%08lx", pszFunction, dwError); 
    WriteEventLogEntry(szMessage, EVENTLOG_ERROR_TYPE); 
} 

void FileSystemService::onAuthFileChange(const chrono::system_clock::time_point& _time_point)
{
    const chrono::system_clock::time_point    empty_time_point;

    unique_lock<mutex> lock(mutex_);
    string endpoint;
    string user;
    string token;
    myapps::client::utility::auth_read(authDataFilePath(), endpoint, user, token);
    auth_file_time_point_ = empty_time_point;//reset the timepoint so we can do the next auth_update
    
    if((auth_endpoint_.empty() || endpoint == auth_endpoint_) && (auth_user_.empty() || user == auth_user_)){
        auth_endpoint_ = endpoint;
        auth_user_ = user;

        if(token.empty()){//logged out
            auth_token_.clear();
            if(wait_status_ == WaitStatusE::Wait){
                wait_status_ = WaitStatusE::Done;
                condition_.notify_one();
            }else{
                wait_status_ = WaitStatusE::Wait;
                Stop();
            }
            return;
        }else{
            auth_token_ = token;
            if(wait_status_ == WaitStatusE::Wait){
                wait_status_ = WaitStatusE::Done;
                condition_.notify_one();
            }
            else {
                lock.unlock();
                engine_.relogin();
            }
        }
    }else{
        auth_token_.clear();
        if(wait_status_ == WaitStatusE::Wait){
            wait_status_ = WaitStatusE::Done;
            condition_.notify_one();
        }else{
            wait_status_ = WaitStatusE::Restart;
            Stop();
        }
        return;
    }
}

void FileSystemService::onAppListFileChange(const chrono::system_clock::time_point& _time_point)
{
    engine_.appListUpdate();
}

bool FileSystemService::waitAuthentication()
{
    unique_lock<mutex> lock(mutex_);
    if(wait_status_ == WaitStatusE::NoWait){
        return false;
    }else if(wait_status_ == WaitStatusE::Restart){
        return true;
    }else{
        while(wait_status_ == WaitStatusE::Wait){
            condition_.wait(lock);
        }
        wait_status_ = WaitStatusE::NoWait;
        return true;
    }
}

NTSTATUS FileSystemService::OnStart(ULONG argc, PWSTR *argv)
{
    SetEnvironmentVariable(L"QT_QPA_PLATFORM_PLUGIN_PATH", L".\\platforms");
    try {
        if(!params_.parse(argc, argv)){
            return STATUS_UNSUCCESSFUL;
        }
    } catch (exception& e) {
        cout << e.what() << "\n";
        return STATUS_UNSUCCESSFUL;
    }

#ifndef SOLID_ON_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#endif

    if (params_.debug_addr_.size() && params_.debug_port_.size()) {
        solid::log_start(
            params_.debug_addr_.c_str(),
            params_.debug_port_.c_str(),
            params_.debug_modules_,
            params_.debug_buffered_);

    } else if (params_.debug_console_) {
        solid::log_start(std::cerr, params_.debug_modules_);
    } else {
        solid::log_start(
            (env_log_path_prefix() + "\\log\\service").c_str(),
            params_.debug_modules_,
            params_.debug_buffered_,
            3,
            1024 * 1024 * 64);
    }
    solid_log(solid::generic_logger, Error, "Start logging. Mount point: "<< utility::narrow(params_.mount_point_));
    {
        namespace fs = boost::filesystem;
        boost::system::error_code err;
        if(fs::is_directory(params_.mount_point_, err)){
            if(fs::is_empty(params_.mount_point_, err)){
                solid_log(solid::generic_logger, Info, "Removing existing mount dir " << utility::narrow(params_.mount_point_));
                fs::remove(params_.mount_point_, err);
                if (err) {
                    solid_log(solid::generic_logger, Error, "cannot remove mount dir "<< utility::narrow(params_.mount_point_) <<" "<<err.message());
                    return STATUS_UNSUCCESSFUL;
                }
            }else{
                solid_log(solid::generic_logger, Error, "cannot mount file system - non empty directory exists instead: "<< utility::narrow(params_.mount_point_));
                log_fail(L"cannot mount file system - directory exists instead %s", params_.mount_point_.c_str());
                return STATUS_UNSUCCESSFUL;
            }
        }else if(fs::is_regular(params_.mount_point_, err)){
            solid_log(solid::generic_logger, Error, "cannot mount file system - file exists instead: "<< utility::narrow(params_.mount_point_));
            log_fail(L"cannot mount file system - file exists instead %s", params_.mount_point_.c_str());
            return STATUS_UNSUCCESSFUL;
        }
        else if (fs::is_regular_file(params_.mount_point_, err)){
            solid_log(solid::generic_logger, Error, "cannot mount file system - regular file exists instead: "<< utility::narrow(params_.mount_point_));
            log_fail(L"cannot mount file system - file exists instead %s", params_.mount_point_.c_str());
            return STATUS_UNSUCCESSFUL;
        }
        else if (fs::is_symlink(params_.mount_point_, err)) {
            solid_log(solid::generic_logger, Warning, "Removing in the way symlink: "<<utility::narrow(params_.mount_point_));
            fs::remove(params_.mount_point_, err);
            if (err) {
                solid_log(solid::generic_logger, Error, "cannot remove symlink " << utility::narrow(params_.mount_point_) << ": " << err.message());
                return STATUS_UNSUCCESSFUL;
            }
        }
        else if (fs::is_other(params_.mount_point_, err)) {
            solid_log(solid::generic_logger, Error, "cannot mount file system - other filesystem item exists instead: "<< utility::narrow(params_.mount_point_));
            log_fail(L"cannot mount file system - file exists instead %s", params_.mount_point_.c_str());
            return STATUS_UNSUCCESSFUL;
        }
        else {
            solid_log(solid::generic_logger, Info, "Mount point does not exist");
        }
        if (err) {
            solid_log(solid::generic_logger, Error, "error " << err.message());
        }
    }
    {
        boost::system::error_code err;
        fs::create_directories( configDirectoryPath(), err);
    }
    wait_status_ = WaitStatusE::Wait;

    this->file_monitor_.add(
        authDataFilePath(),
        [this](const fs::path& _dir, const fs::path& _name, const chrono::system_clock::time_point& _time_point) mutable {
            onAuthFileChange(_time_point);
        }
    );
    
    this->file_monitor_.start();

    waitAuthentication();
    
    myapps::client::service::Configuration cfg;

    {
        lock_guard<mutex> lock(mutex_);
        if(auth_token_.empty()){
            wait_status_ = WaitStatusE::Wait;
            guiStart();
            return STATUS_UNSUCCESSFUL;
        }
        cfg.auth_endpoint_ = auth_endpoint_;
    }
    cfg.secure_ = params_.secure_;
    cfg.compress_ = params_.compress_;
    cfg.secure_prefix_ = params_.secure_prefix_;
	cfg.path_prefix_ = params_.path_prefix_;
	cfg.mount_prefix_ = utility::narrow(params_.mount_point_);
	cfg.temp_folder_ = env_temp_prefix();
    cfg.app_list_path_ = appListDataFilePath().string();
    cfg.auth_get_token_fnc_ = [this](){
        lock_guard<mutex> lock(mutex_);
        return auth_token_;
    };

    cfg.auth_on_response_fnc_ = [this](uint32_t _error, const std::string& _message){
        if(_error == 0 && !_message.empty()){
            lock_guard<mutex> lock(mutex_);
            auth_token_ = _message;
            myapps::client::utility::auth_update(authDataFilePath(), auth_file_time_point_, auth_endpoint_, auth_user_, auth_token_);
        }else if(_error != 0){
            lock_guard<mutex> lock(mutex_);
            guiStart();
        }
    };

#if 0
	cfg.gui_fail_fnc_ = [this](){
		onGuiFail();
	};
	cfg.gui_start_fnc_ = [this](const string &_endpoint){
		onGuiStart(_endpoint, _port);
	};
#endif
    cfg.folder_update_fnc_ = [this](const std::string &_folder){
        SHChangeNotify(SHCNE_UPDATEDIR, SHCNF_PATH | SHCNF_FLUSHNOWAIT, params_.mount_point_.c_str(), NULL);
    };

    cfg.invalidate_cache_fnc_ = [this](const std::string &_app){
        //TODO: fix - seems not to work for what is needed
        
        fs::path app_path = fs::path(params_.mount_point_) / utility::widen(_app);

        engine_.post([app_path](myapps::client::service::Engine &){
            boost::system::error_code err;

            solid_log(solid::generic_logger, Info, "Before remove_all application ["<<app_path.generic_string()<< "]");
            
            fs::remove_all(app_path, err);

            if(err){
                solid_log(solid::generic_logger, Error, "Error deleting application ["<<app_path.generic_string()<<"]: "<<err.message());
            }
        });
    };
    
    engine_.start(cfg);
	
    this->file_monitor_.add(
        appListDataFilePath(),
        [this](const fs::path& _dir, const fs::path& _name, const chrono::system_clock::time_point& _time_point) mutable {
            onAppListFileChange(_time_point);
        }
    );
    
    NTSTATUS  Result = STATUS_SUCCESS;
	ULONG     DebugFlags     = 0;
	
	EnableBackupRestorePrivileges();

    solid_log(solid::generic_logger, Info, "getmaxstdio = " << _getmaxstdio());

    int rv = _setmaxstdio(8192);
    (void)rv;

    solid_log(solid::generic_logger, Info, "getmaxstdio = " << _getmaxstdio());

	Result = host_.Mount(const_cast<PWSTR>(params_.mount_point_.c_str()), 0, FALSE, DebugFlags);
    if (!NT_SUCCESS(Result)) {
		log_fail(L"cannot mount file system");
		return Result;
	}
	
    return Result;
}

NTSTATUS FileSystemService::OnStop()
{
    host_.Unmount();
    engine_.stop();
    return STATUS_SUCCESS;
}

wstring a2w(const string &_a) {
	return wstring(_a.begin(), _a.end());
}

void FileSystemService::guiStart(){
	wostringstream oss;
	oss<<L"myapps_auth.exe";
    DWORD dwExitCode;
    if (!CreateInteractiveProcess(oss.str(), FALSE, 0, 
        &dwExitCode))
    {
        // Log the error and exit.
        WriteErrorLogEntry((PWSTR)L"CreateInteractiveProcess", GetLastError());
        return;
    }
}

void FileSystemService::meStart(){
	wostringstream oss;
	oss<<L"myapps_auth.exe";
    DWORD dwExitCode;
    if (!CreateInteractiveProcess(oss.str(), FALSE, 0, 
        &dwExitCode))
    {
        // Log the error and exit.
        WriteErrorLogEntry((PWSTR)L"CreateInteractiveProcess", GetLastError());
        return;
    }
}

#if 0
void FileSystemService::onGuiFail(){
	DWORD dwSessionId = GetSessionIdOfUser(NULL, NULL); 
    if (dwSessionId == 0xFFFFFFFF) 
    { 
        // Log the error and exit. 
        WriteErrorLogEntry(L"GetSessionIdOfUser", GetLastError()); 
        return; 
    } 
 
    // Display an interactive message in the session. 
    wchar_t szTitle[] = L"Error"; 
    wchar_t szMessage[] = L"Authentication failure - stoping the service"; 
    DWORD dwResponse; 
    if (!DisplayInteractiveMessage(dwSessionId, szTitle, szMessage, MB_OK,  
        TRUE, 10 /*seconds*/, &dwResponse)) 
    { 
        // Log the error and exit. 
        WriteErrorLogEntry(L"DisplayInteractiveMessage", GetLastError()); 
        return;
    } 

	std::thread  t{&FileSystemService::Stop, this};
	t.detach();
}
#endif

// -- FileSystem --------------------------------------------------------------

enum struct ErrorE {
	Success = 0,
};

NTSTATUS error_to_status(const ErrorE _err) {
	switch(_err){
		case ErrorE::Success:
			return STATUS_SUCCESS;
		default:
			return STATUS_UNSUCCESSFUL;
	};
}

inline uint32_t node_flags_to_attributes(const myapps::client::service::NodeFlagsT _node_flags){
	using myapps::client::service::NodeFlagsE;
	using myapps::client::service::NodeFlagsT;
	uint32_t attr = 0;

	if(_node_flags & node_flag(NodeFlagsE::Directory)){
		attr |= FILE_ATTRIBUTE_DIRECTORY;
	}
	if(_node_flags & node_flag(NodeFlagsE::File)){
		attr |= FILE_ATTRIBUTE_NORMAL;
	}
	if(_node_flags & node_flag(NodeFlagsE::Hidden)){
		attr |= FILE_ATTRIBUTE_HIDDEN;
	}
    if((_node_flags & node_flag(NodeFlagsE::PendingDelete)) == 0){
        attr |= FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    }else{
        attr |= 0;
    }

	return attr;
}

//-----------------------------------------------------------------------------

FileSystem::FileSystem(myapps::client::service::Engine &_rengine) :  rengine_(_rengine)
{
}

FileSystem::~FileSystem()
{

	delete []psecurity_data_;
}

NTSTATUS FileSystem::InitSecurityDescriptor(){
	DWORD sz= 0;
	auto path = myapps::client::utility::widen(env_app_data_path());
	GetFileSecurity(
		path.c_str(),
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		nullptr,
		0,
		&sz
	);

	if(sz){
		psecurity_data_ = new char[sz];
		if(GetFileSecurity(
			path.c_str(),
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			(PSECURITY_DESCRIPTOR)psecurity_data_,
			sz,
			&sz)
		){
			security_size_ = sz;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_MEMORY_NOT_ALLOCATED;
}

NTSTATUS FileSystem::Init(PVOID Host0)
{
    FileSystemHost *Host = (FileSystemHost *)Host0;

	base_time_ = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count() * 10 + 116444736000000000LL;

    Host->SetSectorSize(ALLOCATION_UNIT);
    Host->SetSectorsPerAllocationUnit(1);
    Host->SetFileInfoTimeout(1000);
    Host->SetCaseSensitiveSearch(FALSE);
    Host->SetCasePreservedNames(TRUE);
    Host->SetUnicodeOnDisk(TRUE);
    Host->SetPersistentAcls(TRUE);
    Host->SetPostCleanupWhenModifiedOnly(TRUE);
    Host->SetPassQueryDirectoryPattern(TRUE);
    Host->SetVolumeCreationTime(base_time_);
    Host->SetVolumeSerialNumber(0);
    Host->SetFlushAndPurgeOnCleanup(TRUE);
    Host->SetReparsePoints(TRUE);
    Host->SetReparsePointsAccessCheck(FALSE);
    //Host->SetRejectIrpPriorToTransact0(1);

	return InitSecurityDescriptor();
}

NTSTATUS FileSystem::GetVolumeInfo(
    VolumeInfo *VolumeInfo)
{
    WCHAR Root[MAX_PATH];
    ULARGE_INTEGER TotalSize, FreeSize;

    VolumeInfo->TotalSize = 1024;
    VolumeInfo->FreeSize = 0;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetSecurityByName(
    PWSTR FileName,
    PUINT32 PFileAttributes/* or ReparsePointIndex */,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T *PSecurityDescriptorSize)
{
    using myapps::client::service::NodeFlagsT;
    
    if(PFileAttributes != nullptr){
		++FileName;
        NodeFlagsT node_flags;
	    uint64_t size = 0;
        int64_t  base_time = 0;
        if (engine().info(FileName, node_flags, size, base_time)) {
            *PFileAttributes = node_flags_to_attributes(node_flags);
        }
        else {
            return NtStatusFromWin32(ERROR_PATH_NOT_FOUND);
        }
    }
    
	if(PSecurityDescriptorSize != nullptr){

		if (this->security_size_ > *PSecurityDescriptorSize)
        {
            *PSecurityDescriptorSize = this->security_size_;
            return STATUS_BUFFER_OVERFLOW;
        }
		*PSecurityDescriptorSize = this->security_size_;
	}

	if(SecurityDescriptor != nullptr){
		solid_check(IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR )psecurity_data_));
		memcpy(SecurityDescriptor, this->psecurity_data_, this->security_size_);
	}
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Create(
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    UINT32 FileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    UINT64 AllocationSize,
    PVOID *PFileNode,
    PVOID *PFileDesc,
    OpenFileInfo *OpenFileInfo)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::Open(
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    PVOID *PFileNode,
    PVOID *PFileDesc,
    OpenFileInfo *OpenFileInfo)
{
    //skip the first separator
    ++FileName;
    *PFileDesc = engine().open(FileName, CreateOptions, GrantedAccess);

    if(*PFileDesc != nullptr){
        solid_log(solid::generic_logger, Info, "Open ["<<utility::narrow(FileName)<<"] ["<<printOpenFlags(CreateOptions)<<']');
        return GetFileInfo(*PFileNode, *PFileDesc, &OpenFileInfo->FileInfo);
    }else{
        return NtStatusFromWin32(ERROR_FILE_NOT_FOUND);
    }
}

NTSTATUS FileSystem::Overwrite(
    PVOID FileNode,
    PVOID pFileDesc,
    UINT32 FileAttributes,
    BOOLEAN ReplaceFileAttributes,
    UINT64 AllocationSize,
    FileInfo *FileInfo)
{
    return STATUS_SUCCESS;
}

VOID FileSystem::Cleanup(
    PVOID /*pFileNode*/,
    PVOID pFileDesc,
    PWSTR FileName,
    ULONG Flags)
{
    if (Flags & CleanupDelete) {
		//NOTE: it might never be called for read-only filesystems
        engine().cleanup(static_cast<service::Descriptor*>(pFileDesc));
    }
}

VOID FileSystem::Close(
    PVOID pFileNode,
    PVOID pFileDesc)
{
    PVOID &dir_buf = engine().buffer(*static_cast<service::Descriptor*>(pFileDesc));
    FileSystem::DeleteDirectoryBuffer(&dir_buf);
    dir_buf = nullptr;
	engine().close(static_cast<service::Descriptor*>(pFileDesc));
}

NTSTATUS FileSystem::Read(
    PVOID FileNode,
    PVOID pFileDesc,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    PULONG PBytesTransferred)
{
    if(engine().read(static_cast<service::Descriptor*>(pFileDesc), Buffer, Offset, Length, *PBytesTransferred)){
        if (*PBytesTransferred == 0) {
            return  NtStatusFromWin32(ERROR_HANDLE_EOF);
        }
        return STATUS_SUCCESS;
    }else{
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS FileSystem::Write(
    PVOID FileNode,
    PVOID pFileDesc,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    BOOLEAN WriteToEndOfFile,
    BOOLEAN ConstrainedIo,
    PULONG PBytesTransferred,
    FileInfo *FileInfo)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::Flush(
    PVOID FileNode,
    PVOID pFileDesc,
    FileInfo *FileInfo)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::GetFileInfo(
    PVOID /*pFileNode*/,
    PVOID pFileDesc,
    FileInfo *FileInfo)
{
	using myapps::client::service::NodeFlagsT;
    NodeFlagsT node_flags;
	uint64_t size = 0;
    int64_t  base_time = 0;

	engine().info(static_cast<service::Descriptor*>(pFileDesc), node_flags, size, base_time);

	FileInfo->FileAttributes = node_flags_to_attributes(node_flags);
    FileInfo->ReparseTag     = 0;
    FileInfo->FileSize       = size;
    FileInfo->AllocationSize = (FileInfo->FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    FileInfo->CreationTime   = base_time_;
    FileInfo->LastAccessTime = base_time_;
    FileInfo->LastWriteTime  = base_time_;
    FileInfo->ChangeTime     = FileInfo->LastWriteTime;
    FileInfo->IndexNumber    = 0;
    FileInfo->HardLinks      = 0;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::SetBasicInfo(
    PVOID FileNode,
    PVOID pFileDesc,
    UINT32 FileAttributes,
    UINT64 CreationTime,
    UINT64 LastAccessTime,
    UINT64 LastWriteTime,
    UINT64 ChangeTime,
    FileInfo *FileInfo)
{
    if (FileAttributes != INVALID_FILE_ATTRIBUTES)
    {
        solid_log(solid::generic_logger, Info, "["<<pFileDesc<<"] Attributes ["<<printFileAttributes(FileAttributes)<<']');
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::SetFileSize(
    PVOID FileNode,
    PVOID pFileDesc,
    UINT64 NewSize,
    BOOLEAN SetAllocationSize,
    FileInfo *FileInfo)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::CanDelete(
    PVOID FileNode,
    PVOID pFileDesc,
    PWSTR FileName)
{
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Rename(
    PVOID FileNode,
    PVOID FileDesc,
    PWSTR FileName,
    PWSTR NewFileName,
    BOOLEAN ReplaceIfExists)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::GetSecurity(
    PVOID FileNode,
    PVOID pFileDesc,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T *PSecurityDescriptorSize)
{
    if(PSecurityDescriptorSize != nullptr){

		if (this->security_size_ > *PSecurityDescriptorSize)
        {
            *PSecurityDescriptorSize = this->security_size_;
            return STATUS_BUFFER_OVERFLOW;
        }
		*PSecurityDescriptorSize = this->security_size_;
	}

	if(SecurityDescriptor != nullptr){
		solid_check(IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR )psecurity_data_));
		memcpy(SecurityDescriptor, this->psecurity_data_, this->security_size_);
	}

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::SetSecurity(
    PVOID FileNode,
    PVOID pFileDesc,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS FileSystem::ReadDirectory(
    PVOID pFileNode,
    PVOID pFileDesc,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID Buffer,
    ULONG Length,
    PULONG PBytesTransferred)
{
    //return static_cast<Descriptor*>(pFileDesc)->readDirectory(*this,  FileNode, Pattern, Marker, Buffer, Length, PBytesTransferred);
    return BufferedReadDirectory(&engine().buffer(*static_cast<service::Descriptor*>(pFileDesc)),
		    pFileNode, pFileDesc, Pattern, Marker, Buffer, Length, PBytesTransferred);
}

NTSTATUS FileSystem::ReadDirectoryEntry(
    PVOID pFileNode,
    PVOID pFileDesc,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID *pContext,
    DirInfo *DirInfo)
{
	using namespace myapps::client::service;
    wstring	    name;
	uint64_t	size = 0;
    int64_t     base_time = base_time_;
	uint32_t    attributes = 0;
	NodeFlagsT	node_flags;

    if(engine().list(static_cast<service::Descriptor*>(pFileDesc), *pContext, name, node_flags, size, base_time)){
		attributes = node_flags_to_attributes(node_flags);
	}else{
		return STATUS_NO_MORE_FILES;
	}

	memset(DirInfo, 0, sizeof *DirInfo);
    
    DirInfo->Size = (UINT16)(FIELD_OFFSET(FileSystem::DirInfo, FileNameBuf) + name.size() * sizeof(WCHAR));
    DirInfo->FileInfo.FileAttributes = attributes;
    DirInfo->FileInfo.ReparseTag = 0;
    DirInfo->FileInfo.FileSize = size;
    DirInfo->FileInfo.AllocationSize = (size + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT * ALLOCATION_UNIT;
    DirInfo->FileInfo.CreationTime = base_time;
    DirInfo->FileInfo.LastAccessTime = base_time;
    DirInfo->FileInfo.LastWriteTime = base_time;
    DirInfo->FileInfo.ChangeTime = DirInfo->FileInfo.LastWriteTime;
    DirInfo->FileInfo.IndexNumber = 0;
    DirInfo->FileInfo.HardLinks = 0;
    memcpy(DirInfo->FileNameBuf, name.c_str(), name.size() * sizeof(WCHAR));
	return STATUS_SUCCESS;
}


//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
}//namespace