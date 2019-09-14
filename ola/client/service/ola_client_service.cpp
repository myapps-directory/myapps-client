#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <strsafe.h>
#include <winfsp.hpp>

#include "solid/system/log.hpp"

#include "ola/common/utility/encode.hpp"

#include "ola/common/ola_front_protocol.hpp"

#include "boost/program_options.hpp"

#include "ola/client/service/engine.hpp"
#include "ola/client/utility/locale.hpp"

#include <iostream>
#include <sstream>

#include "solid/system/log.hpp"

#include <aclapi.h>
#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

#define PROGNAME "ola-fs"

#define ALLOCATION_UNIT 4096
#define FULLPATH_SIZE (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define log_info(format, ...) Service::Log(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define log_warn(format, ...) Service::Log(EVENTLOG_WARNING_TYPE, format, __VA_ARGS__)
#define log_fail(format, ...) Service::Log(EVENTLOG_ERROR_TYPE, format, __VA_ARGS__)

#define ConcatPath(FN, FP) (0 == StringCbPrintfW(FP, sizeof FP, L"%s%s", _Path, FN))
#define HandleFromFileDesc(FD) ((FileDesc*)(FD))->Handle

using namespace Fsp;
using namespace std;
using namespace ola::client;

namespace {

const solid::LoggerT logger("ola::client::service");

struct Parameters {
    wstring        debug_log_file_;
    uint32_t       debug_flags_;
    wstring        mount_point_;
    vector<string> debug_modules_ = {"ola::.*:VIEW"};
    string         debug_addr_;
    string         debug_port_;
    bool           debug_console_;
    bool           debug_buffered_;
    bool           secure_;
    bool           compress_;
    string         front_endpoint_;

    bool parse(ULONG argc, PWSTR* argv);
};

class FileSystem final : public FileSystemBase {
    ola::client::service::Engine& rengine_;
    DWORD                         security_size_  = 0;
    char*                         psecurity_data_ = nullptr;
    int64_t                       base_time_      = 0;

public:
    FileSystem(ola::client::service::Engine& _rengine);
    ~FileSystem();

private:
    ola::client::service::Engine& engine() const
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
    ola::client::service::Engine engine_;
    FileSystem                   fs_;
    FileSystemHost               host_;
    Parameters                   params_;

public:
    FileSystemService();

protected:
    NTSTATUS OnStart(ULONG Argc, PWSTR* Argv) override;
    NTSTATUS OnStop() override;

private:
    void onGuiStart(int _port);
    void onGuiFail();
};
} //namespace

#ifdef SOLID_ON_WINDOWS
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow)
{
    int     argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
#else
int wmain(int argc, wchar_t** argv)
{
#endif
#if 0
    SetWindowPos(GetConsoleWindow(), NULL, 5000, 5000, 0, 0, 0);
    ShowWindow(GetConsoleWindow(), SW_HIDE);
#endif
    return FileSystemService().Run();
}

namespace {
//TODO: find a better name
string envConfigPathPrefix()
{
    const char* v = getenv("APPDATA");
    if (v == nullptr) {
        v = getenv("LOCALAPPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\OLA";
    return r;
}

string envAppDataPath()
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

//TODO: find a better name
string envLogPathPrefix()
{
    const char* v = getenv("LOCALAPPDATA");
    if (v == nullptr) {
        v = getenv("APPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\OLA\\client";
    return r;
}

string envTempPrefix()
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

bool Parameters::parse(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;

    options_description desc("ola_auth_service");
    // clang-format off
    desc.add_options()
        ("help,h", "List program options")
        ("debug-flags,F", value<uint32_t>(&debug_flags_), "Debug logging flags")
        ("debug-log-file", wvalue<wstring>(&debug_log_file_), "Debug log file")
        ("debug-modules,M", value<vector<string>>(&debug_modules_), "Debug logging modules")
        ("debug-address,A", value<string>(&debug_addr_), "Debug server address (e.g. on linux use: nc -l 9999)")
        ("debug-port,P", value<string>(&debug_port_)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
        ("debug-console,C", value<bool>(&debug_console_)->implicit_value(true)->default_value(false), "Debug console")
        ("debug-buffered,S", value<bool>(&debug_buffered_)->implicit_value(true)->default_value(false), "Debug buffered")
        ("mount-point,m", wvalue<wstring>(&mount_point_)->default_value(L"C:\\ola", "c:\\ola"), "Mount point")
        ("secure,s", value<bool>(&secure_)->implicit_value(true)->default_value(false), "Use SSL to secure communication")
        ("compress", value<bool>(&compress_)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
        ("front", value<std::string>(&front_endpoint_)->default_value(string("192.168.32.130:") + ola::front::default_port()), "OLA Front Endpoint");
    // clang-format off
    variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);
    if (vm.count("help")) {
        cout << desc << "\n";
        return true;
    }
    return false;

}

FileSystemService::FileSystemService() : Service(L"" PROGNAME), fs_(engine_), host_(fs_)
{
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
	PWSTR m_name = L"ola_client_service"; 
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

NTSTATUS FileSystemService::OnStart(ULONG argc, PWSTR *argv)
{

    try {
        if(params_.parse(argc, argv)){
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
            (envLogPathPrefix() + "\\log\\service").c_str(),
            params_.debug_modules_,
            params_.debug_buffered_,
            3,
            1024 * 1024 * 64);
    }

    ola::client::service::Configuration cfg;
    cfg.secure_ = params_.secure_;
    cfg.compress_ = params_.compress_;
    cfg.front_endpoint_ = params_.front_endpoint_;
	cfg.path_prefix_ = envConfigPathPrefix();
	cfg.mount_prefix_ = utility::narrow(params_.mount_point_);
	cfg.temp_folder_ = envTempPrefix();
	cfg.gui_fail_fnc_ = [this](){
		onGuiFail();
	};
	cfg.gui_start_fnc_ = [this](int _port){
		onGuiStart(_port);
	};
    engine_.start(cfg);
	NTSTATUS  Result = STATUS_SUCCESS;
	ULONG     DebugFlags     = 0;
	
	EnableBackupRestorePrivileges();

	host_.SetCaseSensitiveSearch(TRUE);
	host_.SetFlushAndPurgeOnCleanup(TRUE);

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

void FileSystemService::onGuiStart(int _port){
	wostringstream oss;
	oss<<L"ola_client_gui.exe --front "<<a2w(params_.front_endpoint_)<<L" --local "<<_port;
    DWORD dwExitCode;
    if (!CreateInteractiveProcess(oss.str(), FALSE, 0, 
        &dwExitCode))
    {
        // Log the error and exit.
        WriteErrorLogEntry(L"CreateInteractiveProcess", GetLastError());
        return;
    }
}

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

uint32_t node_flags_to_attributes(ola::client::service::NodeFlagsT _node_flags){
	using ola::client::service::NodeFlagsE;
	using ola::client::service::NodeFlagsT;
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

	return attr;
}

//-----------------------------------------------------------------------------

FileSystem::FileSystem(ola::client::service::Engine &_rengine) :  rengine_(_rengine)
{
}

FileSystem::~FileSystem()
{

	delete []psecurity_data_;
}

NTSTATUS FileSystem::InitSecurityDescriptor(){
	DWORD sz= 0;
	auto path = ola::client::utility::widen(envAppDataPath());
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
    using ola::client::service::NodeFlagsT;

	if(PFileAttributes != nullptr){
		++FileName;
        NodeFlagsT node_flags;
	    uint64_t size = 0;
        if(engine().info(FileName, node_flags, size)){

		    *PFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | node_flags_to_attributes(node_flags);

        }else{
            *PFileAttributes = 0;
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
    *PFileDesc = engine().open(FileName, CreateOptions);

    if(*PFileDesc != nullptr){
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
	using ola::client::service::NodeFlagsT;
    NodeFlagsT node_flags;
	uint64_t size = 0;
    
	engine().info(static_cast<service::Descriptor*>(pFileDesc), node_flags, size);

	FileInfo->FileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | node_flags_to_attributes(node_flags);
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
    return STATUS_UNSUCCESSFUL;
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
	using namespace ola::client::service;
	
	wstring	  name;
	uint64_t	  size = 0;
	uint32_t  attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
	NodeFlagsT	node_flags;

    if(engine().list(static_cast<service::Descriptor*>(pFileDesc), *pContext, name, node_flags, size)){
		attributes |= node_flags_to_attributes(node_flags);
	}else{
		return STATUS_NO_MORE_FILES;
	}

	memset(DirInfo, 0, sizeof *DirInfo);
    
    DirInfo->Size = (UINT16)(FIELD_OFFSET(FileSystem::DirInfo, FileNameBuf) + name.size() * sizeof(WCHAR));
    DirInfo->FileInfo.FileAttributes = attributes;
    DirInfo->FileInfo.ReparseTag = 0;
    DirInfo->FileInfo.FileSize = size;
    DirInfo->FileInfo.AllocationSize = (size + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT * ALLOCATION_UNIT;
    DirInfo->FileInfo.CreationTime = base_time_;
    DirInfo->FileInfo.LastAccessTime = base_time_;
    DirInfo->FileInfo.LastWriteTime = base_time_;
    DirInfo->FileInfo.ChangeTime = DirInfo->FileInfo.LastWriteTime;
    DirInfo->FileInfo.IndexNumber = 0;
    DirInfo->FileInfo.HardLinks = 0;
    memcpy(DirInfo->FileNameBuf, name.c_str(), name.size() * sizeof(WCHAR));
	return STATUS_SUCCESS;
}


//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
}//namespace