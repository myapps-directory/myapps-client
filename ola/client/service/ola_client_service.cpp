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

#include "ola/common/utility/crypto.hpp"

#include "ola/common/ola_front_protocol.hpp"

#include "boost/program_options.hpp"

#include "ola/client/service/engine.hpp"
#include <iostream>


#define PROGNAME                        "ola-fs"

#define ALLOCATION_UNIT                 4096
#define FULLPATH_SIZE                   (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define info(format, ...)               Service::Log(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define warn(format, ...)               Service::Log(EVENTLOG_WARNING_TYPE, format, __VA_ARGS__)
#define fail(format, ...)               Service::Log(EVENTLOG_ERROR_TYPE, format, __VA_ARGS__)

#define ConcatPath(FN, FP)              (0 == StringCbPrintfW(FP, sizeof FP, L"%s%s", _Path, FN))
#define HandleFromFileDesc(FD)          ((FileDesc *)(FD))->Handle

using namespace Fsp;
using namespace std;

namespace{

struct Parameters{
    wstring				debug_log_file_;
    uint32_t			debug_flags_;
    wstring				mount_point_;
    vector<string>      debug_modules_;
    string				debug_addr_;
    string				debug_port_;
    bool				debug_console_;
    bool				debug_buffered_;
    bool				secure_;
    bool				compress_;
    string				front_endpoint_;

    bool parse(ULONG argc, PWSTR *argv);
};

class FileSystem final : public FileSystemBase
{
    ola::client::service::Engine &rengine_;
public:
    FileSystem(ola::client::service::Engine &_rengine);
    ~FileSystem();

private:
    ola::client::service::Engine& engine()const{
        return rengine_;
    }

    static NTSTATUS GetFileInfoInternal(HANDLE Handle, FileInfo *FileInfo);
    NTSTATUS Init(PVOID Host)override;
    NTSTATUS GetVolumeInfo(
        VolumeInfo *VolumeInfo)override;
    NTSTATUS GetSecurityByName(
        PWSTR FileName,
        PUINT32 PFileAttributes/* or ReparsePointIndex */,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        SIZE_T *PSecurityDescriptorSize)override;
    NTSTATUS Create(
        PWSTR FileName,
        UINT32 CreateOptions,
        UINT32 GrantedAccess,
        UINT32 FileAttributes,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        UINT64 AllocationSize,
        PVOID *PFileNode,
        PVOID *PFileDesc,
        OpenFileInfo *OpenFileInfo)override;
    NTSTATUS Open(
        PWSTR FileName,
        UINT32 CreateOptions,
        UINT32 GrantedAccess,
        PVOID *PFileNode,
        PVOID *PFileDesc,
        OpenFileInfo *OpenFileInfo)override;
    NTSTATUS Overwrite(
        PVOID FileNode,
        PVOID FileDesc,
        UINT32 FileAttributes,
        BOOLEAN ReplaceFileAttributes,
        UINT64 AllocationSize,
        FileInfo *FileInfo)override;
    VOID Cleanup(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR FileName,
        ULONG Flags)override;
    VOID Close(
        PVOID FileNode,
        PVOID FileDesc)override;
    NTSTATUS Read(
        PVOID FileNode,
        PVOID FileDesc,
        PVOID Buffer,
        UINT64 Offset,
        ULONG Length,
        PULONG PBytesTransferred)override;
    NTSTATUS Write(
        PVOID FileNode,
        PVOID FileDesc,
        PVOID Buffer,
        UINT64 Offset,
        ULONG Length,
        BOOLEAN WriteToEndOfFile,
        BOOLEAN ConstrainedIo,
        PULONG PBytesTransferred,
        FileInfo *FileInfo)override;
    NTSTATUS Flush(
        PVOID FileNode,
        PVOID FileDesc,
        FileInfo *FileInfo)override;
    NTSTATUS GetFileInfo(
        PVOID FileNode,
        PVOID FileDesc,
        FileInfo *FileInfo)override;
    NTSTATUS SetBasicInfo(
        PVOID FileNode,
        PVOID FileDesc,
        UINT32 FileAttributes,
        UINT64 CreationTime,
        UINT64 LastAccessTime,
        UINT64 LastWriteTime,
        UINT64 ChangeTime,
        FileInfo *FileInfo)override;
    NTSTATUS SetFileSize(
        PVOID FileNode,
        PVOID FileDesc,
        UINT64 NewSize,
        BOOLEAN SetAllocationSize,
        FileInfo *FileInfo)override;
    NTSTATUS CanDelete(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR FileName)override;
    NTSTATUS Rename(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR FileName,
        PWSTR NewFileName,
        BOOLEAN ReplaceIfExists)override;
    NTSTATUS GetSecurity(
        PVOID FileNode,
        PVOID FileDesc,
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        SIZE_T *PSecurityDescriptorSize)override;
    NTSTATUS SetSecurity(
        PVOID FileNode,
        PVOID FileDesc,
        SECURITY_INFORMATION SecurityInformation,
        PSECURITY_DESCRIPTOR ModificationDescriptor)override;
    NTSTATUS ReadDirectory(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR Pattern,
        PWSTR Marker,
        PVOID Buffer,
        ULONG Length,
        PULONG PBytesTransferred)override;
    NTSTATUS ReadDirectoryEntry(
        PVOID FileNode,
        PVOID FileDesc,
        PWSTR Pattern,
        PWSTR Marker,
        PVOID *PContext,
        DirInfo *DirInfo)override;
};

class FileSystemService final : public Service
{
    ola::client::service::Engine    engine_;
    FileSystem						fs_;
    FileSystemHost					host_;
    Parameters						params_;
public:
    FileSystemService();

protected:
    NTSTATUS OnStart(ULONG Argc, PWSTR *Argv) override;
    NTSTATUS OnStop() override;
};
}//namespace


int wmain(int argc, wchar_t **argv)
{
    return FileSystemService().Run();
}

namespace{

// -- FileSystemService -------------------------------------------------------

static NTSTATUS EnableBackupRestorePrivileges(VOID)
{
    union
    {
        TOKEN_PRIVILEGES P;
        UINT8 B[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
    } Privileges;
    HANDLE Token;

    Privileges.P.PrivilegeCount = 2;
    Privileges.P.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Privileges.P.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueW(0, SE_BACKUP_NAME, &Privileges.P.Privileges[0].Luid) ||
        !LookupPrivilegeValueW(0, SE_RESTORE_NAME, &Privileges.P.Privileges[1].Luid))
        return FspNtStatusFromWin32(GetLastError());

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FspNtStatusFromWin32(GetLastError());

    if (!AdjustTokenPrivileges(Token, FALSE, &Privileges.P, 0, 0, 0))
    {
        CloseHandle(Token);

        return FspNtStatusFromWin32(GetLastError());
    }

    CloseHandle(Token);

    return STATUS_SUCCESS;
}

static ULONG wcstol_deflt(wchar_t *w, ULONG deflt)
{
    wchar_t *endp;
    ULONG ul = wcstol(w, &endp, 0);
    return L'\0' != w[0] && L'\0' == *endp ? ul : deflt;
}

bool Parameters::parse(ULONG argc, PWSTR *argv){
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
        ("debug-unbuffered,S", value<bool>(&debug_buffered_)->implicit_value(false)->default_value(true), "Debug unbuffered")
        ("mount-point,m", wvalue<wstring>(&mount_point_)->default_value(L"C:\\ola", "c:\\ola"), "Mount point")
        ("secure,s", value<bool>(&secure_)->implicit_value(true)->default_value(false), "Use SSL to secure communication")
        ("compress", value<bool>(&compress_)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
        ("front", value<std::string>(&front_endpoint_)->default_value(string("localhost:") + ola::front::default_port()), "OLA Front Endpoint");
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
#if 0
NTSTATUS FileSystemService::OnStart(ULONG argc, PWSTR *argv)
{
#define argtos(v)                       if (arge > ++argp) v = *argp; else goto usage
#define argtol(v)                       if (arge > ++argp) v = wcstol_deflt(*argp, v); else goto usage

    wchar_t **argp, **arge;
    PWSTR DebugLogFile = 0;
    ULONG DebugFlags = 0;
    PWSTR VolumePrefix = 0;
    PWSTR PassThrough = 0;
    PWSTR MountPoint = 0;
    HANDLE DebugLogHandle = INVALID_HANDLE_VALUE;
    WCHAR PassThroughBuf[MAX_PATH];
    NTSTATUS Result;

    for (argp = argv + 1, arge = argv + argc; arge > argp; argp++)
    {
        if (L'-' != argp[0][0])
            break;
        switch (argp[0][1])
        {
        case L'?':
            goto usage;
        case L'd':
            argtol(DebugFlags);
            break;
        case L'D':
            argtos(DebugLogFile);
            break;
        case L'm':
            argtos(MountPoint);
            break;
        case L'p':
            argtos(PassThrough);
            break;
        case L'u':
            argtos(VolumePrefix);
            break;
        default:
            goto usage;
        }
    }

    if (arge > argp)
        goto usage;

    if (0 == PassThrough && 0 != VolumePrefix)
    {
        PWSTR P;

        P = wcschr(VolumePrefix, L'\\');
        if (0 != P && L'\\' != P[1])
        {
            P = wcschr(P + 1, L'\\');
            if (0 != P &&
                (
                (L'A' <= P[1] && P[1] <= L'Z') ||
                (L'a' <= P[1] && P[1] <= L'z')
                ) &&
                L'$' == P[2])
            {
                StringCbPrintf(PassThroughBuf, sizeof PassThroughBuf, L"%c:%s", P[1], P + 3);
                PassThrough = PassThroughBuf;
            }
        }
    }

    if (0 == PassThrough || 0 == MountPoint)
        goto usage;

    EnableBackupRestorePrivileges();

    if (0 != DebugLogFile)
    {
        Result = FileSystemHost::SetDebugLogFile(DebugLogFile);
        if (!NT_SUCCESS(Result))
        {
            fail(L"cannot open debug log file");
            goto usage;
        }
    }

    Result = fs_.SetPath(PassThrough);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot create file system");
        return Result;
    }

    host_.SetPrefix(VolumePrefix);
    Result = host_.Mount(MountPoint, 0, FALSE, DebugFlags);
    if (!NT_SUCCESS(Result))
    {
        fail(L"cannot mount file system");
        return Result;
    }

    MountPoint = host_.MountPoint();
    info(L"%s%s%s -p %s -m %s",
        L"" PROGNAME,
        0 != VolumePrefix && L'\0' != VolumePrefix[0] ? L" -u " : L"",
            0 != VolumePrefix && L'\0' != VolumePrefix[0] ? VolumePrefix : L"",
        PassThrough,
        MountPoint);

    return STATUS_SUCCESS;

usage:
    static wchar_t usage[] = L""
        "usage: %s OPTIONS\n"
        "\n"
        "options:\n"
        "    -d DebugFlags       [-1: enable all debug logs]\n"
        "    -D DebugLogFile     [file path; use - for stderr]\n"
        "    -u \\Server\\Share    [UNC prefix (single backslash)]\n"
        "    -p Directory        [directory to expose as pass through file system]\n"
        "    -m MountPoint       [X:|*|directory]\n";

    fail(usage, L"" PROGNAME);

    return STATUS_UNSUCCESSFUL;

#undef argtos
#undef argtol
}

#else
NTSTATUS FileSystemService::OnStart(ULONG argc, PWSTR *argv)
{
    try {
        if(!params_.parse(argc, argv)){
            return STATUS_UNSUCCESSFUL;
        }
    } catch (exception& e) {
        cout << e.what() << "\n";
        return STATUS_UNSUCCESSFUL;
    }
    ola::client::service::Configuration cfg;
    cfg.secure_ = params_.secure_;
    cfg.compress_ = params_.compress_;
    cfg.front_endpoint_ = params_.front_endpoint_;
    engine_.start(cfg);
    return STATUS_SUCCESS;
}
#endif

NTSTATUS FileSystemService::OnStop()
{
    host_.Unmount();
    engine_.stop();
    return STATUS_SUCCESS;
}

// -- FileSystem --------------------------------------------------------------

struct FileDesc
{
    FileDesc() : Handle(INVALID_HANDLE_VALUE), DirBuffer()
    {
    }
    ~FileDesc()
    {
        CloseHandle(Handle);
        FileSystem::DeleteDirectoryBuffer(&DirBuffer);
    }
    HANDLE Handle;
    PVOID DirBuffer;
};

FileSystem::FileSystem(ola::client::service::Engine &_rengine) :  rengine_(_rengine)
{
}

FileSystem::~FileSystem()
{
}

NTSTATUS FileSystem::GetFileInfoInternal(HANDLE Handle, FileInfo *FileInfo)
{
    BY_HANDLE_FILE_INFORMATION ByHandleFileInfo;

    if (!GetFileInformationByHandle(Handle, &ByHandleFileInfo))
        return NtStatusFromWin32(GetLastError());

    FileInfo->FileAttributes = ByHandleFileInfo.dwFileAttributes;
    FileInfo->ReparseTag = 0;
    FileInfo->FileSize =
        ((UINT64)ByHandleFileInfo.nFileSizeHigh << 32) | (UINT64)ByHandleFileInfo.nFileSizeLow;
    FileInfo->AllocationSize = (FileInfo->FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    FileInfo->CreationTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftCreationTime)->QuadPart;
    FileInfo->LastAccessTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastAccessTime)->QuadPart;
    FileInfo->LastWriteTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastWriteTime)->QuadPart;
    FileInfo->ChangeTime = FileInfo->LastWriteTime;
    FileInfo->IndexNumber = 0;
    FileInfo->HardLinks = 0;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Init(PVOID Host0)
{
    FileSystemHost *Host = (FileSystemHost *)Host0;
    Host->SetSectorSize(ALLOCATION_UNIT);
    Host->SetSectorsPerAllocationUnit(1);
    Host->SetFileInfoTimeout(1000);
    Host->SetCaseSensitiveSearch(FALSE);
    Host->SetCasePreservedNames(TRUE);
    Host->SetUnicodeOnDisk(TRUE);
    Host->SetPersistentAcls(TRUE);
    Host->SetPostCleanupWhenModifiedOnly(TRUE);
    Host->SetPassQueryDirectoryPattern(TRUE);
    //Host->SetVolumeCreationTime(_CreationTime);
    Host->SetVolumeSerialNumber(0);
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetVolumeInfo(
    VolumeInfo *VolumeInfo)
{
    WCHAR Root[MAX_PATH];
    ULARGE_INTEGER TotalSize, FreeSize;

    //if (!GetVolumePathName(_Path, Root, MAX_PATH))
    //    return NtStatusFromWin32(GetLastError());

    if (!GetDiskFreeSpaceEx(Root, 0, &TotalSize, &FreeSize))
        return NtStatusFromWin32(GetLastError());

    VolumeInfo->TotalSize = TotalSize.QuadPart;
    VolumeInfo->FreeSize = FreeSize.QuadPart;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetSecurityByName(
    PWSTR FileName,
    PUINT32 PFileAttributes/* or ReparsePointIndex */,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T *PSecurityDescriptorSize)
{
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
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Open(
    PWSTR FileName,
    UINT32 CreateOptions,
    UINT32 GrantedAccess,
    PVOID *PFileNode,
    PVOID *PFileDesc,
    OpenFileInfo *OpenFileInfo)
{
    return STATUS_SUCCESS;
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
    PVOID FileNode,
    PVOID pFileDesc,
    PWSTR FileName,
    ULONG Flags)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    if (Flags & CleanupDelete)
    {
        CloseHandle(Handle);

        /* this will make all future uses of Handle to fail with STATUS_INVALID_HANDLE */
        HandleFromFileDesc(pFileDesc) = INVALID_HANDLE_VALUE;
    }
}

VOID FileSystem::Close(
    PVOID pFileNode,
    PVOID pFileDesc0)
{
    FileDesc *pFileDesc = (FileDesc *)pFileDesc0;

    delete pFileDesc;
}

NTSTATUS FileSystem::Read(
    PVOID FileNode,
    PVOID pFileDesc,
    PVOID Buffer,
    UINT64 Offset,
    ULONG Length,
    PULONG PBytesTransferred)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    OVERLAPPED Overlapped = { 0 };

    Overlapped.Offset = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!ReadFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
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
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    LARGE_INTEGER FileSize;
    OVERLAPPED Overlapped = { 0 };

    if (ConstrainedIo)
    {
        if (!GetFileSizeEx(Handle, &FileSize))
            return NtStatusFromWin32(GetLastError());

        if (Offset >= (UINT64)FileSize.QuadPart)
            return STATUS_SUCCESS;
        if (Offset + Length > (UINT64)FileSize.QuadPart)
            Length = (ULONG)((UINT64)FileSize.QuadPart - Offset);
    }

    Overlapped.Offset = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!WriteFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::Flush(
    PVOID FileNode,
    PVOID pFileDesc,
    FileInfo *FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    /* we do not flush the whole volume, so just return SUCCESS */
    if (0 == Handle)
        return STATUS_SUCCESS;

    if (!FlushFileBuffers(Handle))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::GetFileInfo(
    PVOID FileNode,
    PVOID pFileDesc,
    FileInfo *FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    return GetFileInfoInternal(Handle, FileInfo);
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
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    FILE_BASIC_INFO BasicInfo = { 0 };

    if (INVALID_FILE_ATTRIBUTES == FileAttributes)
        FileAttributes = 0;
    else if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    BasicInfo.FileAttributes = FileAttributes;
    BasicInfo.CreationTime.QuadPart = CreationTime;
    BasicInfo.LastAccessTime.QuadPart = LastAccessTime;
    BasicInfo.LastWriteTime.QuadPart = LastWriteTime;
    //BasicInfo.ChangeTime = ChangeTime;

    if (!SetFileInformationByHandle(Handle,
        FileBasicInfo, &BasicInfo, sizeof BasicInfo))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::SetFileSize(
    PVOID FileNode,
    PVOID pFileDesc,
    UINT64 NewSize,
    BOOLEAN SetAllocationSize,
    FileInfo *FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    FILE_ALLOCATION_INFO AllocationInfo;
    FILE_END_OF_FILE_INFO EndOfFileInfo;

    if (SetAllocationSize)
    {
        /*
         * This file system does not maintain AllocationSize, although NTFS clearly can.
         * However it must always be FileSize <= AllocationSize and NTFS will make sure
         * to truncate the FileSize if it sees an AllocationSize < FileSize.
         *
         * If OTOH a very large AllocationSize is passed, the call below will increase
         * the AllocationSize of the underlying file, although our file system does not
         * expose this fact. This AllocationSize is only temporary as NTFS will reset
         * the AllocationSize of the underlying file when it is closed.
         */

        AllocationInfo.AllocationSize.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
            FileAllocationInfo, &AllocationInfo, sizeof AllocationInfo))
            return NtStatusFromWin32(GetLastError());
    }
    else
    {
        EndOfFileInfo.EndOfFile.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
            FileEndOfFileInfo, &EndOfFileInfo, sizeof EndOfFileInfo))
            return NtStatusFromWin32(GetLastError());
    }

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::CanDelete(
    PVOID FileNode,
    PVOID pFileDesc,
    PWSTR FileName)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    FILE_DISPOSITION_INFO DispositionInfo;

    DispositionInfo.DeleteFile = TRUE;

    if (!SetFileInformationByHandle(Handle,
        FileDispositionInfo, &DispositionInfo, sizeof DispositionInfo))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Rename(
    PVOID FileNode,
    PVOID FileDesc,
    PWSTR FileName,
    PWSTR NewFileName,
    BOOLEAN ReplaceIfExists)
{
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetSecurity(
    PVOID FileNode,
    PVOID pFileDesc,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T *PSecurityDescriptorSize)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    DWORD SecurityDescriptorSizeNeeded;

    if (!GetKernelObjectSecurity(Handle,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        SecurityDescriptor, (DWORD)*PSecurityDescriptorSize, &SecurityDescriptorSizeNeeded))
    {
        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
        return NtStatusFromWin32(GetLastError());
    }

    *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::SetSecurity(
    PVOID FileNode,
    PVOID pFileDesc,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    if (!SetKernelObjectSecurity(Handle, SecurityInformation, ModificationDescriptor))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::ReadDirectory(
    PVOID FileNode,
    PVOID FileDesc0,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID Buffer,
    ULONG Length,
    PULONG PBytesTransferred)
{
    FileDesc *pFileDesc = (FileDesc *)FileDesc0;
    return BufferedReadDirectory(&pFileDesc->DirBuffer,
        FileNode, pFileDesc, Pattern, Marker, Buffer, Length, PBytesTransferred);
}

NTSTATUS FileSystem::ReadDirectoryEntry(
    PVOID FileNode,
    PVOID FileDesc0,
    PWSTR Pattern,
    PWSTR Marker,
    PVOID *PContext,
    DirInfo *DirInfo)
{
    FileDesc *pFileDesc = (FileDesc *)FileDesc0;
    HANDLE Handle = pFileDesc->Handle;
    WCHAR FullPath[FULLPATH_SIZE];
    ULONG Length, PatternLength;
    HANDLE FindHandle;
    WIN32_FIND_DATAW FindData;

    if (0 == *PContext)
    {
        if (0 == Pattern)
            Pattern = L"*";
        PatternLength = (ULONG)wcslen(Pattern);

        Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
        if (0 == Length)
            return NtStatusFromWin32(GetLastError());
        if (Length + 1 + PatternLength >= FULLPATH_SIZE)
            return STATUS_OBJECT_NAME_INVALID;

        if (L'\\' != FullPath[Length - 1])
            FullPath[Length++] = L'\\';
        memcpy(FullPath + Length, Pattern, PatternLength * sizeof(WCHAR));
        FullPath[Length + PatternLength] = L'\0';

        FindHandle = FindFirstFileW(FullPath, &FindData);
        if (INVALID_HANDLE_VALUE == FindHandle)
            return STATUS_NO_MORE_FILES;

        *PContext = FindHandle;
    }
    else
    {
        FindHandle = *PContext;
        if (!FindNextFileW(FindHandle, &FindData))
        {
            FindClose(FindHandle);
            return STATUS_NO_MORE_FILES;
        }
    }

    memset(DirInfo, 0, sizeof *DirInfo);
    Length = (ULONG)wcslen(FindData.cFileName);
    DirInfo->Size = (UINT16)(FIELD_OFFSET(FileSystem::DirInfo, FileNameBuf) + Length * sizeof(WCHAR));
    DirInfo->FileInfo.FileAttributes = FindData.dwFileAttributes;
    DirInfo->FileInfo.ReparseTag = 0;
    DirInfo->FileInfo.FileSize =
        ((UINT64)FindData.nFileSizeHigh << 32) | (UINT64)FindData.nFileSizeLow;
    DirInfo->FileInfo.AllocationSize = (DirInfo->FileInfo.FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    DirInfo->FileInfo.CreationTime = ((PLARGE_INTEGER)&FindData.ftCreationTime)->QuadPart;
    DirInfo->FileInfo.LastAccessTime = ((PLARGE_INTEGER)&FindData.ftLastAccessTime)->QuadPart;
    DirInfo->FileInfo.LastWriteTime = ((PLARGE_INTEGER)&FindData.ftLastWriteTime)->QuadPart;
    DirInfo->FileInfo.ChangeTime = DirInfo->FileInfo.LastWriteTime;
    DirInfo->FileInfo.IndexNumber = 0;
    DirInfo->FileInfo.HardLinks = 0;
    memcpy(DirInfo->FileNameBuf, FindData.cFileName, Length * sizeof(WCHAR));

    return STATUS_SUCCESS;
}

}//namespace