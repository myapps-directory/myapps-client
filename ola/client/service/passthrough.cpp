#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <strsafe.h>
#include <winfsp.hpp>

#include <iostream>

#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"

#include "ola/common/utility/encode.hpp"

#define PROGNAME "ola-fs"

#define ALLOCATION_UNIT 4096
#define FULLPATH_SIZE (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#define info(format, ...) Service::Log(EVENTLOG_INFORMATION_TYPE, format, __VA_ARGS__)
#define warn(format, ...) Service::Log(EVENTLOG_WARNING_TYPE, format, __VA_ARGS__)
#define fail(format, ...) Service::Log(EVENTLOG_ERROR_TYPE, format, __VA_ARGS__)

#define ConcatPath(FN, FP) (0 == StringCbPrintfW(FP, sizeof FP, L"%s%s", _Path, FN))
#define HandleFromFileDesc(FD) ((FileDesc*)(FD))->Handle

using namespace Fsp;
//using namespace solid;
using namespace std;

namespace {

class FileSystem final : public FileSystemBase {
public:
    FileSystem();
    ~FileSystem();
    NTSTATUS SetPath(PWSTR Path);

protected:
    static NTSTATUS GetFileInfoInternal(HANDLE Handle, FileInfo* FileInfo);
    NTSTATUS        Init(PVOID Host) override;
    NTSTATUS        GetVolumeInfo(
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

private:
    PWSTR  _Path;
    UINT64 _CreationTime;
};

class FileSystemService final : public Service {
public:
    FileSystemService();

protected:
    NTSTATUS OnStart(ULONG Argc, PWSTR* Argv) override;
    NTSTATUS OnStop() override;

private:
    FileSystem     fs_;
    FileSystemHost host_;
};
} //namespace

int wmain(int argc, wchar_t** argv)
{
    return FileSystemService().Run();
}

namespace {

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

FileSystemService::FileSystemService()
    : Service(L"" PROGNAME)
    , fs_()
    , host_(fs_)
{
}

NTSTATUS FileSystemService::OnStart(ULONG argc, PWSTR* argv)
{
#define argtos(v)      \
    if (arge > ++argp) \
        v = *argp;     \
    else               \
        goto usage
#define argtol(v)                   \
    if (arge > ++argp)              \
        v = wcstol_deflt(*argp, v); \
    else                            \
        goto usage

    wchar_t **argp, **arge;
    PWSTR     DebugLogFile   = 0;
    ULONG     DebugFlags     = 0;
    PWSTR     VolumePrefix   = 0;
    PWSTR     PassThrough    = 0;
    PWSTR     MountPoint     = 0;
    HANDLE    DebugLogHandle = INVALID_HANDLE_VALUE;
    WCHAR     PassThroughBuf[MAX_PATH];
    NTSTATUS  Result;

    for (argp = argv + 1, arge = argv + argc; arge > argp; argp++) {
        if (L'-' != argp[0][0])
            break;
        switch (argp[0][1]) {
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

    if (0 == PassThrough && 0 != VolumePrefix) {
        PWSTR P;

        P = wcschr(VolumePrefix, L'\\');
        if (0 != P && L'\\' != P[1]) {
            P = wcschr(P + 1, L'\\');
            if (0 != P && ((L'A' <= P[1] && P[1] <= L'Z') || (L'a' <= P[1] && P[1] <= L'z')) && L'$' == P[2]) {
                StringCbPrintf(PassThroughBuf, sizeof PassThroughBuf, L"%c:%s", P[1], P + 3);
                PassThrough = PassThroughBuf;
            }
        }
    }

    if (0 == PassThrough || 0 == MountPoint)
        goto usage;

    EnableBackupRestorePrivileges();

    if (0 != DebugLogFile) {
        Result = FileSystemHost::SetDebugLogFile(DebugLogFile);
        if (!NT_SUCCESS(Result)) {
            fail(L"cannot open debug log file");
            goto usage;
        }
    }

    Result = fs_.SetPath(PassThrough);
    if (!NT_SUCCESS(Result)) {
        fail(L"cannot create file system");
        return Result;
    }

    host_.SetPrefix(VolumePrefix);
    Result = host_.Mount(MountPoint, 0, FALSE, DebugFlags);
    if (!NT_SUCCESS(Result)) {
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

NTSTATUS FileSystemService::OnStop()
{
    host_.Unmount();
    return STATUS_SUCCESS;
}

// -- FileSystem --------------------------------------------------------------

struct FileDesc {
    FileDesc()
        : Handle(INVALID_HANDLE_VALUE)
        , DirBuffer()
    {
    }
    ~FileDesc()
    {
        CloseHandle(Handle);
        FileSystem::DeleteDirectoryBuffer(&DirBuffer);
    }
    HANDLE Handle;
    PVOID  DirBuffer;
};

FileSystem::FileSystem()
    : FileSystemBase()
    , _Path()
{
}

FileSystem::~FileSystem()
{
    delete[] _Path;
}

NTSTATUS FileSystem::SetPath(PWSTR Path)
{
    WCHAR    FullPath[MAX_PATH];
    ULONG    Length;
    HANDLE   Handle;
    FILETIME CreationTime;
    DWORD    LastError;

    Handle = CreateFileW(
        Path, FILE_READ_ATTRIBUTES, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (INVALID_HANDLE_VALUE == Handle)
        return NtStatusFromWin32(GetLastError());

    Length = GetFinalPathNameByHandleW(Handle, FullPath, FULLPATH_SIZE - 1, 0);
    if (0 == Length) {
        LastError = GetLastError();
        CloseHandle(Handle);
        return NtStatusFromWin32(LastError);
    }
    if (L'\\' == FullPath[Length - 1])
        FullPath[--Length] = L'\0';

    if (!GetFileTime(Handle, &CreationTime, 0, 0)) {
        LastError = GetLastError();
        CloseHandle(Handle);
        return NtStatusFromWin32(LastError);
    }

    CloseHandle(Handle);

    Length++;
    _Path = new WCHAR[Length];
    memcpy(_Path, FullPath, Length * sizeof(WCHAR));

    _CreationTime = ((PLARGE_INTEGER)&CreationTime)->QuadPart;

    return STATUS_SUCCESS;
}

std::mutex& gmutex()
{
    static std::mutex m;
    return m;
}

NTSTATUS FileSystem::GetFileInfoInternal(HANDLE Handle, FileInfo* FileInfo)
{
    BY_HANDLE_FILE_INFORMATION ByHandleFileInfo;

    if (!GetFileInformationByHandle(Handle, &ByHandleFileInfo))
        return NtStatusFromWin32(GetLastError());

    FileInfo->FileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | (ByHandleFileInfo.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL));
    ;
    FileInfo->ReparseTag     = 0;
    FileInfo->FileSize       = ((UINT64)ByHandleFileInfo.nFileSizeHigh << 32) | (UINT64)ByHandleFileInfo.nFileSizeLow;
    FileInfo->AllocationSize = (FileInfo->FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    FileInfo->CreationTime   = ((PLARGE_INTEGER)&ByHandleFileInfo.ftCreationTime)->QuadPart;
    FileInfo->LastAccessTime = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastAccessTime)->QuadPart;
    FileInfo->LastWriteTime  = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastWriteTime)->QuadPart;
    FileInfo->ChangeTime     = FileInfo->LastWriteTime;
    FileInfo->IndexNumber    = 0;
    FileInfo->HardLinks      = 0;
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "INFO: " << Handle << " attrs " << FileInfo->FileAttributes << endl;
    }
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Init(PVOID Host0)
{
    FileSystemHost* Host = (FileSystemHost*)Host0;
    Host->SetSectorSize(ALLOCATION_UNIT);
    Host->SetSectorsPerAllocationUnit(1);
    Host->SetFileInfoTimeout(1000);
    Host->SetCaseSensitiveSearch(FALSE);
    Host->SetCasePreservedNames(TRUE);
    Host->SetUnicodeOnDisk(TRUE);
    Host->SetPersistentAcls(TRUE);
    Host->SetPostCleanupWhenModifiedOnly(TRUE);
    Host->SetPassQueryDirectoryPattern(TRUE);
    Host->SetVolumeCreationTime(_CreationTime);
    Host->SetVolumeSerialNumber(0);
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetVolumeInfo(
    VolumeInfo* VolumeInfo)
{
    WCHAR          Root[MAX_PATH];
    ULARGE_INTEGER TotalSize, FreeSize;

    if (!GetVolumePathName(_Path, Root, MAX_PATH))
        return NtStatusFromWin32(GetLastError());

    if (!GetDiskFreeSpaceEx(Root, 0, &TotalSize, &FreeSize))
        return NtStatusFromWin32(GetLastError());

    VolumeInfo->TotalSize = TotalSize.QuadPart;
    VolumeInfo->FreeSize  = FreeSize.QuadPart;

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetSecurityByName(
    PWSTR                FileName,
    PUINT32              PFileAttributes /* or ReparsePointIndex */,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T*              PSecurityDescriptorSize)
{
    WCHAR                   FullPath[FULLPATH_SIZE];
    HANDLE                  Handle;
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;
    DWORD                   SecurityDescriptorSizeNeeded;
    NTSTATUS                Result;

    if (!ConcatPath(FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    Handle = CreateFileW(L"C:\\Users\\vipal\\work\\bubbles_release\\bubbles_client.exe",
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        0,
        0,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        0);
    if (INVALID_HANDLE_VALUE == Handle) {
        Result = NtStatusFromWin32(GetLastError());
        goto exit;
    }

    if (0 != PFileAttributes) {
        if (!GetFileInformationByHandleEx(Handle,
                FileAttributeTagInfo,
                &AttributeTagInfo,
                sizeof AttributeTagInfo)) {
            Result = NtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PFileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | (AttributeTagInfo.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL));
    }

    if (0 != PSecurityDescriptorSize) {
        if (!GetKernelObjectSecurity(Handle,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                SecurityDescriptor,
                (DWORD)*PSecurityDescriptorSize,
                &SecurityDescriptorSizeNeeded)) {
            *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
            Result                   = NtStatusFromWin32(GetLastError());
            goto exit;
        }

        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
    }

    Result = STATUS_SUCCESS;

exit:
    if (INVALID_HANDLE_VALUE != Handle)
        CloseHandle(Handle);
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "SECURITYb: " << FileName << " attrs " << *PFileAttributes << endl;
    }
    return Result;
}

NTSTATUS FileSystem::Create(
    PWSTR                FileName,
    UINT32               CreateOptions,
    UINT32               GrantedAccess,
    UINT32               FileAttributes,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    UINT64               AllocationSize,
    PVOID*               PFileNode,
    PVOID*               PFileDesc,
    OpenFileInfo*        OpenFileInfo)
{
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "CREATE: " << FileName << endl;
    }

    WCHAR               FullPath[FULLPATH_SIZE];
    SECURITY_ATTRIBUTES SecurityAttributes;
    ULONG               CreateFlags;
    FileDesc*           pFileDesc;

    if (!ConcatPath(FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    pFileDesc = new FileDesc;

    SecurityAttributes.nLength              = sizeof SecurityAttributes;
    SecurityAttributes.lpSecurityDescriptor = SecurityDescriptor;
    SecurityAttributes.bInheritHandle       = FALSE;

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    if (CreateOptions & FILE_DELETE_ON_CLOSE)
        CreateFlags |= FILE_FLAG_DELETE_ON_CLOSE;

    if (CreateOptions & FILE_DIRECTORY_FILE) {
        /*
         * It is not widely known but CreateFileW can be used to create directories!
         * It requires the specification of both FILE_FLAG_BACKUP_SEMANTICS and
         * FILE_FLAG_POSIX_SEMANTICS. It also requires that FileAttributes has
         * FILE_ATTRIBUTE_DIRECTORY set.
         */
        CreateFlags |= FILE_FLAG_POSIX_SEMANTICS;
        FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    } else
        FileAttributes &= ~FILE_ATTRIBUTE_DIRECTORY;

    if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    pFileDesc->Handle = CreateFileW(FullPath,
        GrantedAccess,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        &SecurityAttributes,
        CREATE_NEW,
        CreateFlags | FileAttributes,
        0);
    if (INVALID_HANDLE_VALUE == pFileDesc->Handle) {
        delete pFileDesc;
        return NtStatusFromWin32(GetLastError());
    }

    *PFileDesc = pFileDesc;

    return GetFileInfoInternal(pFileDesc->Handle, &OpenFileInfo->FileInfo);
}

NTSTATUS FileSystem::Open(
    PWSTR         FileName,
    UINT32        CreateOptions,
    UINT32        GrantedAccess,
    PVOID*        PFileNode,
    PVOID*        PFileDesc,
    OpenFileInfo* OpenFileInfo)
{
    WCHAR     FullPath[FULLPATH_SIZE];
    ULONG     CreateFlags;
    FileDesc* pFileDesc;

    if (!ConcatPath(FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    pFileDesc = new FileDesc;

    CreateFlags = FILE_FLAG_BACKUP_SEMANTICS;
    if (CreateOptions & FILE_DELETE_ON_CLOSE)
        CreateFlags |= FILE_FLAG_DELETE_ON_CLOSE;

    pFileDesc->Handle = CreateFileW(FullPath,
        GrantedAccess,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        OPEN_EXISTING,
        CreateFlags,
        0);
    if (INVALID_HANDLE_VALUE == pFileDesc->Handle) {
        delete pFileDesc;
        DWORD    err = GetLastError();
        NTSTATUS rv  = NtStatusFromWin32(err);
        return rv;
    }

    *PFileDesc = pFileDesc;
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "OPEN: " << FileName << " as " << pFileDesc << endl;
    }
    return GetFileInfoInternal(pFileDesc->Handle, &OpenFileInfo->FileInfo);
}

NTSTATUS FileSystem::Overwrite(
    PVOID     FileNode,
    PVOID     pFileDesc,
    UINT32    FileAttributes,
    BOOLEAN   ReplaceFileAttributes,
    UINT64    AllocationSize,
    FileInfo* FileInfo)
{

    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "OVERWRITE " << endl;
    }
    HANDLE                  Handle         = HandleFromFileDesc(pFileDesc);
    FILE_BASIC_INFO         BasicInfo      = {0};
    FILE_ALLOCATION_INFO    AllocationInfo = {0};
    FILE_ATTRIBUTE_TAG_INFO AttributeTagInfo;

    if (ReplaceFileAttributes) {
        if (0 == FileAttributes)
            FileAttributes = FILE_ATTRIBUTE_NORMAL;

        BasicInfo.FileAttributes = FileAttributes;
        if (!SetFileInformationByHandle(Handle,
                FileBasicInfo,
                &BasicInfo,
                sizeof BasicInfo))
            return NtStatusFromWin32(GetLastError());
    } else if (0 != FileAttributes) {
        if (!GetFileInformationByHandleEx(Handle,
                FileAttributeTagInfo,
                &AttributeTagInfo,
                sizeof AttributeTagInfo))
            return NtStatusFromWin32(GetLastError());

        BasicInfo.FileAttributes = FileAttributes | AttributeTagInfo.FileAttributes;
        if (BasicInfo.FileAttributes ^ FileAttributes) {
            if (!SetFileInformationByHandle(Handle,
                    FileBasicInfo,
                    &BasicInfo,
                    sizeof BasicInfo))
                return NtStatusFromWin32(GetLastError());
        }
    }

    if (!SetFileInformationByHandle(Handle,
            FileAllocationInfo,
            &AllocationInfo,
            sizeof AllocationInfo))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

VOID FileSystem::Cleanup(
    PVOID FileNode,
    PVOID pFileDesc,
    PWSTR FileName,
    ULONG Flags)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    if (Flags & CleanupDelete) {
        CloseHandle(Handle);

        /* this will make all future uses of Handle to fail with STATUS_INVALID_HANDLE */
        HandleFromFileDesc(pFileDesc) = INVALID_HANDLE_VALUE;
    }
}

VOID FileSystem::Close(
    PVOID pFileNode,
    PVOID pFileDesc0)
{
    FileDesc* pFileDesc = (FileDesc*)pFileDesc0;

    delete pFileDesc;
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "CLOSE: " << pFileDesc << endl;
    }
}

NTSTATUS FileSystem::Read(
    PVOID  FileNode,
    PVOID  pFileDesc,
    PVOID  Buffer,
    UINT64 Offset,
    ULONG  Length,
    PULONG PBytesTransferred)
{
    HANDLE     Handle     = HandleFromFileDesc(pFileDesc);
    OVERLAPPED Overlapped = {0};

    Overlapped.Offset     = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!ReadFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped)) {
        wcout << "READ ERROR: " << pFileDesc << " " << Offset << " " << Length << " " << *PBytesTransferred << endl;
        return NtStatusFromWin32(GetLastError());
    }
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "READ: " << pFileDesc << " " << Offset << " " << Length << " " << *PBytesTransferred << endl;
    }
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Write(
    PVOID     FileNode,
    PVOID     pFileDesc,
    PVOID     Buffer,
    UINT64    Offset,
    ULONG     Length,
    BOOLEAN   WriteToEndOfFile,
    BOOLEAN   ConstrainedIo,
    PULONG    PBytesTransferred,
    FileInfo* FileInfo)
{
    HANDLE        Handle = HandleFromFileDesc(pFileDesc);
    LARGE_INTEGER FileSize;
    OVERLAPPED    Overlapped = {0};

    if (ConstrainedIo) {
        if (!GetFileSizeEx(Handle, &FileSize))
            return NtStatusFromWin32(GetLastError());

        if (Offset >= (UINT64)FileSize.QuadPart)
            return STATUS_SUCCESS;
        if (Offset + Length > (UINT64)FileSize.QuadPart)
            Length = (ULONG)((UINT64)FileSize.QuadPart - Offset);
    }

    Overlapped.Offset     = (DWORD)Offset;
    Overlapped.OffsetHigh = (DWORD)(Offset >> 32);

    if (!WriteFile(Handle, Buffer, Length, PBytesTransferred, &Overlapped))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::Flush(
    PVOID     FileNode,
    PVOID     pFileDesc,
    FileInfo* FileInfo)
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
    PVOID     FileNode,
    PVOID     pFileDesc,
    FileInfo* FileInfo)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    NTSTATUS rv = GetFileInfoInternal(Handle, FileInfo);

    return rv;
}

NTSTATUS FileSystem::SetBasicInfo(
    PVOID     FileNode,
    PVOID     pFileDesc,
    UINT32    FileAttributes,
    UINT64    CreationTime,
    UINT64    LastAccessTime,
    UINT64    LastWriteTime,
    UINT64    ChangeTime,
    FileInfo* FileInfo)
{
    HANDLE          Handle    = HandleFromFileDesc(pFileDesc);
    FILE_BASIC_INFO BasicInfo = {0};

    if (INVALID_FILE_ATTRIBUTES == FileAttributes)
        FileAttributes = 0;
    else if (0 == FileAttributes)
        FileAttributes = FILE_ATTRIBUTE_NORMAL;

    BasicInfo.FileAttributes          = FileAttributes;
    BasicInfo.CreationTime.QuadPart   = CreationTime;
    BasicInfo.LastAccessTime.QuadPart = LastAccessTime;
    BasicInfo.LastWriteTime.QuadPart  = LastWriteTime;
    //BasicInfo.ChangeTime = ChangeTime;

    if (!SetFileInformationByHandle(Handle,
            FileBasicInfo,
            &BasicInfo,
            sizeof BasicInfo))
        return NtStatusFromWin32(GetLastError());

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::SetFileSize(
    PVOID     FileNode,
    PVOID     pFileDesc,
    UINT64    NewSize,
    BOOLEAN   SetAllocationSize,
    FileInfo* FileInfo)
{
    HANDLE                Handle = HandleFromFileDesc(pFileDesc);
    FILE_ALLOCATION_INFO  AllocationInfo;
    FILE_END_OF_FILE_INFO EndOfFileInfo;

    if (SetAllocationSize) {
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
                FileAllocationInfo,
                &AllocationInfo,
                sizeof AllocationInfo))
            return NtStatusFromWin32(GetLastError());
    } else {
        EndOfFileInfo.EndOfFile.QuadPart = NewSize;

        if (!SetFileInformationByHandle(Handle,
                FileEndOfFileInfo,
                &EndOfFileInfo,
                sizeof EndOfFileInfo))
            return NtStatusFromWin32(GetLastError());
    }

    return GetFileInfoInternal(Handle, FileInfo);
}

NTSTATUS FileSystem::CanDelete(
    PVOID FileNode,
    PVOID pFileDesc,
    PWSTR FileName)
{
    HANDLE                Handle = HandleFromFileDesc(pFileDesc);
    FILE_DISPOSITION_INFO DispositionInfo;

    DispositionInfo.DeleteFile = TRUE;

    if (!SetFileInformationByHandle(Handle,
            FileDispositionInfo,
            &DispositionInfo,
            sizeof DispositionInfo))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::Rename(
    PVOID   FileNode,
    PVOID   FileDesc,
    PWSTR   FileName,
    PWSTR   NewFileName,
    BOOLEAN ReplaceIfExists)
{
    WCHAR FullPath[FULLPATH_SIZE], NewFullPath[FULLPATH_SIZE];

    if (!ConcatPath(FileName, FullPath))
        return STATUS_OBJECT_NAME_INVALID;

    if (!ConcatPath(NewFileName, NewFullPath))
        return STATUS_OBJECT_NAME_INVALID;

    if (!MoveFileExW(FullPath, NewFullPath, ReplaceIfExists ? MOVEFILE_REPLACE_EXISTING : 0))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::GetSecurity(
    PVOID                FileNode,
    PVOID                pFileDesc,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    SIZE_T*              PSecurityDescriptorSize)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);
    DWORD  SecurityDescriptorSizeNeeded;

    if (!GetKernelObjectSecurity(Handle,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            SecurityDescriptor,
            (DWORD)*PSecurityDescriptorSize,
            &SecurityDescriptorSizeNeeded)) {
        *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
        return NtStatusFromWin32(GetLastError());
    }

    *PSecurityDescriptorSize = SecurityDescriptorSizeNeeded;
    {
        std::lock_guard<mutex> l(gmutex());
        wcout << "SECURITY: " << pFileDesc << endl;
    }
    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::SetSecurity(
    PVOID                FileNode,
    PVOID                pFileDesc,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR ModificationDescriptor)
{
    HANDLE Handle = HandleFromFileDesc(pFileDesc);

    if (!SetKernelObjectSecurity(Handle, SecurityInformation, ModificationDescriptor))
        return NtStatusFromWin32(GetLastError());

    return STATUS_SUCCESS;
}

NTSTATUS FileSystem::ReadDirectory(
    PVOID  FileNode,
    PVOID  FileDesc0,
    PWSTR  Pattern,
    PWSTR  Marker,
    PVOID  Buffer,
    ULONG  Length,
    PULONG PBytesTransferred)
{
    FileDesc* pFileDesc = (FileDesc*)FileDesc0;
    return BufferedReadDirectory(&pFileDesc->DirBuffer,
        FileNode,
        pFileDesc,
        Pattern,
        Marker,
        Buffer,
        Length,
        PBytesTransferred);
}

NTSTATUS FileSystem::ReadDirectoryEntry(
    PVOID    FileNode,
    PVOID    FileDesc0,
    PWSTR    Pattern,
    PWSTR    Marker,
    PVOID*   PContext,
    DirInfo* DirInfo)
{
    FileDesc*        pFileDesc = (FileDesc*)FileDesc0;
    HANDLE           Handle    = pFileDesc->Handle;
    WCHAR            FullPath[FULLPATH_SIZE];
    ULONG            Length, PatternLength;
    HANDLE           FindHandle;
    WIN32_FIND_DATAW FindData;

    if (0 == *PContext) {
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
    } else {
        FindHandle = *PContext;
        if (!FindNextFileW(FindHandle, &FindData)) {
            FindClose(FindHandle);
            return STATUS_NO_MORE_FILES;
        }
    }

    memset(DirInfo, 0, sizeof *DirInfo);
    Length                           = (ULONG)wcslen(FindData.cFileName);
    DirInfo->Size                    = (UINT16)(FIELD_OFFSET(FileSystem::DirInfo, FileNameBuf) + Length * sizeof(WCHAR));
    DirInfo->FileInfo.FileAttributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | (FindData.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL));
    ;
    DirInfo->FileInfo.ReparseTag     = 0;
    DirInfo->FileInfo.FileSize       = ((UINT64)FindData.nFileSizeHigh << 32) | (UINT64)FindData.nFileSizeLow;
    DirInfo->FileInfo.AllocationSize = (DirInfo->FileInfo.FileSize + ALLOCATION_UNIT - 1)
        / ALLOCATION_UNIT * ALLOCATION_UNIT;
    DirInfo->FileInfo.CreationTime   = ((PLARGE_INTEGER)&FindData.ftCreationTime)->QuadPart;
    DirInfo->FileInfo.LastAccessTime = ((PLARGE_INTEGER)&FindData.ftLastAccessTime)->QuadPart;
    DirInfo->FileInfo.LastWriteTime  = ((PLARGE_INTEGER)&FindData.ftLastWriteTime)->QuadPart;
    DirInfo->FileInfo.ChangeTime     = DirInfo->FileInfo.LastWriteTime;
    DirInfo->FileInfo.IndexNumber    = 0;
    DirInfo->FileInfo.HardLinks      = 0;
    memcpy(DirInfo->FileNameBuf, FindData.cFileName, Length * sizeof(WCHAR));

    return STATUS_SUCCESS;
}

} //namespace