#include "solid/system/common.hpp"
#include "ola/client/utility/auth_file.hpp"
#include "ola/common/utility/encode.hpp"
#include <fstream>
#include <sstream>
#include <string>
#include <Windows.h>

using namespace std;

namespace fs = boost::filesystem;

namespace ola{
namespace client{
namespace utility{

namespace{
// trim from start (in place)
static inline void ltrim(std::string& s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string& s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch);
    }).base(),
        s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s)
{
    ltrim(s);
    rtrim(s);
}
} // namespace

void auth_write(
    const boost::filesystem::path &_path,
    const std::string &_endpoint,
    const std::string &_name,
    const std::string &_token
){
#if !defined(SOLID_ON_WINDOWS)
    ofstream ofs(_path.generic_string(), std::ios::trunc);
    if (ofs) {
        ofs << _endpoint << endl;
        ofs << _name << endl;
        ofs << ola::utility::base64_encode(_token) << endl;
        ofs.flush();
    }
#else

    string out;
    {
        ostringstream oss;

        oss << _endpoint << endl;
        oss << _name << endl;
        oss << ola::utility::base64_encode(_token) << endl;
        
        out = oss.str();
    }
    

    // Open the existing file.
    auto hFile = CreateFile(TEXT(_path.generic_string().c_str()),
        GENERIC_WRITE, // open for writing
        0, // do not share
        NULL, // no security
        CREATE_ALWAYS | TRUNCATE_EXISTING, // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL); // no attr. template
    
    if (hFile != INVALID_HANDLE_VALUE) {
        OVERLAPPED overlapped;
        overlapped.Offset     = 0;
        overlapped.OffsetHigh = 0;
        overlapped.hEvent     = 0;

        if (LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, out.size(), 0, &overlapped)) {
            DWORD writen = 0;
            WriteFile(hFile, out.data(), out.size(), &writen, nullptr);
            UnlockFile(hFile, 0, 0, out.size(), 0);

        }
        CloseHandle(hFile);
    }

#endif
}

void auth_read(
    const boost::filesystem::path &_path,
    std::string &_rendpoint,
    std::string &_rname,
    std::string &_rtoken
){
#if !defined(SOLID_ON_WINDOWS)
    ifstream ifs(_path.generic_string());
    if (ifs) {
        getline(ifs, _rendpoint);
        getline(ifs, _rname);
        getline(ifs, _rtoken);
        try {
            _rtoken = ola::utility::base64_decode(_rtoken);
        } catch (std::exception&) {
            _rendpoint.clear();
            _rname.clear();
            _rtoken.clear();
        }
    }
#else
    char buf[4096];

    // Open the existing file.
    auto hFile = CreateFile(TEXT(_path.generic_string().c_str()),
        GENERIC_READ, // open for reading
        0, // do not share
        NULL, // no security
        OPEN_EXISTING, // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL); // no attr. template

    if (hFile != INVALID_HANDLE_VALUE) {
        OVERLAPPED overlapped;
        overlapped.Offset = 0;
        overlapped.OffsetHigh = 0;
        overlapped.hEvent     = 0;

        if (LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &overlapped)) {
            DWORD read_count = 0;
            ReadFile(hFile, buf, 4096, &read_count, nullptr);
            UnlockFile(hFile, 0, 0, 4096, 0);
            if (read_count > 0) {
                istringstream iss(string(buf, read_count));
                getline(iss, _rendpoint);
                getline(iss, _rname);
                getline(iss, _rtoken);
                trim(_rendpoint);
                trim(_rname);
                trim(_rtoken);
                try {
                    _rtoken = ola::utility::base64_decode(_rtoken);
                } catch (std::exception&) {
                    _rendpoint.clear();
                    _rname.clear();
                    _rtoken.clear();
                }
            }
        }
        CloseHandle(hFile);
    }
#endif
}

void auth_update(
    const boost::filesystem::path&         _path,
    std::chrono::system_clock::time_point& _write_time_point,
    std::string&                           _endpoint,
    std::string&                           _name,
    std::string&                           _token)
{
    boost::system::error_code err;

    if(_write_time_point == chrono::system_clock::from_time_t(fs::last_write_time(_path, err))){
        auth_write(_path, _endpoint, _name, _token);
    }
}

}//namespace utility
}//namespace client
}//namespace ola