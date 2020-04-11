#include "ola/client/utility/auth_file.hpp"
#include "ola/common/utility/encode.hpp"
#include <fstream>
#include <string>

using namespace std;

namespace fs = boost::filesystem;

namespace ola{
namespace client{
namespace utility{

void auth_write(
    const boost::filesystem::path &_path,
    const std::string &_endpoint,
    const std::string &_name,
    const std::string &_token
){
    ofstream ofs(_path.generic_string(), std::ios::trunc);
    if (ofs) {
        ofs << _endpoint << endl;
        ofs << _name << endl;
        ofs << ola::utility::base64_encode(_token) << endl;
        ofs.flush();
    }
}

void auth_read(
    const boost::filesystem::path &_path,
    std::string &_rendpoint,
    std::string &_rname,
    std::string &_rtoken
){
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
        ofstream ofs(_path.generic_string(), std::ios::trunc);
        if (ofs) {
            ofs << _endpoint << endl;
            ofs << _name << endl;
            ofs << ola::utility::base64_encode(_token) << endl;
            ofs.flush();
        }
    }
}

}//namespace utility
}//namespace client
}//namespace ola