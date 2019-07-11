#include "../file_cache.hpp"
#include "solid/system/common.hpp"
#include <sstream>
#include <vector>

using namespace std;
using namespace ola::client::service::file_cache;
namespace {

void copy(ostream& _ros, istream& _ris, uint64_t _size)
{
    constexpr size_t buffer_capacity = 4096;
    char             buffer[buffer_capacity];
    uint64_t         read_count = 0;
    if (_ris) {
        uint64_t toread = _size;
        if (toread > buffer_capacity) {
            toread = buffer_capacity;
        }
        while (toread != 0 && _ris.read(buffer, toread)) {
            read_count += toread;
            _ros.write(buffer, toread);
            _size -= toread;
            toread = _size;
            if (toread > buffer_capacity) {
                toread = buffer_capacity;
            }
        }
        solid_check(_size == 0);
    }
}
void create_test_data(ostream& _ros, uint64_t _cnt)
{
    for (auto i = 0; i < _cnt; ++i) {
        _ros << i << ' ';
    }
}

void write(File& _rf, uint64_t _offset, uint64_t _size, istream& _ris)
{
    stringstream ioss;
    _ris.seekg(_offset);
    copy(ioss, _ris, _size);
    _rf.write(_offset, ioss);
}

bool check(const char* _pbuf, uint64_t _offset, uint64_t _size, istream& _ris)
{
    constexpr size_t buf_cap = 1024 * 32;
    char             buf[buf_cap];

    _ris.seekg(_offset);
    while (_size != 0) {
        size_t toread = buf_cap;
        if (toread > _size) {
            toread = _size;
		}
        _ris.read(buf, toread);
        solid_check(memcmp(_pbuf, buf, toread) == 0);
        _size -= toread;
        _pbuf += toread;
    }
}

} //namespace

int test_file_cache_file(int argc, char* argv[])
{

    stringstream ioss;

    create_test_data(ioss, 10000);

    ioss.seekg(0, ios::end);
    const uint64_t data_size = ioss.tellg();

	fs::remove("test.data");

    {
        constexpr size_t buf_cap = 1024 * 100;
        char             buf[buf_cap];
        size_t           bytes_transfered = 0;
        File             f;

        solid_check(f.open("test.data", data_size));

        solid_check(!f.read(buf, 1000, 500, bytes_transfered) && bytes_transfered == 0);

        write(f, 1000, 500, ioss);
        bytes_transfered = 0;
        solid_check(!f.read(buf, 0, 500, bytes_transfered) && bytes_transfered == 0);
        bytes_transfered = 0;
        solid_check(f.read(buf, 1000, 500, bytes_transfered) && bytes_transfered == 500 && check(buf, 1000, 500, ioss));

        write(f, 2000, 500, ioss);
        bytes_transfered = 0;
        solid_check(!f.read(buf, 1400, 1000, bytes_transfered) && bytes_transfered == 100 && check(buf, 1400, 100, ioss));

        //1000-1500 2000-2500
        write(f, 1500, 500, ioss);

        bytes_transfered = 0;
        solid_check(f.read(buf, 1000, 1500, bytes_transfered) && bytes_transfered == 1500 && check(buf, 1000, 1500, ioss));

        //1000-2500
        write(f, 3000, 500, ioss);

        //1000-2500 3000-3500
        bytes_transfered = 0;
        solid_check(!f.read(buf, 2400, 1000, bytes_transfered) && bytes_transfered == 100 && check(buf, 2400, 100, ioss));

        bytes_transfered = 0;
        solid_check(!f.read(buf, 2900, 1000, bytes_transfered) && bytes_transfered == 0);

        bytes_transfered = 0;
        solid_check(!f.read(buf, 3400, 1000, bytes_transfered) && bytes_transfered == 100 && check(buf, 3400, 100, ioss));

        write(f, 4000, 500, ioss);

        //1000-2500 3000-3500 4000-4500
        write(f, 3400, 200, ioss);

        //1000-2500 3000-3600 4000-4500
        bytes_transfered = 0;
        solid_check(!f.read(buf, 3500, 1000, bytes_transfered) && bytes_transfered == 100 && check(buf, 3500, 100, ioss));

        write(f, 3900, 100, ioss);
        //1000-2500 3000-3600 3900-4500
        bytes_transfered = 0;
        solid_check(!f.read(buf, 3900, 1000, bytes_transfered) && bytes_transfered == 600 && check(buf, 3900, 600, ioss));

        write(f, 2000, 2000, ioss);

        //1000-4500
        bytes_transfered = 0;
        solid_check(f.read(buf, 1000, 3500, bytes_transfered) && bytes_transfered == 3500 && check(buf, 1000, 3500, ioss));
    }

    fs::remove("test.data");

    {
        File f;

        solid_check(f.open("test.data", data_size));

        write(f, 1000, 500, ioss);
        write(f, 2000, 500, ioss);
        write(f, 3000, 500, ioss);
        f.close();
    }

    {
        constexpr size_t buf_cap = 1024 * 100;
        char             buf[buf_cap];
        size_t           bytes_transfered = 0;
        File             f;

        solid_check(f.open("test.data", data_size));

        bytes_transfered = 0;
        solid_check(f.read(buf, 1000, 500, bytes_transfered) && bytes_transfered == 500 && check(buf, 1000, 500, ioss));

        bytes_transfered = 0;
        solid_check(f.read(buf, 2000, 500, bytes_transfered) && bytes_transfered == 500 && check(buf, 2000, 500, ioss));

        bytes_transfered = 0;
        solid_check(f.read(buf, 3000, 500, bytes_transfered) && bytes_transfered == 500 && check(buf, 3000, 500, ioss));
    }

    return 0;
}