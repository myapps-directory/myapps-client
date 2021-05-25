#include "file_data.hpp"
#include "solid/system/exception.hpp"
#include "snappy.h"

using namespace std;

namespace ola {
namespace client {
namespace service {
namespace {
    uint64_t stream_copy(std::ostream& _ros, std::istream& _ris) {
        constexpr size_t buffer_size = 1024 * 32;
        char buffer[buffer_size];
        uint64_t size = 0;

        do {
            _ris.read(buffer, buffer_size);
            auto read_count = _ris.gcount();
            if (read_count) {
                _ros.write(buffer, read_count);
                size += read_count;
            }
        } while (!_ris.eof());
        return size;
    }


    uint64_t stream_copy(string& _str, std::istream& _ris) {
        constexpr size_t buffer_size = 1024 * 32;
        char buffer[buffer_size];
        uint64_t size = 0;

        do {
            _ris.read(buffer, buffer_size);
            auto read_count = _ris.gcount();
            if (read_count) {
                _str.append(buffer, read_count);
                size += read_count;
            }
        } while (!_ris.eof());
        return size;
    }
}
uint32_t FileFetchStub::copy(istream& _ris, const uint64_t _chunk_size, const bool _is_compressed) {
    uint32_t size = 0;
    if (_is_compressed) {
        size = stream_copy(compressed_chunk_, _ris);
        chunk_offset_ += size;
        solid_check(chunk_offset_ <= _chunk_size);
        if (chunk_offset_ == _chunk_size) {
            string uncompressed_data;
            uncompressed_data.reserve(compress_chunk_capacity_);
            solid_check(snappy::Uncompress(compressed_chunk_.data(), compressed_chunk_.size(), &uncompressed_data));
            //TODO:
            //ofs_.write(uncompressed_data.data(), uncompressed_data.size());
            decompressed_size_ += uncompressed_data.size();
            //size_t uncompressed_size = 0;
            //solid_check(snappy::GetUncompressedLength(compressed_chunk_.data(), compressed_chunk_.size(), &uncompressed_size));
            //decompressed_size_ += uncompressed_size;
            compressed_chunk_.clear();
            chunk_offset_ = 0;
            ++chunk_index_;
        }
    }
    else {
        //TODO:
        //size = stream_copy(ofs_, _ris);
        chunk_offset_ += size;
        solid_check(chunk_offset_ <= _chunk_size);
        if (chunk_offset_ == _chunk_size) {
            decompressed_size_ += size;
            chunk_offset_ = 0;
            ++chunk_index_;
        }
    }

    return size;
}

} // namespace service
} // namespace client
} //namespace ola