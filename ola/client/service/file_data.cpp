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
uint32_t FileData::copy(istream& _ris, const uint64_t _chunk_size, const bool _is_compressed, bool &_rshould_wake_readers) {
    uint32_t size = 0;
    auto& rstub = *fetch_stub_ptr_;
    if (_is_compressed) {
        size = stream_copy(rstub.compressed_chunk_, _ris);
        rstub.current_chunk_offset_ += size;
        solid_check(rstub.current_chunk_offset_ <= _chunk_size);
        if (rstub.current_chunk_offset_ == _chunk_size) {
            string uncompressed_data;
            uncompressed_data.reserve(rstub.compress_chunk_capacity_);
            
            solid_check(snappy::Uncompress(rstub.compressed_chunk_.data(), rstub.compressed_chunk_.size(), &uncompressed_data));
            
            this->writeToCache(rstub.chunkIndexToOffset(rstub.current_chunk_index_), uncompressed_data);
            
            _rshould_wake_readers = tryFillReads(uncompressed_data, rstub.chunkIndexToOffset(rstub.current_chunk_index_));

            rstub.decompressed_size_ += uncompressed_data.size();
            rstub.compressed_chunk_.clear();
            rstub.current_chunk_offset_ = 0;
            ++rstub.current_chunk_index_;
        }
    }
    else {
        size = this->writeToCache(rstub.chunkIndexToOffset(rstub.current_chunk_index_), _ris);
        _rshould_wake_readers = tryFillReads(string(), rstub.chunkIndexToOffset(rstub.current_chunk_index_));
        rstub.current_chunk_offset_ += size;
        solid_check(rstub.current_chunk_offset_ <= _chunk_size);
        if (rstub.current_chunk_offset_ == _chunk_size) {
            rstub.decompressed_size_ += size;
            rstub.current_chunk_offset_ = 0;
            ++rstub.current_chunk_index_;
        }
    }

    return size;
}

bool FileData::readFromCache(ReadData& _rdata)
{
    size_t bytes_transfered_front = 0;
    size_t bytes_transfered_back = 0;
    const bool   b = file_cache::FileData::readFromCache(_rdata.pbuffer_, _rdata.offset_, _rdata.size_, bytes_transfered_front, bytes_transfered_back);
    _rdata.bytes_transfered_ += (bytes_transfered_front + bytes_transfered_back);
    _rdata.pbuffer_ += bytes_transfered_front;
    _rdata.offset_ += bytes_transfered_front;
    _rdata.size_ -= bytes_transfered_front;
    _rdata.size_ -= bytes_transfered_back;
    return b;
}

bool FileData::readFromMemory(ReadData& _rdata, const std::string& _data, const uint64_t _offset) {
    if (!_data.empty()) {
        uint64_t end_offset = _offset + _data.size();
        if (_rdata.offset_ >= _offset && _rdata.offset_ < end_offset) {
            //we can copy the front part
            size_t to_copy = _data.size() - (_rdata.offset_ - _offset);
            if (to_copy > _rdata.size_) {
                to_copy = _rdata.size_;
            }
            
            memcpy(_rdata.pbuffer_, _data.data() + _rdata.offset_ - _offset, to_copy);
            
            _rdata.bytes_transfered_ += to_copy;
            _rdata.offset_ += to_copy;
            _rdata.pbuffer_ += to_copy;
            _rdata.size_ -= to_copy;
        }

        if (_rdata.size_ != 0 && _offset < (_rdata.offset_ + _rdata.size_) && _offset >= _rdata.offset_) {
            size_t to_copy = (_rdata.offset_ + _rdata.size_) - _offset;
            if (to_copy > _rdata.size_) {
                to_copy = _rdata.size_;
            }

            memcpy(_rdata.pbuffer_ + _rdata.size_ - to_copy, _data.data(), to_copy);
            
            _rdata.bytes_transfered_ += to_copy;
            _rdata.offset_ += to_copy;
            _rdata.pbuffer_ += to_copy;
            _rdata.size_ -= to_copy;
        }
    }
    return _rdata.size_ == 0;
}

bool FileData::tryFillReads(const std::string& _data, const uint64_t _offset)
{
    bool ret_val = false;
    auto& rstub = *fetch_stub_ptr_;
    for (auto* prd = rstub.pfront_; prd != nullptr;) {

        if (readFromMemory(*prd, _data, _offset)) {
        }
        else {
            readFromCache(*prd);
        }
        if (prd->size_ == 0) {
            auto tmp = prd;
            prd = prd->pprev_;
            rstub.erase(*tmp);
            tmp->done_ = true;
            ret_val = true;
        }
        else {
            prd = prd->pprev_;
        }
    }
    return ret_val;
}

} // namespace service
} // namespace client
} //namespace ola