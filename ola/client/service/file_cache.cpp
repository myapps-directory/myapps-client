#include "file_cache.hpp"
#include <algorithm>

using namespace std;

namespace ola {
namespace client {
namespace service {
namespace file_cache {

//-----------------------------------------------------------------------------

/*static*/ uint64_t File::check(const fs::path& _path)
{
    return 0;
}

bool File::open(const fs::path& _path, const uint64_t _size)
{
    return false;
}

void File::close() {
}

bool File::read(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered)
{
    size_t len = _length;
    if (findRange(_offset, len)) {
        stream_.seekg(sizeof(Header) + _offset);
        stream_.read(_pbuf, len);
        _rbytes_transfered += len;
        return len == _length;
    }
    return false;
}

void File::write(const uint64_t _offset, std::istream& _ris)
{
    constexpr size_t buffer_capacity = 4096;
    if (stream_) {
        char     buffer[buffer_capacity];
        uint64_t read_count = 0;

        while (_ris.read(buffer, buffer_capacity)) {
            read_count += buffer_capacity;
            stream_.write(buffer, buffer_capacity);
        }
        size_t cnt = _ris.gcount();
        stream_.write(buffer, cnt);
        read_count += cnt;

        addRange(_offset, read_count);
    }
}

bool File::findRange(const uint64_t _offset, size_t& _rsize) const
{
    const auto less_cmp = [](const Range& _rr, const uint64_t _o) -> bool {
        return (_rr.offset_ + _rr.size_) <= _o;
    };
    auto it = lower_bound(range_vec_.begin(), range_vec_.end(), _offset, less_cmp);
    if (it != range_vec_.end() && _offset >= it->offset_ && _offset < (it->offset_ + it->size_)) {
        auto remsize = (it->offset_ + it->size_) - _offset;
        if (remsize < _rsize) {
            _rsize = remsize;
		}
        return true;
    }

    return false;
}

void File::addRange(const uint64_t _offset, const uint64_t _size)
{
    const auto less_cmp = [](const Range& _rr, const uint64_t _o) -> bool {
        return (_rr.offset_ + _rr.size_) <= _o;
    };

    auto it = lower_bound(range_vec_.begin(), range_vec_.end(), _offset, less_cmp);
    if (it != range_vec_.end() && _offset >= it->offset_ && _offset < (it->offset_ + it->size_)) {
        //overlapping ranges
        if ((it->offset_ + it->size_) < (_offset + _size)) {
            it->size_ = (_offset + _size) - it->offset_;
        }
    } else {
        it = range_vec_.insert(it, Range(_offset, _size));
    }

    auto nextit = it + 1;
    while (nextit != range_vec_.end()) {
        if (nextit->offset_ < (it->offset_ + it->size_)) {
            //overlapping
            if ((it->offset_ + it->size_) < (nextit->offset_ + nextit->size_)) {
                it->size_ = (nextit->offset_ + nextit->size_) - it->offset_;
            }
            nextit = range_vec_.erase(nextit);
        } else {
            break;
        }
    }
}

//-----------------------------------------------------------------------------

void FileData::writeToCache(const uint64_t _offset, istream& _ris)
{
    file_.write(_offset, _ris);
}

bool FileData::readFromCache(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered)
{
    return file_.read(_pbuf, _offset, _length, _rbytes_transfered);
}

//-----------------------------------------------------------------------------

void Engine::open(FileData& _rfd)
{
}
void Engine::tryOpen(FileData& _rfd)
{
}
void Engine::close(FileData& _rfd)
{
}
UniqueIdT Engine::cache(FileData* _pfd)
{
    return UniqueIdT();
}

std::unique_ptr<FileData> Engine::uncache(const UniqueIdT& _uid)
{
    return std::unique_ptr<FileData>();
}

} //namespace file_cache
} //namespace service
} //namespace client
} //namespace ola