#include "file_cache.hpp"
#include "ola/common/utility/encode.hpp"
#include "solid/system/cassert.hpp"
#include <algorithm>

#include <cereal/archives/binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>

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

template <class T>
struct BufferWrapper {
    static constexpr size_t size = sizeof(T);

    union {
        T    t_;
        char b_[size];
    } u_;

    char* buffer()
    {
        return u_.b_;
    }

    T& data()
    {
        return u_.t_;
    }
};

bool File::open(const fs::path& _path, const uint64_t _size)
{
    size_ = _size;

    stream_.open(_path.generic_string(), ios::in | ios::out | ios::binary);
    if (!stream_.is_open()) {
        stream_.open(_path.generic_string(), ios::in | ios::out | ios::binary | ios::trunc);
    }
    if (stream_.is_open()) {
        BufferWrapper<Header> h;
        stream_.read(h.buffer(), h.size);

        if (!stream_.eof()) {
            if (h.data().size_ != _size) {
                stream_.close();
                fs::remove(_path);
                return false;
            }

            if (!loadRanges()) {
                stream_.close();
                fs::remove(_path);
                return false;
            }
        } else {
            stream_.clear();
            BufferWrapper<Header> h;
            h.data().size_ = _size;
            stream_.seekp(0);
            stream_.write(h.buffer(), h.size);
        }
        return true;
    } else {
        return false;
    }
}

bool File::loadRanges()
{
    stream_.seekg(sizeof(Header) + size_);
    cereal::BinaryInputArchive a(stream_);

    size_t s = -1; //dummy value

    a(range_vec_, s);

    if (range_vec_.size() != s) {
        range_vec_.clear();
        return false;
    }
    return true;
}
void File::storeRanges()
{
    stream_.seekp(sizeof(Header) + size_);
    cereal::BinaryOutputArchive a(stream_);

    size_t s = range_vec_.size();
    a(range_vec_, s);
}

void File::close()
{
    if (stream_.is_open()) {
        storeRanges();
        stream_.flush();
        stream_.close();
    }
}

bool File::read(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered)
{
    size_t len = _length;
    if (findRange(_offset, len)) {
        stream_.seekg(sizeof(Header) + _offset);
        stream_.read(_pbuf, len);
        solid_assert(len == stream_.gcount());
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

        stream_.seekp(sizeof(Header) + _offset);

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
        return _rr.offset_ < _o;
    };

    auto it = lower_bound(range_vec_.begin(), range_vec_.end(), _offset, less_cmp);

    if (it != range_vec_.begin()) {
        auto prev_it = it - 1;
        solid_assert(_offset > prev_it->offset_);
        if (_offset < (prev_it->offset_ + prev_it->size_)) {
            auto remsize = (prev_it->offset_ + prev_it->size_) - _offset;
            if (remsize < _rsize) {
                _rsize = remsize;
            }
            return true;
        }
    }
    if (it != range_vec_.end()) {
        solid_assert(_offset <= it->offset_);
        if (_offset == it->offset_) {
            if (it->size_ < _rsize) {
                _rsize = it->size_;
            }
            return true;
        }
    }
    return false;
}

void File::addRange(const uint64_t _offset, const uint64_t _size)
{
    const auto less_cmp = [](const Range& _rr, const uint64_t _o) -> bool {
        return _rr.offset_ < _o;
    };

    auto it = lower_bound(range_vec_.begin(), range_vec_.end(), _offset, less_cmp);

    if (it != range_vec_.begin()) {
        auto prev_it = it - 1;
        solid_assert(_offset > prev_it->offset_);
        if (_offset <= (prev_it->offset_ + prev_it->size_)) {
            if ((_offset + _size) > (prev_it->offset_ + prev_it->size_)) {
                prev_it->size_ = (_offset + _size) - prev_it->offset_;
                it             = prev_it;
                goto Optimize;
            } else {
                //range already contained
                return;
            }
        }
    }

    if (it != range_vec_.end()) {
        if (it->offset_ == _offset) {
            if ((_offset + _size) > (it->offset_ + it->size_)) {
                it->size_ = (_offset + _size) - it->offset_;
                goto Optimize;
            } else {
                return;
            }
        }
        it = range_vec_.insert(it, Range(_offset, _size));
    } else {
        range_vec_.insert(it, Range(_offset, _size));
        return;
    }

Optimize:
    auto nextit = it + 1;
    while (nextit != range_vec_.end()) {
        if (nextit->offset_ <= (it->offset_ + it->size_)) {
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

string namefy(const std::string& _path)
{
    string r{};
    r.reserve(_path.size());
    for (char c : _path) {
        if (c == '\\') {
            r += '&';
            r += '_';
        } else if (c == '&') {
            r += '&';
            r += '&';
        } else {
            r += c;
        }
    }
    return string{std::move(r)};
}

string denamefy(const std::string& _path)
{
    string r;
    r.reserve(_path.size());
    bool has_escape = false;
    for (char c : _path) {
        assert(c != '\\');
        if (c == '&') {
            if (has_escape) {
                r += '&';
                has_escape = false;
            } else {
                has_escape = true;
            }
        } else if (c == '_') {
            if (has_escape) {
                r += '\\';
                has_escape = false;
            } else {
                r += '_';
            }
        } else {
            if (has_escape) {
                r += '&';
            }
            r += c;
        }
    }
    return string{std::move(r)};
}

std::string namefy_b64(const std::string& _txt)
{
    string s = utility::base64_encode(utility::sha256(_txt));
    for (auto& c : s) {
        if (c == '/') {
            c = '_';
        }
    }
    return s;
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
void Engine::start(const fs::path& _path)
{
    path_ = _path;
    fs::create_directories(path_);
}
void Engine::open(FileData& _rfd)
{
}
void Engine::tryOpen(FileData& _rfd, const uint64_t _size, const std::string& _app_id, const std::string& _build_name, const std::string& _remote_path)
{
    string d = utility::base64_encode(_app_id);
    string f = namefy_b64(_remote_path);

	for (auto& c : d) {
        if (c == '/') {
            c = '_';
        }
    }

    d += '\\';
    d += _build_name;
    d = namefy(d);

    fs::path p = path_;

	p /= d;

	fs::create_directories(p);

	p /= f;

	_rfd.file_.open(p, _size);
}
void Engine::close(FileData& _rfd)
{
    _rfd.file_.close();
}
UniqueIdT Engine::cache(FileData* _pfd)
{
    delete _pfd;
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