#pragma once
#include "boost/filesystem.hpp"
#include "solid/frame/common.hpp"
#include "solid/system/pimpl.hpp"
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace ola {
namespace client {
namespace service {
namespace file_cache {

namespace fs = boost::filesystem;

std::string namefy(const std::string& _path);
std::string denamefy(const std::string& _path);

class File {
    struct Header {
        uint64_t size_;
        uint64_t usage_;
    };
    struct Range {
        uint64_t offset_;
        uint64_t size_;

        Range(uint64_t _offset = 0, uint64_t _size = 0)
            : offset_(_offset)
            , size_(_size)
        {
        }

        template <class Archive>
        void serialize(Archive& _a)
        {
            _a(offset_, size_);
        }

        bool operator<(const Range& _r)const {
            return (offset_ + size_) <= _r.offset_ || ( offset_ < _r.offset_ && ((offset_ + size_) < (_r.offset_ + _r.size_)));
        }
    };
    using RangeVectorT = std::vector<Range>;
    RangeVectorT range_vec_;
    std::fstream stream_;
    uint64_t     size_           = 0;
    uint64_t     usage_          = 0;
    bool         modified_range_ = false;
    bool         modified_head_  = false;

public:
    static uint64_t check(const fs::path& _path);

    bool open(const fs::path& _path, const uint64_t _size = 0);

    void close();

    uint64_t write(const uint64_t _offset, std::istream& _ris);
    bool read(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered_front, size_t& _rbytes_transfered_back);

    void write(const uint64_t _offset, const char *_pbuf, size_t _size);

    void flush();

    void usage(const uint64_t _usage)
    {
        if (usage_ != _usage) {
            usage_         = _usage;
            modified_head_ = true;
        }
    }

    uint64_t usage() const
    {
        return usage_;
    }

    size_t rangeCount() const
    {
        return range_vec_.size();
    }

    uint64_t size() const
    {
        return size_;
    }

    bool isComplete()const {
        return range_vec_.size() == 1 && range_vec_.front().size_ == size_;
    }

private:
    void addRange(const uint64_t _offset, const uint64_t _size);
    bool findRangeFront(const uint64_t _offset, size_t& _rsize) const;
    bool findRangeBack(const uint64_t _offset, uint64_t &_rstart_offset, size_t& _rsize) const;

    bool loadRanges();
    void storeRanges();
    void storeHead();
}; // namespace file_cache

struct FileData {
    std::string app_id_;
    std::string build_unique_;
    File        file_;
    size_t      cache_index_ = solid::InvalidIndex();

    virtual ~FileData() = default;

    uint64_t writeToCache(const uint64_t _offset, std::istream& _ris);
    void writeToCache(const uint64_t _offset, const char *_pdata, size_t _size);
    bool readFromCache(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered_front, size_t& _rbytes_transfered_back);

    size_t rageCount() const
    {
        return file_.rangeCount();
    }
    bool isComplete()const {
        return file_.isComplete();
    }
};

struct Configuration {
    fs::path base_path_;

    uint64_t max_size_      = 5 * 1024 * 1024 * 1024;
    uint64_t max_file_size_ = 200 * 1024 * 1024;
    size_t   max_count_     = 10 * 1024;
};

using UniqueIdT = solid::frame::UniqueId;

class Engine {
    struct Implementation;
    solid::PimplT<Implementation> pimpl_;

public:
    using CheckApplicationExistFunctionT = std::function<bool(const std::string&, const std::string&)>;

    Engine();
    ~Engine();

    void start(Configuration&& _config);

    void open(FileData& _rfd, const uint64_t _size, const std::string& _app_id, const std::string& _build_unique, const std::string& _remote_path);

    void close(FileData& _rfd);

    void flush(FileData& _rfd);

    uint64_t usedSize() const;
    size_t   applicationCount() const;
    size_t   fileCount() const;
    void     removeApplication(const std::string& _app_id, const std::string& _build_unique);

    const Configuration& configuration() const;

    void removeOldApplications(const CheckApplicationExistFunctionT& _app_check_fnc);
};

} // namespace file_cache
} // namespace service
} // namespace client
} //namespace ola