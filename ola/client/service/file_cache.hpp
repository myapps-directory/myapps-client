#pragma once
#include "boost/filesystem.hpp"
#include "solid/frame/common.hpp"
#include <fstream>
#include <vector>
#include <memory>
#include <string>

namespace ola {
namespace client {
namespace service {
namespace file_cache {

namespace fs = boost::filesystem;

std::string namefy(const std::string& _path);
std::string denamefy(const std::string& _path);

std::string namefy_b64(const std::string& _path);

class File {
    struct Header {
        uint64_t size_;
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
    };
    using RangeVectorT = std::vector<Range>;
    RangeVectorT range_vec_;
    std::fstream stream_;
    uint64_t     size_;

public:
    static uint64_t check(const fs::path& _path);

	bool open(const fs::path& _path, const uint64_t _size);

	void close();

	void write(const uint64_t _offset, std::istream& _ris);
    bool read(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered);

private:
	void addRange(const uint64_t _offset, const uint64_t _size);
    bool findRange(const uint64_t _offset, size_t& _rsize) const;

	bool loadRanges();
    void storeRanges();
};

struct FileData {
    std::string app_id_;
    std::string build_unique_;
    File file_;

    virtual ~FileData() = default;

	void writeToCache(const uint64_t _offset, std::istream& _ris);
    bool readFromCache(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered);
};

using UniqueIdT = solid::frame::UniqueId;

class Engine {
public:
    void start(const fs::path &_path);

    template <class T>
    std::unique_ptr<T> create(const UniqueIdT& _uid, const uint64_t _size, const std::string &_storage_id, const std::string& _app_id, const std::string &_build_unique, const std::string& _remote_path)
	{
        std::unique_ptr<T> ptr = std::unique_ptr<T>(static_cast<T*>(uncache(_uid).release()));
        if (ptr) {
            open(*ptr);
            return ptr;
        }
        ptr = std::make_unique<T>(_storage_id, _remote_path);
        ptr->app_id_ = _app_id;
        ptr->build_unique_ = _build_unique;
        tryOpen(*ptr, _size, _app_id, _build_unique, _remote_path);
		return ptr;
	}	

	template <class T>
    UniqueIdT release(std::unique_ptr<T>& _data_ptr)
	{
		close(*_data_ptr);
		return cache(_data_ptr.release());
	}

private:
    void open(FileData& _rfd);
    void tryOpen(FileData& _rfd, const uint64_t _size, const std::string& _app_id, const std::string &_build_unique, const std::string& _remote_path);
    void close(FileData& _rfd);
    UniqueIdT cache(FileData* _pfd);
	std::unique_ptr<FileData> uncache(const UniqueIdT& _uid);

private:
    fs::path path_;
};


} //namespace file_cache
} //namespace service
} //namespace client
} //namespace ola