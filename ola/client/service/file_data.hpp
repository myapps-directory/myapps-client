#pragma once

#include <memory>
#include <istream>
#include <set>
#include "file_cache.hpp"

#include "ola/common/ola_front_protocol_main.hpp"

namespace ola {
namespace client {
namespace service {

struct ReadData {
    size_t    bytes_transfered_ = 0;
    char*     pbuffer_;
    uint64_t  offset_;
    size_t    size_;
    ReadData* pnext_ = nullptr;
    ReadData* pprev_ = nullptr;
    bool      done_  = false;

    ReadData(
        char*    _pbuffer,
        uint64_t _offset,
        size_t   _size)
        : pbuffer_(_pbuffer)
        , offset_(_offset)
        , size_(_size)
    {
    }
};

struct FileFetchStub {
    ReadData* pfront_ = nullptr;
    ReadData* pback_ = nullptr;
    uint64_t decompressed_size_ = 0;
    std::string   compressed_chunk_;
    uint32_t chunk_index_ = 0;
    uint32_t chunk_offset_ = 0;
    const uint32_t compress_chunk_capacity_ = 0;
    const uint8_t  compress_algorithm_type_ = 0;
    std::shared_ptr<front::main::FetchStoreRequest> request_ptr_;
    std::shared_ptr<front::main::FetchStoreResponse>   response_ptr_[2];
    std::set<uint32_t>  chunk_set_;
    uint32_t            contiguous_chunk_count_ = 0;//used for prefetching
    uint32_t            last_chunk_index_ = 0;

    FileFetchStub(
        uint32_t _compress_chunk_capacity,
        uint8_t  _compress_algorithm_type
    )
        : compress_chunk_capacity_(_compress_chunk_capacity)
        , compress_algorithm_type_(_compress_algorithm_type){}

    bool isLastChunk(const uint64_t _size, const uint64_t chunk_index_)const {
        return ((chunk_index_ + 1) * compress_chunk_capacity_) >= _size;
    }

    bool enqueue(ReadData& _rdata)
    {
        _rdata.pnext_ = pback_;
        _rdata.pprev_ = nullptr;
        if (pback_ == nullptr) {
            pback_ = pfront_ = &_rdata;
            return true;
        }
        else {
            pback_->pprev_ = &_rdata;
            pback_ = &_rdata;
            return false;
        }
    }

    void enqueueChunks(const uint64_t _offset, const uint64_t _size) {
        uint32_t chunk_index = offsetToChunkIndex(_offset);

        do {
            if (!chunk_set_.empty()) {
                chunk_index_ = chunk_index;
            }

            auto rv = chunk_set_.insert(chunk_index);
            if (rv.second) {//insertion took place
                if (chunk_index != last_chunk_index_) {
                    if (chunk_index == (last_chunk_index_ + 1)) {
                        ++contiguous_chunk_count_;
                    }
                    else {
                        contiguous_chunk_count_ = 0;
                    }
                }
            }

            ++chunk_index;
        } while (chunkIndexToOffset(chunk_index) < (_offset + _size));
    }

    uint32_t offsetToChunkIndex(const uint64_t _offset)const {
        return _offset / compress_chunk_capacity_;
    }
    uint64_t chunkIndexToOffset(const uint32_t _chunk_index)const {
        return _chunk_index * compress_chunk_capacity_;
    }

    void erase(ReadData& _rdata)
    {
        if (_rdata.pprev_ != nullptr) {
            _rdata.pprev_->pnext_ = _rdata.pnext_;
        }
        else {
            pback_ = _rdata.pnext_;
        }
        if (_rdata.pnext_ != nullptr) {
            _rdata.pnext_->pprev_ = _rdata.pprev_;
        }
        else {
            pfront_ = _rdata.pprev_;
        }
    }

    uint32_t copy(std::istream& _ris, const uint64_t _chunk_size, const bool _is_compressed);
};

struct FileData : file_cache::FileData {
    std::string               remote_path_;
    std::unique_ptr<FileFetchStub> fetch_stub_ptr_;
    
    FileData(const std::string& _remote_path)
        : remote_path_(_remote_path)
    {
    }

    FileData(const FileData& _rfd)
        : remote_path_(_rfd.remote_path_)
    {
    }

    bool readFromCache(ReadData& _rdata)
    {
        size_t bytes_transfered_front = 0;
        size_t bytes_transfered_back = 0;
        const bool   b          = file_cache::FileData::readFromCache(_rdata.pbuffer_, _rdata.offset_, _rdata.size_, bytes_transfered_front, bytes_transfered_back);
        _rdata.bytes_transfered_ += (bytes_transfered_front + bytes_transfered_back);
        _rdata.pbuffer_ += bytes_transfered_front;
        _rdata.offset_ += bytes_transfered_front;
        _rdata.size_ -= bytes_transfered_front;
        _rdata.size_ -= bytes_transfered_back;
        return b;
    }

    bool enqueue(ReadData& _rdata, const uint64_t _size, const uint32_t _compress_chunk_capacity, const uint8_t _compress_algorithm_type)
    {
        if (!fetch_stub_ptr_) {
            fetch_stub_ptr_ = std::make_unique<FileFetchStub>(_compress_chunk_capacity, _compress_algorithm_type);
        }
        
        fetch_stub_ptr_->enqueueChunks(_rdata.offset_, _rdata.size_);

        return fetch_stub_ptr_->enqueue(_rdata);
    }

    bool isOk()const {
        return true;
    }

    size_t findAvailableFetchIndex() const;
    size_t isReadHandledByPendingFetch(const ReadData& _rread_data) const;
};


} // namespace service
} // namespace client
} //namespace ola