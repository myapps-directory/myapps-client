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
    uint32_t current_chunk_index_ = -1;
    uint32_t current_chunk_offset_ = 0;
    const uint32_t compress_chunk_capacity_ = 0;
    const uint8_t  compress_algorithm_type_ = 0;
    std::shared_ptr<front::main::FetchStoreRequest> request_ptr_;
    std::shared_ptr<front::main::FetchStoreResponse>   response_ptr_[2];
    std::deque<uint32_t>  chunk_dq_;
    uint32_t            contiguous_chunk_count_ = 0;//used for prefetching
    uint32_t            last_chunk_index_ = 0;
    bool                pending_request_ = false;

    FileFetchStub(
        uint32_t _compress_chunk_capacity,
        uint8_t  _compress_algorithm_type
    )
        : compress_chunk_capacity_(_compress_chunk_capacity)
        , compress_algorithm_type_(_compress_algorithm_type){}

    bool isLastChunk()const {
        return chunk_dq_.size() <= 1;
    }

    void nextChunk(){
        chunk_dq_.pop_front();
        if (!chunk_dq_.empty()) {
            current_chunk_index_ = chunk_dq_.front();
        }
        else {
            current_chunk_index_ = -1;
        }
    }

    uint32_t peekNextChunk()const {
        solid_assert(chunk_dq_.size() > 1);
        return *(chunk_dq_.begin() + 1);
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

    bool insertChunk(const uint32_t _index) {
        for (const auto& i : chunk_dq_) {
            if (i == _index) {
                return false;
            }
        }
        chunk_dq_.push_back(_index);
        return true;
    }

    void enqueueChunks(const uint64_t _offset, const uint64_t _size) {
        uint32_t chunk_index = offsetToChunkIndex(_offset);

        do {
            auto inserted = insertChunk(chunk_index);
            if (inserted) {//insertion happened
                if (chunk_index != last_chunk_index_) {
                    if (chunk_index == (last_chunk_index_ + 1)) {
                        ++contiguous_chunk_count_;
                    }
                    else {
                        contiguous_chunk_count_ = 0;

                    }

                    last_chunk_index_ = chunk_index;
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

    void prepareFetchingChunk() {
        solid_check(!chunk_dq_.empty());
        current_chunk_index_ = chunk_dq_.front();
        current_chunk_offset_ = 0;
    }

    void wakeAllReaderThreads() {
        while (pfront_ != nullptr) {
            pfront_->done_ = true;
            erase(*pfront_);
        }
    }
    void storeResponse(std::shared_ptr<front::main::FetchStoreResponse>& _rres_ptr) {
        if (!response_ptr_[0]) {
            response_ptr_[0] = _rres_ptr;
        }
        else {
            solid_check(!response_ptr_[1]);
            response_ptr_[1] = _rres_ptr;
        }
    }
};

struct FileData : file_cache::FileData {
    std::string               remote_path_;
    std::unique_ptr<FileFetchStub> fetch_stub_ptr_;
    uint32_t                   error_ = 0;
    
    FileData(const std::string& _remote_path)
        : remote_path_(_remote_path)
    {
    }

    FileData(const FileData& _rfd)
        : remote_path_(_rfd.remote_path_)
    {
    }

    uint32_t copy(std::istream& _ris, const uint64_t _chunk_size, const bool _is_compressed, bool& _rshould_wake_readers);

    bool readFromCache(ReadData& _rdata);

    bool readFromMemory(ReadData& _rdata, const std::string& _data, const uint64_t _offset);


    bool enqueue(ReadData& _rdata, const uint64_t _size, const uint32_t _compress_chunk_capacity, const uint8_t _compress_algorithm_type)
    {
        if (!fetch_stub_ptr_) {
            //lazy initialization
            fetch_stub_ptr_ = std::make_unique<FileFetchStub>(_compress_chunk_capacity, _compress_algorithm_type);
        }
        
        fetch_stub_ptr_->enqueueChunks(_rdata.offset_, _rdata.size_);

        return fetch_stub_ptr_->enqueue(_rdata);
    }

    void prepareFetchingChunk() {
        fetch_stub_ptr_->prepareFetchingChunk();
    }

    uint32_t error()const {
        return error_;
    }

    void error(uint32_t _error) {
        error_ = _error;
        fetch_stub_ptr_->wakeAllReaderThreads();
    }

    bool isExpectedResponse(const uint32_t _chunk_index, const uint32_t _chunk_offset) const {
        return fetch_stub_ptr_->current_chunk_index_ == _chunk_index && fetch_stub_ptr_->current_chunk_offset_ >= _chunk_offset;
    }

    void storeResponse(std::shared_ptr<front::main::FetchStoreResponse>& _rres_ptr) {
        fetch_stub_ptr_->storeResponse(_rres_ptr);
    }
    
    void storeRequest(std::shared_ptr<front::main::FetchStoreRequest>&& _rres_ptr)
    {
        fetch_stub_ptr_->request_ptr_ = std::move(_rres_ptr);
    }

    uint32_t currentChunkOffset()const {
        return fetch_stub_ptr_->current_chunk_offset_;
    }
    uint32_t currentChunkIndex()const {
        return fetch_stub_ptr_->current_chunk_index_;
    }

    auto& responsePointer(const size_t _index) {
        return fetch_stub_ptr_->response_ptr_[_index];
    }
    auto& requestPointer() {
        return fetch_stub_ptr_->request_ptr_;
    }

    uint64_t decompressedSize()const {
        return fetch_stub_ptr_->decompressed_size_;
    }

    bool isLastChunk()const {
        return fetch_stub_ptr_->isLastChunk();
    }

    uint32_t peekNextChunk()const {
        return fetch_stub_ptr_->peekNextChunk();
    }

    bool tryFillReads(const std::string& _data, const uint64_t _offset);

    void pendingRequest(const bool _b) {
        fetch_stub_ptr_->pending_request_ = _b;
    }

    bool pendingRequest()const {
        return fetch_stub_ptr_->pending_request_;
    }

    void tryClearFetchStub() {
        
    }
};


} // namespace service
} // namespace client
} //namespace ola