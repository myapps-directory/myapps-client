#include "file_cache.hpp"
#include "ola/common/utility/encode.hpp"
#include "solid/system/cassert.hpp"
#include <algorithm>
#include <chrono>
#include <mutex>
#include <stack>

#include "solid/system/log.hpp"
#include <cereal/archives/binary.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>

using namespace std;

namespace ola {
namespace client {
namespace service {
namespace file_cache {

namespace {
const solid::LoggerT logger("ola::client::file_cache");

struct FileStub;

struct Hash {
    size_t operator()(const std::reference_wrapper<const string>& _rrw) const
    {
        std::hash<string> h;
        return h(_rrw.get());
    }
};

struct Equal {
    bool operator()(const std::reference_wrapper<const string>& _rrw1, const std::reference_wrapper<const string>& _rrw2) const
    {
        return _rrw1.get() == _rrw2.get();
    }
};

struct ApplicationStub {
    using FileMapT = std::unordered_map<reference_wrapper<const string>, size_t, Hash, Equal>;
    string   name_;
    string   build_;
    FileMapT file_map_;

    void erase(const string& _file_name)
    {
        file_map_.erase(_file_name);
    }

    void clear()
    {
        name_.clear();
        build_.clear();
        file_map_.clear();
    }
};

struct FileStub {
    string           name_;
    ApplicationStub* papp_   = nullptr;
    uint64_t         size_   = 0;
    uint64_t         usage_  = -1;
    bool             in_use_ = false;

    void clear()
    {
        name_.clear();
        papp_   = nullptr;
        size_   = 0;
        usage_  = -1;
        in_use_ = false;
    }
};

struct FileStubLess {
    bool operator()(const FileStub* _p1, const FileStub* _p2) const
    {
        if (_p1->usage_ < _p2->usage_)
            return true;
        if (_p1->usage_ > _p2->usage_)
            return false;

        if (_p1->size_ < _p2->size_)
            return true;
        if (_p1->size_ > _p2->size_)
            return false;

        return _p1 < _p2;
    }
};

using FileMapT          = std::map<FileStub*, size_t, FileStubLess>;
using ApplicationMapT   = std::unordered_map<std::reference_wrapper<const string>, ApplicationStub*, Hash, Equal>;
using ApplicationDqT    = std::deque<ApplicationStub>;
using FileDqT           = std::deque<FileStub>;
using ApplicationStackT = std::stack<ApplicationStub*>;
using IndexStackT       = std::stack<size_t>;

} //namespace
//-----------------------------------------------------------------------------

struct Engine::Implementation {
    Configuration     config_;
    uint64_t          current_size_ = -1;
    ApplicationDqT    app_dq_;
    ApplicationStackT app_free_stack_;
    ApplicationMapT   app_map_;
    FileDqT           file_dq_;
    IndexStackT       file_free_index_stack_;
    FileMapT          file_map_;
    mutex             mutex_;

    uint64_t computeUsage() const
    {
        return std::chrono::steady_clock::now().time_since_epoch().count();
    }

    fs::path computeFilePath(const string& _app_id, const string& _build, const string& _file_name)
    {
        string d = _app_id;

        d += '\\';
        d += _build;
        d = namefy(d);

        fs::path p = config_.base_path_;
        p /= d;
        p /= _file_name;
        return p;
    }

    bool             exists(FileData& _rfd, ApplicationStub*& _rpapp, const std::string& _app_id, const std::string& _build_unique, const std::string& _name) const;
    ApplicationStub* application(const std::string& _app_id, const std::string& _build_unique);
    bool             ensureSpace(uint64_t _size);
    void             startUsingFile(FileData& _rfd, ApplicationStub& _rapp, const std::string& _name, const uint64_t _size);
    void             doneUsingFile(FileData& _rfd);
    void             eraseFile(const size_t _index);
    void             removeApplication(ApplicationStub& _rapp);
    bool             extractApplicationName(const string& _path, string& _rname, string& _rbuild);
    void             addApplicationFiles(ApplicationStub& _rapp, const fs::path& _path, uint64_t& _rsize);
    void             addApplicationFile(ApplicationStub& _rapp, const string& _name, uint64_t& _rsize);
    void             flush(FileData& _rfd);
};
//-----------------------------------------------------------------------------

Engine::Engine()
    : pimpl_(solid::make_pimpl<Implementation>())
{
}
Engine::~Engine() {}

void Engine::start(Configuration&& _config)
{
    pimpl_->config_ = std::move(_config);
    boost::system::error_code err;
    fs::create_directories(configuration().base_path_, err);
    solid_log(logger, Info, "Base path: " << configuration().base_path_);

    fs::directory_iterator it, end;

    try {
        it = fs::directory_iterator(configuration().base_path_);
    } catch (const std::exception&) {
        it = end;
    }

    uint64_t size = 0;

    while (it != end) {
        if (is_directory(*it)) {
            ApplicationStub* papp = nullptr;
            {
                lock_guard<mutex> lock{pimpl_->mutex_};
                if (pimpl_->app_free_stack_.empty()) {
                    pimpl_->app_dq_.emplace_back();
                    papp = &pimpl_->app_dq_.back();
                } else {
                    papp = pimpl_->app_free_stack_.top();
                    pimpl_->app_free_stack_.pop();
                }
            }
            if (pimpl_->extractApplicationName(it->path().leaf().generic_string(), papp->name_, papp->build_)) {
                lock_guard<mutex> lock{pimpl_->mutex_};
                pimpl_->app_map_[papp->name_] = papp;
                pimpl_->addApplicationFiles(*papp, it->path(), size);
            } else {
                papp->clear();
                lock_guard<mutex> lock{pimpl_->mutex_};
                pimpl_->app_free_stack_.push(papp);
            }
        }
        ++it;
    }

    lock_guard<mutex> lock{pimpl_->mutex_};
    pimpl_->current_size_ = size;
}

bool Engine::Implementation::extractApplicationName(const string& _path, string& _rname, string& _rbuild)
{
    auto path = denamefy(_path);

    auto off = path.rfind('\\');
    if (off == string::npos) {
        solid_log(logger, Info, _path << ": " << path << " invalid");
        return false;
    }

    _rname  = path.substr(0, off);
    _rbuild = path.substr(off + 1);

    solid_log(logger, Info, _path << " -> " << _rname << ' ' << _rbuild);
    return true;
}

void Engine::Implementation::addApplicationFile(ApplicationStub& _rapp, const string& _name, uint64_t& _rsize)
{
    File f;
    f.open(computeFilePath(_rapp.name_, _rapp.build_, _name));
    _rsize += f.size();

    size_t file_idx = -1;
    if (file_free_index_stack_.size()) {
        file_idx = file_free_index_stack_.top();
        file_free_index_stack_.pop();
    } else {
        file_idx = file_dq_.size();
        file_dq_.emplace_back();
    }

    FileStub& rfs = file_dq_[file_idx];
    rfs.name_     = _name;
    rfs.size_     = f.size();
    rfs.usage_    = f.usage();
    rfs.papp_     = &_rapp;

    file_map_[&rfs] = file_idx;

    _rapp.file_map_[rfs.name_] = file_idx;

    solid_log(logger, Info, _rapp.name_ << ' ' << _rapp.build_ << ' ' << _name << ' ' << _rsize << ' ' << rfs.size_ << ' ' << rfs.usage_ << ' ' << file_idx);
}

void Engine::Implementation::addApplicationFiles(ApplicationStub& _rapp, const fs::path& _path, uint64_t& _rsize)
{
    solid_log(logger, Info, _rapp.name_ << ' ' << _rapp.name_ << ' ' << _path);
    fs::directory_iterator it, end;

    try {
        it = fs::directory_iterator(_path);
    } catch (const std::exception& /*ex*/) {
        it = end;
    }

    while (it != end) {
        if (!fs::is_directory(*it)) {
            addApplicationFile(_rapp, it->path().filename().generic_string(), _rsize);
        }
        ++it;
    }
}

uint64_t Engine::usedSize() const
{
    lock_guard<mutex> lock{pimpl_->mutex_};
    return pimpl_->current_size_;
}

size_t Engine::fileCount() const
{
    lock_guard<mutex> lock{pimpl_->mutex_};
    return pimpl_->file_dq_.size() - pimpl_->file_free_index_stack_.size();
}

size_t Engine::applicationCount() const
{
    lock_guard<mutex> lock{pimpl_->mutex_};
    return pimpl_->app_map_.size();
}

const Configuration& Engine::configuration() const
{
    return pimpl_->config_;
}

void Engine::open(FileData& _rfd, const uint64_t _size, const std::string& _app_id, const std::string& _build_unique, const std::string& _remote_path)
{

    string d = _app_id;
    string f = namefy_b64(_remote_path);

    d += '\\';
    d += _build_unique;
    d = namefy(d);

    _rfd.cache_index_     = -1;
    ApplicationStub* papp = nullptr;

    lock_guard<mutex> lock{pimpl_->mutex_};

    if (pimpl_->exists(_rfd, papp, _app_id, _build_unique, f) || ((papp = pimpl_->application(_app_id, _build_unique)) != nullptr && pimpl_->ensureSpace(_size))) {

        fs::path p = configuration().base_path_;

        p /= d;

		boost::system::error_code err;
		fs::create_directories(p, err);

		string s = err.message();

        p /= f;

        pimpl_->startUsingFile(_rfd, *papp, f, _size);
        _rfd.file_.open(p, _size);
    }

    solid_log(logger, Info, _size << ' ' << _app_id << ' ' << _build_unique << ' ' << _remote_path << " -> " << _rfd.cache_index_);
}

ApplicationStub* Engine::Implementation::application(const std::string& _app_id, const std::string& _build_unique)
{
    solid_log(logger, Info, _app_id << ' ' << _build_unique);
    auto it = app_map_.find(_app_id);
    if (it != app_map_.end()) {
        if (it->second->build_ == _build_unique) {
            return it->second;
        }
    } else {
        ApplicationStub* papp;
        if (app_free_stack_.empty()) {
            app_dq_.emplace_back();
            papp = &app_dq_.back();
        } else {
            papp = app_free_stack_.top();
            app_free_stack_.pop();
        }

        papp->build_ = _build_unique;
        papp->name_  = _app_id;

        app_map_[papp->name_] = papp;

        return papp;
    }
    return nullptr;
}

bool Engine::Implementation::exists(FileData& _rfd, ApplicationStub*& _rpapp, const std::string& _app_id, const std::string& _build_unique, const std::string& _name) const
{
    auto it = app_map_.find(_app_id);
    if (it != app_map_.end()) {
        if (it->second->build_ == _build_unique) {
            _rpapp   = it->second;
            auto fit = it->second->file_map_.find(_name);
            if (fit != it->second->file_map_.end()) {
                _rfd.cache_index_ = fit->second;
                solid_log(logger, Info, _app_id << ' ' << _build_unique << ' ' << _name << "-> true");
                return true;
            }
        }
    }
    solid_log(logger, Info, _app_id << ' ' << _build_unique << ' ' << _name << "-> false");
    return false;
}

bool Engine::Implementation::ensureSpace(uint64_t _size)
{
    solid_log(logger, Info, _size);
    if (current_size_ == solid::InvalidSize()) {
        return false;
    }

    if (_size > config_.max_file_size_) {
        return false;
    }

    if ((current_size_ + _size) <= config_.max_size_) {
        return file_map_.size() < config_.max_count_;
    }

    auto it = file_map_.begin();

    uint64_t required_size = ((current_size_ + _size) - config_.max_size_);

    uint64_t freeing_size = 0;

    while (it != file_map_.end()) {
        if (!it->first->in_use_) {
            freeing_size += it->first->size_;
            if (freeing_size > required_size) {
                break;
            }
        }
        ++it;
    }

    if (freeing_size >= required_size) {
        freeing_size = 0;

        it = file_map_.begin();

        while (it != file_map_.end()) {
            if (!it->first->in_use_) {
                freeing_size += it->first->size_;
                eraseFile(it->second);
                it = file_map_.erase(it);
                if (freeing_size > required_size) {
                    break;
                }
                continue;
            }
            ++it;
        }
        solid_check(current_size_ > freeing_size);
        current_size_ -= freeing_size;
        return true;
    }

    return false;
}

void Engine::Implementation::eraseFile(const size_t _index)
{
    file_free_index_stack_.push(_index);
    FileStub& rfs = file_dq_[_index];

    solid_log(logger, Info, _index << ' ' << rfs.usage_ << ' ' << rfs.size_);

    rfs.papp_->erase(rfs.name_);
    boost::system::error_code err;
    fs::remove(computeFilePath(rfs.papp_->name_, rfs.papp_->build_, rfs.name_), err);
    rfs.clear();
}

void Engine::Implementation::startUsingFile(FileData& _rfd, ApplicationStub& _rapp, const std::string& _name, const uint64_t _size)
{
    solid_log(logger, Info, _name << ' ' << _size);
    if (_rfd.cache_index_ == solid::InvalidIndex()) {
        if (!file_free_index_stack_.empty()) {
            _rfd.cache_index_ = file_free_index_stack_.top();
            file_free_index_stack_.pop();
        } else {
            _rfd.cache_index_ = file_dq_.size();
            file_dq_.emplace_back();
        }

        FileStub& rfs = file_dq_[_rfd.cache_index_];
        rfs.size_     = _size;
        rfs.name_     = _name;
        rfs.papp_     = &_rapp;
        current_size_ += _size;
        _rapp.file_map_[rfs.name_] = _rfd.cache_index_;
    } else {
        file_map_.erase(&file_dq_[_rfd.cache_index_]);
    }

    FileStub& rfs = file_dq_[_rfd.cache_index_];
    rfs.in_use_   = true;

    solid_check(rfs.size_ == _size && rfs.name_ == _name);

    file_map_[&rfs] = _rfd.cache_index_;
}

void Engine::Implementation::doneUsingFile(FileData& _rfd)
{
    solid_log(logger, Info, _rfd.cache_index_);
    solid_check(_rfd.cache_index_ != solid::InvalidIndex());

    FileStub& rfs = file_dq_[_rfd.cache_index_];

    //file_map_.erase(&rfs);

    rfs.in_use_ = false;
    //rfs.usage_  = computeUsage();
    _rfd.file_.usage(rfs.usage_);

    //file_map_[&rfs] = _rfd.cache_index_;

    _rfd.cache_index_ = solid::InvalidIndex();
}

void Engine::close(FileData& _rfd)
{
    solid_log(logger, Info, _rfd.cache_index_);
    lock_guard<mutex> lock{pimpl_->mutex_};

    pimpl_->flush(_rfd);
    pimpl_->doneUsingFile(_rfd);
    _rfd.file_.close();
}

void Engine::flush(FileData& _rfd){
    lock_guard<mutex> lock{pimpl_->mutex_};

    pimpl_->flush(_rfd);
}

void Engine::Implementation::flush(FileData& _rfd)
{
    solid_check(_rfd.cache_index_ != solid::InvalidIndex());

    FileStub& rfs = file_dq_[_rfd.cache_index_];
    file_map_.erase(&rfs);
    rfs.usage_              = computeUsage();
    file_map_[&rfs] = _rfd.cache_index_;
    solid_log(logger, Info, _rfd.cache_index_ << ' ' << rfs.usage_);

    _rfd.file_.usage(rfs.usage_);
    _rfd.file_.flush();
}

void Engine::Implementation::removeApplication(ApplicationStub& _rapp)
{
    solid_log(logger, Info, _rapp.name_ << ' ' << _rapp.build_);
    for (const auto& p : _rapp.file_map_) {
        FileStub& rfs  = file_dq_[p.second];
        auto      path = computeFilePath(_rapp.name_, _rapp.build_, rfs.name_);

		boost::system::error_code err;
        fs::remove(path, err);
        file_map_.erase(&rfs);
        rfs.clear();
        file_free_index_stack_.push(p.second);
    }
    _rapp.clear();
}

void Engine::removeApplication(const std::string& _app_id, const std::string& _build_unique)
{
    solid_log(logger, Info, _app_id << ' ' << _build_unique);
    lock_guard<mutex> lock{pimpl_->mutex_};
    auto              it = pimpl_->app_map_.find(_app_id);
    if (it != pimpl_->app_map_.end()) {
        if (it->second->build_ == _build_unique) {
            pimpl_->removeApplication(*it->second);
            pimpl_->app_map_.erase(it);
            pimpl_->app_free_stack_.push(it->second);
        }
    }
}
void Engine::removeOldApplications(const CheckApplicationExistFunctionT& _app_check_fnc)
{
    lock_guard<mutex> lock{pimpl_->mutex_};
    auto              it = pimpl_->app_map_.begin();
    while (it != pimpl_->app_map_.end()) {
        if (!_app_check_fnc(it->second->name_, it->second->build_)) {
            auto papp = it->second;
            it        = pimpl_->app_map_.erase(it);
            pimpl_->removeApplication(*papp);
            pimpl_->app_free_stack_.push(papp);
        } else {
            ++it;
        }
    }
}

//-----------------------------------------------------------------------------
//	File
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
    solid_log(logger, Info, this << " path = " << _path.generic_string() << " " << _size);
    size_           = _size;
    modified_range_ = false;
    modified_head_  = false;
    stream_.open(_path.generic_string(), ios::in | ios::out | ios::binary);
    if (!stream_.is_open()) {
        stream_.open(_path.generic_string(), ios::in | ios::out | ios::binary | ios::trunc);
    }
    if (stream_.is_open()) {
        BufferWrapper<Header> h;
        stream_.read(h.buffer(), h.size);

        if (!stream_.eof()) {
            if (_size != 0) {
                if (h.data().size_ != _size) {
                    stream_.close();
                    boost::system::error_code err;
                    fs::remove(_path, err);
                    return false;
                }
            } else {
                size_ = h.data().size_;
            }
            if (!loadRanges()) {
                stream_.close();
                boost::system::error_code err;
                fs::remove(_path, err);
                return false;
            }
        } else {
            stream_.clear();
            BufferWrapper<Header> h;
            h.data().size_ = _size;
            stream_.seekp(0);
            stream_.write(h.buffer(), h.size);
            modified_range_ = true;
            modified_head_  = true;
        }
        return true;
    } else {
        return false;
    }
}

bool File::loadRanges()
{
    stream_.seekg(sizeof(Header) + size_);
    size_t s = -1; //dummy value

    try {
        cereal::BinaryInputArchive a(stream_);

        a(range_vec_, s);
    } catch (...) {
        solid_assert(false);
        return false;
    }
    solid_log(logger, Info, this << " " << range_vec_.size() << " " << s);

    if (range_vec_.size() != s) {
        range_vec_.clear();
        return false;
    }
    return true;
}
void File::storeRanges()
{
    if (modified_range_) {

        stream_.clear();
        stream_.seekp(sizeof(Header) + size_);

        try {
            cereal::BinaryOutputArchive a(stream_);

            size_t s = range_vec_.size();
            a(range_vec_, s);

            solid_log(logger, Info, this << " " << range_vec_.size() << " " << s);
        } catch (...) {
            solid_assert(false);
        }
        modified_range_ = false;
    }
}

void File::storeHead()
{
    if (modified_head_) {

        stream_.clear();
        BufferWrapper<Header> h;
        h.data().size_  = size_;
        h.data().usage_ = usage_;
        stream_.seekp(0);
        stream_.write(h.buffer(), h.size);
        modified_head_ = false;
    }
}

void File::close()
{
    solid_log(logger, Info, this << " ");
    if (stream_.is_open()) {
        storeRanges();
        stream_.flush();
        stream_.close();
    }
}

void File::flush()
{
    if (stream_.is_open()) {
        storeHead();
        storeRanges();
        stream_.flush();
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
        modified_range_ = true;
        flush();
        solid_log(logger, Info, this << " " << range_vec_.size());
    }
}

void File::write(const uint64_t _offset, const std::string& _str)
{
    if (stream_) {
        stream_.seekp(sizeof(Header) + _offset);
        stream_.write(_str.data(), _str.size());

        addRange(_offset, _str.size());
        modified_range_ = true;
        flush();
        solid_log(logger, Info, this << " " << range_vec_.size());
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
            solid_assert(!range_vec_.empty());
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

void FileData::writeToCache(const uint64_t _offset, const string& _str)
{
    file_.write(_offset, _str);
}

bool FileData::readFromCache(char* _pbuf, uint64_t _offset, size_t _length, size_t& _rbytes_transfered)
{
    return file_.read(_pbuf, _offset, _length, _rbytes_transfered);
}

} //namespace file_cache
} //namespace service
} //namespace client
} //namespace ola