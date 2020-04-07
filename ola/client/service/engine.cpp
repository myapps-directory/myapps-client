#include "ola/client/service/engine.hpp"

#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"
#include "solid/system/log.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"

#include "ola/common/utility/encode.hpp"

#include "ola/client/auth/auth_protocol.hpp"
#include "ola/client/utility/locale.hpp"

#include "file_cache.hpp"
#include "ola/common/ola_front_protocol.hpp"
#include "shortcut_creator.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/any.hpp>
#include <boost/filesystem.hpp>
#include <boost/functional/hash.hpp>

#include <atomic>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <variant>

using namespace solid;
using namespace std;
using namespace ola;
using namespace ola::front;

namespace ola {
namespace client {
namespace service {

namespace {
const solid::LoggerT logger("ola::client::service::engine");

constexpr const char* media_name = ".m";

enum struct EntryTypeE : uint8_t {
    Unknown,
    Directory,
    Application,
    File,
    Shortcut,
    Media,
};

enum struct EntryFlagsE : uint8_t {
    Hidden,
    Invisible,
    Volatile,
    Delete,
    Update,
};

using EntryFlagsT = std::underlying_type<EntryFlagsE>::type;

inline EntryFlagsT entry_flag(const EntryFlagsE _flag)
{
    return 1 << static_cast<EntryFlagsT>(_flag);
}

inline bool entry_has_flag(const EntryFlagsT _flags, const EntryFlagsE _flag)
{
    return (_flags & (1 << static_cast<EntryFlagsT>(_flag))) != 0;
}

enum struct EntryStatusE : uint8_t {
    FetchRequired,
    FetchPending,
    FetchError,
    Fetched
};

/*
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
*/

struct Equal {
    bool operator()(const std::reference_wrapper<const string>& _rrw1, const std::reference_wrapper<const string>& _rrw2) const
    {
        return boost::algorithm::iequals(_rrw1.get(), _rrw2.get(), std::locale());
    }
};

struct Hash {
    std::size_t operator()(const std::reference_wrapper<const string>& _rrw) const
    {
        std::size_t seed = 0;
        std::locale locale;

        for (std::string::const_iterator it = _rrw.get().begin();
             it != _rrw.get().end(); ++it) {
            boost::hash_combine(seed, std::toupper(*it, locale));
        }

        return seed;
    }
};

struct Entry;
using EntryPointerT   = std::shared_ptr<Entry>;
using EntryMapT       = std::unordered_map<const std::reference_wrapper<const string>, EntryPointerT, Hash, Equal>;
using EntryPtrMapT    = std::unordered_map<const std::reference_wrapper<const string>, Entry*, Hash, Equal>;
using EntryPtrVectorT = std::vector<Entry*>;
using UpdatesMapT     = std::unordered_map<string, pair<string, string>>;

struct DirectoryData {
    EntryMapT entry_map_;

    virtual ~DirectoryData() {}

    virtual EntryPointerT find(const string& _path) const;

    virtual void erase(const EntryPointerT& _rentry_ptr);

    void insertEntry(EntryPointerT&& _uentry_ptr);

    bool empty() const
    {
        return entry_map_.empty();
    }
};

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

struct FetchStub {
    enum StatusE {
        NotUsedE,
        PendingE,
        FetchedE,
        WaitE,
    };

    uint64_t                              offset_ = 0;
    size_t                                size_   = 0;
    StatusE                               status_ = NotUsedE;
    shared_ptr<FetchStoreRequest>         request_ptr_;
    shared_ptr<front::FetchStoreResponse> response_ptr_;
};

struct FileData : file_cache::FileData {
    enum StatusE {
        PendingE,
        ErrorE,
    };
    ReadData* pfront_ = nullptr;
    ReadData* pback_  = nullptr;
    StatusE   status_ = PendingE;
    FetchStub fetch_stubs_[2];
    string    remote_path_;
    uint64_t  prefetch_offset_;
    size_t    contiguous_read_count_;

    FileData(const string& _remote_path)
        : remote_path_(_remote_path)
    {
    }

    FileData(const FileData& _rfd)
        : remote_path_(_rfd.remote_path_)
    {
    }

    bool readFromCache(ReadData& _rdata)
    {
        size_t bytes_transfered = 0;
        bool   b                = file_cache::FileData::readFromCache(_rdata.pbuffer_, _rdata.offset_, _rdata.size_, bytes_transfered);
        _rdata.bytes_transfered_ += bytes_transfered;
        _rdata.pbuffer_ += bytes_transfered;
        _rdata.offset_ += bytes_transfered;
        _rdata.size_ -= bytes_transfered;
        return b;
    }

    bool readFromResponses(ReadData& _rdata, bool _is_front);

    bool enqueue(ReadData& _rdata)
    {
        _rdata.pnext_ = pback_;
        _rdata.pprev_ = nullptr;
        if (pback_ == nullptr) {
            pback_ = pfront_ = &_rdata;
            return true;
        } else {
            pback_->pprev_ = &_rdata;
            pback_         = &_rdata;
            return false;
        }
    }

    void erase(ReadData& _rdata)
    {
        if (_rdata.pprev_ != nullptr) {
            _rdata.pprev_->pnext_ = _rdata.pnext_;
        } else {
            pfront_ = _rdata.pnext_;
        }
        if (_rdata.pnext_ != nullptr) {
            _rdata.pnext_->pprev_ = _rdata.pprev_;
        } else {
            pback_ = _rdata.pprev_;
        }
    }
    size_t findAvailableFetchIndex() const;
    size_t isReadHandledByPendingFetch(const ReadData& _rread_data) const;
    bool   readFromResponse(const size_t _idx, ReadData& _rdata, bool _is_front);
    void   updateContiguousRead(uint64_t _offset, uint64_t _size);
};

struct ApplicationData : DirectoryData {
    std::string     app_id_; //used for updates
    std::string     app_unique_;
    std::string     build_unique_;
    EntryPtrVectorT shortcut_vec_;
    atomic<size_t>  use_count_ = 0;

    ApplicationData(const std::string& _app_unique, const std::string& _build_unique)
        : app_unique_(_app_unique)
        , build_unique_(_build_unique)
    {
    }

    ApplicationData(const ApplicationData& _rad)
        : app_unique_(_rad.app_unique_)
        , build_unique_(_rad.build_unique_)
    {
    }

    void insertShortcut(Entry* _pentry)
    {
        shortcut_vec_.emplace_back(_pentry);
    }

    bool canBeDeleted() const
    {
        return use_count_.load() == 0;
    }

    void useApplication()
    {
        auto v = use_count_.fetch_add(1);
        solid_log(logger, Info, "" << v);
    }

    void releaseApplication()
    {
        auto v = use_count_.fetch_sub(1);
        solid_log(logger, Info, "" << v);
    }
};

struct ShortcutData {
    stringstream ioss_;

    ShortcutData() {}
    ShortcutData(const ShortcutData&) {}
};

struct MediaData : DirectoryData {
    mutable Entry* pfront_ = nullptr;
    mutable Entry* pback_  = nullptr;

    EntryPointerT find(const string& _path) const override;
    void          erase(const EntryPointerT& _rentry_ptr) override;
    void          insertEntry(const Configuration& _rcfg, EntryPointerT&& _uentry_ptr);

    Entry* front() const
    {
        return pfront_;
    }

    void erase(Entry& _re) const;

    void pushBack(Entry& _re) const;

    void popFront() const;
};

struct RootData : DirectoryData {
    EntryPtrMapT app_entry_map_;

    Entry*        findApplication(const string& _path) const;
    void          insertApplication(Entry* _pentry);
    EntryPointerT eraseApplication(Entry& _rentry);
};

using UniqueIdT = solid::frame::UniqueId;

struct Entry {
    std::mutex&              rmutex_;
    std::condition_variable& rcv_;
    string                   name_;
    string                   remote_;
    EntryTypeE               type_   = EntryTypeE::Unknown;
    EntryStatusE             status_ = EntryStatusE::FetchRequired;
    EntryFlagsT              flags_  = 0;
    std::weak_ptr<Entry>     parent_;
    Entry*                   pmaster_ = nullptr;
    uint64_t                 size_    = 0;
    boost::any               data_any_;
    Entry*                   pnext_ = nullptr;
    Entry*                   pprev_ = nullptr;

    Entry(
        const EntryTypeE _type, EntryPointerT& _rparent_ptr, std::mutex& _rmutex, std::condition_variable& _rcv, const string& _name,
        const uint64_t _size = 0)
        : rmutex_(_rmutex)
        , rcv_(_rcv)
        , name_(_name)
        , type_(_type)
        , parent_(_rparent_ptr)
        , pmaster_(_rparent_ptr->pmaster_)
        , size_(_size)
    {
    }

    Entry(
        const EntryTypeE _type, std::mutex& _rmutex, std::condition_variable& _rcv, const string& _name)
        : rmutex_(_rmutex)
        , rcv_(_rcv)
        , name_(_name)
        , type_(_type)
        , size_(0)
    {
    }

    bool isDirectory() const
    {
        return type_ == EntryTypeE::Application || type_ == EntryTypeE::Directory;
    }

    bool isFile() const
    {
        return type_ == EntryTypeE::File;
    }

    bool isMedia() const
    {
        return type_ == EntryTypeE::Media;
    }

    bool isApplication() const
    {
        return type_ == EntryTypeE::Application;
    }

    bool isShortcut() const
    {
        return type_ == EntryTypeE::Shortcut;
    }

    inline DirectoryData* directoryDataPtr()
    {
        DirectoryData* pdd = boost::any_cast<ApplicationData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        pdd = boost::any_cast<MediaData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        pdd = boost::any_cast<RootData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        return boost::any_cast<DirectoryData>(&data_any_);
    }

    inline const DirectoryData* directoryDataPtr() const
    {
        const DirectoryData* pdd = boost::any_cast<ApplicationData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        pdd = boost::any_cast<MediaData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        pdd = boost::any_cast<RootData>(&data_any_);
        if (pdd) {
            return pdd;
        }
        return boost::any_cast<DirectoryData>(&data_any_);
    }

    inline ApplicationData* applicationDataPtr()
    {
        return boost::any_cast<ApplicationData>(&data_any_);
    }

    inline const ApplicationData* applicationDataPtr() const
    {
        return boost::any_cast<ApplicationData>(&data_any_);
    }

    inline FileData* fileDataPtr()
    {
        return boost::any_cast<FileData>(&data_any_);
    }

    inline const FileData* fileDataPtr() const
    {
        return boost::any_cast<FileData>(&data_any_);
    }

    inline FileData& fileData()
    {
        return *fileDataPtr();
    }

    inline const FileData& fileData() const
    {
        return *fileDataPtr();
    }

    inline const ShortcutData& shortcutData() const
    {
        return *boost::any_cast<ShortcutData>(&data_any_);
    }

    inline ShortcutData& shortcutData()
    {
        return *boost::any_cast<ShortcutData>(&data_any_);
    }

    inline RootData& rootData()
    {
        return *boost::any_cast<RootData>(&data_any_);
    }

    inline MediaData& mediaData()
    {
        return *boost::any_cast<MediaData>(&data_any_);
    }

    inline ApplicationData& applicationData()
    {
        return *applicationDataPtr();
    }

    inline const ApplicationData& applicationData() const
    {
        return *applicationDataPtr();
    }

    inline DirectoryData& directoryData()
    {
        return *directoryDataPtr();
    }

    inline const DirectoryData& directoryData() const
    {
        return *directoryDataPtr();
    }

    EntryPointerT find(const string& _path) const
    {
        EntryPointerT entry_ptr;
        if (auto pd = directoryDataPtr(); pd != nullptr) {
            entry_ptr = pd->find(_path);
        }
        return entry_ptr;
    }

    void erase(const EntryPointerT& _rentry_ptr)
    {
        if (auto pd = directoryDataPtr(); pd != nullptr) {
            pd->erase(_rentry_ptr);
        }
    }

    void flagSet(const EntryFlagsE _flag)
    {
        flags_ |= entry_flag(_flag);
    }

    void flagReset(const EntryFlagsE _flag)
    {
        flags_ &= (~entry_flag(_flag));
    }

    std::mutex& mutex() const
    {
        return rmutex_;
    }
    std::condition_variable& conditionVariable() const
    {
        return rcv_;
    }

    void info(NodeFlagsT& _rnode_flags, uint64_t& _rsize) const
    {
        _rnode_flags = 0;
        _rsize       = size_;
        switch (type_) {
        case EntryTypeE::Unknown:
            solid_throw("Unknown entry type");
            break;
        case EntryTypeE::File:
        case EntryTypeE::Shortcut:
            _rnode_flags |= node_flag(NodeFlagsE::File);
            break;
        case EntryTypeE::Application:
        case EntryTypeE::Directory:
            _rnode_flags |= node_flag(NodeFlagsE::Directory);
            break;
        }

        if (flags_ & entry_flag(EntryFlagsE::Hidden)) {
            _rnode_flags |= node_flag(NodeFlagsE::Hidden);
        }
    }

    bool canInsertUnkownEntry() const
    {
        if (
            status_ == EntryStatusE::Fetched || status_ == EntryStatusE::FetchError || type_ == EntryTypeE::File || type_ == EntryTypeE::Shortcut) {
            return false;
        }
        return true;
    }

    bool empty() const
    {
        if (data_any_.empty()) {
            return true;
        } else if (auto pd = directoryDataPtr(); pd != nullptr) {
            return pd->empty();
        }
        return false;
    }

    bool isErasable() const
    {
        return (status_ == EntryStatusE::FetchRequired || status_ == EntryStatusE::FetchError) && empty();
    }
    bool isInvisible() const
    {
        //TODO: get rid of checking type
        return type_ == EntryTypeE::Unknown || entry_has_flag(flags_, EntryFlagsE::Invisible);
    }
    bool isVolatile() const
    {
        return entry_has_flag(flags_, EntryFlagsE::Volatile);
    }

    bool hasDelete() const
    {
        return entry_has_flag(flags_, EntryFlagsE::Delete);
    }

    bool hasUpdate() const
    {
        return entry_has_flag(flags_, EntryFlagsE::Update);
    }
};

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;

EntryPointerT DirectoryData::find(const string& _path) const
{
    auto it = entry_map_.find(_path);
    if (it != entry_map_.end()) {
        return atomic_load(&it->second);
    }
    return EntryPointerT{};
}

void DirectoryData::erase(const EntryPointerT& _rentry_ptr)
{
    auto it = entry_map_.find(_rentry_ptr->name_);
    if (it != entry_map_.end() && it->second == _rentry_ptr) {
        entry_map_.erase(it);
    }
}

void DirectoryData::insertEntry(EntryPointerT&& _uentry_ptr)
{
    const string& rname = _uentry_ptr->name_;
    entry_map_.emplace(rname, std::move(_uentry_ptr));
}

void MediaData::erase(Entry& _re) const
{
    if (_re.pprev_ != nullptr) {
        _re.pprev_->pnext_ = _re.pnext_;
    } else {
        pfront_ = _re.pnext_;
    }

    if (_re.pnext_ != nullptr) {
        _re.pnext_->pprev_ = _re.pprev_;
    } else {
        pback_ = _re.pprev_;
    }
}

void MediaData::pushBack(Entry& _re) const
{
    _re.pprev_ = pback_;
    _re.pnext_ = nullptr;

    if (pback_ != nullptr) {
        pback_->pnext_ = &_re;
        pback_         = &_re;
    } else {
        pback_ = pfront_ = &_re;
    }
}

void MediaData::popFront() const
{
    if (pfront_ != nullptr) {
        erase(*pfront_);
    }
}

EntryPointerT MediaData::find(const string& _path) const
{
    auto it = entry_map_.find(_path);
    if (it != entry_map_.end()) {
        erase(*it->second);
        pushBack(*it->second);
        return atomic_load(&it->second);
    }
    return EntryPointerT{};
}

void MediaData::erase(const EntryPointerT& _rentry_ptr)
{
    erase(*_rentry_ptr);
    pushBack(*_rentry_ptr);
}

void MediaData::insertEntry(const Configuration& _rcfg, EntryPointerT&& _uentry_ptr)
{
    while (entry_map_.size() >= _rcfg.media_cache_size_) {
        auto it = entry_map_.find(front()->name_);
        solid_check(it != entry_map_.end() && it->second.get() == front());
        if (it->second.use_count() == 1) {
            popFront();
            entry_map_.erase(it);
        } else {
            break;
        }
    }

    pushBack(*_uentry_ptr);
    DirectoryData::insertEntry(std::move(_uentry_ptr));
}

Entry* RootData::findApplication(const string& _path) const
{
    auto it = app_entry_map_.find(_path);
    if (it != app_entry_map_.end()) {
        return it->second;
    }
    return nullptr;
}

void RootData::insertApplication(Entry* _pentry)
{
    app_entry_map_.emplace(_pentry->applicationData().app_unique_, _pentry);
}

EntryPointerT RootData::eraseApplication(Entry& _rentry)
{
    auto it = entry_map_.find(_rentry.name_);
    if (it->second.use_count() != 1) {
        return EntryPointerT{};
    }

    auto& rad = it->second->applicationData();

    for (auto pse : rad.shortcut_vec_) {
        entry_map_.erase(pse->name_);
    }
    rad.shortcut_vec_.clear();

    EntryPointerT entry_ptr = std::move(it->second);

    entry_map_.erase(it);

    return entry_ptr;
}

} //namespace
//-----------------------------------------------------------------------------
struct Descriptor {
    void*         pdirectory_buffer_ = nullptr;
    EntryPointerT entry_ptr_;

    Descriptor(EntryPointerT&& _uentry_ptr)
        : entry_ptr_(std::move(_uentry_ptr))
    {
    }
};

using ListNodeDequeT = decltype(ola::front::ListStoreResponse::node_dq_);

struct Engine::Implementation {
    using RecipientVectorT = std::vector<frame::mprpc::RecipientId>;
    using MutexDequeT      = std::deque<mutex>;
    using CVDequeT         = std::deque<condition_variable>;

    Configuration             config_;
    AioSchedulerT             scheduler_;
    frame::Manager            manager_;
    CallPool<void()>          workpool_;
    frame::aio::Resolver      resolver_;
    frame::mprpc::ServiceT    front_rpc_service_;
    frame::mprpc::ServiceT    gui_rpc_service_;
    mutex                     mutex_;
    mutex                     root_mutex_;
    condition_variable        root_cv_;
    bool                      running_ = true;
    string                    auth_endpoint_;
    string                    auth_user_;
    string                    auth_token_;
    RecipientVectorT          auth_recipient_v_;
    frame::mprpc::RecipientId gui_recipient_id_;
    EntryPointerT             root_entry_ptr_;
    EntryPointerT             media_entry_ptr_;
    atomic<size_t>            current_mutex_index_ = 0;
    MutexDequeT               mutex_dq_;
    CVDequeT                  cv_dq_;
    string                    os_id_;
    string                    language_id_;
    ShortcutCreator           shortcut_creator_;
    file_cache::Engine        file_cache_engine_;
    atomic<size_t>            open_count_ = 0;
    thread                    update_thread;
    atomic<bool>              first_run_{true};

public:
    Implementation(
        const Configuration& _rcfg)
        : config_(_rcfg)
        , workpool_{WorkPoolConfiguration{}, 1}
        , resolver_{workpool_}
        , front_rpc_service_{manager_}
        , gui_rpc_service_{manager_}
        , shortcut_creator_{config_.temp_folder_}
    {
    }

    ~Implementation()
    {
        if (update_thread.joinable()) {
            {
                lock_guard<mutex> lock(root_mutex_);
                running_ = false;
                root_cv_.notify_one();
            }
            update_thread.join();
        }
    }

public:
    void onFrontConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onFrontConnectionInit(frame::mprpc::ConnectionContext& _ctx);
    void onFrontAuthResponse(
        frame::mprpc::ConnectionContext&      _ctx,
        const front::AuthRequest&             _rreq,
        std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr);

    void onGuiAuthRequest(
        frame::mprpc::ConnectionContext&    _rctx,
        std::shared_ptr<auth::AuthRequest>& _rrecv_msg_ptr,
        ErrorConditionT const&              _rerror);
    void onGuiRegisterRequest(
        frame::mprpc::ConnectionContext& _rctx,
        auth::RegisterRequest&           _rmsg);
    void loadAuthData();

    void onFrontListAppsResponse(
        frame::mprpc::ConnectionContext&          _ctx,
        std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr);

    void onAllApplicationsFetched();
    void cleanFileCache();

    void update();
    void updateApplications(const UpdatesMapT& _updates_map);

    EntryPointerT createEntry(EntryPointerT& _rparent_ptr, const string& _name, const EntryTypeE _type = EntryTypeE::Unknown, const uint64_t _size = 0);

    EntryPointerT tryInsertUnknownEntry(EntryPointerT& _rparent_ptr, const string& _path);

    void eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock);

    void createEntryData(unique_lock<mutex>& _lock, EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq);

    void insertDirectoryEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name);
    void insertFileEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name, uint64_t _size);

    void createRootEntry();

    bool entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock);

    bool findOrCreateEntry(
        const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, std::string& _remote_path,
        const string*& _rpapp_unique, const string*& _rpbuild_unique);

    void asyncFetch(EntryPointerT& _rentry_ptr, const size_t _fetch_index, const uint64_t _offset, uint64_t _size);

    bool list(
        EntryPointerT& _rentry_ptr,
        void*&         _rpctx,
        std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize);
    bool read(
        EntryPointerT& _rentry_ptr,
        char*          _pbuf,
        uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);
    void tryFetch(EntryPointerT& _rentry_ptr, ReadData& _rread_data);
    void tryPreFetch(EntryPointerT& _rentry_ptr);

    fs::path cachePath() const
    {
        fs::path p = config_.path_prefix_;
        p /= "cache";
        return p;
    }

    void releaseApplication(Entry& _rapp_entry);

private:
    void getAuthToken(const frame::mprpc::RecipientId& _recipient_id, string& _rtoken, const string* const _ptoken = nullptr);

    void tryAuthenticate(frame::mprpc::ConnectionContext& _ctx, const string* const _ptoken = nullptr);

    fs::path authDataDirectoryPath() const
    {
        fs::path p = config_.path_prefix_;
        p /= "config";
        return p;
    }

    fs::path authDataFilePath() const
    {
        return authDataDirectoryPath() / "auth.data";
    }

    void storeAuthData(const string& _user, const string& _token);

    void insertApplicationEntry(std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr);
    void insertMountEntry(EntryPointerT& _rparent_ptr, const fs::path& _local, const string& _remote);
    bool canPreFetch(const EntryPointerT& _rentry_ptr) const;

    bool readFromFile(
        EntryPointerT&      _rentry_ptr,
        unique_lock<mutex>& _rlock,
        char*               _pbuf,
        uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);

    bool readFromShortcut(
        EntryPointerT& _rentry_ptr,
        char*          _pbuf,
        uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);

    void remoteFetchApplication(
        front::ListAppsResponse::AppVectorT&                  _rapp_id_vec,
        std::shared_ptr<front::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
        size_t                                                  _app_index);
};

Engine::Engine() {}

Engine::~Engine() {}

namespace {

template <class M>
void complete_message(
    frame::mprpc::ConnectionContext& _rctx,
    std::shared_ptr<M>&              _rsent_msg_ptr,
    std::shared_ptr<M>&              _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror)
{
    //solid_check(false); //this method should not be called
}

struct FrontProtocolSetup {
    template <class T>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<T> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<T>(complete_message<T>, _rtid);
    }
};
} //namespace

struct GuiProtocolSetup {
    Engine::Implementation& impl_;
    GuiProtocolSetup(Engine::Implementation& _impl)
        : impl_(_impl)
    {
    }

    void operator()(front::ProtocolT& _rprotocol, TypeToType<auth::RegisterRequest> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        auto lambda = [& impl_ = this->impl_](
                          frame::mprpc::ConnectionContext&        _rctx,
                          std::shared_ptr<auth::RegisterRequest>& _rsent_msg_ptr,
                          std::shared_ptr<auth::RegisterRequest>& _rrecv_msg_ptr,
                          ErrorConditionT const&                  _rerror) {
            impl_.onGuiRegisterRequest(_rctx, *_rrecv_msg_ptr);
        };
        _rprotocol.registerMessage<auth::RegisterRequest>(lambda, _rtid);
    }

    template <class M>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<M> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<M>(complete_message<M>, _rtid);
    }
};

void Engine::start(const Configuration& _rcfg)
{
    solid_log(logger, Verbose, "");
    pimpl_ = make_unique<Implementation>(_rcfg);

    {
        pimpl_->mutex_dq_.resize(pimpl_->config_.mutex_count_);
        pimpl_->cv_dq_.resize(pimpl_->config_.cv_count_);
    }

    pimpl_->createRootEntry();

    {
        file_cache::Configuration config;
        config.base_path_ = pimpl_->cachePath();
        //TODO: set other configuration fields
        pimpl_->file_cache_engine_.start(std::move(config));
    }

    pimpl_->scheduler_.start(1);

    pimpl_->loadAuthData();

    {
        auto                        proto = ProtocolT::create();
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);

        front::protocol_setup(FrontProtocolSetup(), *proto);

        cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(pimpl_->resolver_, ola::front::default_port());

        cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;

        {
            auto connection_start_lambda = [this](frame::mprpc::ConnectionContext& _ctx) {
                pimpl_->onFrontConnectionStart(_ctx);
            };
            auto connection_stop_lambda = [this](frame::mprpc::ConnectionContext& _ctx) {
                solid_log(logger, Verbose, "Connection stopping");
            };
            cfg.client.connection_start_fnc = std::move(connection_start_lambda);
            cfg.connection_stop_fnc         = std::move(connection_stop_lambda);
        }

        if (_rcfg.secure_) {
            frame::mprpc::openssl::setup_client(
                cfg,
                [_rcfg](frame::aio::openssl::Context& _rctx) -> ErrorCodeT {
                    _rctx.loadVerifyFile(_rcfg.securePath("ola-ca-cert.pem").c_str());
                    _rctx.loadCertificateFile(_rcfg.securePath("ola-client-front-cert.pem").c_str());
                    _rctx.loadPrivateKeyFile(_rcfg.securePath("ola-client-front-key.pem").c_str());
                    return ErrorCodeT();
                },
                frame::mprpc::openssl::NameCheckSecureStart{"ola-server"});
        }

        if (_rcfg.compress_) {
            frame::mprpc::snappy::setup(cfg);
        }

        pimpl_->front_rpc_service_.start(std::move(cfg));
    }

    {
        auto                        proto = auth::ProtocolT::create();
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);

        auth::protocol_setup(GuiProtocolSetup(*pimpl_), *proto);

        cfg.server.listener_address_str = "127.0.0.1:0";

        pimpl_->gui_rpc_service_.start(std::move(cfg));
    }

    auto err = pimpl_->front_rpc_service_.createConnectionPool(pimpl_->auth_endpoint_.c_str(), 1);
    solid_check(!err, "creating connection pool: " << err.message());

    if (!err) {
        auto lambda = [pimpl = pimpl_.get()](
                          frame::mprpc::ConnectionContext&          _rctx,
                          std::shared_ptr<front::ListAppsRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                    _rerror) {
            if (_rrecv_msg_ptr) {
                pimpl->onFrontListAppsResponse(_rctx, _rrecv_msg_ptr);
            }
        };

        auto req_ptr     = make_shared<ListAppsRequest>();
        req_ptr->choice_ = 'a'; //TODO change to 'a' -> aquired apps

        err = pimpl_->front_rpc_service_.sendRequest(pimpl_->auth_endpoint_.c_str(), req_ptr, lambda);
        solid_check(!err);
        pimpl_->running_ = true;
    }
}

void Engine::stop()
{
    pimpl_.reset(nullptr);
}

void*& Engine::buffer(Descriptor& _rdesc)
{
    return _rdesc.pdirectory_buffer_;
}

bool Engine::info(const fs::path& _path, NodeFlagsT& _rnode_flags, uint64_t& _rsize)
{
    EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
    mutex&             rmutex    = entry_ptr->mutex();
    unique_lock<mutex> lock{rmutex};

    if (pimpl_->entry(_path, entry_ptr, lock)) {
        entry_ptr->info(_rnode_flags, _rsize);

        Entry* papp_entry = nullptr;
        if (entry_ptr && entry_ptr->pmaster_ && entry_ptr->pmaster_->isApplication()) {
            papp_entry = entry_ptr->pmaster_;
            pimpl_->releaseApplication(*papp_entry);
        }

        solid_log(logger, Verbose, "INFO: " << _path.generic_path() << " " << static_cast<int>(_rnode_flags) << " " << _rsize);
        return true;
    }
    solid_log(logger, Verbose, "INFO: FAIL " << _path.generic_path());
    return false;
}

Descriptor* Engine::open(const fs::path& _path, uint32_t _create_flags)
{
    EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
    mutex&             rmutex    = entry_ptr->mutex();
    unique_lock<mutex> lock{rmutex};

    if (pimpl_->entry(_path, entry_ptr, lock)) {
        auto pdesc = new Descriptor(std::move(entry_ptr));
        ++pimpl_->open_count_;
        solid_log(logger, Verbose, "OPEN: " << _create_flags << ' ' << _path.generic_path() << " -> " << pdesc << " entry: " << pdesc->entry_ptr_.get() << " open_count = " << pimpl_->open_count_);
        return pdesc;
    }
    return nullptr;
}

void Engine::cleanup(Descriptor* _pdesc)
{
    solid_log(logger, Verbose, "CLEANUP: " << _pdesc << " entry: " << _pdesc->entry_ptr_.get() << " open_count = " << pimpl_->open_count_);
}

void Engine::close(Descriptor* _pdesc)
{
    --pimpl_->open_count_;
    solid_log(logger, Info, "open_count = " << pimpl_->open_count_);

    if (_pdesc->entry_ptr_->type_ == EntryTypeE::File) {
        mutex&             rmutex = _pdesc->entry_ptr_->mutex();
        unique_lock<mutex> lock{rmutex};
        const auto         use_cnt = _pdesc->entry_ptr_.use_count();

        solid_log(logger, Verbose, "CLOSE: " << _pdesc << " entry: " << _pdesc->entry_ptr_.get() << " use count = " << use_cnt << " open_count = " << pimpl_->open_count_);
        if (use_cnt == 2) {
            if (_pdesc->entry_ptr_->isVolatile()) {
                solid_log(logger, Info, "Erase volatile entry: " << _pdesc->entry_ptr_->name_);
                pimpl_->eraseEntryFromParent(std::move(_pdesc->entry_ptr_), std::move(lock));
            } else {
                pimpl_->file_cache_engine_.close(_pdesc->entry_ptr_->fileData());
                _pdesc->entry_ptr_->data_any_.clear();
            }

        } else {
            pimpl_->file_cache_engine_.flush(_pdesc->entry_ptr_->fileData());
        }
    } else {
        solid_log(logger, Verbose, "CLOSE: " << _pdesc << " entry: " << _pdesc->entry_ptr_.get() << " open_count = " << pimpl_->open_count_);
    }
    Entry* papp_entry = nullptr;
    if (_pdesc->entry_ptr_ && _pdesc->entry_ptr_->pmaster_ && _pdesc->entry_ptr_->pmaster_->isApplication()) {
        papp_entry = _pdesc->entry_ptr_->pmaster_;
    }
    delete _pdesc;

    if (papp_entry != nullptr) {
        pimpl_->releaseApplication(*papp_entry);
    }
}

bool Engine::Implementation::findOrCreateEntry(
    const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, std::string& _remote_path,
    const string*& _rpapp_unique, const string*& _rpbuild_unique)
{
    Entry* papp_entry = nullptr;
    auto   it         = _path.begin();
    for (; it != _path.end(); ++it) {
        const auto&   e     = *it;
        string        s     = e.generic_string();
        EntryPointerT e_ptr = _rentry_ptr->find(s);

        solid_log(logger, Verbose, "\t" << s);

        if (!e_ptr) {
            _rentry_ptr = tryInsertUnknownEntry(_rentry_ptr, s);
            if (_rentry_ptr) {
                _remote_path += '/';
                _remote_path += s;

            } else {
                break;
            }
        } else {
            _rentry_ptr = std::move(e_ptr);

            if (_rentry_ptr->isApplication()) {
                papp_entry = _rentry_ptr.get();
                papp_entry->applicationData().useApplication(); //under root mutex
            }

            if (_rentry_ptr->isShortcut()) {
                papp_entry = _rentry_ptr->pmaster_;
                papp_entry->applicationData().useApplication(); //under root mutex
            }

            mutex& rmutex = _rentry_ptr->mutex();
            _rlock.unlock(); //no overlapping locks
            {
                unique_lock<mutex> tlock{rmutex};
                _rlock.swap(tlock);
            }

            if (_rentry_ptr->isApplication()) {
                _remote_path.clear();
                //_rpstorage_id = &_rentry_ptr->remote_;

                auto& rad       = _rentry_ptr->applicationData();
                _rpapp_unique   = &rad.app_unique_;
                _rpbuild_unique = &rad.build_unique_;
            } else if (_rentry_ptr->isMedia()) {
                break;
            } else if (!_rentry_ptr->remote_.empty()) {
                _remote_path += '/';
                _remote_path += _rentry_ptr->remote_;
            } else {
                _remote_path += '/';
                _remote_path += _rentry_ptr->name_;
            }
        }
    }

    if (!_rentry_ptr) {
        if (_rlock.owns_lock()) {
            _rlock.unlock();
        }
        if (papp_entry != nullptr) {
            //no lock
            releaseApplication(*papp_entry);
        }
        return false;
    }

    if (_rentry_ptr->isMedia()) {
        solid_check(papp_entry == nullptr);
        ++it;
        if (it == _path.end()) {
            return false;
        }

        string encoded_storage_id = it->generic_string();
        ++it;
        while (it != _path.end()) {
            _remote_path += it->generic_string();
            ++it;
            if (it != _path.end()) {
                _remote_path += '/';
            }
        }

        string name      = encoded_storage_id + '/' + _remote_path;
        auto   entry_ptr = _rentry_ptr->find(name);
        if (entry_ptr) {
            _rentry_ptr = std::move(entry_ptr);
            return true;
        }

        string storage_id = ola::utility::hex_decode(encoded_storage_id);

        entry_ptr           = createEntry(_rentry_ptr, name);
        entry_ptr->pmaster_ = entry_ptr.get();
        entry_ptr->remote_  = std::move(storage_id);
        entry_ptr->status_  = EntryStatusE::FetchRequired;
        entry_ptr->flagSet(EntryFlagsE::Volatile);

        _rentry_ptr->mediaData().insertEntry(config_, EntryPointerT(entry_ptr));

        _rentry_ptr = std::move(entry_ptr);
    }
    return true;
}

bool Engine::Implementation::entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock)
{
    string        remote_path;
    const string* papp_unique   = nullptr;
    const string* pbuild_unique = nullptr;

    if (!findOrCreateEntry(_path, _rentry_ptr, _rlock, remote_path, papp_unique, pbuild_unique)) {
        solid_log(logger, Info, "failed findOrCreateEntry");
        return false;
    }

    auto generic_path_str = _path.generic_string();

    solid_log(logger, Info, "Open (generic_path = " << generic_path_str << " remote_path = " << remote_path << ")");

    if (_rentry_ptr->status_ == EntryStatusE::FetchRequired) {
        _rentry_ptr->status_ = EntryStatusE::FetchPending;

        auto lambda = [entry_ptr = _rentry_ptr, &generic_path_str, this](
                          frame::mprpc::ConnectionContext&           _rctx,
                          std::shared_ptr<front::ListStoreRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::ListStoreResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                     _rerror) mutable {
            auto&              m = entry_ptr->mutex();
            unique_lock<mutex> lock{m};
            if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                entry_ptr->status_ = EntryStatusE::Fetched;
                createEntryData(lock, entry_ptr, generic_path_str, _rrecv_msg_ptr->node_dq_);
            } else {
                entry_ptr->status_ = EntryStatusE::FetchError;
            }
            entry_ptr->conditionVariable().notify_all();
        };

        auto req_ptr         = make_shared<ListStoreRequest>();
        req_ptr->path_       = remote_path;
        req_ptr->storage_id_ = _rentry_ptr->pmaster_->remote_;

        front_rpc_service_.sendRequest(auth_endpoint_.c_str(), req_ptr, lambda);
    }

    if (_rentry_ptr->status_ == EntryStatusE::FetchPending) {
        _rentry_ptr->conditionVariable().wait(_rlock, [&_rentry_ptr]() { return _rentry_ptr->status_ != EntryStatusE::FetchPending; });
    }

    if (_rentry_ptr->status_ == EntryStatusE::FetchError) {
        if (_rentry_ptr->type_ == EntryTypeE::Unknown) {
            Entry* papp_entry = nullptr;
            if (_rentry_ptr->pmaster_ && _rentry_ptr->pmaster_->isApplication()) {
                papp_entry = _rentry_ptr->pmaster_;
            }
            eraseEntryFromParent(std::move(_rentry_ptr), std::move(_rlock));
            solid_check(!_rlock.owns_lock());
            //papp_entry cannot be invalidated because we have not release it yet
            if (papp_entry != nullptr) {
                releaseApplication(*papp_entry);
            }
        }
        solid_log(logger, Verbose, "Fail open: " << _path.generic_path());

        return false;
    } else {
        solid_check(_rentry_ptr->type_ > EntryTypeE::Unknown);
        //NOTE: the app_entry, if any, remains under use
        if (_rentry_ptr->type_ == EntryTypeE::File) {
            if (_rentry_ptr->data_any_.empty()) {
                _rentry_ptr->data_any_ = FileData(remote_path);
                if (papp_unique != nullptr) {
                    file_cache_engine_.open(_rentry_ptr->fileData(), _rentry_ptr->size_, *papp_unique, *pbuild_unique, remote_path);
                }
            }
        }

        solid_log(logger, Verbose, "Open " << _rentry_ptr.get() << " " << _path.generic_path() << " type: " << static_cast<uint16_t>(_rentry_ptr->type_) << " remote: " << remote_path);

        //success
        return true;
    }
}

void Engine::info(Descriptor* _pdesc, NodeFlagsT& _rnode_flags, uint64_t& _rsize)
{
    auto&             m = _pdesc->entry_ptr_->mutex();
    lock_guard<mutex> lock(m);

    _pdesc->entry_ptr_->info(_rnode_flags, _rsize);
}

bool Engine::list(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize)
{
    return pimpl_->list(_pdesc->entry_ptr_, _rpctx, _rname, _rnode_flags, _rsize);
}

bool Engine::read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    return pimpl_->read(_pdesc->entry_ptr_, static_cast<char*>(_pbuf), _offset, _length, _rbytes_transfered);
}

// -- Implementation --------------------------------------------------------------------

void Engine::Implementation::releaseApplication(Entry& _rapp_entry)
{
    lock_guard<mutex>                     lock(root_mutex_);
    auto&                                 rad = _rapp_entry.applicationData();
    front::ListAppsResponse::AppVectorT   new_app_id_vec;
    auto&                                 rrd = root_entry_ptr_->rootData();

    rad.releaseApplication();

    if (rad.canBeDeleted()) {
        solid_log(logger, Info, "" << _rapp_entry.name_ << " can be deleted");

        if ((_rapp_entry.hasDelete() || _rapp_entry.hasUpdate())) {
            auto entry_ptr = rrd.eraseApplication(_rapp_entry);
            if (entry_ptr) {
                solid_check(entry_ptr.get() == &_rapp_entry);
                file_cache_engine_.removeApplication(rad.app_unique_, rad.build_unique_);
                solid_log(logger, Info, "app " << rad.app_unique_ << " deleted");

                rrd.app_entry_map_.erase(entry_ptr->applicationData().app_unique_);

                if (_rapp_entry.hasUpdate()) {
                    new_app_id_vec.emplace_back(std::move(rad.app_id_), std::move(rad.app_unique_));
                    solid_log(logger, Info, "app " << rad.app_unique_ << " to be updated");
                }
                config_.folder_update_fnc_("");
            }
        }
    }

    if (!new_app_id_vec.empty()) {
        auto req_ptr = make_shared<front::FetchBuildConfigurationRequest>();

        //TODO:
        req_ptr->lang_  = "US_en";
        req_ptr->os_id_ = "Windows10x86_64";
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Directory);
        //ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Name);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::EXEs);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Flags);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Shortcuts);
        req_ptr->property_vec_.emplace_back("brief");

        remoteFetchApplication(new_app_id_vec, req_ptr, 0);
    }
}

bool Engine::Implementation::list(
    EntryPointerT& _rentry_ptr,
    void*&         _rpctx,
    std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize)
{
    using ContextT = pair<int, EntryMapT::const_iterator>;

    auto&              m{_rentry_ptr->mutex()};
    unique_lock<mutex> lock(m);
    ContextT*          pctx = nullptr;
    DirectoryData*     pdd  = _rentry_ptr->directoryDataPtr();

    if (_rpctx) {
        pctx = static_cast<ContextT*>(_rpctx);
    } else {
        pctx   = new pair<int, EntryMapT::const_iterator>(0, pdd->entry_map_.begin());
        _rpctx = pctx;
    }

    if (pctx->first == 0) {
        //L".";
        _rname       = L".";
        _rsize       = 0;
        _rnode_flags = node_flag(NodeFlagsE::Directory);
        ++pctx->first;
        return true;
    } else if (pctx->first == 1) {
        //L"..";
        _rname       = L"..";
        _rsize       = 0;
        _rnode_flags = node_flag(NodeFlagsE::Directory);
        ++pctx->first;
        return true;
    } else {

        while (pctx->second != pdd->entry_map_.end()) {
            const EntryPointerT& rentry_ptr = pctx->second->second;

            if (rentry_ptr->isInvisible()) {
                ++pctx->second;
                continue;
            }

            _rname       = utility::widen(pctx->second->second->name_);
            _rsize       = pctx->second->second->size_;
            const auto t = pctx->second->second->type_;
            _rnode_flags = node_flag(t == EntryTypeE::Application || t == EntryTypeE::Directory ? NodeFlagsE::Directory : NodeFlagsE::File);
            if (pctx->second->second->flags_ & entry_flag(EntryFlagsE::Hidden)) {
                _rnode_flags |= node_flag(NodeFlagsE::Hidden);
            }
            ++pctx->second;
            return true;
        }

        delete pctx;
        _rpctx = nullptr;
    }

    return false;
}

bool FileData::readFromResponses(ReadData& _rdata, const bool _is_front)
{
    if (fetch_stubs_[0].offset_ < fetch_stubs_[1].offset_) {
        if (readFromResponse(0, _rdata, _is_front))
            return true;
        return readFromResponse(1, _rdata, _is_front);
    } else {
        if (readFromResponse(1, _rdata, _is_front))
            return true;
        return readFromResponse(0, _rdata, _is_front);
    }
}

void check_file(char* _pbuf, uint64_t _offset, unsigned long _length)
{
    static ifstream ifs("C:\\Users\\vipal\\work\\bubbles_release\\bubbles_client.exe", ios::binary);
    solid_assert(ifs);
    char buf[1024 * 256];

    ifs.seekg(_offset);
    ifs.read(buf, _length);
    solid_assert(memcmp(_pbuf, buf, _length) == 0);
}

bool Engine::Implementation::read(
    EntryPointerT& _rentry_ptr,
    char*          _pbuf,
    uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{

    auto&              m = _rentry_ptr->mutex();
    unique_lock<mutex> lock(m);

    if (_offset >= _rentry_ptr->size_) {
        _rbytes_transfered = 0;
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " zero");
        return true;
    }

    {
        size_t remaining_len = _rentry_ptr->size_ - _offset;
        if (_length > remaining_len) {
            _length = remaining_len;
        }
    }

    switch (_rentry_ptr->type_) {
    case EntryTypeE::File:
        return readFromFile(_rentry_ptr, lock, _pbuf, _offset, _length, _rbytes_transfered);
    case EntryTypeE::Shortcut:
        return readFromShortcut(_rentry_ptr, _pbuf, _offset, _length, _rbytes_transfered);
    default:
        solid_throw("Try read from unknown entry type");
    }
}

bool Engine::Implementation::readFromFile(
    EntryPointerT&      _rentry_ptr,
    unique_lock<mutex>& _rlock,
    char*               _pbuf,
    uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    FileData& rfile_data = _rentry_ptr->fileData();
    ReadData  read_data{_pbuf, _offset, _length};

    if (rfile_data.readFromCache(read_data)) {
        _rbytes_transfered = read_data.bytes_transfered_;
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " read from cache " << _rbytes_transfered);
        return true;
    }

    if (rfile_data.readFromResponses(read_data, false)) {
        _rbytes_transfered = read_data.bytes_transfered_;
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " read from responses " << _rbytes_transfered);
        return true;
    }

    if (rfile_data.enqueue(read_data)) {
        //the queue was empty
        tryFetch(_rentry_ptr, read_data);
        tryPreFetch(_rentry_ptr);
    }
    solid_log(logger, Verbose, _rentry_ptr.get() << " wait");
    _rentry_ptr->conditionVariable().wait(_rlock, [&read_data]() { return read_data.done_; });

    if (rfile_data.status_ == FileData::ErrorE) {
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " error reading");
        return false;
    }

    _rbytes_transfered = read_data.bytes_transfered_;
    solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " " << _offset << " " << _length << " " << _rbytes_transfered);
    return true;
}

bool Engine::Implementation::readFromShortcut(
    EntryPointerT& _rentry_ptr,
    char*          _pbuf,
    uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    ShortcutData& rshortcut_data = _rentry_ptr->shortcutData();

    rshortcut_data.ioss_.seekg(_offset);
    rshortcut_data.ioss_.read(_pbuf, _length);
    _rbytes_transfered = rshortcut_data.ioss_.gcount();
    return true;
}

size_t FileData::isReadHandledByPendingFetch(const ReadData& _rread_data) const
{
    size_t fetch_index = InvalidIndex();

    {
        auto& rfetch_stub = fetch_stubs_[0];
        if (rfetch_stub.status_ == FetchStub::PendingE) {
            if (
                rfetch_stub.offset_ <= _rread_data.offset_ && _rread_data.offset_ < (rfetch_stub.offset_ + rfetch_stub.size_)) {
                return 0;
            }
        }
    }
    {
        auto& rfetch_stub = fetch_stubs_[1];
        if (rfetch_stub.status_ == FetchStub::PendingE) {
            if (
                rfetch_stub.offset_ <= _rread_data.offset_ && _rread_data.offset_ < (rfetch_stub.offset_ + rfetch_stub.size_)) {
                return 1;
            }
        }
    }

    return InvalidIndex();
}

size_t FileData::findAvailableFetchIndex() const
{
    auto& rfetch_stub0 = fetch_stubs_[0];
    auto& rfetch_stub1 = fetch_stubs_[1];

    if (rfetch_stub0.status_ == FetchStub::NotUsedE)
        return 0;
    if (rfetch_stub1.status_ == FetchStub::NotUsedE)
        return 1;

    if (rfetch_stub0.status_ == FetchStub::FetchedE)
        return 0;
    if (rfetch_stub1.status_ == FetchStub::FetchedE)
        return 1;
    return InvalidIndex();
}

void Engine::Implementation::tryFetch(EntryPointerT& _rentry_ptr, ReadData& _rread_data)
{
    FileData& rfile_data = _rentry_ptr->fileData();

    //try to avoid double prefetching
    if (auto fetch_index = rfile_data.isReadHandledByPendingFetch(_rread_data); fetch_index != InvalidIndex() && rfile_data.fetch_stubs_[fetch_index].size_ != 0) {
        solid_log(logger, Verbose, _rentry_ptr.get() << " read handled by pending " << fetch_index);
        //check if we can use the secondary buffer to speed-up fetching
        auto&  rfs         = rfile_data.fetch_stubs_[fetch_index];
        auto   next_offset = rfs.offset_ + rfs.size_;
        size_t second_fetch_index;
        if (canPreFetch(_rentry_ptr) && next_offset < _rentry_ptr->size_ && (second_fetch_index = rfile_data.findAvailableFetchIndex()) != InvalidIndex()) {
            solid_log(logger, Verbose, _rentry_ptr.get() << " prefetch " << second_fetch_index << " " << next_offset);
            asyncFetch(_rentry_ptr, second_fetch_index, next_offset, config_.max_stream_size_ /*_rread_data.size_*/);
        }
        return;
    }

    if (auto fetch_index = rfile_data.findAvailableFetchIndex(); fetch_index != InvalidIndex()) {
        solid_log(logger, Verbose, _rentry_ptr.get() << " read " << fetch_index << " " << _rread_data.offset_);
        asyncFetch(_rentry_ptr, fetch_index, _rread_data.offset_, canPreFetch(_rentry_ptr) ? config_.max_stream_size_ : _rread_data.size_);

        auto&  rfetch_stub = rfile_data.fetch_stubs_[fetch_index];
        auto   next_offset = rfetch_stub.offset_ + rfetch_stub.size_;
        size_t second_fetch_index;

        if (canPreFetch(_rentry_ptr) && next_offset < _rentry_ptr->size_ && (second_fetch_index = rfile_data.findAvailableFetchIndex()) != InvalidIndex()) {
            asyncFetch(_rentry_ptr, second_fetch_index, next_offset, config_.max_stream_size_);
        }
    }
}

void copy_stream(ReadData& _rread_data, const uint64_t _offset, istream& _ris, uint64_t _size)
{
    solid_check(_offset <= _rread_data.offset_);
    _ris.clear();
    _ris.seekg(_rread_data.offset_ - _offset);
    _ris.read(_rread_data.pbuffer_, _size);
    uint64_t sz = _ris.gcount();
    _rread_data.offset_ += sz;
    _rread_data.pbuffer_ += sz;
    _rread_data.bytes_transfered_ += sz;
    _rread_data.size_ -= sz;
}

bool FileData::readFromResponse(const size_t _idx, ReadData& _rdata, bool _is_front)
{
    FetchStub& rfetch_stub = fetch_stubs_[_idx];
    if (rfetch_stub.status_ != FetchStub::FetchedE && rfetch_stub.status_ != FetchStub::WaitE) {
        return false;
    }

    if (rfetch_stub.offset_ <= _rdata.offset_ && _rdata.offset_ < (rfetch_stub.offset_ + rfetch_stub.size_)) {
        uint64_t tocopy = (rfetch_stub.offset_ + rfetch_stub.size_) - _rdata.offset_;
        if (tocopy > _rdata.size_) {
            tocopy = _rdata.size_;
        }

        copy_stream(_rdata, rfetch_stub.offset_, rfetch_stub.response_ptr_->ioss_, tocopy);

        if (_is_front && rfetch_stub.status_ == FetchStub::WaitE) {
            rfetch_stub.status_ = FetchStub::FetchedE;
        }
        return _rdata.size_ == 0;
    }
    return false;
}

void FileData::updateContiguousRead(uint64_t _offset, uint64_t _size)
{
    if (_offset == prefetch_offset_) {
        ++contiguous_read_count_;
    } else {
        contiguous_read_count_ = 0;
    }
    prefetch_offset_ = _offset + _size;
}

bool Engine::Implementation::canPreFetch(const EntryPointerT& _rentry_ptr) const
{
    const FileData& rfile_data = _rentry_ptr->fileData();
    return (rfile_data.contiguous_read_count_ >= config_.min_contiguous_read_count_) && rfile_data.prefetch_offset_ < _rentry_ptr->size_;
}

void Engine::Implementation::tryPreFetch(EntryPointerT& _rentry_ptr)
{
    FileData& rfile_data = _rentry_ptr->fileData();
    size_t    fetch_index;
    if (canPreFetch(_rentry_ptr) && ((fetch_index = rfile_data.findAvailableFetchIndex()) != InvalidIndex())) {
        solid_log(logger, Verbose, _rentry_ptr.get() << " " << fetch_index << " " << rfile_data.prefetch_offset_);
        asyncFetch(_rentry_ptr, fetch_index, rfile_data.prefetch_offset_, 0);
    }
}

void Engine::Implementation::asyncFetch(EntryPointerT& _rentry_ptr, const size_t _fetch_index, const uint64_t _offset, uint64_t _size)
{
    solid_log(logger, Verbose, _rentry_ptr.get() << " " << _fetch_index << " " << _offset << " " << _size);
    FileData& rfile_data  = _rentry_ptr->fileData();
    auto&     rfetch_stub = rfile_data.fetch_stubs_[_fetch_index];

    rfetch_stub.status_ = FetchStub::PendingE;
    rfetch_stub.offset_ = _offset;
    rfetch_stub.size_   = _size;

    auto lambda = [entry_ptr = _rentry_ptr, this, _fetch_index](
                      frame::mprpc::ConnectionContext&            _rctx,
                      std::shared_ptr<front::FetchStoreRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::FetchStoreResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                      _rerror) mutable {
        solid_check(_rrecv_msg_ptr, _rerror.message());
        solid_log(logger, Verbose, "recv data: " << _rsent_msg_ptr->offset_ << " " << _rrecv_msg_ptr->size_);
        auto&             m = entry_ptr->mutex();
        lock_guard<mutex> lock{m};
        FileData*         pfd = entry_ptr->fileDataPtr();
        if (pfd == nullptr) {
            return;
        }
        FileData& rfile_data  = (*pfd);
        auto&     rfetch_stub = rfile_data.fetch_stubs_[_fetch_index];

        rfetch_stub.status_       = FetchStub::FetchedE;
        rfetch_stub.response_ptr_ = std::move(_rrecv_msg_ptr);

        rfile_data.writeToCache(_rsent_msg_ptr->offset_, rfetch_stub.response_ptr_->ioss_);

        rfetch_stub.size_ = rfetch_stub.response_ptr_->size_ >= 0 ? rfetch_stub.response_ptr_->size_ : -rfetch_stub.response_ptr_->size_;

        for (auto* prd = rfile_data.pfront_; prd != nullptr;) {
            if (prd->offset_ >= rfetch_stub.offset_ && prd->offset_ < (rfetch_stub.offset_ + rfetch_stub.size_)) {
                uint64_t tocopy = (rfetch_stub.offset_ + rfetch_stub.size_) - prd->offset_;
                if (tocopy > prd->size_) {
                    tocopy = prd->size_;
                }

                copy_stream(*prd, rfetch_stub.offset_, rfetch_stub.response_ptr_->ioss_, tocopy);
            } else if (prd == rfile_data.pfront_ && prd->offset_ >= rfetch_stub.offset_ && rfetch_stub.offset_ < (prd->offset_ + prd->size_)) {
                //TODO: maybe more checks are needed
                rfetch_stub.status_ = FetchStub::WaitE;
            }

            if (prd->size_ == 0) {
                auto tmp = prd;
                prd      = prd->pprev_;
                rfile_data.erase(*tmp);
                tmp->done_ = true;
                entry_ptr->conditionVariable().notify_all();
            } else {
                rfile_data.readFromResponses(*prd, prd == rfile_data.pfront_);
                prd = prd->pprev_;
            }
        }

        for (auto* prd = rfile_data.pfront_; prd != nullptr; prd = prd->pprev_) {
            tryFetch(entry_ptr, *prd);
        }
        tryPreFetch(entry_ptr);
    };

    if (!rfetch_stub.request_ptr_) {
        rfetch_stub.request_ptr_ = make_shared<FetchStoreRequest>();
    }
    rfetch_stub.request_ptr_->path_       = rfile_data.remote_path_;
    rfetch_stub.request_ptr_->storage_id_ = _rentry_ptr->pmaster_->remote_;
    rfetch_stub.request_ptr_->offset_     = rfetch_stub.offset_;
    rfetch_stub.request_ptr_->size_       = rfetch_stub.size_;

    front_rpc_service_.sendRequest(auth_endpoint_.c_str(), rfetch_stub.request_ptr_, lambda);
}

//-----------------------------------------------------------------------------

void Engine::Implementation::getAuthToken(const frame::mprpc::RecipientId& _recipient_id, string& _rtoken, const string* const _ptoken)
{
    bool start_gui = false;
    {
        lock_guard<mutex> lock(mutex_);
        if (_ptoken != nullptr && auth_token_ == *_ptoken) {
            auth_token_.clear();
        }
        if (!auth_token_.empty()) {
            _rtoken = auth_token_;
            return;
        } else {
            auth_recipient_v_.emplace_back(_recipient_id);
            start_gui = auth_recipient_v_.size() == 1 && gui_recipient_id_.empty();
        }
    }
    if (start_gui) {
        solid_log(logger, Info, "No stored credentials - start gui");
        config_.gui_start_fnc_(auth_endpoint_, gui_rpc_service_.configuration().server.listenerPort());
    }
}

void Engine::Implementation::tryAuthenticate(frame::mprpc::ConnectionContext& _ctx, const string* const _ptoken)
{
    string auth_token;
    getAuthToken(_ctx.recipientId(), auth_token, _ptoken);

    if (!auth_token.empty()) {
        auto req_ptr = std::make_shared<AuthRequest>();
        req_ptr->pass_ = auth_token;
        auto lambda  = [this](
                          frame::mprpc::ConnectionContext&      _rctx,
                          std::shared_ptr<front::AuthRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                _rerror) {
            if (_rrecv_msg_ptr) {
                onFrontAuthResponse(_rctx, *_rsent_msg_ptr, _rrecv_msg_ptr);
            }
        };

        front_rpc_service_.sendRequest(_ctx.recipientId(), req_ptr, lambda);
    }
}

void Engine::Implementation::onFrontConnectionStart(frame::mprpc::ConnectionContext& _ctx)
{
    auto req_ptr = std::make_shared<front::InitRequest>();
    auto lambda  = [this](
                      frame::mprpc::ConnectionContext&      _rctx,
                      std::shared_ptr<front::InitRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::InitResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                _rerror) {
        if (_rrecv_msg_ptr) {
            if (_rrecv_msg_ptr->error_ == 0) {
                onFrontConnectionInit(_rctx);
            }
        }
    };

    _ctx.service().sendRequest(_ctx.recipientId(), req_ptr, lambda);
}

void Engine::Implementation::onFrontConnectionInit(frame::mprpc::ConnectionContext& _ctx)
{
    tryAuthenticate(_ctx);
}

void Engine::Implementation::onFrontAuthResponse(
    frame::mprpc::ConnectionContext&      _ctx,
    const front::AuthRequest&             _rreq,
    std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr)
{
    if (!_rrecv_msg_ptr)
        return;

    if (_rrecv_msg_ptr->error_) {
        solid_log(logger, Info, "Failed authentincating user [" << auth_user_ << "] using stored credentials");
        tryAuthenticate(_ctx, &_rreq.pass_);
    } else {
        if (!_rrecv_msg_ptr->message_.empty()) {
            solid_log(logger, Info, "Success authentincating user [" << auth_user_ << "] using stored credentials");
            lock_guard<mutex> lock(mutex_);
            auth_token_ = std::move(_rrecv_msg_ptr->message_);
        }
        front_rpc_service_.connectionNotifyEnterActiveState(_ctx.recipientId());
    }
}

void Engine::Implementation::onGuiAuthRequest(
    frame::mprpc::ConnectionContext&    _rctx,
    std::shared_ptr<auth::AuthRequest>& _rrecv_msg_ptr,
    ErrorConditionT const&              _rerror)
{
    if (_rrecv_msg_ptr) {
        auto res_ptr = std::make_shared<auth::AuthResponse>(*_rrecv_msg_ptr);
        _rctx.service().sendResponse(_rctx.recipientId(), res_ptr);
    }
    if (_rrecv_msg_ptr && !_rrecv_msg_ptr->token_.empty()) {
        solid_log(logger, Info, "Success password authenticating user: " << _rrecv_msg_ptr->user_);
        auto req_ptr   = std::make_shared<front::AuthRequest>();
        req_ptr->pass_ = _rrecv_msg_ptr->token_;
        RecipientVectorT recipient_v;
        {
            lock_guard<mutex> lock(mutex_);
            gui_recipient_id_.clear();
            recipient_v = std::move(auth_recipient_v_);
            auth_user_  = _rrecv_msg_ptr->user_;
            auth_token_ = _rrecv_msg_ptr->token_;
        }

        auto lambda = [this](
                          frame::mprpc::ConnectionContext&      _rctx,
                          std::shared_ptr<front::AuthRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                _rerror) {
            if (_rrecv_msg_ptr) {
                onFrontAuthResponse(_rctx, *_rsent_msg_ptr, _rrecv_msg_ptr);
            }
        };

        for (const auto& recipient_id : recipient_v) {
            front_rpc_service_.sendRequest(recipient_id, req_ptr, lambda);
        }
        storeAuthData(_rrecv_msg_ptr->user_, _rrecv_msg_ptr->token_);
    } else {
        solid_log(logger, Error, "Failed to authenticate - closing");
        //gui failed
        RecipientVectorT recipient_v;
        {
            lock_guard<mutex> lock(mutex_);
            gui_recipient_id_.clear();
            recipient_v = std::move(auth_recipient_v_);
        }
        for (const auto& recipient_id : recipient_v) {
            front_rpc_service_.closeConnection(recipient_id);
        }
        config_.gui_fail_fnc_();
    }
}

void Engine::Implementation::onGuiRegisterRequest(
    frame::mprpc::ConnectionContext& _rctx,
    auth::RegisterRequest&           _rmsg)
{
    auto rsp_ptr = make_shared<auth::RegisterResponse>(_rmsg);
    {
        lock_guard<mutex> lock(mutex_);
        if (gui_recipient_id_.empty()) {
            gui_recipient_id_ = _rctx.recipientId();
            rsp_ptr->error_   = 0;
            rsp_ptr->user_    = auth_user_;
        } else {
            rsp_ptr->error_ = 1; //TODO: proper id
        }
    }
    if (rsp_ptr->error_ == 0) {

        auto lambda = [this](
                          frame::mprpc::ConnectionContext&         _rctx,
                          std::shared_ptr<auth::RegisterResponse>& _rsent_msg_ptr,
                          std::shared_ptr<auth::AuthRequest>&      _rrecv_msg_ptr,
                          ErrorConditionT const&                   _rerror) {
            onGuiAuthRequest(_rctx, _rrecv_msg_ptr, _rerror);
        };
        gui_rpc_service_.sendMessage(_rctx.recipientId(), rsp_ptr, lambda, {frame::mprpc::MessageFlagsE::AwaitResponse, frame::mprpc::MessageFlagsE::Response});
    } else {
        gui_rpc_service_.sendResponse(_rctx.recipientId(), rsp_ptr);
    }
}

void Engine::Implementation::loadAuthData()
{
    const auto path = authDataFilePath();
    ifstream   ifs(path.generic_string());
    if (ifs) {
        getline(ifs, auth_endpoint_);
        getline(ifs, auth_user_);
        getline(ifs, auth_token_);
        try {
            auth_token_ = ola::utility::base64_decode(auth_token_);
            solid_check(!auth_token_.empty() && auth_endpoint_ == config_.front_endpoint_);
        } catch (std::exception& e) {
            auth_user_.clear();
            auth_token_.clear();
            auth_endpoint_ = config_.front_endpoint_;
        }
        solid_log(logger, Info, "Loaded auth data from: " << path.generic_string() << " for user: " << auth_user_);
    } else {
        solid_log(logger, Error, "Failed loading auth data from: " << path.generic_string());
        auth_endpoint_ = config_.front_endpoint_;
    }
}

void Engine::Implementation::storeAuthData(const string& _user, const string& _token)
{
    fs::create_directories(authDataDirectoryPath());
    const auto path = authDataFilePath();

    ofstream ofs(path.generic_string(), std::ios::trunc);
    if (ofs) {
        ofs << auth_endpoint_ << endl;
        ofs << _user << endl;
        ofs << ola::utility::base64_encode(_token) << endl;
        ofs.flush();
        solid_log(logger, Info, "Stored auth data to: " << path.generic_string());
    } else {
        solid_log(logger, Error, "Failed storing auth data to: " << path.generic_string());
    }
}

void Engine::Implementation::remoteFetchApplication(
    front::ListAppsResponse::AppVectorT&                  _rapp_id_vec,
    std::shared_ptr<front::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
    size_t                                                  _app_index)
{
    _rsent_msg_ptr->app_id_ = _rapp_id_vec[_app_index].id_;

    auto lambda = [this, _app_index, app_id_vec = std::move(_rapp_id_vec)](
                      frame::mprpc::ConnectionContext&                         _rctx,
                      std::shared_ptr<front::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                                   _rerror) mutable {
        if (_rrecv_msg_ptr) {

            ++_app_index;

            if (_rrecv_msg_ptr->error_ == 0) {

                this->workpool_.push(
                    [this, recv_msg_ptr = std::move(_rrecv_msg_ptr), is_last = _app_index >= app_id_vec.size()]() mutable {
                        insertApplicationEntry(recv_msg_ptr);
                        if (is_last) {
                            //done with all applications
                            onAllApplicationsFetched();
                        }
                    });
            } else {
                solid_log(logger, Error, "Failed FetchBuildConfiguration: " << _rrecv_msg_ptr->error_ << " " << _rrecv_msg_ptr->message_);
            }

            if (_app_index < app_id_vec.size()) {
                remoteFetchApplication(app_id_vec, _rsent_msg_ptr, _app_index);
            }
        }
    };

    front_rpc_service_.sendRequest(auth_endpoint_.c_str(), _rsent_msg_ptr, lambda);
}

void Engine::Implementation::cleanFileCache()
{
    auto check_application_exist_lambda = [this](const std::string& _app_unique, const std::string& _build_unique) {
        unique_lock<mutex> lock{root_mutex_};

        RootData& rrd = root_entry_ptr_->rootData();

        auto pentry = rrd.findApplication(_app_unique);
        if (pentry) {
            return pentry->applicationData().build_unique_ == _build_unique;
        }
        return false;
    };
    file_cache_engine_.removeOldApplications(check_application_exist_lambda);
}

void Engine::Implementation::update()
{

    int         done = 0;
    UpdatesMapT updates_map;
    auto        list_lambda = [this, &done, &updates_map](
                           frame::mprpc::ConnectionContext&          _rctx,
                           std::shared_ptr<front::ListAppsRequest>&  _rsent_msg_ptr,
                           std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr,
                           ErrorConditionT const&                    _rerror) {
        if (_rrecv_msg_ptr) {
            auto req_ptr = make_shared<FetchBuildUpdatesRequest>();
            req_ptr->app_id_vec_.reserve(_rrecv_msg_ptr->app_vec_.size());
            for (auto&& a : _rrecv_msg_ptr->app_vec_) {
                req_ptr->app_id_vec_.emplace_back(std::move(a.id_));
            }
            req_ptr->lang_  = "US_en";
            req_ptr->os_id_ = "Windows10x86_64";

            auto lambda = [this, &done, &updates_map](
                              frame::mprpc::ConnectionContext&                   _rctx,
                              std::shared_ptr<front::FetchBuildUpdatesRequest>&  _rsent_msg_ptr,
                              std::shared_ptr<front::FetchBuildUpdatesResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                             _rerror) {
                if (_rrecv_msg_ptr) {
                    updates_map.clear();
                    for (size_t i = 0; i < _rrecv_msg_ptr->app_vec_.size(); ++i) {
                        const auto& app_unique   = _rrecv_msg_ptr->app_vec_[i].first;
                        const auto& build_unique = _rrecv_msg_ptr->app_vec_[i].second;
                        const auto& app_id       = _rsent_msg_ptr->app_id_vec_[i];

                        updates_map[app_unique] = make_pair(app_id, build_unique);
                        solid_log(logger, Info, "update: app_unique = " << app_unique << " build_unique = " << build_unique);
                    }
                    unique_lock<mutex> lock(root_mutex_);
                    done = 1;
                    root_cv_.notify_one();
                } else {
                    unique_lock<mutex> lock(root_mutex_);
                    done = -1;
                    root_cv_.notify_one();
                }
            };

            const auto err = front_rpc_service_.sendRequest(auth_endpoint_.c_str(), req_ptr, lambda);
            if (!err) {
                return;
            }
        }

        unique_lock<mutex> lock(root_mutex_);
        done = -1;
        root_cv_.notify_one();
    };

    while (true) {
        {
            unique_lock<mutex> lock(root_mutex_);

            root_cv_.wait_for(lock, chrono::seconds(config_.update_poll_seconds_), [this]() { return !running_; });
            if (!running_) {
                return;
            }
        }

        auto req_ptr     = make_shared<ListAppsRequest>();
        req_ptr->choice_ = 'a';

        const auto err = front_rpc_service_.sendRequest(auth_endpoint_.c_str(), req_ptr, list_lambda);
        if (!err) {
            unique_lock<mutex> lock(root_mutex_);

            root_cv_.wait(lock, [&done]() { return done != 0; });
            if (done > 0) {
                updateApplications(updates_map);
            }
        }
    }
}

void Engine::Implementation::updateApplications(const UpdatesMapT& _updates_map)
{
    //under root lock
    //get new applications
    front::ListAppsResponse::AppVectorT new_app_id_vec;

    auto& rrd = root_entry_ptr_->rootData();
    bool  erased_applications = false;

    for (const auto& u : _updates_map) {
        if (rrd.findApplication(u.first) == nullptr) {
            new_app_id_vec.emplace_back(u.second.first, u.first); //app_id
            solid_log(logger, Info, "new application: " << u.first << " : " << u.second.second);
        }
    }

    //find deleted and updated apps
    for (auto app_it = rrd.app_entry_map_.begin(); app_it != rrd.app_entry_map_.end();) {
        Entry&           rapp_entry = *app_it->second;
        ApplicationData& rad        = rapp_entry.applicationData();
        const auto       it         = _updates_map.find(rad.app_unique_);
        if (it == _updates_map.end()) {
            //app needs to be delete

            lock_guard app_lock(rapp_entry.mutex());

            if (rad.canBeDeleted()) {
                solid_log(logger, Info, "app " << rad.app_unique_ << " can be deleted");
                auto entry_ptr = rrd.eraseApplication(rapp_entry); //rad will be valid as long as entry_ptr
                if (entry_ptr) {
                    erased_applications = true;
                    solid_check(entry_ptr.get() == &rapp_entry);
                    app_it = rrd.app_entry_map_.erase(app_it);
                    file_cache_engine_.removeApplication(rad.app_unique_, rad.build_unique_);
                    solid_log(logger, Info, "app " << rad.app_unique_ << " is deleted");
                    continue;
                }
            } else {
                rapp_entry.flagSet(EntryFlagsE::Delete);
                solid_log(logger, Info, "app " << rad.app_unique_ << " cannot be deleted");
            }

        } else if (it->second.second != rad.build_unique_) {
            //app needs to be updated

            lock_guard app_lock(rapp_entry.mutex());

            if (rad.canBeDeleted()) {
                auto entry_ptr = rrd.eraseApplication(rapp_entry);
                if (entry_ptr) {
                    erased_applications = true;
                    solid_check(entry_ptr.get() == &rapp_entry);
                    file_cache_engine_.removeApplication(rad.app_unique_, rad.build_unique_);
                    new_app_id_vec.emplace_back(it->second.first, rad.app_unique_);
                    app_it = rrd.app_entry_map_.erase(app_it);
                    solid_log(logger, Info, "app " << it->first << " is to be updated");
                    continue;
                } else {
                    rapp_entry.flagSet(EntryFlagsE::Update);
                    rad.app_id_ = it->second.first;
                    solid_log(logger, Info, "app " << it->first << " cannot be updated");
                }

            } else {
                rapp_entry.flagSet(EntryFlagsE::Update);
                rad.app_id_ = it->second.first;
                solid_log(logger, Info, "app " << it->first << " cannot be updated");
            }
        }
        ++app_it;
    }

    if (!new_app_id_vec.empty()) {
        auto req_ptr = make_shared<front::FetchBuildConfigurationRequest>();

        //TODO:
        req_ptr->lang_  = "en_US";
        req_ptr->os_id_ = "Windows10x86_64";
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Directory);
        //ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Name);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::EXEs);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Flags);
        ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Shortcuts);
        req_ptr->property_vec_.emplace_back("brief");

        remoteFetchApplication(new_app_id_vec, req_ptr, 0);
    } else if(erased_applications){
        config_.folder_update_fnc_("");
    }
}

void Engine::Implementation::onAllApplicationsFetched()
{
    bool expect = true;

    if (first_run_.compare_exchange_strong(expect, false)) {
        cleanFileCache();
        update_thread = thread(&Implementation::update, this);
    }
    config_.folder_update_fnc_("");
}

void Engine::Implementation::onFrontListAppsResponse(
    frame::mprpc::ConnectionContext&          _ctx,
    std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr)
{
    if (_rrecv_msg_ptr->app_vec_.empty()) {

        if (_rrecv_msg_ptr->error_ == 0) {
            onAllApplicationsFetched();
        }

        return;
    }

    auto req_ptr = make_shared<front::FetchBuildConfigurationRequest>();

    //TODO:
    req_ptr->lang_  = "en_US";
    req_ptr->os_id_ = "Windows10x86_64";
    ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Directory);
    //ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Name);
    ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::EXEs);
    ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Flags);
    ola::utility::Build::set_option(req_ptr->fetch_options_, ola::utility::Build::FetchOptionsE::Shortcuts);
    req_ptr->property_vec_.emplace_back("brief");

    remoteFetchApplication(_rrecv_msg_ptr->app_vec_, req_ptr, 0);
}

void Engine::Implementation::createRootEntry()
{
    lock_guard<mutex> lock{root_mutex_};

    root_entry_ptr_            = make_shared<Entry>(EntryTypeE::Directory, root_mutex_, cv_dq_[0], "");
    root_entry_ptr_->data_any_ = RootData();
    root_entry_ptr_->status_   = EntryStatusE::Fetched;

    media_entry_ptr_            = make_shared<Entry>(EntryTypeE::Media, root_entry_ptr_, root_mutex_, cv_dq_[0], media_name, 0);
    media_entry_ptr_->data_any_ = MediaData();
    media_entry_ptr_->status_   = EntryStatusE::Fetched;
    media_entry_ptr_->flagSet(EntryFlagsE::Invisible);

    root_entry_ptr_->directoryData().insertEntry(EntryPointerT(media_entry_ptr_));
}

void Engine::Implementation::insertMountEntry(EntryPointerT& _rparent_ptr, const fs::path& _local, const string& _remote)
{
    EntryPointerT entry_ptr   = _rparent_ptr;
    string        remote_path = "./";
    for (const auto& e : _local) {
        string        s     = e.generic_string();
        EntryPointerT e_ptr = entry_ptr->find(s);

        solid_log(logger, Verbose, "\t" << s);

        if (!e_ptr) {
            entry_ptr->status_ = EntryStatusE::FetchRequired;
            auto ep            = tryInsertUnknownEntry(entry_ptr, s);
            entry_ptr->status_ = EntryStatusE::Fetched;
            solid_check(ep);
            entry_ptr = ep;
            remote_path += "./";
            entry_ptr->type_ = EntryTypeE::Directory;
        } else {
            entry_ptr = std::move(e_ptr);
            remote_path += "./";
        }
    }
    remote_path += _remote;
    entry_ptr->remote_ = std::move(remote_path);
    entry_ptr->status_ = EntryStatusE::FetchRequired;
}

string to_system_path(const string& _path)
{
    string to;
    to.reserve(_path.size());
    for (char c : _path) {
        if (c == '/') {
            c = '\\';
        }
        to += c;
    }
    return to;
}

void Engine::Implementation::insertApplicationEntry(std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr)
{
    //NOTE: because of the entry_ptr, which after inserting it into root entry
    //will have use count == 2, the application cannot be deleted on releaseApplication
    //before adding all application shortcuts below.
    auto entry_ptr = createEntry(
        root_entry_ptr_, _rrecv_msg_ptr->configuration_.directory_,
        EntryTypeE::Application);

    entry_ptr->remote_   = _rrecv_msg_ptr->storage_id_;
    entry_ptr->data_any_ = ApplicationData(_rrecv_msg_ptr->app_unique_, _rrecv_msg_ptr->build_unique_);
    entry_ptr->pmaster_  = entry_ptr.get();

    if (_rrecv_msg_ptr->configuration_.hasHiddenDirectoryFlag()) {
        entry_ptr->flagSet(EntryFlagsE::Hidden);
    }

    if (!_rrecv_msg_ptr->configuration_.mount_vec_.empty()) {
#if 0
        entry_ptr->status_ = EntryStatusE::FetchRequired;
#else
        entry_ptr->status_ = EntryStatusE::Fetched;
        for (const auto& me : _rrecv_msg_ptr->configuration_.mount_vec_) {
            insertMountEntry(entry_ptr, me.first, me.second);
        }
#endif

    } else {
        entry_ptr->status_ = EntryStatusE::FetchRequired;
    }

    solid_log(logger, Info, entry_ptr->name_);
    size_t overlap_index = 0;
    auto&  rm            = root_entry_ptr_->mutex();
    {
        lock_guard<mutex> lock{rm};
        //TODO: also create coresponding shortcuts
        if (root_entry_ptr_->directoryData().find(entry_ptr->name_)) {
            overlap_index = 1;

            do {
                std::ostringstream oss;
                oss << entry_ptr->name_ << '_' << overlap_index;
                if (!root_entry_ptr_->directoryData().find(oss.str())) {
                    entry_ptr->name_ = oss.str();
                    break;
                }
                ++overlap_index;
            } while (true);
        }
        root_entry_ptr_->rootData().insertApplication(entry_ptr.get());
        root_entry_ptr_->directoryData().insertEntry(EntryPointerT(entry_ptr)); //insert copy
    }

    const auto& app_folder_name = entry_ptr->name_;

    if (!_rrecv_msg_ptr->configuration_.shortcut_vec_.empty()) {
        for (const auto& sh : _rrecv_msg_ptr->configuration_.shortcut_vec_) {
            ostringstream oss;
            oss << sh.name_;
            if (overlap_index != 0) {
                oss << '_' << overlap_index;
            }
            oss << ".lnk";
            auto skt_entry_ptr = createEntry(
                root_entry_ptr_, oss.str(),
                EntryTypeE::Shortcut);

            skt_entry_ptr->status_   = EntryStatusE::Fetched;
            skt_entry_ptr->data_any_ = ShortcutData();
            skt_entry_ptr->pmaster_  = entry_ptr.get();

            {
                auto papp_entry = skt_entry_ptr->pmaster_;
                solid_log(logger, Info, papp_entry->applicationData().app_unique_);
            }

            skt_entry_ptr->size_ = shortcut_creator_.create(
                skt_entry_ptr->shortcutData().ioss_,
                to_system_path(config_.mount_prefix_ + '/' + app_folder_name + '/' + sh.command_),
                sh.arguments_,
                to_system_path(config_.mount_prefix_ + '/' + app_folder_name + '/' + sh.run_folder_),
                to_system_path(config_.mount_prefix_ + '/' + app_folder_name + '/' + sh.icon_),
                _rrecv_msg_ptr->configuration_.property_vec_.front().second);
            {
                lock_guard<mutex> lock{rm};
                entry_ptr->applicationData().insertShortcut(skt_entry_ptr.get());
                root_entry_ptr_->directoryData().insertEntry(std::move(skt_entry_ptr));
            }
        }
    }
}

EntryPointerT Engine::Implementation::createEntry(EntryPointerT& _rparent_ptr, const string& _name, const EntryTypeE _type, const uint64_t _size)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name << " " << _size);
    const size_t index = current_mutex_index_.fetch_add(1);
    return make_shared<Entry>(_type, _rparent_ptr, mutex_dq_[index % mutex_dq_.size()], cv_dq_[index % cv_dq_.size()], _name, _size);
}

void Engine::Implementation::insertDirectoryEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name);

    auto entry_ptr = _rparent_ptr->directoryData().find(_name);

    if (!entry_ptr) {
        _rparent_ptr->directoryData().insertEntry(createEntry(_rparent_ptr, _name, EntryTypeE::Directory));
    } else {
        _lock.unlock();
        //make sure the entry is directory
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::Directory;

        if (entry_ptr->directoryDataPtr() == nullptr) {
            entry_ptr->data_any_ = DirectoryData();
        }
    }
}

void Engine::Implementation::insertFileEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name, uint64_t _size)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name << " " << _size);

    auto entry_ptr = _rparent_ptr->directoryData().find(_name);

    if (!entry_ptr) {
        _rparent_ptr->directoryData().insertEntry(createEntry(_rparent_ptr, _name, EntryTypeE::File));
    } else {
        _lock.unlock();
        //make sure the entry is file
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::File;
        entry_ptr->size_ = _size;
    }
}

EntryPointerT Engine::Implementation::tryInsertUnknownEntry(EntryPointerT& _rparent_ptr, const string& _name)
{
    solid_log(logger, Info, _rparent_ptr->name_ << "->" << _name);

    if (!_rparent_ptr->canInsertUnkownEntry()) {
        return EntryPointerT{};
    }

    if (_rparent_ptr->directoryDataPtr() == nullptr) {
        _rparent_ptr->data_any_ = DirectoryData();
    }

    auto entry_ptr     = createEntry(_rparent_ptr, _name);
    entry_ptr->status_ = EntryStatusE::FetchRequired;
    _rparent_ptr->directoryData().insertEntry(EntryPointerT(entry_ptr));
    return entry_ptr;
}

void Engine::Implementation::eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock)
{
    solid_log(logger, Info, _uentry_ptr->name_);

    EntryPointerT entry_ptr{std::move(_uentry_ptr)};
    EntryPointerT parent_ptr;

    {
        unique_lock<mutex> lock{std::move(_ulock)};
        parent_ptr = entry_ptr->parent_.lock();
    }

    if (parent_ptr) {
        unique_lock<mutex> lock{parent_ptr->mutex()};
        if (entry_ptr.use_count() == 2) {
            if (parent_ptr->status_ != EntryStatusE::Fetched || entry_ptr->isVolatile()) {
                parent_ptr->erase(entry_ptr);
                entry_ptr.reset();
                if (parent_ptr->isErasable()) {
                    eraseEntryFromParent(std::move(parent_ptr), std::move(lock));
                }
            }
        }
    }
}

void Engine::Implementation::createEntryData(unique_lock<mutex>& _lock, EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq)
{
    solid_log(logger, Info, _path_str);
    if (_rnode_dq.size() == 1 && _rnode_dq.front().name_.empty()) {
        _rentry_ptr->type_ = EntryTypeE::File;
        _rentry_ptr->size_ = _rnode_dq.front().size_;

        _rentry_ptr->data_any_.clear();
        return;
    }

    if (_rentry_ptr->directoryDataPtr() == nullptr) {
        _rentry_ptr->data_any_ = DirectoryData();
    }

    for (const auto& n : _rnode_dq) {
        //TODO: we do not create the EntryData here
        // so we must handle the situation in open(..)
        if (n.name_.back() == '/') {
            string name = n.name_;
            name.pop_back();
            insertDirectoryEntry(_lock, _rentry_ptr, name);
        } else {
            insertFileEntry(_lock, _rentry_ptr, n.name_, n.size_);
        }
    }
}

} //namespace service
} //namespace client
} //namespace ola
