#include "myapps/client/service/engine.hpp"

#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"
#include "solid/system/log.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"
#include "solid/frame/mprpc/mprpcprotocol_serialization_v3.hpp"

#include "myapps/common/utility/encode.hpp"

#include "myapps/common/utility/version.hpp"

#include "myapps/client/auth/auth_protocol.hpp"
#include "myapps/client/utility/locale.hpp"
#include "myapps/client/utility/app_list_file.hpp"

#include "file_data.hpp"
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
using namespace myapps;
using namespace myapps::front;

namespace myapps {
namespace client {
namespace service {

namespace {
const solid::LoggerT logger("myapps::client::service::engine");

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
    Media,
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

        for (const auto &c: _rrw.get()) {
            boost::hash_combine(seed, std::toupper(c, locale));
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
using AppListFileT = myapps::client::utility::AppListFile;


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

struct ApplicationData : DirectoryData {
    std::string     app_id_; //used for updates
    std::string     app_unique_;
    std::string     build_unique_;
    EntryPtrVectorT shortcut_vec_;
    atomic<size_t>  use_count_ = 0;
    uint32_t        compress_chunk_capacity_ = 0;
    uint8_t         compress_algorithm_type_ = 0;

    ApplicationData(
        const std::string& _app_unique, const std::string& _build_unique
    )
        : app_unique_(_app_unique)
        , build_unique_(_build_unique)
    {
    }

    ApplicationData(const ApplicationData& _rad)
        : app_unique_(_rad.app_unique_)
        , build_unique_(_rad.build_unique_)
        , compress_chunk_capacity_(_rad.compress_chunk_capacity_)
        , compress_algorithm_type_(_rad.compress_algorithm_type_)
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
    int64_t                  base_time_ = 0;
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

    bool isMediaRoot() const
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

    void info(NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time) const
    {
        solid_log(logger, Info, ""<<this->name_<< " "<<size_);
        _rnode_flags = 0;
        _rsize       = size_;
        _rbase_time = base_time_;

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

    bool isMedia() const
    {
        return entry_has_flag(flags_, EntryFlagsE::Media);
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
        solid_check_log(it != entry_map_.end() && it->second.get() == front(), logger, "");
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

using ListNodeDequeT = decltype(myapps::front::main::ListStoreResponse::node_dq_);

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
    mutex                     mutex_;
    mutex                     root_mutex_;
    condition_variable        root_cv_;
    RecipientVectorT          auth_recipient_vec_;
    bool                      running_ = true;
    bool                      app_list_update_ = false;
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
    thread                    update_thread_;
    atomic<bool>              first_run_{true};
    AppListFileT              app_list_;
public:
    Implementation(
        const Configuration& _rcfg)
        : config_(_rcfg)
        , workpool_{WorkPoolConfiguration{}, 1}
        , resolver_{workpool_}
        , front_rpc_service_{manager_}
        , shortcut_creator_{config_.temp_folder_}
    {
    }

    ~Implementation()
    {
        front_rpc_service_.stop();

        if (update_thread_.joinable()) {
            {
                lock_guard<mutex> lock(root_mutex_);
                running_ = false;
                root_cv_.notify_one();
            }
            update_thread_.join();
        }
    }

public:
    void onFrontConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onFrontConnectionInit(frame::mprpc::ConnectionContext& _ctx);
    void onFrontAuthResponse(
        frame::mprpc::ConnectionContext&      _ctx,
        const front::core::AuthRequest&             _rreq,
        std::shared_ptr<core::AuthResponse>& _rrecv_msg_ptr);

    void loadAuthData();

    void onFrontListAppsResponse(
        frame::mprpc::ConnectionContext&          _ctx,
        std::shared_ptr<main::ListAppsResponse>& _rrecv_msg_ptr);

    void onAllApplicationsFetched();
    void cleanFileCache();

    void update();
    void updateApplications(const UpdatesMapT& _updates_map);

    EntryPointerT createEntry(EntryPointerT& _rparent_ptr, const string& _name, const EntryTypeE _type = EntryTypeE::Unknown, const uint64_t _size = 0);

    EntryPointerT tryInsertUnknownEntry(EntryPointerT& _rparent_ptr, const string& _path);

    void eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock);

    void createEntryData(
        unique_lock<mutex>& _lock, EntryPointerT& _rentry_ptr,
        ListNodeDequeT& _rnode_dq,
        const uint32_t _compress_chunk_capacity,
        const uint8_t _compress_algorithm_type
    );

    void insertDirectoryEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name);
    void insertFileEntry(unique_lock<mutex>& _lock, EntryPointerT& _rparent_ptr, const string& _name, const uint64_t _size, const int64_t _base_time);

    void createRootEntry();

    bool fetch(EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, const string& _remote_path);
    bool entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, const bool _open = false);

    void asyncFetchStoreFileHandleResponse(
        frame::mprpc::ConnectionContext& _rctx, EntryPointerT& _rentry_ptr,
        std::shared_ptr<main::FetchStoreRequest>& _rsent_msg_ptr,
        std::shared_ptr<main::FetchStoreResponse>& _rrecv_msg_ptr
    );
    void asyncFetchStoreFile(
        frame::mprpc::ConnectionContext* _pctx, EntryPointerT& _rentry_ptr,
        std::shared_ptr<main::FetchStoreRequest>& _rreq_msg_ptr,
        const uint32_t _chunk_index, const uint32_t _chunk_offset);

    bool list(
        EntryPointerT& _rentry_ptr,
        void*&         _rpctx,
        std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time);
    bool read(
        Descriptor* _pdesc,
        char*          _pbuf,
        uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);
    void tryFetch(EntryPointerT& _rentry_ptr);

    fs::path cachePath() const
    {
        fs::path p = config_.path_prefix_;
        p /= "cache";
        return p;
    }

    void releaseApplication(Entry& _rapp_entry);

private:
    void tryAuthenticate(frame::mprpc::ConnectionContext& _ctx);

    void insertApplicationEntry(
        std::shared_ptr<main::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
        const myapps::utility::ApplicationListItem &_app
    );
    void insertMountEntry(EntryPointerT& _rparent_ptr, const fs::path& _local, const string& _remote);

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
        main::ListAppsResponse::AppVectorT&                  _rapp_id_vec,
        std::shared_ptr<main::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
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
}

} //namespace

void Engine::start(const Configuration& _rcfg)
{
    solid_log(logger, Verbose, "");

    pimpl_ = make_unique<Implementation>(_rcfg);

    {
        pimpl_->mutex_dq_.resize(pimpl_->config_.mutex_count_);
        pimpl_->cv_dq_.resize(pimpl_->config_.cv_count_);
    }

    pimpl_->app_list_.load(pimpl_->config_.app_list_path_);

    pimpl_->createRootEntry();

    {
        file_cache::Configuration config;
        config.base_path_ = pimpl_->cachePath();
        //TODO: set other configuration fields
        pimpl_->file_cache_engine_.start(std::move(config));
    }

    pimpl_->scheduler_.start(1);

    {
        auto                        proto = frame::mprpc::serialization_v3::create_protocol<reflection::v1::metadata::Variant, myapps::front::ProtocolTypeIndexT>(
            myapps::utility::metadata_factory,
            [&](auto& _rmap) {
                auto lambda = [&](const myapps::front::ProtocolTypeIndexT _id, const std::string_view _name, auto const& _rtype) {
                    using TypeT = typename std::decay_t<decltype(_rtype)>::TypeT;
                    _rmap.template registerMessage<TypeT>(_id, _name, complete_message<TypeT>);
                };
                myapps::front::core::configure_protocol(lambda);
                myapps::front::main::configure_protocol(lambda);
            }
        );
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);

        cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(pimpl_->resolver_, myapps::front::default_port());

        cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;

        {
            auto connection_start_lambda = [this](frame::mprpc::ConnectionContext& _rctx) {
                _rctx.any() = std::make_tuple(front::core::version, front::main::version, myapps::utility::version);
                pimpl_->onFrontConnectionStart(_rctx);
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
                    //_rctx.loadCertificateFile(_rcfg.securePath("ola-client-front-cert.pem").c_str());
                    //_rctx.loadPrivateKeyFile(_rcfg.securePath("ola-client-front-key.pem").c_str());
                    return ErrorCodeT();
                },
                frame::mprpc::openssl::NameCheckSecureStart{"front.myapps.space"});
        }

        if (_rcfg.compress_) {
            frame::mprpc::snappy::setup(cfg);
        }

        pimpl_->front_rpc_service_.start(std::move(cfg));
    }

    auto err = pimpl_->front_rpc_service_.createConnectionPool(pimpl_->config_.auth_endpoint_.c_str(), 1);
    solid_check_log(!err, logger, "creating connection pool: " << err.message());

    if (!err) {
        auto lambda = [pimpl = pimpl_.get()](
                          frame::mprpc::ConnectionContext&          _rctx,
                          std::shared_ptr<main::ListAppsRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<main::ListAppsResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                    _rerror) {
            if (_rrecv_msg_ptr) {
                pimpl->onFrontListAppsResponse(_rctx, _rrecv_msg_ptr);
            }
        };

        auto req_ptr     = make_shared<main::ListAppsRequest>();
        req_ptr->choice_ = 'a';

        err = pimpl_->front_rpc_service_.sendRequest(pimpl_->config_.auth_endpoint_.c_str(), req_ptr, lambda);
        solid_check_log(!err, logger, "err = "<<err.message());
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

void Engine::relogin()
{
    Implementation::RecipientVectorT auth_recipient_vec;
    {
        lock_guard<mutex> lock(pimpl_->mutex_);
        auth_recipient_vec = std::move(pimpl_->auth_recipient_vec_);
    }

    auto lambda = [this](
                      frame::mprpc::ConnectionContext&      _rctx,
                      std::shared_ptr<core::AuthRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<core::AuthResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                _rerror) {
        if (_rrecv_msg_ptr) {
            pimpl_->onFrontAuthResponse(_rctx, *_rsent_msg_ptr, _rrecv_msg_ptr);
        }
    };

    auto req_ptr   = std::make_shared<core::AuthRequest>();
    req_ptr->pass_ = pimpl_->config_.auth_get_token_fnc_();

    for (const auto& recipient_id : auth_recipient_vec) {
        pimpl_->front_rpc_service_.sendRequest(recipient_id, req_ptr, lambda);
    }
}

void Engine::appListUpdate() {
    lock_guard<mutex> lock(pimpl_->mutex_);
    if (!pimpl_->app_list_update_) {
        pimpl_->app_list_update_ = true;
        pimpl_->root_cv_.notify_one();
    }
}

bool Engine::info(const fs::path& _path, NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time)
{
    try {
        EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
        mutex& rmutex = entry_ptr->mutex();
        unique_lock<mutex> lock{ rmutex };

        if (pimpl_->entry(_path, entry_ptr, lock)) {
            entry_ptr->info(_rnode_flags, _rsize, _rbase_time);

            Entry* papp_entry = nullptr;
            if (entry_ptr && entry_ptr->pmaster_ && entry_ptr->pmaster_->isApplication()) {
                papp_entry = entry_ptr->pmaster_;
                pimpl_->releaseApplication(*papp_entry);
            }

            solid_log(logger, Verbose, "INFO: " << _path.generic_path() << " " << static_cast<int>(_rnode_flags) << " " << _rsize);
            return true;
        }
    }
    catch (std::exception &e) {
        solid_log(logger, Error, _path.generic_path() << " Exception caught: "<<e.what());
    }catch(...){
        solid_log(logger, Error, _path.generic_path()<<" Unknown Exception caught");
    }
    solid_log(logger, Verbose, "INFO: FAIL " << _path.generic_path());
    return false;
}

//#define OLA_VALIDATE_READ
//#define OLA_VALIDATE_TIME

#if defined(OLA_VALIDATE_READ) || defined(OLA_VALIDATE_TIME)

string base_path = "F:\\builds\\apps\\VLC\\";
const string app_name = "VLC Media Player";
#define FULLPATH_SIZE (MAX_PATH + FSP_FSCTL_TRANSACT_PATH_SIZEMAX / sizeof(WCHAR))

#endif

#if defined(OLA_VALIDATE_TIME)
int64_t get_file_base_time(const string &_file_path)
{
    int64_t retval = 0;
    HANDLE Handle = CreateFileA(_file_path.c_str(),
        FILE_READ_ATTRIBUTES | READ_CONTROL, 0, 0,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
    if (Handle != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION ByHandleFileInfo;

        if (GetFileInformationByHandle(Handle, &ByHandleFileInfo)) {
            retval = ((PLARGE_INTEGER)&ByHandleFileInfo.ftLastWriteTime)->QuadPart;
        }
        CloseHandle(Handle);
    }
    return retval;
}
#endif

Descriptor* Engine::open(const fs::path& _path, uint32_t _create_flags, uint32_t _granted_access)
{
    try{
        EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
        mutex&             rmutex    = entry_ptr->mutex();
        unique_lock<mutex> lock{rmutex};

        if (pimpl_->entry(_path, entry_ptr, lock, true)) {
            auto pdesc = new Descriptor(std::move(entry_ptr));
            ++pimpl_->open_count_;
            solid_log(logger, Verbose, "OPEN: " << _create_flags << ' ' << _path.generic_path() << " -> " << pdesc << " entry: " << pdesc->entry_ptr_.get() << " open_count = " << pimpl_->open_count_);
            return pdesc;
        }
    }
    catch (std::exception& e) {
        solid_log(logger, Error, _path.generic_path() << " Exception caught: " << e.what());
    }
    catch (...) {
        solid_log(logger, Error, _path.generic_path() << " Unknown Exception caught");
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

bool Engine::Implementation::fetch(EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, const string& _remote_path) {
    if (_rentry_ptr->status_ == EntryStatusE::FetchRequired) {
        _rentry_ptr->status_ = EntryStatusE::FetchPending;
        auto lambda = [entry_ptr = _rentry_ptr, this](
            frame::mprpc::ConnectionContext& _rctx,
            std::shared_ptr<main::ListStoreRequest>& _rsent_msg_ptr,
            std::shared_ptr<main::ListStoreResponse>& _rrecv_msg_ptr,
            ErrorConditionT const& _rerror) mutable {
                auto& m = entry_ptr->mutex();
                unique_lock<mutex> lock{ m };
                if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                    entry_ptr->status_ = EntryStatusE::Fetched;
                    if (entry_ptr->isApplication()) {
                        auto& rad = entry_ptr->applicationData();
                        rad.compress_chunk_capacity_ = _rrecv_msg_ptr->compress_chunk_capacity_;
                        rad.compress_algorithm_type_ = _rrecv_msg_ptr->compress_algorithm_type_;
                    }
                    createEntryData(
                        lock, entry_ptr, _rrecv_msg_ptr->node_dq_,
                        _rrecv_msg_ptr->compress_chunk_capacity_,
                        _rrecv_msg_ptr->compress_algorithm_type_
                    );
                }
                else {
                    entry_ptr->status_ = EntryStatusE::FetchError;
                }
                entry_ptr->conditionVariable().notify_all();
        };

        auto req_ptr = make_shared<main::ListStoreRequest>();
        req_ptr->path_ = _remote_path;
        req_ptr->storage_id_ = _rentry_ptr->pmaster_->remote_;

        front_rpc_service_.sendRequest(config_.auth_endpoint_.c_str(), req_ptr, lambda);
    }

    if (_rentry_ptr->status_ == EntryStatusE::FetchPending) {
        _rentry_ptr->conditionVariable().wait(_rlock, [&_rentry_ptr]() { return _rentry_ptr->status_ != EntryStatusE::FetchPending; });
    }

    return _rentry_ptr->status_ == EntryStatusE::Fetched;
}

bool Engine::Implementation::entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock, const bool _open)
{
    Entry* papp_entry = nullptr;
    string remote_path;
    const string* papp_unique = nullptr;
    const string* pbuild_unique = nullptr;

    auto   it = _path.begin();
    for (; it != _path.end(); ++it) {
        const auto& path_item = *it;
        string      path_item_string = path_item.generic_string();

        fetch(_rentry_ptr, _rlock, remote_path);

        EntryPointerT path_entry_ptr = _rentry_ptr->find(path_item_string);

        if (path_entry_ptr) {
            solid_log(logger, Verbose, "\t" << path_item_string);

            _rentry_ptr = std::move(path_entry_ptr);

            if (_rentry_ptr->isApplication()) {
                papp_entry = _rentry_ptr.get();
                papp_entry->applicationData().useApplication(); //under root mutex
            }else if (_rentry_ptr->isShortcut()) {
                papp_entry = _rentry_ptr->pmaster_;
                papp_entry->applicationData().useApplication(); //under root mutex
            }

            mutex& rmutex = _rentry_ptr->mutex();
            _rlock.unlock(); //no overlapping locks
            {
                unique_lock<mutex> tlock{ rmutex };
                _rlock.swap(tlock);
            }

            if (_rentry_ptr->isApplication()) {
                remote_path.clear();
                //_rpstorage_id = &_rentry_ptr->remote_;

                auto& rad = _rentry_ptr->applicationData();
                papp_unique = &rad.app_unique_;
                pbuild_unique = &rad.build_unique_;
            }
            else if (_rentry_ptr->isMediaRoot()) {
                break;
            }
            else if (!_rentry_ptr->remote_.empty()) {
                remote_path += '/';
                remote_path += _rentry_ptr->remote_;
            }
            else {
                remote_path += '/';
                remote_path += _rentry_ptr->name_;
            }
        }
        else {
            if (papp_entry != nullptr) {
                releaseApplication(*papp_entry);
            }
            return false;
        }
    }//for

    if (_rentry_ptr->isFile()) {
        if (_open && _rentry_ptr->data_any_.empty()) {
            _rentry_ptr->data_any_ = FileData(remote_path);
            if (papp_unique != nullptr) {
                file_cache_engine_.open(_rentry_ptr->fileData(), _rentry_ptr->size_, *papp_unique, *pbuild_unique, remote_path);
            }
        }
    }else if (_rentry_ptr->isDirectory()){
        solid_check_log(fetch(_rentry_ptr, _rlock, remote_path), logger, "fetch should not failed");
    }else if (_rentry_ptr->isMediaRoot()) {
        solid_check_log(papp_entry == nullptr, logger, "papp_entry is null");
        ++it;
        if (it == _path.end()) {
            return false;
        }

        string encoded_storage_id = it->generic_string();
        ++it;
        while (it != _path.end()) {
            remote_path += it->generic_string();
            ++it;
            if (it != _path.end()) {
                remote_path += '/';
            }
        }

        string name = encoded_storage_id + '/' + remote_path;
        auto   entry_ptr = _rentry_ptr->find(name);
        if (entry_ptr) {
            _rentry_ptr = std::move(entry_ptr);
        }
        else {

            string storage_id = myapps::utility::hex_decode(encoded_storage_id);

            entry_ptr = createEntry(_rentry_ptr, name);
            entry_ptr->pmaster_ = entry_ptr.get();
            entry_ptr->remote_ = std::move(storage_id);
            entry_ptr->status_ = EntryStatusE::FetchRequired;
            entry_ptr->flagSet(EntryFlagsE::Volatile);
            entry_ptr->flagSet(EntryFlagsE::Media);

            _rentry_ptr->mediaData().insertEntry(config_, EntryPointerT(entry_ptr));

            _rentry_ptr = std::move(entry_ptr);
        }

        if (fetch(_rentry_ptr, _rlock, remote_path)) {
            if (_rentry_ptr->isFile()) {
                _rentry_ptr->fileData().remote_path_ = std::move(remote_path);
            }
        }else{
            eraseEntryFromParent(std::move(_rentry_ptr), std::move(_rlock));
            solid_check_log(!_rlock.owns_lock(), logger, "not owning lock");
            return false;
        }
    }
    return true;
}

void Engine::info(Descriptor* _pdesc, NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time)
{
    try {
        auto& m = _pdesc->entry_ptr_->mutex();
        lock_guard<mutex> lock(m);

        _pdesc->entry_ptr_->info(_rnode_flags, _rsize, _rbase_time);
    }
    catch (std::exception& e) {
        solid_log(logger, Error, " Exception caught: " << e.what());
    }
    catch (...) {
        solid_log(logger, Error, " Unknown Exception caught");
    }
}

bool Engine::list(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time)
{
    try {
        return pimpl_->list(_pdesc->entry_ptr_, _rpctx, _rname, _rnode_flags, _rsize, _rbase_time);
    }
    catch (std::exception& e) {
        solid_log(logger, Error, " Exception caught: " << e.what());
    }
    catch (...) {
        solid_log(logger, Error, " Unknown Exception caught");
    }
    return false;
}

bool Engine::read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    try {
        return pimpl_->read(_pdesc, static_cast<char*>(_pbuf), _offset, _length, _rbytes_transfered);
    }
    catch (std::exception& e) {
        solid_log(logger, Error, " Exception caught: " << e.what());
    }
    catch (...) {
        solid_log(logger, Error, " Unknown Exception caught");
    }
    return false;
}

// -- Implementation --------------------------------------------------------------------

void Engine::Implementation::releaseApplication(Entry& _rapp_entry)
{
    lock_guard<mutex>                     lock(root_mutex_);
    auto&                                 rad = _rapp_entry.applicationData();
    main::ListAppsResponse::AppVectorT    new_app_id_vec;
    auto&                                 rrd = root_entry_ptr_->rootData();

    rad.releaseApplication();

    if (rad.canBeDeleted()) {
        solid_log(logger, Info, "" << _rapp_entry.name_ << " can be deleted");

        if ((_rapp_entry.hasDelete() || _rapp_entry.hasUpdate())) {
            auto entry_ptr = rrd.eraseApplication(_rapp_entry);
            if (entry_ptr) {
                solid_check_log(entry_ptr.get() == &_rapp_entry, logger, "incorrect entry_ptr");
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
        auto req_ptr = make_shared<main::FetchBuildConfigurationRequest>();

        //TODO:
        req_ptr->lang_  = "US_en";
        req_ptr->os_id_ = "Windows10x86_64";
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Directory);
        //myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Name);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::EXEs);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Flags);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Shortcuts);
        req_ptr->property_vec_.emplace_back("brief");

        remoteFetchApplication(new_app_id_vec, req_ptr, 0);
    }
}

bool Engine::Implementation::list(
    EntryPointerT& _rentry_ptr,
    void*&         _rpctx,
    std::wstring& _rname, NodeFlagsT& _rnode_flags, uint64_t& _rsize, int64_t& _rbase_time)
{
    using ContextT = pair<int, EntryMapT::const_iterator>;

    auto&              m{_rentry_ptr->mutex()};
    unique_lock<mutex> lock(m);
    ContextT*          pctx = nullptr;
    DirectoryData*     pdd  = _rentry_ptr->directoryDataPtr();
#ifdef OLA_VALIDATE_TIME
    bool   should_validate = false;
    if (_rentry_ptr->pmaster_) {
        should_validate = _rentry_ptr->pmaster_->name_ == app_name;;
    }
#endif
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

            _rname      = utility::widen(rentry_ptr->name_);
            _rsize      = rentry_ptr->size_;
            _rbase_time = rentry_ptr->base_time_;

            const auto t = rentry_ptr->type_;
#ifdef OLA_VALIDATE_TIME
            if (should_validate && t == EntryTypeE::File) {
                string path = rentry_ptr->name_;
                auto crt_entry = rentry_ptr->parent_.lock();

                while (crt_entry && crt_entry->type_ == EntryTypeE::Directory) {
                    path = crt_entry->name_ + '\\' + path;
                    crt_entry = crt_entry->parent_.lock();
                }
                path = base_path + path;
                _rbase_time = get_file_base_time(path);
            }
#endif
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

bool Engine::Implementation::read(
    Descriptor* _pdesc,
    char*       _pbuf,
    uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    bool rv;
#ifdef OLA_VALIDATE_READ
    string file_path = base_path;
    bool   should_validate = false;
#endif
    {
        auto& m = _pdesc->entry_ptr_->mutex();
        unique_lock<mutex> lock(m);

        if (_offset >= _pdesc->entry_ptr_->size_) {
            _rbytes_transfered = 0;
            solid_log(logger, Verbose, "READ: " << _pdesc->entry_ptr_.get() << " zero");
            return true;
        }

        {
            size_t remaining_len = _pdesc->entry_ptr_->size_ - _offset;
            if (_length > remaining_len) {
                _length = remaining_len;
            }
        }

#ifdef OLA_VALIDATE_READ
        file_path += _pdesc->entry_ptr_->fileData().remote_path_;
        should_validate = _pdesc->entry_ptr_->pmaster_->name_ == app_name;
#endif

        switch (_pdesc->entry_ptr_->type_) {
        case EntryTypeE::File:
            rv = readFromFile(_pdesc->entry_ptr_, lock, _pbuf, _offset, _length, _rbytes_transfered);
            break;
        case EntryTypeE::Shortcut:
            rv = readFromShortcut(_pdesc->entry_ptr_, _pbuf, _offset, _length, _rbytes_transfered);
#ifdef OLA_VALIDATE_READ
            should_validate = false;
#endif
            break;
        default:
            solid_throw("Try read from unknown entry type");
        }
    }
    solid_check_log(_length == _rbytes_transfered, logger, _length<<" vs "<< _rbytes_transfered);
#ifdef OLA_VALIDATE_READ
    if (should_validate) {
        ifstream ifs(file_path, ifstream::binary);
        solid_check(ifs);
        char* pbuf = new char[_length];

        ifs.seekg(_offset);
        ifs.read(pbuf, _length);
        solid_check(ifs.gcount() == _length);
        //solid_check(memcmp(pbuf, _pbuf, _length) == 0);
        if (memcmp(pbuf, _pbuf, _length) != 0) {
            size_t i = 0;
            for (; i < _length; ++i) {
                if (pbuf[i] != _pbuf[i]) {
                    break;
                }
            }
            solid_check(i == _length);
        }

        delete[]pbuf;
    }
#endif
    return rv;
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
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " " << _offset << " " << _length << " " << _rbytes_transfered);
        return true;
    }
    
    if (!rfile_data.isInitiated()) {
        solid_check_log(_rentry_ptr->pmaster_->isApplication(), logger, "not an application");
        const auto& app_data = _rentry_ptr->pmaster_->applicationData();
        rfile_data.init(app_data.compress_chunk_capacity_, app_data.compress_algorithm_type_);
    }

    if (rfile_data.enqueue(read_data, _rentry_ptr->size_)) {
        //the queue was empty
        tryFetch(_rentry_ptr);
    }
    solid_log(logger, Verbose, _rentry_ptr.get() << " wait");
    _rentry_ptr->conditionVariable().wait(_rlock, [&read_data]() { return read_data.done_; });

    if (rfile_data.error() != 0) {
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " error reading "<<rfile_data.error());
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

void Engine::Implementation::tryFetch(EntryPointerT& _rentry_ptr)
{
    FileData& rfile_data = _rentry_ptr->fileData();
    rfile_data.prepareFetchingChunk();
    rfile_data.pendingRequest(true);

    auto req_ptr = make_shared<main::FetchStoreRequest>();
    
    req_ptr->path_ = rfile_data.remote_path_;
    req_ptr->storage_id_ = _rentry_ptr->pmaster_->remote_;
    req_ptr->chunk_index_ = rfile_data.currentChunkIndex();
    req_ptr->chunk_offset_ = 0;

    asyncFetchStoreFile(nullptr, _rentry_ptr, req_ptr, rfile_data.currentChunkIndex(), 0);
}

void Engine::Implementation::asyncFetchStoreFileHandleResponse(
    frame::mprpc::ConnectionContext& _rctx, EntryPointerT& _rentry_ptr,
    std::shared_ptr<main::FetchStoreRequest>& _rsent_msg_ptr,
    std::shared_ptr<main::FetchStoreResponse>& _rrecv_msg_ptr
) {
    FileData& rfile_data = _rentry_ptr->fileData();
    bool should_wake_readers = false;
    const uint32_t received_size = rfile_data.copy(_rrecv_msg_ptr->ioss_, _rrecv_msg_ptr->chunk_.size_, _rrecv_msg_ptr->chunk_.isCompressed(), should_wake_readers);

    solid_log(logger, Info, _rentry_ptr->name_ <<" Received " << received_size << " offset " << rfile_data.currentChunkOffset() << " crt_idx " << rfile_data.currentChunkIndex()<< " idx "<< _rsent_msg_ptr->chunk_index_ << " off " << _rsent_msg_ptr->chunk_offset_ << " totalsz " << _rrecv_msg_ptr->chunk_.size_);

    if (should_wake_readers) {
        _rentry_ptr->conditionVariable().notify_all();
    }

    if (rfile_data.responsePointer(0)) {
        solid_log(logger, Info, _rentry_ptr->name_ << " response pointer");
        auto res_ptr1 = std::move(rfile_data.responsePointer(0));
        auto res_ptr2 = std::move(rfile_data.responsePointer(1));
        asyncFetchStoreFileHandleResponse(_rctx, _rentry_ptr, _rsent_msg_ptr, res_ptr1);
        if (res_ptr2) {
            asyncFetchStoreFileHandleResponse(_rctx, _rentry_ptr, _rsent_msg_ptr, res_ptr2);
        }
        return;
    }

    if (_rrecv_msg_ptr->isResponsePart()) {
        //do we need to request more data for current chunk:
        if ((_rrecv_msg_ptr->chunk_.size_ - rfile_data.currentChunkOffset()) > received_size) {
            rfile_data.pendingRequest(true);
            asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.currentChunkIndex(), rfile_data.currentChunkOffset() + received_size);
            return;
        }
        else {
            rfile_data.pendingRequest(false);
        }
    }
    else if (rfile_data.currentChunkOffset() == 0 && !rfile_data.pendingRequest()) {//should try send another request
        rfile_data.storeRequest(std::move(_rsent_msg_ptr));
    }
    else if (rfile_data.currentChunkOffset() == 0 && rfile_data.pendingRequest() && (received_size == _rrecv_msg_ptr->chunk_.size_)) {//should try send another request
        rfile_data.storeRequest(std::move(_rsent_msg_ptr));
        rfile_data.pendingRequest(false);
    }
    else {
        rfile_data.storeRequest(std::move(_rsent_msg_ptr));
        solid_log(logger, Info, _rentry_ptr->name_ << "");
        rfile_data.pendingRequest(false);
        return;
    }

    //is there a next chunk
    
    if (rfile_data.currentChunkIndex() != -1 && rfile_data.currentChunkOffset() == 0) {
        rfile_data.pendingRequest(true);
        solid_log(logger, Info, _rentry_ptr->name_ << "");
        asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.currentChunkIndex(), 0);
    }
    else if (!rfile_data.isLastChunk()) {
        solid_log(logger, Info, _rentry_ptr->name_ << " not last chunk ");
        rfile_data.pendingRequest(true);
        asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.peekNextChunk(), 0);
    }
    else {
        solid_log(logger, Info, _rentry_ptr->name_ << "");
    }
}

void Engine::Implementation::asyncFetchStoreFile(
    frame::mprpc::ConnectionContext* _pctx, EntryPointerT& _rentry_ptr,
    std::shared_ptr<main::FetchStoreRequest>& _rreq_msg_ptr,
    const uint32_t _chunk_index, const uint32_t _chunk_offset)
{
    solid_log(logger, Info, _rentry_ptr->name_ << " " << _chunk_index << " " << _chunk_offset);
    auto lambda = [entry_ptr = _rentry_ptr, this/*, _chunk_index, _chunk_offset*/](
        frame::mprpc::ConnectionContext& _rctx,
        std::shared_ptr<main::FetchStoreRequest>& _rsent_msg_ptr,
        std::shared_ptr<main::FetchStoreResponse>& _rrecv_msg_ptr,
        ErrorConditionT const& _rerror
        )mutable {
            FileData& rfile_data = entry_ptr->fileData();
            auto& m = entry_ptr->mutex();
            unique_lock<mutex> lock(m);

            if (_rrecv_msg_ptr) {
                if (_rrecv_msg_ptr->error_ == 0) {
                    _rrecv_msg_ptr->ioss_.seekg(0);

                    //if (_rfetch_stub.chunk_index_ == _chunk_index && _rfetch_stub.chunk_offset_ >= _chunk_offset) {
                    if(rfile_data.isExpectedResponse(_rsent_msg_ptr->chunk_index_, _rsent_msg_ptr->chunk_offset_)){
                        asyncFetchStoreFileHandleResponse(_rctx, entry_ptr, _rsent_msg_ptr, _rrecv_msg_ptr);
                        rfile_data.tryClearFetchStub();
                    }
                    else {
                        solid_log(logger, Info, entry_ptr->name_ << " store response for " << _rsent_msg_ptr->chunk_index_ << " " << _rsent_msg_ptr->chunk_offset_);
                        rfile_data.storeResponse(_rrecv_msg_ptr);
                    }
                }
                else {
                    rfile_data.error(_rrecv_msg_ptr->error_);
                    entry_ptr->conditionVariable().notify_all();
                }
            }
            else {
                rfile_data.error(-1);
                entry_ptr->conditionVariable().notify_all();
            }
    };
    
    FileData& rfile_data = _rentry_ptr->fileData();
    if (_pctx) {

        std::shared_ptr<main::FetchStoreRequest> req_ptr;
        if (rfile_data.requestPointer()) {
            req_ptr = std::move(rfile_data.requestPointer());
        }
        else {
            req_ptr = make_shared<main::FetchStoreRequest>();
            req_ptr->storage_id_ = _rreq_msg_ptr->storage_id_;
            req_ptr->path_ = _rreq_msg_ptr->path_;
        }
        req_ptr->chunk_index_ = _chunk_index;
        req_ptr->chunk_offset_ = _chunk_offset;
        const auto err = _pctx->service().sendRequest(_pctx->recipientId(), req_ptr, lambda);
        if (err) {
            rfile_data.error(-1);
            _rentry_ptr->conditionVariable().notify_all();
        }
    }
    else {
        const auto err = front_rpc_service_.sendRequest(config_.auth_endpoint_.c_str(), _rreq_msg_ptr, lambda);
        if (err) {
            rfile_data.error(-1);
            _rentry_ptr->conditionVariable().notify_all();
        }
    }
}

//-----------------------------------------------------------------------------

void Engine::Implementation::tryAuthenticate(frame::mprpc::ConnectionContext& _rctx)
{
    string auth_token = config_.auth_get_token_fnc_();

    if (!auth_token.empty()) {
        auto req_ptr = std::make_shared<core::AuthRequest>();
        req_ptr->pass_ = auth_token;
        auto lambda  = [this](
                          frame::mprpc::ConnectionContext&      _rctx,
                          std::shared_ptr<core::AuthRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<core::AuthResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                _rerror) {
            if (_rrecv_msg_ptr) {
                onFrontAuthResponse(_rctx, *_rsent_msg_ptr, _rrecv_msg_ptr);
            }
        };

        front_rpc_service_.sendRequest(_rctx.recipientId(), req_ptr, lambda);
    } else {
        lock_guard<mutex> lock(mutex_);
        auth_recipient_vec_.emplace_back(_rctx.recipientId());
    }
}

void Engine::Implementation::onFrontConnectionStart(frame::mprpc::ConnectionContext& _ctx)
{
    auto req_ptr = std::make_shared<main::InitRequest>();
    auto lambda  = [this](
                      frame::mprpc::ConnectionContext&      _rctx,
                      std::shared_ptr<main::InitRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<core::InitResponse>& _rrecv_msg_ptr,
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
    frame::mprpc::ConnectionContext&      _rctx,
    const core::AuthRequest&             _rreq,
    std::shared_ptr<core::AuthResponse>& _rrecv_msg_ptr)
{
    if (!_rrecv_msg_ptr)
        return;

    if (_rrecv_msg_ptr->error_) {
        solid_log(logger, Info, "Authentication failed: "<< _rrecv_msg_ptr->error_);
        bool call_on_response = false;
        {
            lock_guard<mutex> lock(mutex_);
            auth_recipient_vec_.emplace_back(_rctx.recipientId());
            call_on_response = (auth_recipient_vec_.size() == 1);
        }

        if (call_on_response) {
            config_.auth_on_response_fnc_(_rrecv_msg_ptr->error_, _rrecv_msg_ptr->message_);
        }
    } else {
        solid_log(logger, Info, "Authentication Success");

        if (!_rrecv_msg_ptr->message_.empty()) {
            config_.auth_on_response_fnc_(_rrecv_msg_ptr->error_, _rrecv_msg_ptr->message_);
        }
        front_rpc_service_.connectionNotifyEnterActiveState(_rctx.recipientId());
    }
}

void Engine::Implementation::remoteFetchApplication(
    main::ListAppsResponse::AppVectorT&                  _rapp_id_vec,
    std::shared_ptr<main::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
    size_t                                                  _app_index)
{
    _rsent_msg_ptr->app_id_ = _rapp_id_vec[_app_index].id_;
    _rsent_msg_ptr->build_id_ = app_list_.find(_rapp_id_vec[_app_index].unique_).name_;

    auto lambda = [this, _app_index, app_id_vec = std::move(_rapp_id_vec)](
                      frame::mprpc::ConnectionContext&                         _rctx,
                      std::shared_ptr<main::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<main::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                                   _rerror) mutable {
        if (_rrecv_msg_ptr) {

            ++_app_index;

            if (_rrecv_msg_ptr->error_ == 0) {

                this->workpool_.push(
                    [this, recv_msg_ptr = std::move(_rrecv_msg_ptr), is_last = _app_index >= app_id_vec.size(), app = app_id_vec[_app_index - 1]]() mutable {
                        insertApplicationEntry(recv_msg_ptr, app);
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

    front_rpc_service_.sendRequest(config_.auth_endpoint_.c_str(), _rsent_msg_ptr, lambda);
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
                           std::shared_ptr<main::ListAppsRequest>&  _rsent_msg_ptr,
                           std::shared_ptr<main::ListAppsResponse>& _rrecv_msg_ptr,
                           ErrorConditionT const&                    _rerror) {
        if (_rrecv_msg_ptr) {
            auto req_ptr = make_shared<main::FetchBuildUpdatesRequest>();
            req_ptr->app_id_vec_.reserve(_rrecv_msg_ptr->app_vec_.size());
            for (auto&& a : _rrecv_msg_ptr->app_vec_) {
                auto build_req = app_list_.find(a.unique_).name_;
                if (build_req != myapps::utility::app_item_invalid) {
                    req_ptr->app_id_vec_.emplace_back(std::move(a.id_), app_list_.find(a.unique_).name_);
                }
            }
            req_ptr->lang_  = "US_en";
            req_ptr->os_id_ = "Windows10x86_64";

            auto lambda = [this, &done, &updates_map](
                              frame::mprpc::ConnectionContext&                   _rctx,
                              std::shared_ptr<main::FetchBuildUpdatesRequest>&  _rsent_msg_ptr,
                              std::shared_ptr<main::FetchBuildUpdatesResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                             _rerror) {
                if (_rrecv_msg_ptr) {
                    updates_map.clear();
                    for (size_t i = 0; i < _rrecv_msg_ptr->app_vec_.size(); ++i) {
                        const auto& app_unique   = _rrecv_msg_ptr->app_vec_[i].first;
                        const auto& build_unique = _rrecv_msg_ptr->app_vec_[i].second;
                        const auto& app_id       = _rsent_msg_ptr->app_id_vec_[i];
                        if (!build_unique.empty()) {
                            updates_map[app_unique] = make_pair(app_id.first, build_unique);
                        }
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

            const auto err = front_rpc_service_.sendRequest(config_.auth_endpoint_.c_str(), req_ptr, lambda);
            if (!err) {
                return;
            }
        }

        unique_lock<mutex> lock(root_mutex_);
        done = -1;
        root_cv_.notify_one();
    };

    while (true) {
        bool app_list_update = false;
        {
            unique_lock<mutex> lock(root_mutex_);

            root_cv_.wait_for(lock, chrono::seconds(config_.update_poll_seconds_), [this]() { return !running_ && app_list_update_; });
            if (!running_) {
                return;
            }
            if (app_list_update_) {
                app_list_update_ = false;
                app_list_update = true;
            }
        }

        app_list_.load(config_.app_list_path_);

        auto req_ptr     = make_shared<main::ListAppsRequest>();
        req_ptr->choice_ = 'a';

        const auto err = front_rpc_service_.sendRequest(config_.auth_endpoint_.c_str(), req_ptr, list_lambda);
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
    main::ListAppsResponse::AppVectorT new_app_id_vec;

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
                    solid_check_log(entry_ptr.get() == &rapp_entry, logger, "incorrect entry ptr");
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
                    solid_check_log(entry_ptr.get() == &rapp_entry, logger, "incorrect entry ptr");
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
        auto req_ptr = make_shared<main::FetchBuildConfigurationRequest>();

        //TODO:
        req_ptr->lang_  = "en_US";
        req_ptr->os_id_ = "Windows10x86_64";
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Directory);
        //myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Name);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::EXEs);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Flags);
        myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Shortcuts);
        req_ptr->property_vec_.emplace_back("brief");
        req_ptr->property_vec_.emplace_back("version");

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
        update_thread_ = thread(&Implementation::update, this);
    }
    config_.folder_update_fnc_("");
}

void Engine::Implementation::onFrontListAppsResponse(
    frame::mprpc::ConnectionContext&          _ctx,
    std::shared_ptr<main::ListAppsResponse>& _rrecv_msg_ptr)
{
    if (_rrecv_msg_ptr->app_vec_.empty()) {

        if (_rrecv_msg_ptr->error_ == 0) {
            onAllApplicationsFetched();
        }

        return;
    }

    auto req_ptr = make_shared<main::FetchBuildConfigurationRequest>();

    //TODO:
    req_ptr->lang_  = "en_US";
    req_ptr->os_id_ = "Windows10x86_64";
    myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Directory);
    //myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Name);
    myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::EXEs);
    myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Flags);
    myapps::utility::Build::set_option(req_ptr->fetch_options_, myapps::utility::Build::FetchOptionsE::Shortcuts);
    req_ptr->property_vec_.emplace_back("brief");
    req_ptr->property_vec_.emplace_back("version");

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
            solid_check_log(ep, logger, "empty entry ptr");
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

void Engine::Implementation::insertApplicationEntry(
    std::shared_ptr<main::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
    const myapps::utility::ApplicationListItem& _app)
{
    //NOTE: because of the entry_ptr, which after inserting it into root entry
    //will have use count == 2, the application cannot be deleted on releaseApplication
    //before adding all application shortcuts below.
    auto entry_ptr = createEntry(
        root_entry_ptr_, _rrecv_msg_ptr->configuration_.directory_,
        EntryTypeE::Application);

    entry_ptr->remote_   = _rrecv_msg_ptr->build_storage_id_;
    entry_ptr->data_any_ = ApplicationData(_rrecv_msg_ptr->app_unique_, _rrecv_msg_ptr->build_unique_);
    entry_ptr->pmaster_  = entry_ptr.get();

    if (_rrecv_msg_ptr->configuration_.hasHiddenDirectoryFlag()) {
        entry_ptr->flagSet(EntryFlagsE::Hidden);
    }

    bool is_invisible = false;
    if (
        _app.isFlagSet(myapps::utility::AppFlagE::Default) &&
        _rrecv_msg_ptr->configuration_.exe_vec_.size() == 1 && 
        _rrecv_msg_ptr->configuration_.exe_vec_[0] == "ola_updater.exe" &&
        _rrecv_msg_ptr->configuration_.property_vec_.size() >= 2 &&
        _rrecv_msg_ptr->configuration_.property_vec_[1].second == myapps::utility::version_full()
    ) {
        entry_ptr->flagSet(EntryFlagsE::Invisible);
        is_invisible = true;
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
    
    if (!is_invisible && !_rrecv_msg_ptr->configuration_.shortcut_vec_.empty()) {
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
                sh.icon_.empty() ? sh.icon_ : to_system_path(config_.mount_prefix_ + '/' + app_folder_name + '/' + sh.icon_),
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

void Engine::Implementation::insertDirectoryEntry(unique_lock<mutex>& _rlock, EntryPointerT& _rparent_ptr, const string& _name)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name);

    auto entry_ptr = _rparent_ptr->directoryData().find(_name);

    if (!entry_ptr) {
        _rparent_ptr->directoryData().insertEntry(createEntry(_rparent_ptr, _name, EntryTypeE::Directory));
    } else {
        _rlock.unlock();
        {
            //make sure the entry is directory
            auto& rm = entry_ptr->mutex();
            lock_guard<mutex> lock{ rm };
            entry_ptr->type_ = EntryTypeE::Directory;

            if (entry_ptr->directoryDataPtr() == nullptr) {
                entry_ptr->data_any_ = DirectoryData();
            }
        }
        _rlock.lock();
    }
}

void Engine::Implementation::insertFileEntry(
    unique_lock<mutex>& _rlock, EntryPointerT& _rparent_ptr, const string& _name,
    const uint64_t _size, const int64_t _base_time
)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name << " " << _size);

    auto entry_ptr = _rparent_ptr->directoryData().find(_name);

    if (!entry_ptr) {
        auto entry_ptr = createEntry(_rparent_ptr, _name, EntryTypeE::File, _size);
        entry_ptr->base_time_ = _base_time;
        _rparent_ptr->directoryData().insertEntry(std::move(entry_ptr));
    } else {
        _rlock.unlock();
        {
            //make sure the entry is file
            auto& rm = entry_ptr->mutex();
            lock_guard<mutex> lock{ rm };
            entry_ptr->type_ = EntryTypeE::File;
            entry_ptr->size_ = _size;
            entry_ptr->base_time_ = _base_time;
        }
        _rlock.lock();
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

void Engine::Implementation::createEntryData(
    unique_lock<mutex>& _lock, EntryPointerT& _rentry_ptr,
    ListNodeDequeT& _rnode_dq,
    const uint32_t _compress_chunk_capacity,
    const uint8_t _compress_algorithm_type
)
{
    solid_log(logger, Info, _rentry_ptr->name_);

    if (_rnode_dq.size() == 1 && _rnode_dq.front().name_.empty()) {
        _rentry_ptr->type_ = EntryTypeE::File;
        _rentry_ptr->size_ = _rnode_dq.front().size_;
        if (_rentry_ptr->isMedia()) {
            _rentry_ptr->data_any_ = FileData("");
            _rentry_ptr->fileData().init(_compress_chunk_capacity, _compress_algorithm_type);
        }
        else {
            _rentry_ptr->data_any_.clear();
        }
        return;
    }

    if (_rentry_ptr->directoryDataPtr() == nullptr) {
        solid_assert(_rentry_ptr->type_ == EntryTypeE::Directory || _rentry_ptr->type_ == EntryTypeE::Unknown);
        _rentry_ptr->type_ = EntryTypeE::Directory;
        _rentry_ptr->data_any_ = DirectoryData();
    }
    else if (_rentry_ptr->isApplication()) {
        _rentry_ptr->applicationData().compress_chunk_capacity_ = _compress_chunk_capacity;
        _rentry_ptr->applicationData().compress_algorithm_type_ = _compress_algorithm_type;
    }
    else if (_rentry_ptr->type_ == EntryTypeE::Unknown) {
        _rentry_ptr->type_ = EntryTypeE::Directory;
    }

    for (const auto& n : _rnode_dq) {
        //TODO: we do not create the EntryData here
        // so we must handle the situation in open(..)
        if (n.name_.back() == '/') {
            string name = n.name_;
            name.pop_back();
            insertDirectoryEntry(_lock, _rentry_ptr, name);
        } else {
            insertFileEntry(_lock, _rentry_ptr, n.name_, n.size_, n.base_time_);
        }
    }
}

} //namespace service
} //namespace client
} //namespace myapps
