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

#include "ola/common/utility/crypto.hpp"

#include "ola/client/gui/gui_protocol.hpp"
#include "ola/client/utility/locale.hpp"

#include "ola/common/ola_front_protocol.hpp"
#include "shortcut_creator.hpp"

#include "boost/filesystem.hpp"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/functional/hash.hpp>

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

enum struct EntryTypeE : uint8_t {
    Unknown,
    Directory,
    Application,
    File,
    Shortcut
};

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
using EntryPointerT = std::shared_ptr<Entry>;
using EntryMapT     = std::unordered_map<const std::reference_wrapper<const string>, EntryPointerT, Hash, Equal>;

struct DirectoryData {
    EntryMapT entry_map_;

    void erase(const EntryPointerT& _rentry_ptr);

    EntryPointerT find(const string& _path) const;

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

struct FileData {
    enum StatusE {
        PendingE,
        ErrorE,
    };
    ReadData* pfront_ = nullptr;
    ReadData* pback_  = nullptr;
    StatusE   status_ = PendingE;
    FetchStub fetch_stubs_[2];
    string    storage_id_;
    string    remote_path_;
    uint64_t  prefetch_offset_;
    size_t    contiguous_read_count_;

    FileData(const string& _storage_id, const string& _remote_path)
        : storage_id_(_storage_id)
        , remote_path_(_remote_path)
    {
    }

    bool readFromCache(ReadData& _rdata)
    {
        return false;
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

    void writeToCache(const uint64_t _offset, istream& _ris);
};

struct ApplicationData : DirectoryData {
};

using DirectoryDataPointerT   = std::unique_ptr<DirectoryData>;
using FileDataPointerT        = std::unique_ptr<FileData>;
using ApplicationDataPointerT = std::unique_ptr<ApplicationData>;
using UniqueIdT               = solid::frame::UniqueId;
using EntryDataVariantT       = std::variant<
    UniqueIdT,
    DirectoryDataPointerT, ApplicationDataPointerT, FileDataPointerT>; //the order should be consistent with EntryTypeE

struct Entry {
    std::mutex&              rmutex_;
    std::condition_variable& rcv_;
    string                   name_;
    string                   remote_;
    EntryTypeE               type_   = EntryTypeE::Unknown;
    EntryStatusE             status_ = EntryStatusE::FetchRequired;
    std::weak_ptr<Entry>     parent_;
    uint64_t                 size_ = 0;
    EntryDataVariantT        data_var_;

    Entry(
        const EntryTypeE _type, EntryPointerT& _rparent_ptr, std::mutex& _rmutex, std::condition_variable& _rcv, const string& _name,
        const uint64_t _size = 0)
        : rmutex_(_rmutex)
        , rcv_(_rcv)
        , name_(_name)
        , type_(_type)
        , parent_(_rparent_ptr)
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

    inline DirectoryData* directoryData() const
    {
        DirectoryData* pdd = nullptr;
        if (auto pd = std::get_if<DirectoryDataPointerT>(&data_var_)) {
            pdd = pd->get();
        } else if (auto pd = std::get_if<ApplicationDataPointerT>(&data_var_)) {
            pdd = pd->get();
        }
        return pdd;
    }

    EntryPointerT find(const string& _path) const
    {
        EntryPointerT entry_ptr;
        if (auto pd = directoryData(); pd != nullptr) {
            entry_ptr = pd->find(_path);
        }
        return entry_ptr;
    }

    void erase(const EntryPointerT& _rentry_ptr)
    {
        if (auto pd = directoryData(); pd != nullptr) {
            pd->erase(_rentry_ptr);
        }
    }

    std::mutex& mutex() const
    {
        return rmutex_;
    }
    std::condition_variable& conditionVariable() const
    {
        return rcv_;
    }

    void info(NodeTypeE& _rnode_type, uint64_t& _rsize) const
    {
        _rsize = size_;
        switch (type_) {
        case EntryTypeE::Unknown:
            solid_throw("Unknown entry type");
            break;
        case EntryTypeE::File:
        case EntryTypeE::Shortcut:
            _rnode_type = NodeTypeE::File;
            break;
        case EntryTypeE::Application:
        case EntryTypeE::Directory:
            _rnode_type = NodeTypeE::Directory;
            break;
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
        if (auto pd = std::get_if<UniqueIdT>(&data_var_); pd != nullptr) {
            return true;
        } else if (auto pd = std::get_if<DirectoryDataPointerT>(&data_var_); pd != nullptr) {
            return (*pd)->empty();
        }
        return false;
    }

    bool isErasable() const
    {
        return (status_ == EntryStatusE::FetchRequired || status_ == EntryStatusE::FetchError) && empty();
    }
};

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;

void DirectoryData::erase(const EntryPointerT& _rentry_ptr)
{
    auto it = entry_map_.find(_rentry_ptr->name_);
    if (it != entry_map_.end() && it->second == _rentry_ptr) {
        entry_map_.erase(it);
    }
}

EntryPointerT DirectoryData::find(const string& _path) const
{
    auto it = entry_map_.find(_path);
    if (it != entry_map_.end()) {
        return atomic_load(&it->second);
    }
    return EntryPointerT{};
}

void DirectoryData::insertEntry(EntryPointerT&& _uentry_ptr)
{
    entry_map_.emplace(_uentry_ptr->name_, std::move(_uentry_ptr));
}

} //namespace

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
    string                    auth_user_;
    string                    auth_token_;
    RecipientVectorT          auth_recipient_v_;
    frame::mprpc::RecipientId gui_recipient_id_;
    EntryPointerT             root_entry_ptr_;
    atomic<size_t>            current_mutex_index_ = 0;
    MutexDequeT               mutex_dq_;
    CVDequeT                  cv_dq_;
    string                    os_id_;
    string                    language_id_;
    ShortcutCreator           shortcut_creator_;

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

public:
    void onFrontConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onFrontAuthResponse(
        frame::mprpc::ConnectionContext&      _ctx,
        const front::AuthRequest&             _rreq,
        std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr);

    void onGuiAuthRequest(
        frame::mprpc::ConnectionContext&   _rctx,
        std::shared_ptr<gui::AuthRequest>& _rrecv_msg_ptr,
        ErrorConditionT const&             _rerror);
    void onGuiRegisterRequest(
        frame::mprpc::ConnectionContext& _rctx,
        gui::RegisterRequest&            _rmsg);
    void loadAuthData();

    void onFrontListAppsResponse(
        frame::mprpc::ConnectionContext&          _ctx,
        std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr);

    EntryPointerT createEntry(EntryPointerT& _rparent_ptr, const string& _name, const EntryTypeE _type = EntryTypeE::Unknown, const uint64_t _size = 0);

    EntryPointerT tryInsertUnknownEntry(EntryPointerT& _rparent_ptr, const string& _path);

    void eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock);

    void createEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq);

    void insertDirectoryEntry(EntryPointerT& _rparent_ptr, const string& _name);
    void insertFileEntry(EntryPointerT& _rparent_ptr, const string& _name, uint64_t _size);

    void createRootEntry();

    bool entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock);

    void asyncFetch(EntryPointerT& _rentry_ptr, const size_t _fetch_index, const uint64_t _offset, uint64_t _size);

    bool list(
        EntryPointerT& _rentry_ptr,
        void*&         _rpctx,
        std::wstring& _rname, NodeTypeE& _rnode_type, uint64_t& _rsize);
    bool read(
        EntryPointerT& _rentry_ptr,
        char*          _pbuf,
        uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);
    void tryFetch(EntryPointerT& _rentry_ptr, ReadData& _rread_data);
    void tryPreFetch(EntryPointerT& _rentry_ptr);

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

    void remoteFetchApplication(
        std::shared_ptr<front::ListAppsResponse>&               _apps_response,
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

    void operator()(front::ProtocolT& _rprotocol, TypeToType<gui::RegisterRequest> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        auto lambda = [& impl_ = this->impl_](
                          frame::mprpc::ConnectionContext&       _rctx,
                          std::shared_ptr<gui::RegisterRequest>& _rsent_msg_ptr,
                          std::shared_ptr<gui::RegisterRequest>& _rrecv_msg_ptr,
                          ErrorConditionT const&                 _rerror) {
            impl_.onGuiRegisterRequest(_rctx, *_rrecv_msg_ptr);
        };
        _rprotocol.registerMessage<gui::RegisterRequest>(lambda, _rtid);
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
                [](frame::aio::openssl::Context& _rctx) -> ErrorCodeT {
                    _rctx.loadVerifyFile("ola-ca-cert.pem");
                    _rctx.loadCertificateFile("ola-front-client-cert.pem");
                    _rctx.loadPrivateKeyFile("ola-front-client-key.pem");
                    return ErrorCodeT();
                },
                frame::mprpc::openssl::NameCheckSecureStart{"ola-front-server"});
        }

        if (_rcfg.compress_) {
            frame::mprpc::snappy::setup(cfg);
        }

        pimpl_->front_rpc_service_.start(std::move(cfg));
    }

    {
        auto                        proto = gui::ProtocolT::create();
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);

        gui::protocol_setup(GuiProtocolSetup(*pimpl_), *proto);

        cfg.server.listener_address_str = "127.0.0.1:0";

        pimpl_->gui_rpc_service_.start(std::move(cfg));
    }

    {
        pimpl_->mutex_dq_.resize(pimpl_->config_.mutex_count_);
        pimpl_->cv_dq_.resize(pimpl_->config_.cv_count_);
    }

    pimpl_->createRootEntry();

    auto err = pimpl_->front_rpc_service_.createConnectionPool(_rcfg.front_endpoint_.c_str(), 1);
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
        req_ptr->choice_ = 'o';

        err = pimpl_->front_rpc_service_.sendRequest(_rcfg.front_endpoint_.c_str(), req_ptr, lambda);
        solid_check(!err);
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

bool Engine::info(const fs::path& _path, NodeTypeE& _rnode_type, uint64_t& _rsize)
{
    EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
    mutex&             rmutex    = entry_ptr->mutex();
    unique_lock<mutex> lock{rmutex};

    if (pimpl_->entry(_path, entry_ptr, lock)) {
        entry_ptr->info(_rnode_type, _rsize);
        solid_log(logger, Verbose, "INFO: " << _path.generic_path() << " " << static_cast<int>(_rnode_type) << " " << _rsize);
        return true;
    }
    solid_log(logger, Verbose, "INFO: FAIL " << _path.generic_path());
    return false;
}

Descriptor* Engine::open(const fs::path& _path)
{

    EntryPointerT      entry_ptr = atomic_load(&pimpl_->root_entry_ptr_);
    mutex&             rmutex    = entry_ptr->mutex();
    unique_lock<mutex> lock{rmutex};

    if (pimpl_->entry(_path, entry_ptr, lock)) {
        auto pdesc = new Descriptor(std::move(entry_ptr));
        solid_log(logger, Verbose, "OPEN: " << _path.generic_path() << " -> " << pdesc << " entry: " << pdesc->entry_ptr_.get());
        return pdesc;
    }
    return nullptr;
}

void Engine::cleanup(Descriptor* _pdesc)
{
}

void Engine::close(Descriptor* _pdesc)
{
    if (_pdesc->entry_ptr_->type_ == EntryTypeE::File) {
        //_pdesc->entry_ptr_->data_var_ = UniqueIdT(); //TODO store propper UniqueId
    }
    solid_log(logger, Verbose, "CLOSE: " << _pdesc << " entry: " << _pdesc->entry_ptr_.get());
    delete _pdesc;
}

bool Engine::Implementation::entry(const fs::path& _path, EntryPointerT& _rentry_ptr, unique_lock<mutex>& _rlock)
{
    auto   generic_path_str = _path.generic_string();
    string remote_path;
    string storage_id;

    for (const auto& e : _path) {
        string        s     = e.generic_string();
        EntryPointerT e_ptr = _rentry_ptr->find(s);

        solid_log(logger, Verbose, "\t" << s);

        if (!e_ptr) {
            _rentry_ptr = tryInsertUnknownEntry(_rentry_ptr, s);
            if (_rentry_ptr) {
                remote_path += '/';
                remote_path += s;
            } else {
                return false;
            }
        } else {
            _rentry_ptr   = std::move(e_ptr);
            mutex& rmutex = _rentry_ptr->mutex();
            _rlock.unlock(); //no overlapping locks
            unique_lock<mutex> tlock{rmutex};
            _rlock.swap(tlock);

            if (_rentry_ptr->type_ == EntryTypeE::Application) {
                remote_path.clear();
                storage_id = _rentry_ptr->remote_;
            } else if (!_rentry_ptr->remote_.empty()) {
                remote_path += '/';
                remote_path += _rentry_ptr->remote_;
            } else {
                remote_path += '/';
                remote_path += _rentry_ptr->name_;
            }
        }
    }

    solid_log(logger, Info, "Open (generic_path = " << generic_path_str << " remote_path = " << remote_path << ")");

    if (_rentry_ptr->status_ == EntryStatusE::FetchRequired) {
        _rentry_ptr->status_ = EntryStatusE::FetchPending;

        auto lambda = [entry_ptr = _rentry_ptr, &generic_path_str, this](
                          frame::mprpc::ConnectionContext&           _rctx,
                          std::shared_ptr<front::ListStoreRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::ListStoreResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                     _rerror) mutable {
            auto&             m = entry_ptr->mutex();
            lock_guard<mutex> lock{m};
            if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                entry_ptr->status_ = EntryStatusE::Fetched;
                createEntryData(entry_ptr, generic_path_str, _rrecv_msg_ptr->node_dq_);
            } else {
                entry_ptr->status_ = EntryStatusE::FetchError;
            }
            entry_ptr->conditionVariable().notify_all();
        };

        auto req_ptr         = make_shared<ListStoreRequest>();
        req_ptr->path_       = remote_path;
        req_ptr->storage_id_ = storage_id;

        front_rpc_service_.sendRequest(config_.front_endpoint_.c_str(), req_ptr, lambda);
    }

    if (_rentry_ptr->status_ == EntryStatusE::FetchPending) {
        _rentry_ptr->conditionVariable().wait(_rlock, [&_rentry_ptr]() { return _rentry_ptr->status_ != EntryStatusE::FetchPending; });
    }

    if (_rentry_ptr->status_ == EntryStatusE::FetchError) {
        if (_rentry_ptr->type_ == EntryTypeE::Unknown) {
            eraseEntryFromParent(std::move(_rentry_ptr), std::move(_rlock));
        }
        solid_log(logger, Verbose, "Fail open: " << _path.generic_path());

        return false;
    } else {
        solid_check(_rentry_ptr->type_ > EntryTypeE::Unknown);

        if (_rentry_ptr->type_ == EntryTypeE::File) {
            //TODO: move creation to FileCache
            if (holds_alternative<UniqueIdT>(_rentry_ptr->data_var_)) {
                _rentry_ptr->data_var_ = make_unique<FileData>(storage_id, remote_path);
            }
        }

        solid_log(logger, Verbose, "Open " << _rentry_ptr.get() << " " << _path.generic_path() << " type: " << static_cast<uint16_t>(_rentry_ptr->type_) << " remote: " << remote_path);

        //success
        return true;
    }
}

void Engine::info(Descriptor* _pdesc, NodeTypeE& _rnode_type, uint64_t& _rsize)
{
    auto&             m = _pdesc->entry_ptr_->mutex();
    lock_guard<mutex> lock(m);

    _pdesc->entry_ptr_->info(_rnode_type, _rsize);
}

bool Engine::list(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, NodeTypeE& _rnode_type, uint64_t& _rsize)
{
    return pimpl_->list(_pdesc->entry_ptr_, _rpctx, _rname, _rnode_type, _rsize);
}

bool Engine::read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    return pimpl_->read(_pdesc->entry_ptr_, static_cast<char*>(_pbuf), _offset, _length, _rbytes_transfered);
}

// -- Implementation --------------------------------------------------------------------

bool Engine::Implementation::list(
    EntryPointerT& _rentry_ptr,
    void*&         _rpctx,
    std::wstring& _rname, NodeTypeE& _rnode_type, uint64_t& _rsize)
{
    using ContextT = pair<int, EntryMapT::const_iterator>;

    auto&              m{_rentry_ptr->mutex()};
    unique_lock<mutex> lock(m);
    ContextT*          pctx = nullptr;
    DirectoryData*     pdd  = _rentry_ptr->directoryData();

    if (_rpctx) {
        pctx = static_cast<ContextT*>(_rpctx);
    } else {
        pctx   = new pair<int, EntryMapT::const_iterator>(0, pdd->entry_map_.begin());
        _rpctx = pctx;
    }

    if (pctx->first == 0) {
        //L".";
        _rname      = L".";
        _rsize      = 0;
        _rnode_type = NodeTypeE::Directory;
        ++pctx->first;
        return true;
    } else if (pctx->first == 1) {
        //L"..";
        _rname      = L"..";
        _rsize      = 0;
        _rnode_type = NodeTypeE::Directory;
        ++pctx->first;
        return true;
    } else {

        while (pctx->second != pdd->entry_map_.end()) {
            const EntryPointerT& rentry_ptr = pctx->second->second;

            if (rentry_ptr->type_ == EntryTypeE::Unknown) {
                ++pctx->second;
                continue;
            }

            _rname       = utility::widen(pctx->second->second->name_);
            _rsize       = pctx->second->second->size_;
            const auto t = pctx->second->second->type_;
            _rnode_type  = t == EntryTypeE::Application || t == EntryTypeE::Directory ? NodeTypeE::Directory : NodeTypeE::File;
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

    FileData& rfile_data = *get<FileDataPointerT>(_rentry_ptr->data_var_);
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
    _rentry_ptr->conditionVariable().wait(lock, [&read_data]() { return read_data.done_; });

    if (rfile_data.status_ == FileData::ErrorE) {
        solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " error reading");
        return false;
    }

    _rbytes_transfered = read_data.bytes_transfered_;
    solid_log(logger, Verbose, "READ: " << _rentry_ptr.get() << " " << _offset << " " << _length << " " << _rbytes_transfered);
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
    FileData& rfile_data = *get<FileDataPointerT>(_rentry_ptr->data_var_);

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
    _ris.seekg(_rread_data.offset_ - _offset);
    _ris.read(_rread_data.pbuffer_, _size);
    uint64_t sz = _ris.gcount();
    _rread_data.offset_ += sz;
    _rread_data.pbuffer_ += sz;
    _rread_data.bytes_transfered_ += sz;
    _rread_data.size_ -= sz;
}

void FileData::writeToCache(const uint64_t _offset, istream& _ris)
{
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
    const FileData& rfile_data = *get<FileDataPointerT>(_rentry_ptr->data_var_);
    return (rfile_data.contiguous_read_count_ >= config_.min_contiguous_read_count_) && rfile_data.prefetch_offset_ < _rentry_ptr->size_;
}

void Engine::Implementation::tryPreFetch(EntryPointerT& _rentry_ptr)
{
    FileData& rfile_data = *get<FileDataPointerT>(_rentry_ptr->data_var_);
    size_t    fetch_index;
    if (canPreFetch(_rentry_ptr) && ((fetch_index = rfile_data.findAvailableFetchIndex()) != InvalidIndex())) {
        solid_log(logger, Verbose, _rentry_ptr.get() << " " << fetch_index << " " << rfile_data.prefetch_offset_);
        asyncFetch(_rentry_ptr, fetch_index, rfile_data.prefetch_offset_, 0);
    }
}

void Engine::Implementation::asyncFetch(EntryPointerT& _rentry_ptr, const size_t _fetch_index, const uint64_t _offset, uint64_t _size)
{
    solid_log(logger, Verbose, _rentry_ptr.get() << " " << _fetch_index << " " << _offset << " " << _size);
    FileData& rfile_data  = *get<FileDataPointerT>(_rentry_ptr->data_var_);
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
        FileDataPointerT* pfd = get_if<FileDataPointerT>(&entry_ptr->data_var_);
        if (pfd == nullptr) {
            return;
        }
        FileData& rfile_data  = *(*pfd);
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
    rfetch_stub.request_ptr_->storage_id_ = rfile_data.storage_id_;
    rfetch_stub.request_ptr_->offset_     = rfetch_stub.offset_;
    rfetch_stub.request_ptr_->size_       = rfetch_stub.size_;

    front_rpc_service_.sendRequest(config_.front_endpoint_.c_str(), rfetch_stub.request_ptr_, lambda);
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
        config_.gui_start_fnc_(gui_rpc_service_.configuration().server.listenerPort());
    }
}

void Engine::Implementation::tryAuthenticate(frame::mprpc::ConnectionContext& _ctx, const string* const _ptoken)
{
    string auth_token;
    getAuthToken(_ctx.recipientId(), auth_token, _ptoken);

    if (!auth_token.empty()) {
        auto req_ptr = std::make_shared<AuthRequest>(auth_token);
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
        tryAuthenticate(_ctx, &_rreq.auth_);
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
    frame::mprpc::ConnectionContext&   _rctx,
    std::shared_ptr<gui::AuthRequest>& _rrecv_msg_ptr,
    ErrorConditionT const&             _rerror)
{
    if (_rrecv_msg_ptr) {
        auto res_ptr = std::make_shared<gui::AuthResponse>(*_rrecv_msg_ptr);
        _rctx.service().sendResponse(_rctx.recipientId(), res_ptr);
    }
    if (_rrecv_msg_ptr && !_rrecv_msg_ptr->token_.empty()) {
        solid_log(logger, Info, "Success password authenticating user: " << _rrecv_msg_ptr->user_);
        auto req_ptr   = std::make_shared<front::AuthRequest>();
        req_ptr->auth_ = _rrecv_msg_ptr->token_;
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
    gui::RegisterRequest&            _rmsg)
{
    auto rsp_ptr = make_shared<gui::RegisterResponse>(_rmsg);
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
                          frame::mprpc::ConnectionContext&        _rctx,
                          std::shared_ptr<gui::RegisterResponse>& _rsent_msg_ptr,
                          std::shared_ptr<gui::AuthRequest>&      _rrecv_msg_ptr,
                          ErrorConditionT const&                  _rerror) {
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
        getline(ifs, auth_user_);
        getline(ifs, auth_token_);
        solid_log(logger, Info, "Loaded auth data from: " << path.generic_string() << " for user: " << auth_user_);
    } else {
        solid_log(logger, Error, "Failed loading auth data to: " << path.generic_string());
    }
}

void Engine::Implementation::storeAuthData(const string& _user, const string& _token)
{
    fs::create_directories(authDataDirectoryPath());
    const auto path = authDataFilePath();

    ofstream ofs(path.generic_string());
    if (ofs) {
        ofs << _user << endl;
        ofs << _token << endl;
        solid_log(logger, Info, "Stored auth data to: " << path.generic_string());
    } else {
        solid_log(logger, Error, "Failed storing auth data to: " << path.generic_string());
    }
}

void Engine::Implementation::remoteFetchApplication(
    std::shared_ptr<front::ListAppsResponse>&               _apps_response,
    std::shared_ptr<front::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
    size_t                                                  _app_index)
{
    _rsent_msg_ptr->app_id_ = _apps_response->app_id_vec_[_app_index];

    auto lambda = [this, _app_index, apps_response = std::move(_apps_response)](
                      frame::mprpc::ConnectionContext&                         _rctx,
                      std::shared_ptr<front::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                                   _rerror) mutable {
        if (_rrecv_msg_ptr) {
            insertApplicationEntry(_rrecv_msg_ptr);
            ++_app_index;
            if (_app_index < apps_response->app_id_vec_.size()) {
                remoteFetchApplication(apps_response, _rsent_msg_ptr, _app_index);
            }
        }
    };

    front_rpc_service_.sendRequest(config_.front_endpoint_.c_str(), _rsent_msg_ptr, lambda);
}

void Engine::Implementation::onFrontListAppsResponse(
    frame::mprpc::ConnectionContext&          _ctx,
    std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr)
{
    if (_rrecv_msg_ptr->app_id_vec_.empty()) {
        return;
    }

    auto req_ptr = make_shared<front::FetchBuildConfigurationRequest>();

    //TODO:
    req_ptr->lang_  = "US_en";
    req_ptr->os_id_ = "Windows10x86_64";

    remoteFetchApplication(_rrecv_msg_ptr, req_ptr, 0);
}

void Engine::Implementation::createRootEntry()
{
    root_entry_ptr_            = make_shared<Entry>(EntryTypeE::Directory, root_mutex_, cv_dq_[0], "");
    root_entry_ptr_->data_var_ = make_unique<DirectoryData>();
    root_entry_ptr_->status_   = EntryStatusE::Fetched;
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

void Engine::Implementation::insertApplicationEntry(std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr)
{
    auto entry_ptr = createEntry(
        root_entry_ptr_, _rrecv_msg_ptr->build_configuration_.directory_,
        EntryTypeE::Application);

    entry_ptr->remote_   = _rrecv_msg_ptr->storage_id_;
    entry_ptr->data_var_ = make_unique<ApplicationData>();

    if (!_rrecv_msg_ptr->build_configuration_.mount_vec_.empty()) {
#if 0
        entry_ptr->status_ = EntryStatusE::FetchRequired;
#else
        entry_ptr->status_ = EntryStatusE::Fetched;
        for (const auto& me : _rrecv_msg_ptr->build_configuration_.mount_vec_) {
            insertMountEntry(entry_ptr, me.first, me.second);
        }
#endif

    } else {
        entry_ptr->status_ = EntryStatusE::FetchRequired;
    }

    if (!_rrecv_msg_ptr->build_configuration_.shortcut_vec_.empty()) {
        for (const auto& sh : _rrecv_msg_ptr->build_configuration_.shortcut_vec_) {
            shortcut_creator_.create(
				sh.name_,
                _rrecv_msg_ptr->build_configuration_.directory_+ '\\' + sh.command_,
                "",
				sh.run_folder_,
				sh.icon_,
                ""
			);
		}
    }

    solid_log(logger, Info, entry_ptr->name_);

    auto&             rm = root_entry_ptr_->mutex();
    lock_guard<mutex> lock{rm};
    //TODO: also create coresponding shortcuts

    get<DirectoryDataPointerT>(root_entry_ptr_->data_var_)->insertEntry(std::move(entry_ptr));
}

EntryPointerT Engine::Implementation::createEntry(EntryPointerT& _rparent_ptr, const string& _name, const EntryTypeE _type, const uint64_t _size)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name << " " << _size);
    const size_t index = current_mutex_index_.fetch_add(1);
    return make_shared<Entry>(_type, _rparent_ptr, mutex_dq_[index % mutex_dq_.size()], cv_dq_[index % cv_dq_.size()], _name, _size);
}

void Engine::Implementation::insertDirectoryEntry(EntryPointerT& _rparent_ptr, const string& _name)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name);

    auto entry_ptr = _rparent_ptr->directoryData()->find(_name);

    if (!entry_ptr) {
        _rparent_ptr->directoryData()->insertEntry(createEntry(_rparent_ptr, _name, EntryTypeE::Directory));
    } else {
        //make sure the entry is directory
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::Directory;

        if (entry_ptr->directoryData() == nullptr) {
            entry_ptr->data_var_ = make_unique<DirectoryData>();
        }
    }
}

void Engine::Implementation::insertFileEntry(EntryPointerT& _rparent_ptr, const string& _name, uint64_t _size)
{
    solid_log(logger, Info, _rparent_ptr->name_ << " " << _name << " " << _size);

    auto entry_ptr = _rparent_ptr->directoryData()->find(_name);

    if (!entry_ptr) {
        _rparent_ptr->directoryData()->insertEntry(createEntry(_rparent_ptr, _name, EntryTypeE::File));
    } else {
        //make sure the entry is file
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::File;
        entry_ptr->size_ = _size;
        if (entry_ptr->directoryData() == nullptr) {
            entry_ptr->data_var_ = UniqueIdT{};
        }
    }
}

EntryPointerT Engine::Implementation::tryInsertUnknownEntry(EntryPointerT& _rparent_ptr, const string& _name)
{
    solid_log(logger, Info, _rparent_ptr->name_ << "->" << _name);

    if (!_rparent_ptr->canInsertUnkownEntry()) {
        return EntryPointerT{};
    }

    if (_rparent_ptr->directoryData() == nullptr) {
        _rparent_ptr->data_var_ = make_unique<DirectoryData>();
    }

    auto entry_ptr     = createEntry(_rparent_ptr, _name);
    entry_ptr->status_ = EntryStatusE::FetchRequired;
    _rparent_ptr->directoryData()->insertEntry(EntryPointerT(entry_ptr));
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
        entry_ptr->parent_.reset();
    }

    if (parent_ptr) {
        unique_lock<mutex> lock{parent_ptr->mutex()};
        if (parent_ptr->status_ != EntryStatusE::Fetched) {
            parent_ptr->erase(entry_ptr);

            if (parent_ptr->isErasable()) {
                eraseEntryFromParent(std::move(parent_ptr), std::move(lock));
            }
        }
    }
}

void Engine::Implementation::createEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq)
{
    solid_log(logger, Info, _path_str);
    if (_rnode_dq.size() == 1 && _rnode_dq.front().name_.empty()) {
        _rentry_ptr->type_ = EntryTypeE::File;
        _rentry_ptr->size_ = _rnode_dq.front().size_;

        _rentry_ptr->data_var_ = UniqueIdT{};
        return;
    }

    _rentry_ptr->data_var_ = make_unique<DirectoryData>();

    for (const auto& n : _rnode_dq) {
        //TODO: we do not create the EntryData here
        // so we must handle the situation in open(..)
        if (n.name_.back() == '/') {
            string name = n.name_;
            name.pop_back();
            insertDirectoryEntry(_rentry_ptr, name);
        } else {
            insertFileEntry(_rentry_ptr, n.name_, n.size_);
        }
    }
}

} //namespace service
} //namespace client
} //namespace ola
