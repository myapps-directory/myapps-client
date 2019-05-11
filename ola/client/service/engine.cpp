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

#include "boost/filesystem.hpp"
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <unordered_map>

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
    Pending,
    Error,
    Directory,
    File,
    Application,
    Shortcut
};

struct Entry;
using EntryPointerT = std::shared_ptr<Entry>;

struct EntryData {
    virtual ~EntryData() {}

    bool isDirectory() const
    {
        const auto t = type();
        return t == EntryTypeE::Directory || t == EntryTypeE::Application;
    }

    virtual EntryTypeE type() const
    {
        return EntryTypeE::Unknown;
    }

    virtual void erase(const EntryPointerT& _rentry_ptr)
    {
    }

    virtual EntryPointerT find(const string& _path) const
    {
        return EntryPointerT{};
    }

    virtual bool read(void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
    {
        return false;
    }

    virtual bool node(void*& _rpctx, std::wstring& _rname, uint64_t& _rsize, NodeTypeE& _rnode_type)
    {
        return false;
    }

    virtual const std::string& storageId() const
    {
        static const string s;
        solid_throw("should not be called");
        return s;
    }

    virtual void insertEntry(EntryPointerT&& _entry)
    {
    }
};

using EntryDataPtrT = std::unique_ptr<EntryData>;

struct Entry {
    std::mutex&              rmutex_;
    std::condition_variable& rcv_;
    string                   name_;
    EntryDataPtrT            data_ptr_;
    EntryTypeE               type_ = EntryTypeE::Unknown;
    std::weak_ptr<Entry>     parent_;
    uint64_t                 size_ = 0;

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

    EntryPointerT find(const string& _path)
    {
        EntryPointerT entry_ptr;
        if (data_ptr_) {
            entry_ptr = data_ptr_->find(_path);
        }
        return entry_ptr;
    }

    void erase(const EntryPointerT& _rentry_ptr)
    {
        if (data_ptr_) {
            data_ptr_->erase(_rentry_ptr);
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

    void info(uint64_t& _rsize, NodeTypeE& _rnode_type)
    {
        _rsize = size_;
        switch (type_) {
        case EntryTypeE::Unknown:
        case EntryTypeE::Pending:
            solid_throw("Unknown entry type");
            break;
        case EntryTypeE::File:
            _rnode_type = NodeTypeE::File;
            break;
        case EntryTypeE::Application:
        case EntryTypeE::Directory:
            _rnode_type = NodeTypeE::Directory;
            break;
        }
    }

    bool node(void*& _rpctx, std::wstring& _rname, uint64_t& _rsize, NodeTypeE& _rnode_type)
    {
        solid_check(data_ptr_, "NO entry data");
        return data_ptr_->node(_rpctx, _rname, _rsize, _rnode_type);
    }

    bool read(void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
    {
        solid_check(data_ptr_, "NO entry data");
        return data_ptr_->read(_pbuf, _offset, _length, _rbytes_transfered);
    }

    const std::string& storageId()
    {
        static const std::string s;
        if (type_ == EntryTypeE::Application) {
            return data_ptr_->storageId();
        } else if (auto parent_ptr = parent_.lock()) {
            return parent_ptr->storageId();
        } else {
            return s;
        }
    }
};

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

using EntryMapT = std::unordered_map<const std::reference_wrapper<const string>, EntryPointerT, Hash, Equal>;

struct DirectoryData : EntryData {
    EntryMapT entry_map_;

    EntryTypeE type() const override
    {
        return EntryTypeE::Directory;
    }

    void erase(const EntryPointerT& _rentry_ptr)
    {
        auto it = entry_map_.find(_rentry_ptr->name_);
        if (it != entry_map_.end() && it->second == _rentry_ptr) {
            entry_map_.erase(it);
        }
    }

    EntryPointerT find(const string& _path) const override
    {
        auto it = entry_map_.find(_path);
        if (it != entry_map_.end()) {
            return it->second;
        }
        return EntryPointerT{};
    }

    void insertEntry(EntryPointerT&& _entry_ptr) override
    {
        entry_map_.emplace(_entry_ptr->name_, std::move(_entry_ptr));
    }

    bool node(void*& _rpctx, std::wstring& _rname, uint64_t& _rsize, NodeTypeE& _rnode_type) override
    {
        using ContextT = pair<int, EntryMapT::const_iterator>;
        ContextT* pctx = nullptr;
        if (_rpctx) {
            pctx = static_cast<ContextT*>(_rpctx);
        } else {
            pctx   = new pair<int, EntryMapT::const_iterator>(0, entry_map_.begin());
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
        } else if (pctx->second != entry_map_.end()) {
            _rname       = utility::widen(pctx->second->second->name_);
            _rsize       = pctx->second->second->size_;
            const auto t = pctx->second->second->type_;
            _rnode_type  = t == EntryTypeE::Application || t == EntryTypeE::Directory ? NodeTypeE::Directory : NodeTypeE::File;
            ++pctx->second;
            return true;
        }

        return false;
    }
};

struct FileData : EntryData {
    EntryTypeE type() const override
    {
        return EntryTypeE::File;
    }
};

struct ApplicationData : DirectoryData {
    string storage_id_;

    EntryTypeE type() const override
    {
        return EntryTypeE::Application;
    }

    const std::string& storageId() const override
    {
        return storage_id_;
    }
};

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;

} //namespace

struct Descriptor {
    void*         pdirectory_buffer_ = nullptr;
    EntryPointerT entry_ptr_;

    Descriptor(EntryPointerT&& _entry_ptr)
        : entry_ptr_(std::move(_entry_ptr))
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

public:
    Implementation(
        const Configuration& _rcfg)
        : config_(_rcfg)
        , workpool_{WorkPoolConfiguration{}, 1}
        , resolver_{workpool_}
        , front_rpc_service_{manager_}
        , gui_rpc_service_{manager_}
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

    EntryPointerT createEntry(EntryPointerT& _parent, const string& _name, const EntryTypeE _type = EntryTypeE::Unknown, const uint64_t _size = 0);

    EntryPointerT tryInsertUnknownEntry(EntryPointerT& _parent, const string& _path);

    void eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock);

    void createEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq);

    void insertDirectoryEntry(EntryPointerT& _parent, const string& _name);
    void insertFileEntry(EntryPointerT& _parent, const string& _name, uint64_t _size);

    void createFileEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str);
    void createDirectoryEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str);

    void createRootEntry();

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
            cfg.client.connection_start_fnc = std::move(connection_start_lambda);
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

        pimpl_->front_rpc_service_.sendRequest(_rcfg.front_endpoint_.c_str(), req_ptr, lambda);
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

Descriptor* Engine::open(const fs::path& _path)
{
    EntryPointerT      entry_ptr = pimpl_->root_entry_ptr_;
    mutex&             rmutex    = entry_ptr->mutex();
    unique_lock<mutex> lock{rmutex};
    auto               generic_path_str = _path.relative_path().generic_string();

    for (const auto& e : _path) {
        string        s  = e.generic_string();
        EntryPointerT ep = entry_ptr->find(s);

        if (!ep) {
            entry_ptr = pimpl_->tryInsertUnknownEntry(entry_ptr, s);
        } else {
            entry_ptr     = std::move(ep);
            mutex& rmutex = entry_ptr->mutex();
            lock.unlock(); //no overlapping locks
            unique_lock<mutex> tlock{rmutex};
            lock.swap(tlock);
        }
    }

    if (entry_ptr->type_ == EntryTypeE::Unknown) {
        entry_ptr->type_ = EntryTypeE::Unknown;

        auto lambda = [entry_ptr, &generic_path_str, this](
                          frame::mprpc::ConnectionContext&           _rctx,
                          std::shared_ptr<front::ListStoreRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::ListStoreResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                     _rerror) mutable {
            auto&             m = entry_ptr->mutex();
            lock_guard<mutex> lock{m};
            if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                this->pimpl_->createEntryData(entry_ptr, generic_path_str, _rrecv_msg_ptr->node_dq_);
            } else {
                entry_ptr->type_ = EntryTypeE::Error;
            }
            entry_ptr->conditionVariable().notify_all();
        };

        auto req_ptr         = make_shared<ListStoreRequest>();
        req_ptr->path_       = generic_path_str;
        req_ptr->storage_id_ = entry_ptr->storageId();

        pimpl_->front_rpc_service_.sendRequest(pimpl_->config_.front_endpoint_.c_str(), req_ptr, lambda);
    }

    if (entry_ptr->type_ == EntryTypeE::Pending) {
        entry_ptr->conditionVariable().wait(lock, [&entry_ptr]() { return entry_ptr->type_ != EntryTypeE::Pending; });
    }

    if (entry_ptr->type_ == EntryTypeE::Error) {
        pimpl_->eraseEntryFromParent(std::move(entry_ptr), std::move(lock));
        return nullptr;
    } else {
        solid_check(entry_ptr->type_ > EntryTypeE::Error);
        //success
        return new Descriptor(std::move(entry_ptr));
    }
}

void Engine::cleanup(Descriptor* _pdesc)
{
}

void Engine::close(Descriptor* _pdesc)
{
    delete _pdesc;
}

void Engine::info(Descriptor* _pdesc, uint64_t& _rsize, NodeTypeE& _rnode_type)
{
    auto&             m = _pdesc->entry_ptr_->mutex();
    lock_guard<mutex> lock(m);

    _pdesc->entry_ptr_->info(_rsize, _rnode_type);
}

bool Engine::node(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, uint64_t& _rsize, NodeTypeE& _rnode_type)
{
    auto&             m = _pdesc->entry_ptr_->mutex();
    lock_guard<mutex> lock(m);

    return _pdesc->entry_ptr_->node(_rpctx, _rname, _rsize, _rnode_type);
}

bool Engine::read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered)
{
    auto&             m = _pdesc->entry_ptr_->mutex();
    lock_guard<mutex> lock(m);

    return _pdesc->entry_ptr_->read(_pbuf, _offset, _length, _rbytes_transfered);
}

// -- Implementation --------------------------------------------------------------------

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
        for (const auto& recipient_id : recipient_v) {
            front_rpc_service_.sendMessage(recipient_id, req_ptr, {frame::mprpc::MessageFlagsE::AwaitResponse});
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

void Engine::Implementation::insertApplicationEntry(std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr)
{

}

void Engine::Implementation::remoteFetchApplication(
    std::shared_ptr<front::ListAppsResponse>&               _apps_response,
    std::shared_ptr<front::FetchBuildConfigurationRequest>& _rsent_msg_ptr,
    size_t                                                  _app_index)
{
    auto lambda = [this, _app_index, apps_response = std::move(_apps_response)](
                      frame::mprpc::ConnectionContext&                         _rctx,
                      std::shared_ptr<front::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                                   _rerror) mutable {
        if (_rrecv_msg_ptr) {
            insertApplicationEntry(_rrecv_msg_ptr);
            ++_app_index;
            if (_app_index < apps_response->app_id_vec_.size()) {
                remoteFetchApplication(apps_response, _rsent_msg_ptr, _app_index + 1);
            }
        }
    };

    _rsent_msg_ptr->app_id_ = _apps_response->app_id_vec_[_app_index];

    front_rpc_service_.sendRequest(config_.front_endpoint_.c_str(), _rsent_msg_ptr, lambda);
}

void Engine::Implementation::onFrontListAppsResponse(
    frame::mprpc::ConnectionContext&          _ctx,
    std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr)
{
    if (_rrecv_msg_ptr->app_id_vec_.empty()) {
        return;
    }

    auto req_ptr    = make_shared<front::FetchBuildConfigurationRequest>();
    req_ptr->lang_  = "";
    req_ptr->os_id_ = "Windows10x86_64";

    remoteFetchApplication(_rrecv_msg_ptr, req_ptr, 0);
}

void Engine::Implementation::createRootEntry()
{
    root_entry_ptr_            = make_shared<Entry>(EntryTypeE::Directory, mutex_dq_[0], cv_dq_[0], "");
    root_entry_ptr_->data_ptr_ = make_unique<DirectoryData>();
}

EntryPointerT Engine::Implementation::createEntry(EntryPointerT& _parent, const string& _name, const EntryTypeE _type, const uint64_t _size)
{
    const size_t index = current_mutex_index_.fetch_add(1);
    return make_shared<Entry>(_type, _parent, mutex_dq_[index % mutex_dq_.size()], cv_dq_[index % cv_dq_.size()], _name, _size);
}

void Engine::Implementation::insertDirectoryEntry(EntryPointerT& _parent_ptr, const string& _name)
{
    solid_check(_parent_ptr->data_ptr_ && _parent_ptr->data_ptr_->isDirectory());
    auto entry_ptr = _parent_ptr->data_ptr_->find(_name);

    if (!entry_ptr) {
        _parent_ptr->data_ptr_->insertEntry(createEntry(_parent_ptr, _name, EntryTypeE::Directory));
    } else {
        //make sure the entry is directory
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::Directory;
        if (entry_ptr->data_ptr_ && !entry_ptr->data_ptr_->isDirectory()) {
            entry_ptr->data_ptr_.reset();
        }
    }
}

void Engine::Implementation::insertFileEntry(EntryPointerT& _parent_ptr, const string& _name, uint64_t _size)
{
    solid_check(_parent_ptr->data_ptr_ && !_parent_ptr->data_ptr_->isDirectory());
    auto entry_ptr = _parent_ptr->data_ptr_->find(_name);

    if (!entry_ptr) {
        _parent_ptr->data_ptr_->insertEntry(createEntry(_parent_ptr, _name, EntryTypeE::File));
    } else {
        //make sure the entry is file
        auto&             rm = entry_ptr->mutex();
        lock_guard<mutex> lock{rm};
        entry_ptr->type_ = EntryTypeE::File;
        entry_ptr->size_ = _size;
        if (entry_ptr->data_ptr_ && entry_ptr->data_ptr_->isDirectory()) {
            entry_ptr->data_ptr_.reset();
        }
    }
}

EntryPointerT Engine::Implementation::tryInsertUnknownEntry(EntryPointerT& _parent, const string& _name)
{
    if (_parent->type_ >= EntryTypeE::Error) {
        return EntryPointerT{};
    }
    if (!_parent->data_ptr_) {
        _parent->data_ptr_ = make_unique<DirectoryData>();
    } else if (_parent->data_ptr_->isDirectory()) {
        return EntryPointerT{};
    }
    auto entry_ptr = createEntry(_parent, _name);
    _parent->data_ptr_->insertEntry(EntryPointerT(entry_ptr));
    return entry_ptr;
}

void Engine::Implementation::eraseEntryFromParent(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock)
{
    EntryPointerT entry_ptr{std::move(_uentry_ptr)};
    EntryPointerT parent_ptr;

    {
        unique_lock<mutex> lock{std::move(_ulock)};
        parent_ptr = entry_ptr->parent_.lock();
    }

    if (parent_ptr) {
        unique_lock<mutex> lock{parent_ptr->mutex()};
        parent_ptr->erase(entry_ptr);
    }
}

void Engine::Implementation::createFileEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str)
{
    //TODO: implement chaching
    _rentry_ptr->data_ptr_ = make_unique<FileData>();
}

void Engine::Implementation::createDirectoryEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str)
{
    //TODO: implement chaching
    _rentry_ptr->data_ptr_ = make_unique<DirectoryData>();
}

void Engine::Implementation::createEntryData(EntryPointerT& _rentry_ptr, const std::string& _path_str, ListNodeDequeT& _rnode_dq)
{
    if (_rnode_dq.size() == 1 && _rnode_dq.front().name_.empty()) {
        _rentry_ptr->type_ = EntryTypeE::File;
        _rentry_ptr->size_ = _rnode_dq.front().size_;

        createFileEntryData(_rentry_ptr, _path_str);
        return;
    }

    createDirectoryEntryData(_rentry_ptr, _path_str);

    for (const auto& n : _rnode_dq) {
        //TODO: we do not create the EntryData here
        // so we must handle the situation in open(..)
        if (n.name_.back() == '/') {
            insertDirectoryEntry(_rentry_ptr, n.name_);
        } else {
            insertFileEntry(_rentry_ptr, n.name_, n.size_);
        }
    }
}

} //namespace service
} //namespace client
} //namespace ola
