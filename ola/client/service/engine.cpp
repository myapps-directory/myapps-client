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
#include <fstream>
#include <mutex>

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

    virtual EntryPointerT find(const fs::path& _path)
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
};

using EntryDataPtrT = std::unique_ptr<EntryData>;

struct Entry {
    std::mutex&              rmutex_;
    std::condition_variable& rcv_;
    string                   name_;
    EntryDataPtrT            data_ptr_;
    EntryTypeE               type_    = EntryTypeE::Unknown;
    Entry*                   pparent_ = nullptr;
    uint64_t                 size_    = 0;

    Entry(std::mutex& _rmutex, std::condition_variable& _rcv)
        : rmutex_(_rmutex)
        , rcv_(_rcv)
    {
    }

    EntryPointerT find(const fs::path& _path)
    {
        EntryPointerT entry_ptr;
        if (data_ptr_) {
            entry_ptr = data_ptr_->find(_path);
        }
        return entry_ptr;
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
        if (type_ == EntryTypeE::Application) {
            return data_ptr_->storageId();
        } else {
            solid_check(pparent_ != nullptr);
            return pparent_->storageId();
        }
    }
};

struct DirectoryData : EntryData {
};

struct ApplicationData : DirectoryData {
    string storage_id_;

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

    EntryPointerT createEntry(EntryPointerT& _parent, const fs::path& _path);

    void eraseEntry(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock);

    void createEntryData(const EntryPointerT& _rentry_ptr, ListNodeDequeT &_rnode_dq);

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
    unique_lock<mutex> lock{entry_ptr->mutex()};

    for (const auto& e : _path) {
        EntryPointerT ep = entry_ptr->find(e);

        if (!ep) {
            entry_ptr = pimpl_->createEntry(entry_ptr, e);
        } else {
            entry_ptr = std::move(ep);
            lock      = unique_lock<mutex>(entry_ptr->mutex());
        }
    }

    if (entry_ptr->type_ == EntryTypeE::Unknown) {
        entry_ptr->type_ = EntryTypeE::Unknown;

        auto lambda = [entry_ptr, this](
                          frame::mprpc::ConnectionContext&           _rctx,
                          std::shared_ptr<front::ListStoreRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::ListStoreResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                     _rerror) {
            auto&             m = entry_ptr->mutex();
            lock_guard<mutex> lock{m};
            if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                this->pimpl_->createEntryData(entry_ptr, _rrecv_msg_ptr->node_dq_);
            } else {
                entry_ptr->type_ = EntryTypeE::Error;
            }
            entry_ptr->conditionVariable().notify_all();
        };

        auto req_ptr         = make_shared<ListStoreRequest>();
        req_ptr->path_       = _path.relative_path().generic_string();
        req_ptr->storage_id_ = entry_ptr->storageId();

        pimpl_->front_rpc_service_.sendRequest(pimpl_->config_.front_endpoint_.c_str(), req_ptr, lambda);
    }

    if (entry_ptr->type_ == EntryTypeE::Pending) {
        entry_ptr->conditionVariable().wait(lock, [&entry_ptr]() { return entry_ptr->type_ != EntryTypeE::Pending; });
    }

    if (entry_ptr->type_ == EntryTypeE::Error) {
        pimpl_->eraseEntry(std::move(entry_ptr), std::move(lock));
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

void Engine::Implementation::onFrontListAppsResponse(
    frame::mprpc::ConnectionContext&          _ctx,
    std::shared_ptr<front::ListAppsResponse>& _rrecv_msg_ptr)
{
}

EntryPointerT Engine::Implementation::createEntry(EntryPointerT& _parent, const fs::path& _path)
{
    return EntryPointerT{};
}

void Engine::Implementation::eraseEntry(EntryPointerT&& _uentry_ptr, unique_lock<mutex>&& _ulock) {
}

void Engine::Implementation::createEntryData(const EntryPointerT& _rentry_ptr, ListNodeDequeT& _rnode_dq)
{

}
} //namespace service
} //namespace client
} //namespace ola
