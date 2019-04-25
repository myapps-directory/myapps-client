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
#include "ola/common/ola_front_protocol.hpp"

#include "boost/filesystem.hpp"
#include <fstream>
#include <mutex>

using namespace solid;
using namespace std;
using namespace ola;
using namespace ola::front;
namespace bf = boost::filesystem;

namespace ola {
namespace client {
namespace service {

namespace {
const solid::LoggerT logger("ola::client::service::engine");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;
} //namespace

struct Engine::Implementation {
    using RecipientVectorT = std::vector<frame::mprpc::RecipientId>;

    Configuration             config_;
    AioSchedulerT             scheduler_;
    frame::Manager            manager_;
    FunctionWorkPool<>        workpool_;
    frame::aio::Resolver      resolver_;
    frame::mprpc::ServiceT    front_rpc_service_;
    frame::mprpc::ServiceT    gui_rpc_service_;
    mutex                     mutex_;
    string                    auth_user_;
    string                    auth_token_;
    RecipientVectorT          auth_recipient_v_;
    frame::mprpc::RecipientId gui_recipient_id_;

public:
    Implementation(
        const Configuration& _rcfg)
        : config_(_rcfg)
        , workpool_{WorkPoolConfiguration()}
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

private:
    void getAuthToken(const frame::mprpc::RecipientId& _recipient_id, string& _rtoken, const string* const _ptoken = nullptr);

    void tryAuthenticate(frame::mprpc::ConnectionContext& _ctx, const string* const _ptoken = nullptr);

    bf::path authDataDirectoryPath() const
    {
        bf::path p = config_.path_prefix_;
        p /= "config";
        return p;
    }

    bf::path authDataFilePath() const
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

bool Engine::entry(const EntryIdT& _entry_id, size_t& _rcrt, std::wstring& _rname, uint64_t& _rsize, EntryTypeE& _rentry_type)
{

    return false;
}
bool Engine::entry(const wchar_t* _path, EntryIdT& _entry_id)
{
    if (_path[0] == L'\\' && _path[1] == L'\0') {
        return true;
    }
    return false;
}
bool Engine::entry(const EntryIdT& _entry_id, uint64_t& _rsize, EntryTypeE& _rentry_type)
{
    if (_entry_id.empty()) {
        //root
        _rentry_type = EntryTypeE::Directory;
        _rsize       = 0;
        return true;
    } else if (_entry_id.size() == 1) {

    } else {
    }
    return false;
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
    bf::create_directories(authDataDirectoryPath());
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

} //namespace service
} //namespace client
} //namespace ola
