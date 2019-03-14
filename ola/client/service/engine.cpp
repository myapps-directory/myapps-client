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

#include "ola/common/ola_front_protocol.hpp"
#include "ola/client/gui/gui_protocol.hpp"

using namespace solid;
using namespace std;
using namespace ola;
using namespace ola::front;

namespace ola {
namespace client {
namespace service {

namespace {
const solid::LoggerT logger("ola::client::service::engine");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;
} //namespace

struct Engine::Data {
    Configuration          config_;
    AioSchedulerT          scheduler_;
    frame::Manager         manager_;
    FunctionWorkPool<>     workpool_;
    frame::aio::Resolver   resolver_;
    frame::mprpc::ServiceT rpc_service_;
    frame::mprpc::ServiceT gui_rpc_service_;

public:
    Data(
        const Configuration& _rcfg)
        : config_(_rcfg)
        , workpool_{WorkPoolConfiguration()}
        , resolver_{workpool_}
        , rpc_service_{manager_}
        , gui_rpc_service_{manager_}
    {
    }
public:
    void onConnectionStart(frame::mprpc::ConnectionContext &_ctx);
    void onAuthResponse(frame::mprpc::ConnectionContext &_ctx, AuthResponse &_rresponse);

	void onGuiMessage(
        frame::mprpc::ConnectionContext&	_rctx,
        std::shared_ptr<gui::AuthMessage>&              _rsent_msg_ptr,
        std::shared_ptr<gui::AuthMessage>&              _rrecv_msg_ptr,
        ErrorConditionT const&             _rerror
	) {
	}
};

Engine::Engine() {}
Engine::~Engine(){}

namespace{

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
}//namespace


struct GuiProtocolSetup{
    Engine::Data &data_;
    GuiProtocolSetup(Engine::Data& _data)
        : data_(_data)
    {
    }

    template <class M>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<M> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        auto lambda = [&data_ = this->data_](
            frame::mprpc::ConnectionContext& _rctx,
            std::shared_ptr<M>&              _rsent_msg_ptr,
            std::shared_ptr<M>&              _rrecv_msg_ptr,
            ErrorConditionT const&           _rerror
        ){
            data_.onGuiMessage(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror);
        };
        _rprotocol.registerMessage<M>(lambda, _rtid);
    }
};

void Engine::start(const Configuration& _rcfg)
{
    pimpl_ = make_unique<Data>(_rcfg);
    
    pimpl_->scheduler_.start(1);

    {
        auto                        proto = ProtocolT::create();
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);

        front::protocol_setup(FrontProtocolSetup(), *proto);

        cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(pimpl_->resolver_, ola::front::default_port());

        cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;
        
        {
        auto connection_start_lambda = [this](frame::mprpc::ConnectionContext &_ctx){
                pimpl_->onConnectionStart(_ctx);
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
        
        if(_rcfg.compress_){
            frame::mprpc::snappy::setup(cfg);
        }

        pimpl_->rpc_service_.start(std::move(cfg));
    }

    {
        auto                        proto = gui::ProtocolT::create();
        frame::mprpc::Configuration cfg(pimpl_->scheduler_, proto);
        
        gui::protocol_setup(GuiProtocolSetup(*pimpl_), *proto);

        cfg.server.listener_address_str = "0.0.0.0:0";

        pimpl_->gui_rpc_service_.start(std::move(cfg));
    }

    auto err = pimpl_->rpc_service_.createConnectionPool(_rcfg.front_endpoint_.c_str(), 1);
    solid_check(!err, "creating connection pool: "<<err.message());
}

void Engine::stop()
{
    pimpl_.reset(nullptr);
}

// -- Data --------------------------------------------------------------------

void Engine::Data::onConnectionStart(frame::mprpc::ConnectionContext &_ctx){

}

void Engine::Data::onAuthResponse(frame::mprpc::ConnectionContext &_ctx, AuthResponse &_rresponse){

}

} //namespace service
} //namespace client
} //namespace ola
