#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "gui_auth_widget.hpp"


#include "solid/system/log.hpp"
#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/reactor.hpp"
#include "solid/frame/service.hpp"

#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"
#include "solid/frame/mprpc/mprpccompression_snappy.hpp"


#include "ola/common/utility/crypto.hpp"

#include "ola/common/ola_front_protocol.hpp"
#include "gui_protocol.hpp"

#include "boost/program_options.hpp"

#include <QtGui>
#include <QApplication>

#include <signal.h>

#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

#include <iostream>
#include <fstream>

using namespace ola;
using namespace solid;
using namespace std;

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;
using SchedulerT = frame::Scheduler<frame::Reactor>;

//-----------------------------------------------------------------------------
//      Parameters
//-----------------------------------------------------------------------------
namespace{
struct Parameters{
    vector<string>          dbg_modules;
    string                  dbg_addr;
    string                  dbg_port;
    bool                    dbg_console;
    bool                    dbg_buffered;

    bool                    secure;
    bool                    compress;
    bool                    auto_pilot;

    string                  front_endpoint;
    string                  local_endpoint;

    Parameters(){}

    bool parse(ULONG argc, PWSTR* argv);
};

void front_configure_service(const Parameters &_params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);
void local_configure_service(const Parameters &_params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);

}//namespace
//-----------------------------------------------------------------------------
//      main
//-----------------------------------------------------------------------------
#ifdef SOLID_ON_WINDOWS
int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow){
    int     wargc;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    int argc = 1;
    char *argv[1] = {GetCommandLineA()};
#else
int main(int argc, char *argv[]){
#endif
    Parameters params;
    
    if(params.parse(wargc, wargv)) return 0;
#if !defined(SOLID_ON_WINDOWS)
    signal(SIGPIPE, SIG_IGN);
#endif
    
    if (params.dbg_addr.size() && params.dbg_port.size()) {
        solid::log_start(
            params.dbg_addr.c_str(),
            params.dbg_port.c_str(),
            params.dbg_modules,
            params.dbg_buffered);

    } else if (params.dbg_console) {
        solid::log_start(std::cerr, params.dbg_modules);
    } else {
        solid::log_start(
            "ola_client_gui",
            params.dbg_modules,
            params.dbg_buffered,
            3,
            1024 * 1024 * 64);
    }


    QApplication                        app(argc, argv);

    AioSchedulerT                       aioscheduler;

    frame::Manager                      manager;
    frame::ServiceT                     service{manager};

    frame::mprpc::ServiceT              front_rpc_service{manager};
    frame::mprpc::ServiceT              local_rpc_service{manager};
    
    FunctionWorkPool<>                  fwp{WorkPoolConfiguration()};
    frame::aio::Resolver                resolver(fwp);

    ErrorConditionT                     err;
    
    client::gui::AuthWidget             auth_widget;

    aioscheduler.start(1);

    auth_widget.start();

    int rv = app.exec();

    return rv;
}

//-----------------------------------------------------------------------------
namespace{
bool Parameters::parse(ULONG argc, PWSTR* argv){
    using namespace boost::program_options;
    try{
        options_description desc("Bubbles client");
        desc.add_options()
            ("help,h", "List program options")
            ("debug-modules,M", value<vector<string>>(&dbg_modules),"Debug logging modules (e.g. \".*:EW\", \"\\*:VIEW\")")
            ("debug-address,A", value<string>(&dbg_addr), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&dbg_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&dbg_console)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-unbuffered,S", value<bool>(&dbg_buffered)->implicit_value(false)->default_value(true), "Debug unbuffered")

            ("front,f", value<std::string>(&front_endpoint)->required(), "Front Server endpoint: address:port")
            ("local,l", value<std::string>(&front_endpoint)->required(), "Local Server endpoint: address:port")
            ("secure,s", value<bool>(&secure)->implicit_value(true)->default_value(true), "Use SSL to secure communication")
            ("compress", value<bool>(&compress)->implicit_value(true)->default_value(true), "Use Snappy to compress communication")
            ("auto,a", value<bool>(&auto_pilot)->implicit_value(true)->default_value(true), "Auto randomly move the bubble")
        ;
        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            return true;
        }
        return false;
    }catch(exception& e){
        cout << e.what() << "\n";
        return true;
    }
}

//-----------------------------------------------------------------------------

template <class M>
void complete_message(
    frame::mprpc::ConnectionContext& _rctx,
    std::shared_ptr<M>&              _rsent_msg_ptr,
    std::shared_ptr<M>&              _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror)
{
    //solid_check(false); //this method should not be called
}

//-----------------------------------------------------------------------------
// Front
//-----------------------------------------------------------------------------
struct FrontSetup {
    template <class T>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<T> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<T>(complete_message<T>, _rtid);
    }
};
void front_configure_service(const Parameters &_params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres){
    auto                        proto = front::ProtocolT::create();
    frame::mprpc::Configuration cfg(_rsch, proto);

    front::protocol_setup(FrontSetup(), *proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, ola::front::default_port());

    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;
    
    {
//         auto connection_stop_lambda = [&_rctx](frame::mpipc::ConnectionContext &_ctx){
//             engine_ptr->onConnectionStop(_ctx);
//         };
        auto connection_start_lambda = [](frame::mprpc::ConnectionContext &_ctx){
            
        };
        //cfg.connection_stop_fnc = std::move(connection_stop_lambda);
        cfg.client.connection_start_fnc = std::move(connection_start_lambda);
    }

    if (_params.secure) {
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
    
    if(_params.compress){
        frame::mprpc::snappy::setup(cfg);
    }

    _rsvc.start(std::move(cfg));
}

//-----------------------------------------------------------------------------
// Front
//-----------------------------------------------------------------------------
struct LocalSetup {
    template <class T>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<T> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<T>(complete_message<T>, _rtid);
    }
};

void local_configure_service(const Parameters &_params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres){
    auto                        proto = client::gui::ProtocolT::create();
    frame::mprpc::Configuration cfg(_rsch, proto);

    client::gui::protocol_setup(LocalSetup(), *proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, "0");

    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Active;

    _rsvc.start(std::move(cfg));
}
}//namespace
