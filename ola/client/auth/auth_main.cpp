#undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif #undef UNICODE
#define UNICODE
#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "main_window.hpp"

#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"
#include "solid/system/log.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/reactor.hpp"
#include "solid/frame/service.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"

#include "ola/common/utility/encode.hpp"

#include "auth_protocol.hpp"
#include "ola/common/ola_front_protocol.hpp"

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#include <QApplication>
#include <QtGui>
#include <QStyleFactory>

#include <signal.h>

#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

#include <fstream>
#include <future>
#include <iostream>

using namespace ola;
using namespace solid;
using namespace std;

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;
using SchedulerT    = frame::Scheduler<frame::Reactor>;

//-----------------------------------------------------------------------------
//      Parameters
//-----------------------------------------------------------------------------
namespace {

const solid::LoggerT logger("ola::client::auth");

struct Parameters {
    vector<string> dbg_modules;
    string         dbg_addr;
    string         dbg_port;
    bool           dbg_console  = false;
    bool           dbg_buffered = false;
    bool           secure;
    bool           compress;
    string         front_endpoint;
    string         local_port;
    string         secure_prefix;

    Parameters() {}

    bool parse(ULONG argc, PWSTR* argv);

    string securePath(const string& _name) const
    {
        return secure_prefix + '/' + _name;
    }
};

struct Engine {
    client::auth::MainWindow&             main_window_;
    frame::mprpc::ServiceT&               front_rpc_service_;
    frame::mprpc::ServiceT&               local_rpc_service_;
    Parameters&                           params_;
    shared_ptr<client::auth::AuthRequest> local_auth_req_ptr_;
    frame::mprpc::RecipientId             local_recipient_id_;
    std::shared_ptr<front::AuthRequest>   front_auth_req_ptr_;
    frame::mprpc::RecipientId             front_recipient_id_;
    mutex                                 mutex_;
    string                                captcha_token_;

    Engine(
        client::auth::MainWindow&   _main_window,
        frame::mprpc::ServiceT& _front_rpc_service,
        frame::mprpc::ServiceT& _local_rpc_service,
        Parameters&             _params)
        : main_window_(_main_window)
        , front_rpc_service_(_front_rpc_service)
        , local_rpc_service_(_local_rpc_service)
        , params_(_params)
    {
    }

    void onConnectionInit(frame::mprpc::ConnectionContext& _ctx);
    void onConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onConnectionStop(frame::mprpc::ConnectionContext& _ctx);

    void onAuthStart(const string& _user, const string& _pass, const string& _code);

    void onCaptchaResponse(
        frame::mprpc::ConnectionContext& _rctx,
        std::shared_ptr<front::CaptchaRequest>&                _rsent_msg_ptr,
        std::shared_ptr<front::CaptchaResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                              _rerror);
    void onAuthResponse(
        frame::mprpc::ConnectionContext&      _rctx,
        std::shared_ptr<front::AuthRequest>&  _rsent_msg_ptr,
        std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                _rerror);

    bool localRegister(client::auth::MainWindow& _rwidget);
};

void front_configure_service(Engine& _rengine, const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);
void local_configure_service(const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);

//TODO: find a better name
string envLogPathPrefix()
{
    const char* v = getenv("LOCALAPPDATA");
    if (v == nullptr) {
        v = getenv("APPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\OLA\\client";
    return r;
}

} //namespace
//-----------------------------------------------------------------------------
//      main
//-----------------------------------------------------------------------------
#ifdef SOLID_ON_WINDOWS

string get_current_process_path()
{
    constexpr const size_t path_capacity = 2048;
    char                   path[path_capacity];
    solid_check(GetModuleFileNameA(nullptr, path, path_capacity) != 0, "Failed GetModuleFileName: " << last_system_error().message());
    return string(path);
}

QString get_qt_plugin_path() {
    boost::filesystem::path path = get_current_process_path();
    const string            p    = (path.parent_path() / "plugins").string();
    solid_log(logger, Info, "qt plugin path: "<<p);
    return QString::fromStdString(p);
}

int CALLBACK WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR pCmdLine, int nCmdShow)
{
    int     wargc;
    LPWSTR* wargv   = CommandLineToArgvW(GetCommandLineW(), &wargc);
    int     argc    = 1;
    char*   argv[1] = {GetCommandLineA()};


    {
        const auto m_singleInstanceMutex = CreateMutex(NULL, TRUE, L"OLA_AUTH_SHARED_MUTEX");
        if (m_singleInstanceMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
            HWND existingApp = FindWindow(0, L"MyApps.space");
            if (existingApp) {
                SetForegroundWindow(existingApp);
            }
            return -1; // Exit the app. For MFC, return false from InitInstance.
        }
    }
#else
int main(int argc, char* argv[])
{
#endif
    Parameters params;

    if (params.parse(wargc, wargv))
        return 0;
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
            (envLogPathPrefix() + "\\log\\auth").c_str(),
            params.dbg_modules,
            params.dbg_buffered,
            3,
            1024 * 1024 * 64);
    }

    qRegisterMetaType<ola::client::auth::CaptchaPointerT>("CaptchaPointerT");

    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);

    QApplication::addLibraryPath(get_qt_plugin_path());

    QApplication app(argc, argv);

    AioSchedulerT aioscheduler;

    frame::Manager  manager;
    frame::ServiceT service{manager};

    frame::mprpc::ServiceT front_rpc_service{manager};
    frame::mprpc::ServiceT local_rpc_service{manager};

    CallPool<void()>     cwp{WorkPoolConfiguration(), 1};
    frame::aio::Resolver resolver(cwp);

    client::auth::MainWindow main_window;
    Engine               engine(main_window, front_rpc_service, local_rpc_service, params);

    aioscheduler.start(1);

    local_configure_service(params, local_rpc_service, aioscheduler, resolver);

    solid_log(logger, Info, "try register on local service");

    if (!engine.localRegister(main_window)) {
        cout << "register failed" << endl;
        solid_log(logger, Info, "register failed");
        return 0;
    }
    
    main_window.setWindowIcon(QIcon(":/auth.ico"));
 
    main_window.start(
        [&engine](const std::string& _user, const std::string& _pass, const std::string &_code) {
            engine.onAuthStart(_user, ola::utility::sha256hex(_pass), _code);
        });

    SetWindowText(GetActiveWindow(), L"MyApps.space");

    front_configure_service(engine, params, front_rpc_service, aioscheduler, resolver);
    
    //app.setStyle("Fusion");
    const int rv = app.exec();
    front_rpc_service.stop();
    local_rpc_service.stop();
    return rv;
}

//-----------------------------------------------------------------------------
namespace {
bool Parameters::parse(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;
    try {
        options_description desc("ola_client_auth application");
        // clang-format off
		desc.add_options()
			("help,h", "List program options")
			("debug-modules,M", value<vector<string>>(&dbg_modules)->default_value(std::vector<std::string>{"ola::.*:VI=",".*:EWX"}, ""), "Debug logging modules (e.g. \".*:EW\", \"\\*:VIEWX\")")
			("debug-address,A", value<string>(&dbg_addr), "Debug server address (e.g. on linux use: nc -l 9999)")
			("debug-port,P", value<string>(&dbg_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
			("debug-console,C", value<bool>(&dbg_console)->implicit_value(true)->default_value(false), "Debug console")
			("debug-buffered,S", value<bool>(&dbg_buffered)->implicit_value(true)->default_value(false), "Debug unbuffered")
            ("front,f", value<std::string>(&front_endpoint)->required(), "Front Server endpoint: address:port")
			("local,l", value<std::string>(&local_port)->default_value(""), "Local Server Port")
			("unsecure", value<bool>(&secure)->implicit_value(false)->default_value(true), "Do not use SSL to secure communication")
			("compress", value<bool>(&compress)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("secure-prefix", value<std::string>(&secure_prefix)->default_value("certs"), "Secure Path prefix")
        ;
        // clang-format on
        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            return true;
        }
        return false;
    } catch (exception& e) {
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

void front_configure_service(Engine& _rengine, const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres)
{
    auto                        proto = front::ProtocolT::create();
    frame::mprpc::Configuration cfg(_rsch, proto);

    front::protocol_setup(FrontSetup(), *proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, ola::front::default_port());

    cfg.client.connection_start_state     = frame::mprpc::ConnectionState::Passive;
    cfg.pool_max_active_connection_count  = 1;
    cfg.pool_max_pending_connection_count = 1;

    {
        auto connection_stop_lambda = [&_rengine](frame::mprpc::ConnectionContext& _ctx) {
            _rengine.onConnectionStop(_ctx);
        };
        auto connection_start_lambda = [&_rengine](frame::mprpc::ConnectionContext& _ctx) {
            _rengine.onConnectionStart(_ctx);
        };
        cfg.connection_stop_fnc         = std::move(connection_stop_lambda);
        cfg.client.connection_start_fnc = std::move(connection_start_lambda);
    }

    if (_params.secure) {
        frame::mprpc::openssl::setup_client(
            cfg,
            [_params](frame::aio::openssl::Context& _rctx) -> ErrorCodeT {
                _rctx.loadVerifyFile(_params.securePath("ola-ca-cert.pem").c_str());
                _rctx.loadCertificateFile(_params.securePath("ola-client-front-cert.pem").c_str());
                _rctx.loadPrivateKeyFile(_params.securePath("ola-client-front-key.pem").c_str());
                return ErrorCodeT();
            },
            frame::mprpc::openssl::NameCheckSecureStart{"ola-server"});
    }

    if (_params.compress) {
        frame::mprpc::snappy::setup(cfg);
    }

    _rsvc.start(std::move(cfg));
    _rsvc.createConnectionPool(_params.front_endpoint.c_str(), 1);
}

//-----------------------------------------------------------------------------
// Local
//-----------------------------------------------------------------------------
struct LocalSetup {
    template <class T>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<T> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<T>(complete_message<T>, _rtid);
    }
};

void local_configure_service(const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres)
{
    auto                        proto = client::auth::ProtocolT::create();
    frame::mprpc::Configuration cfg(_rsch, proto);

    client::auth::protocol_setup(LocalSetup(), *proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, _params.local_port.c_str());

    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Active;

    {
        auto connection_stop_lambda = [](frame::mprpc::ConnectionContext& _ctx) {
            QApplication::quit();
        };

        cfg.connection_stop_fnc = std::move(connection_stop_lambda);
    }

    _rsvc.start(std::move(cfg));
}

bool Engine::localRegister(client::auth::MainWindow& _rwidget)
{
    if (params_.local_port.empty()) {
        return true;
    }
    promise<bool> prom;

    auto msg_ptr = make_shared<client::auth::RegisterRequest>();
    auto lambda  = [this, &prom, &_rwidget](
                      frame::mprpc::ConnectionContext&                 _rctx,
                      std::shared_ptr<client::auth::RegisterRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<client::auth::RegisterResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                           _rerror) {
        if (_rrecv_msg_ptr) {
            if (_rrecv_msg_ptr->error_) {
                prom.set_value(false);
            } else {

                local_auth_req_ptr_ = std::make_shared<client::auth::AuthRequest>(*_rrecv_msg_ptr);
                local_recipient_id_ = _rctx.recipientId();
                _rwidget.setUser(_rrecv_msg_ptr->user_);
                prom.set_value(true);
            }
        } else {
            prom.set_value(false);
        }
    };
    local_rpc_service_.sendRequest("127.0.0.1", msg_ptr, lambda, {frame::mprpc::MessageFlagsE::OneShotSend});
    auto fut = prom.get_future();
    return /*fut.wait_for(chrono::seconds(10)) == future_status::ready &&*/ fut.get();
}

void Engine::onAuthStart(const string& _user, const string& _pass, const string &_code)
{
    //on gui thread
    {
        lock_guard<mutex> lock(mutex_);
        front_auth_req_ptr_ = std::make_shared<front::AuthRequest>();
        front_auth_req_ptr_->captcha_text_ = _code;
        front_auth_req_ptr_->captcha_token_ = captcha_token_;
        front_auth_req_ptr_->user_          = _user;
        front_auth_req_ptr_->pass_          = _pass;

        if (!front_recipient_id_.empty()) {
            auto lambda = [this](
                              frame::mprpc::ConnectionContext&      _rctx,
                              std::shared_ptr<front::AuthRequest>&  _rsent_msg_ptr,
                              std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                _rerror) {
                onAuthResponse(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror);
            };
            if (!front_rpc_service_.sendRequest(front_recipient_id_, front_auth_req_ptr_, lambda)) {
                front_auth_req_ptr_.reset();
            }
        }
    }
}

void Engine::onConnectionStart(frame::mprpc::ConnectionContext& _ctx)
{
    auto req_ptr = std::make_shared<front::InitRequest>();
    auto lambda  = [this](
                      frame::mprpc::ConnectionContext&      _rctx,
                      std::shared_ptr<front::InitRequest>&  _rsent_msg_ptr,
                      std::shared_ptr<front::InitResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                _rerror) {
        if (_rrecv_msg_ptr) {
            if (_rrecv_msg_ptr->error_ == 0) {
                onConnectionInit(_rctx);
            } else {
                cout << "ERROR initiating connection: version " << _rctx.peerVersionMajor() << '.' << _rctx.peerVersionMinor() << " error " << _rrecv_msg_ptr->error_ << ':' << _rrecv_msg_ptr->message_ << endl;
            }
        }
    };

    _ctx.service().sendRequest(_ctx.recipientId(), req_ptr, lambda);
}

void Engine::onConnectionInit(frame::mprpc::ConnectionContext& _ctx)
{
    main_window_.onlineSignal(true);
    {
        lock_guard<mutex> lock(mutex_);
        front_recipient_id_ = _ctx.recipientId();

        auto req_ptr = std::make_shared<front::CaptchaRequest>();

        auto lambda = [this](
                          frame::mprpc::ConnectionContext&         _rctx,
                          std::shared_ptr<front::CaptchaRequest>&  _rsent_msg_ptr,
                          std::shared_ptr<front::CaptchaResponse>& _rrecv_msg_ptr,
                          ErrorConditionT const&                   _rerror) {
            onCaptchaResponse(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror);
        };

        _ctx.service().sendRequest(_ctx.recipientId(), req_ptr, lambda);
    }
}
void Engine::onConnectionStop(frame::mprpc::ConnectionContext& _ctx)
{
    main_window_.onlineSignal(false);
    {
        lock_guard<mutex> lock(mutex_);
        if (front_recipient_id_ == _ctx.recipientId()) {
            front_recipient_id_.clear();
        }
    }
}

void Engine::onCaptchaResponse(
    frame::mprpc::ConnectionContext&         _rctx,
    std::shared_ptr<front::CaptchaRequest>&  _rsent_msg_ptr,
    std::shared_ptr<front::CaptchaResponse>& _rrecv_msg_ptr,
    ErrorConditionT const&                   _rerror)
{
    if (_rrecv_msg_ptr && !_rrecv_msg_ptr->captcha_image_.empty() && !_rrecv_msg_ptr->captcha_token_.empty()) {
        lock_guard<mutex> lock(mutex_);
        captcha_token_ = std::move(_rrecv_msg_ptr->captcha_token_);
        main_window_.onCaptcha(std::move(_rrecv_msg_ptr->captcha_image_));
    } else {
        this_thread::sleep_for(chrono::seconds(2));
    }
}

void Engine::onAuthResponse(
    frame::mprpc::ConnectionContext&      _rctx,
    std::shared_ptr<front::AuthRequest>&  _rsent_msg_ptr,
    std::shared_ptr<front::AuthResponse>& _rrecv_msg_ptr,
    ErrorConditionT const&                _rerror)
{
    if (_rrecv_msg_ptr) {
        solid_log(logger, Info, "AuthResponse: " << _rrecv_msg_ptr->error_ << " " << _rrecv_msg_ptr->message_);
        if (_rrecv_msg_ptr->error_) {
            main_window_.authFailSignal();
            this_thread::sleep_for(chrono::seconds(2));
            onConnectionInit(_rctx);
        } else {
            main_window_.authSuccessSignal();
            if (!params_.local_port.empty()) {

                local_auth_req_ptr_->user_  = _rsent_msg_ptr->user_;
                local_auth_req_ptr_->token_ = _rrecv_msg_ptr->message_;
                auto lambda                 = [this](
                                  frame::mprpc::ConnectionContext&             _rctx,
                                  std::shared_ptr<client::auth::AuthRequest>&  _rsent_msg_ptr,
                                  std::shared_ptr<client::auth::AuthResponse>& _rrecv_msg_ptr,
                                  ErrorConditionT const&                       _rerror) {
                    main_window_.closeSignal();
                };

                if (local_rpc_service_.sendMessage(
                        local_recipient_id_,
                        local_auth_req_ptr_,
                        lambda,
                        {frame::mprpc::MessageFlagsE::AwaitResponse, frame::mprpc::MessageFlagsE::Response})) {
                    main_window_.closeSignal();
                }
            } else {
            }
        }
    } else {
        solid_log(logger, Info, "No AuthResponse");
        //offline

        {
            lock_guard<mutex> lock(mutex_);
            front_auth_req_ptr_ = std::move(_rsent_msg_ptr);
        }
    }
}

} //namespace
