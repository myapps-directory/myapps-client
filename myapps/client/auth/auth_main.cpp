// myapps/client/auth/auth_main.cpp

// This file is part of MyApps.directory project
// Copyright (C) 2020, 2021, 2022, 2023, 2024, 2025 Valentin Palade (vipalade @ gmail . com)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

#include "solid/system/exception.hpp"
#include "solid/system/log.hpp"
#include "solid/utility/string.hpp"

#include "solid/utility/threadpool.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/reactor.hpp"
#include "solid/frame/service.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcprotocol_serialization_v3.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"

#include "myapps/common/utility/encode.hpp"
#include "myapps/common/utility/version.hpp"

#include "myapps/client/utility/auth_file.hpp"
#include "myapps/client/utility/locale.hpp"

#include "myapps/common/front_protocol_auth.hpp"
#include "myapps/common/front_protocol_main.hpp"

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"

#include <QApplication>
#include <QStyleFactory>
#include <QtGui>

#include <signal.h>

#include <wtsapi32.h>
#pragma comment(lib, "wtsapi32.lib")
#include <userenv.h>
#pragma comment(lib, "userenv.lib")

#include <fstream>
#include <future>
#include <iostream>

using namespace myapps;
using namespace solid;
using namespace std;

namespace fs = boost::filesystem;

//-----------------------------------------------------------------------------
//      Parameters
//-----------------------------------------------------------------------------
namespace {
constexpr string_view service_name("myapps_auth");
const solid::LoggerT  logger("myapps::client::auth");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor<frame::mprpc::EventT>>;
using SchedulerT    = frame::Scheduler<frame::Reactor<Event<32>>>;
using CallPoolT     = ThreadPool<Function<void()>, Function<void()>>;

struct Parameters {
    vector<string> debug_modules;
    string         debug_addr;
    string         debug_port;
    bool           debug_console  = false;
    bool           debug_buffered = false;
    bool           secure;
    bool           compress;
    string         front_endpoint;
    string         secure_prefix;
    string         path_prefix;

    string securePath(const string& _name) const
    {
        return secure_prefix + '/' + _name;
    }
    string configPath(const string& _path_prefix) const;

    bool                                  parse(ULONG argc, PWSTR* argv);
    boost::program_options::variables_map bootstrapCommandLine(ULONG argc, PWSTR* argv);
    void                                  writeConfigurationFile(string _path, const boost::program_options::options_description& _od, const boost::program_options::variables_map& _vm) const;
};

struct Engine {
    client::auth::MainWindow& main_window_;
    frame::mprpc::ServiceT&   front_rpc_service_;
    Parameters&               params_;
    frame::mprpc::RecipientId front_recipient_id_;
    mutex                     mutex_;
    string                    captcha_token_;
    string                    auth_token_;
    string                    auth_login_;
    string                    auth_endpoint_;
    string                    auth_user_;
    string                    auth_email_;

    Engine(
        client::auth::MainWindow& _main_window,
        frame::mprpc::ServiceT&   _front_rpc_service,
        Parameters&               _params)
        : main_window_(_main_window)
        , front_rpc_service_(_front_rpc_service)
        , params_(_params)
    {
    }

    fs::path authDataDirectoryPath() const
    {
        fs::path p = params_.path_prefix;
        p /= "config";
        return p;
    }

    fs::path authDataFilePath() const
    {
        return authDataDirectoryPath() / "auth.data";
    }

    void onConnectionInit(frame::mprpc::ConnectionContext& _ctx);
    void onConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onConnectionStop(frame::mprpc::ConnectionContext& _ctx);

    bool onAuthStart(const string& _user, const string& _pass, const string& _code);
    bool onCreateStart(const string& _user, const string& _email, const string& _pass, const string& _code);
    bool onAmendStart(string _user, string _email, const string& _pass, const string& _new_pass);
    bool onValidateStart(const string& _code);
    bool onAuthFetchStart();
    bool onDeleteAccountStart(const string& _pass, const string& _reason);

    void onCaptchaResponse(
        frame::mprpc::ConnectionContext&                             _rctx,
        frame::mprpc::MessagePointerT<front::auth::CaptchaRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<front::auth::CaptchaResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                                       _rerror);
    void onAuthResponse(
        frame::mprpc::ConnectionContext&                          _rctx,
        frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                                    _rerror);
    void onDeleteAccountResponse(
        frame::mprpc::ConnectionContext&                      _rctx,
        frame::mprpc::MessagePointerT<front::core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                                _rerror);
    void loadAuthData();
    void storeAuthData();

    bool logout();

    bool passwordForgot(const string& _login, const string& _code);
    bool passwordReset(const string& _token, const string& _pass, const string& _code);
};

void front_configure_service(Engine& _rengine, const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);

// TODO: find a better name
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
    r += "\\MyApps.dir\\client";
    return r;
}
string env_config_path_prefix()
{
    const char* v = getenv("APPDATA");
    if (v == nullptr) {
        v = getenv("LOCALAPPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\MyApps.dir";
    return r;
}

} // namespace
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

QString get_qt_plugin_path()
{
    boost::filesystem::path path = get_current_process_path();
    const string            p    = (path.parent_path() / "plugins").string();
    solid_log(logger, Info, "qt plugin path: " << p);
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
            HWND existingApp = FindWindow(0, L"MyApps.directory");
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

    if (!params.parse(wargc, wargv))
        return 0;
#if !defined(SOLID_ON_WINDOWS)
    signal(SIGPIPE, SIG_IGN);
#endif

    if (params.debug_addr.size() && params.debug_port.size()) {
        solid::log_start(
            params.debug_addr.c_str(),
            params.debug_port.c_str(),
            params.debug_modules,
            params.debug_buffered);

    } else if (params.debug_console) {
        solid::log_start(std::cerr, params.debug_modules);
    } else {
        solid::log_start(
            (envLogPathPrefix() + "\\log\\auth").c_str(),
            params.debug_modules,
            params.debug_buffered,
            3,
            1024 * 1024 * 64);
    }

    qRegisterMetaType<myapps::client::auth::CaptchaPointerT>("CaptchaPointerT");

    // QApplication::setHighDpiScaleFactorRoundingPolicy(Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);
    // QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    // QApplication::setAttribute(Qt::AA_DisableHighDpiScaling);
    // SetProcessDPIAware();
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    QApplication::addLibraryPath(get_qt_plugin_path());

    QApplication app(argc, argv);

    app.setStyle("fusion");

    AioSchedulerT aioscheduler;

    frame::Manager  manager;
    frame::ServiceT service{manager};

    frame::mprpc::ServiceT front_rpc_service{manager};

    CallPoolT            cwp{{1, 1000, 0}, [](const size_t) {}, [](const size_t) {}};
    frame::aio::Resolver resolver([&cwp](std::function<void()>&& _fnc) { cwp.pushOne(std::move(_fnc)); });

    client::auth::MainWindow main_window;
    Engine                   engine(main_window, front_rpc_service, params);

    aioscheduler.start(1);

    main_window.setWindowIcon(QIcon(":/auth.ico"));

    engine.loadAuthData();

    {
        client::auth::Configuration config;
        config.authenticate_fnc_ = [&engine](const string& _user, const string& _pass, const string& _code) {
            return engine.onAuthStart(_user, _pass.empty() ? _pass : myapps::utility::hex_encode(myapps::utility::sha256(_pass)), _code);
        };
        config.create_fnc_ = [&engine](const string& _user, const string& _email, const string& _pass, const string& _code) {
            return engine.onCreateStart(_user, _email, myapps::utility::hex_encode(myapps::utility::sha256(_pass)), _code);
        };

        config.amend_fnc_ = [&engine](const string& _user, const string& _email, const string& _pass, const string& _new_pass) {
            return engine.onAmendStart(_user, _email, myapps::utility::hex_encode(myapps::utility::sha256(_pass)), _new_pass.empty() ? _new_pass : myapps::utility::hex_encode(myapps::utility::sha256(_pass)));
        };

        config.delete_account_fnc_ = [&engine](const string& _pass, const string& _reason) {
            return engine.onDeleteAccountStart(myapps::utility::hex_encode(myapps::utility::sha256(_pass)), _reason);
        };

        config.validate_fnc_ = [&engine](const string& _code) {
            return engine.onValidateStart(_code);
        };

        config.resend_validate_fnc_ = [&engine]() {
            return engine.onValidateStart("");
        };

        config.auth_fetch_fnc_ = [&engine]() {
            return engine.onAuthFetchStart();
        };

        config.logout_fnc_ = [&engine]() {
            return engine.logout();
        };

        config.forgot_fnc_ = [&engine](const string& _login, const string& _code) {
            return engine.passwordForgot(_login, _code);
        };

        config.reset_fnc_ = [&engine](const string& _token, const string& _pass, const string& _code) {
            return engine.passwordReset(_token, myapps::utility::hex_encode(myapps::utility::sha256(_pass)), _code);
        };

        config.login_ = QString::fromStdString(engine.auth_login_);

        main_window.start(std::move(config));
    }

    SetWindowText(GetActiveWindow(), L"MyApps.directory");

    front_configure_service(engine, params, front_rpc_service, aioscheduler, resolver);
    {
        HWND existingApp = FindWindow(0, L"MyApps.directory");
        if (existingApp) {
            SetForegroundWindow(existingApp);
        }
    }
    // app.setStyle("Fusion");
    const int rv = app.exec();
    front_rpc_service.stop();
    return rv;
}

//-----------------------------------------------------------------------------

namespace std {
std::ostream& operator<<(std::ostream& os, const std::vector<string>& vec)
{
    for (auto item : vec) {
        os << item << ",";
    }
    return os;
}
} // namespace std

//-----------------------------------------------------------------------------

namespace {

//-----------------------------------------------------------------------------
// Parameters
//-----------------------------------------------------------------------------
string Parameters::configPath(const std::string& _path_prefix) const
{
    return _path_prefix + "\\config\\" + string(service_name) + ".config";
}
//-----------------------------------------------------------------------------
boost::program_options::variables_map Parameters::bootstrapCommandLine(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;
    boost::program_options::options_description desc{"Bootstrap Options"};
    // clang-format off
    desc.add_options()
        ("version,v", "Version string")
        ("help,h", "Help Message")
        ("config,c", value<string>(), "Configuration File Path")
        ("generate-config", value<bool>()->implicit_value(true)->default_value(false), "Write configuration file and exit")
        ;
    // clang-format off
    variables_map vm;
    store(basic_command_line_parser(argc, argv).options(desc).allow_unregistered().run(), vm);
    notify(vm);
    return vm;
}


bool Parameters::parse(ULONG argc, PWSTR* argv)
{
    using namespace boost::program_options;
    try {
        string              config_file_path;
        bool                generate_config_file;
        options_description generic(string(service_name) + " generic options");
        // clang-format off
        generic.add_options()
            ("version,v", "Version string")
            ("help,h", "Help Message")
            ("config,c", value<string>(&config_file_path), "Configuration File Path")
            ("generate-config", value<bool>(&generate_config_file)->implicit_value(true)->default_value(false), "Write configuration file and exit")
            ;
        // clang-format on
        options_description config(string(service_name) + " configuration options");
        // clang-format off
        config.add_options()
            ("debug-modules,M", value<std::vector<std::string>>(&this->debug_modules)->default_value(std::vector<std::string>{"myapps::.*:VIEW", ".*:EWX"}), "Debug logging modules")
            ("debug-address,A", value<string>(&debug_addr)->default_value(""), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&debug_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&debug_console)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-buffered,S", value<bool>(&this->debug_buffered)->implicit_value(true)->default_value(true), "Debug unbuffered")
            ("secure,s", value<bool>(&secure)->implicit_value(true)->default_value(true), "Use SSL to secure communication")
            ("compress", value<bool>(&compress)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("secure-prefix", value<std::string>(&secure_prefix)->default_value("certs"), "Secure Path prefix")
            ("path-prefix", value<std::string>(&path_prefix)->default_value(env_config_path_prefix()), "Path prefix")
            ("front,f", value<std::string>(&front_endpoint)->default_value(string(MYAPPS_FRONT_URL)), "MyApps.directory Front Endpoint")
            ;
        // clang-format off

        options_description cmdline_options;
        cmdline_options.add(generic).add(config);

        options_description config_file_options;
        config_file_options.add(config);

        options_description visible("Allowed options");
        visible.add(generic).add(config);

        variables_map vm;
        store(basic_command_line_parser(argc, argv).options(cmdline_options).run(), vm);

        auto bootstrap = bootstrapCommandLine(argc, argv);

        if (bootstrap.count("help") != 0u) {
            cout << visible << endl;
            return false;
        }

        if (bootstrap.count("version") != 0u) {
            cout << myapps::utility::version_full() << endl;
            cout << "SolidFrame: " << solid::version_full() << endl;
            return false;
        }

        string cfg_path;

        if (bootstrap.count("config")) {
            cfg_path = bootstrap["config"].as<std::string>();
        }

        if (cfg_path.empty()) {
            string prefix;
            if (bootstrap.count("path-prefix")) {
                prefix = bootstrap["path-prefix"].as<std::string>();
            }
            else {
                prefix = env_config_path_prefix();
            }
            cfg_path = configPath(prefix);
        }

        generate_config_file = bootstrap["generate-config"].as<bool>();

        if (generate_config_file) {
            writeConfigurationFile(cfg_path, config_file_options, vm);
            return false;
        }

        if (!cfg_path.empty()) {
            ifstream ifs(cfg_path);
            if (!ifs) {
                cout << "cannot open config file: " << cfg_path << endl;
                if (bootstrap.count("config")) {
                    //exit only if the config path was explicitly given
                    return false;
                }
            }
            else {
                store(parse_config_file(ifs, config_file_options), vm);
            }
        }

        notify(vm);
    }
    catch (exception& e) {
        cout << e.what() << "\n";
        return false;
    }
    return true;
}
//-----------------------------------------------------------------------------
void write_value(std::ostream& _ros, const string& _name, const boost::any& _rav)
{
    if (_rav.type() == typeid(bool)) {
        _ros << _name << '=' << boost::any_cast<bool>(_rav) << endl;
    }
    else if (_rav.type() == typeid(uint16_t)) {
        _ros << _name << '=' << boost::any_cast<uint16_t>(_rav) << endl;
    }
    else if (_rav.type() == typeid(uint32_t)) {
        _ros << _name << '=' << boost::any_cast<uint32_t>(_rav) << endl;
    }
    else if (_rav.type() == typeid(uint64_t)) {
        _ros << _name << '=' << boost::any_cast<uint64_t>(_rav) << endl;
    }
    else if (_rav.type() == typeid(std::string)) {
        _ros << _name << '=' << boost::any_cast<std::string>(_rav) << endl;
    }
    else if (_rav.type() == typeid(std::wstring)) {
        _ros << _name << '=' << myapps::client::utility::narrow(boost::any_cast<std::wstring>(_rav)) << endl;
    }
    else if (_rav.type() == typeid(std::vector<std::string>)) {
        const auto& v = boost::any_cast<const std::vector<std::string>&>(_rav);
        for (const auto& val : v) {
            _ros << _name << '=' << val << endl;
        }
        if (v.empty()) {
            _ros << '#' << _name << '=' << endl;
        }
    }
    else {
        _ros << _name << '=' << "<UNKNOWN-TYPE>" << endl;
    }
}
//-----------------------------------------------------------------------------
void Parameters::writeConfigurationFile(string _path, const boost::program_options::options_description& _od, const boost::program_options::variables_map& _vm)const
{
    if (boost::filesystem::exists(_path)) {

        cout << "File \"" << _path << "\" already exists - renamed to: " << _path << ".old" << endl;

        boost::filesystem::rename(_path, _path + ".old");
    }

    ofstream ofs(_path);

    if (!ofs) {
        cout << "Could not open file \"" << _path << "\" for writing" << endl;
        return;
    }
    if (!_od.options().empty()) {
        ofs << '#' << " " << service_name << " configuration file" << endl;
        ofs << endl;

        for (auto& opt : _od.options()) {
            ofs << '#' << ' ' << opt->description() << endl;
            const auto& val = _vm[opt->long_name()];
            write_value(ofs, opt->long_name(), val.value());
            ofs << endl;
        }
    }
    ofs.flush();
    ofs.close();
    cout << service_name << " configuration file writen: " << _path << endl;
}
//-----------------------------------------------------------------------------

template <class M>
void complete_message(
    frame::mprpc::ConnectionContext& _rctx,
    frame::mprpc::MessagePointerT<M>&              _rsent_msg_ptr,
    frame::mprpc::MessagePointerT<M>&              _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror)
{
    //solid_check(false); //this method should not be called
}

//-----------------------------------------------------------------------------
// Front
//-----------------------------------------------------------------------------


void front_configure_service(Engine& _rengine, const Parameters& _params, frame::mprpc::ServiceT& _rsvc, AioSchedulerT& _rsch, frame::aio::Resolver& _rres)
{
    auto                        proto = frame::mprpc::serialization_v3::create_protocol<reflection::v1::metadata::Variant, myapps::front::ProtocolTypeIdT>(
        myapps::utility::metadata_factory,
        [&](auto& _rmap) {
            auto lambda = [&](const myapps::front::ProtocolTypeIdT _id, const std::string_view _name, auto const& _rtype) {
                using TypeT = typename std::decay_t<decltype(_rtype)>::TypeT;
                _rmap.template registerMessage<TypeT>(_id, _name, complete_message<TypeT>);
            };
            myapps::front::core::configure_protocol(lambda);
            myapps::front::auth::configure_protocol(lambda);
        }
    );
    frame::mprpc::Configuration cfg(_rsch, proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, myapps::front::default_port());

    cfg.client.connection_start_state     = frame::mprpc::ConnectionState::Passive;
    cfg.pool_max_active_connection_count  = 1;
    cfg.pool_max_pending_connection_count = 1;
    cfg.client.connection_timeout_keepalive = 30s;
    cfg.connection_recv_buffer_start_capacity_kb = myapps::utility::client_connection_recv_buffer_start_capacity_kb;
    cfg.connection_send_buffer_start_capacity_kb = myapps::utility::client_connection_send_buffer_start_capacity_kb;


    {
        auto connection_stop_lambda = [&_rengine](frame::mprpc::ConnectionContext& _rctx) {
            _rengine.onConnectionStop(_rctx);
        };
        auto connection_start_lambda = [&_rengine](frame::mprpc::ConnectionContext& _rctx) {
            _rctx.any() = std::make_tuple(front::core::version, front::main::version, front::auth::version);
            _rengine.onConnectionStart(_rctx);
        };
        cfg.connection_stop_fnc         = std::move(connection_stop_lambda);
        cfg.client.connection_start_fnc = std::move(connection_start_lambda);
    }

    if (_params.secure) {
        frame::mprpc::openssl::setup_client(
            cfg,
            [_params](frame::aio::openssl::Context& _rctx) -> ErrorCodeT {
                _rctx.loadVerifyFile(_params.securePath("ola-ca-cert.pem").c_str());
                //_rctx.loadCertificateFile(_params.securePath("ola-client-front-cert.pem").c_str());
                //_rctx.loadPrivateKeyFile(_params.securePath("ola-client-front-key.pem").c_str());
                return ErrorCodeT();
            },
            frame::mprpc::openssl::NameCheckSecureStart{"front.myapps.space"});
    }

    if (_params.compress) {
        frame::mprpc::snappy::setup(cfg);
    }

    _rsvc.start(std::move(cfg));
    _rsvc.createConnectionPool(_rengine.auth_endpoint_.c_str(), 1);
}

bool Engine::onAuthStart(const string& _login, const string& _pass, const string &_code)
{
    //on gui thread
    {
        lock_guard<mutex> lock(mutex_);
        auto req_ptr = frame::mprpc::make_message<front::core::AuthRequest>();
        req_ptr->captcha_text_ = _code;
        req_ptr->captcha_token_ = captcha_token_;
        req_ptr->user_          = _login;
        req_ptr->pass_          = _pass;

        if (!front_recipient_id_.empty()) {
            auto lambda = [this](
                              frame::mprpc::ConnectionContext&      _rctx,
                              frame::mprpc::MessagePointerT<front::core::AuthRequest>&  _rsent_msg_ptr,
                              frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                _rerror) {
                onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
            };
            front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
            auth_login_ = _login;
            return true;
        } else {
            return false;
        }
    }
    
}

bool Engine::onCreateStart(const string& _user, const string& _email, const string& _pass, const string& _code)
{
    {
        lock_guard<mutex> lock(mutex_);
        auto req_ptr = frame::mprpc::make_message<front::auth::CreateRequest>();
        req_ptr->captcha_text_  = _code;
        req_ptr->captcha_token_ = captcha_token_;
        req_ptr->user_          = _user;
        req_ptr->email_         = _email;
        req_ptr->pass_          = _pass;

        if (!front_recipient_id_.empty()) {
            auto lambda = [this](
                              frame::mprpc::ConnectionContext&      _rctx,
                              frame::mprpc::MessagePointerT<front::auth::CreateRequest>&  _rsent_msg_ptr,
                              frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                _rerror) {
                onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
            };
            front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
            auth_login_ = _user;
            return true;
        } else {
            return false;
        }
    }
}
bool Engine::onAuthFetchStart()
{
    auto req_ptr = frame::mprpc::make_message<front::auth::FetchRequest>();
    lock_guard<mutex> lock(mutex_);
    auth_user_.clear();
    auth_email_.clear();

    auto lambda = [this](
                        frame::mprpc::ConnectionContext&           _rctx,
                        frame::mprpc::MessagePointerT<front::auth::FetchRequest>& _rsent_msg_ptr,
                        frame::mprpc::MessagePointerT<front::auth::FetchResponse>&      _rrecv_msg_ptr,
                        ErrorConditionT const&                     _rerror) {
        lock_guard<mutex> lock(mutex_);
        if (_rrecv_msg_ptr) {
            auth_user_ = _rrecv_msg_ptr->user_;
            auth_email_ = _rrecv_msg_ptr->email_;
        }
        main_window_.onAmendFetch(auth_user_, auth_email_);
    };
    front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
    return true;
}

bool Engine::onAmendStart(string _user, string _email, const string& _pass, const string& _new_pass) 
{
    solid::to_lower(_user);
    solid::to_lower(_email);

    if (_user == auth_user_ && _email == auth_email_ && _new_pass.empty()) {
        return false;
    }

    auto req_ptr = frame::mprpc::make_message<front::auth::AmendRequest>();
    req_ptr->ticket_ = auth_token_;
    if (_user != auth_user_) {
        auth_user_ = _user;
        req_ptr->new_user_ = auth_user_;
    }
    if (_email != auth_email_) {
        auth_email_         = _email;
        req_ptr->new_email_ = auth_email_;
    }
    req_ptr->pass_ = _pass;
    req_ptr->new_pass_ = _new_pass;

    auto lambda = [this](
                      frame::mprpc::ConnectionContext&           _rctx,
                      frame::mprpc::MessagePointerT<front::auth::AmendRequest>&  _rsent_msg_ptr,
                      frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                     _rerror) {
        {
            lock_guard<mutex> lock(mutex_);
            auth_login_ = auth_user_;
        }
        
        onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
    };
    front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda, {frame::mprpc::MessageFlagsE::AwaitResponse, frame::mprpc::MessageFlagsE::OneShotSend});

    return false;
}

bool Engine::onDeleteAccountStart(const string& _pass, const string& _reason)
{
    auto req_ptr = frame::mprpc::make_message<front::auth::DeleteRequest>();
    req_ptr->ticket_ = auth_token_;
    req_ptr->pass_ = _pass;
    if(_reason.size() <= 1000){
        req_ptr->reason_ = _reason;
    }else{
        req_ptr->reason_.assign(_reason.data(), 1000);
    }

    auto lambda = [this](
                      frame::mprpc::ConnectionContext&           _rctx,
                      frame::mprpc::MessagePointerT<front::auth::DeleteRequest>&  _rsent_msg_ptr,
                      frame::mprpc::MessagePointerT<front::core::Response>& _rrecv_msg_ptr,
                      ErrorConditionT const&                     _rerror) {
       
        
        onDeleteAccountResponse(_rctx, _rrecv_msg_ptr, _rerror);
    };

    front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda, {frame::mprpc::MessageFlagsE::AwaitResponse, frame::mprpc::MessageFlagsE::OneShotSend});

    return true;
}

void Engine::onDeleteAccountResponse(
    frame::mprpc::ConnectionContext&      _rctx,
    frame::mprpc::MessagePointerT<front::core::Response>& _rrecv_msg_ptr,
    ErrorConditionT const&                _rerror)
{
    if(_rrecv_msg_ptr){
        main_window_.onDeleteAccountResponse(_rrecv_msg_ptr->message_);
    }else if(_rerror){
        main_window_.onDeleteAccountResponse(_rerror.message());
    }else{
        main_window_.onDeleteAccountResponse("Unknown error");
    }
}

bool Engine::onValidateStart(const string& _code)
{
    auto req_ptr = frame::mprpc::make_message<front::auth::ValidateRequest>();
    req_ptr->text_ = _code;
    req_ptr->ticket_ = auth_token_;
    
    lock_guard<mutex> lock(mutex_);
    if (!front_recipient_id_.empty()) {
        auto lambda = [this](
                          frame::mprpc::ConnectionContext&           _rctx,
                          frame::mprpc::MessagePointerT<front::auth::ValidateRequest>& _rsent_msg_ptr,
                          frame::mprpc::MessagePointerT<front::core::AuthResponse>&      _rrecv_msg_ptr,
                          ErrorConditionT const&                     _rerror) {
            if (_rsent_msg_ptr->text_.empty()) {
                //validation email resend request
                main_window_.onEmailValidationResent();
            } else {
                onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
            }
        };
        front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
        return true;
    }
    return false;
}



void Engine::onConnectionStart(frame::mprpc::ConnectionContext& _ctx)
{
    auto req_ptr = frame::mprpc::make_message<front::auth::InitRequest>();
    auto lambda  = [this](
                      frame::mprpc::ConnectionContext&      _rctx,
                      frame::mprpc::MessagePointerT<front::auth::InitRequest>&  _rsent_msg_ptr,
                      frame::mprpc::MessagePointerT<front::core::InitResponse>& _rrecv_msg_ptr,
                      ErrorConditionT const&                _rerror) {
        if (_rrecv_msg_ptr) {
            if (_rrecv_msg_ptr->error_ == 0) {
                onConnectionInit(_rctx);
            } else {
                cout << "ERROR initiating connection: error " << _rrecv_msg_ptr->error_ << ':' << _rrecv_msg_ptr->message_ << endl;
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

        if (auth_token_.empty()) {
            auto req_ptr = frame::mprpc::make_message<front::auth::CaptchaRequest>();

            auto lambda = [this](
                              frame::mprpc::ConnectionContext&         _rctx,
                              frame::mprpc::MessagePointerT<front::auth::CaptchaRequest>&  _rsent_msg_ptr,
                              frame::mprpc::MessagePointerT<front::auth::CaptchaResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                   _rerror) {
                onCaptchaResponse(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror);
            };

            _ctx.service().sendRequest(_ctx.recipientId(), req_ptr, lambda);
        } else {
            auto req_ptr = frame::mprpc::make_message < front::core:: AuthRequest > ();
            req_ptr->pass_ = auth_token_;

            auto lambda = [this](
                              frame::mprpc::ConnectionContext&         _rctx,
                              frame::mprpc::MessagePointerT<front::core::AuthRequest>&     _rsent_msg_ptr,
                              frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
                              ErrorConditionT const&                   _rerror) {
                if (_rrecv_msg_ptr) {
                    if (_rrecv_msg_ptr->error_ != 0) {
                        lock_guard<mutex> lock(mutex_);
                        auth_token_.clear();
                    }
                    onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
                }
            };

            _ctx.service().sendRequest(_ctx.recipientId(), req_ptr, lambda);
        }
    }
}
void Engine::onConnectionStop(frame::mprpc::ConnectionContext& _ctx)
{
    solid_log(logger, Warning, "reason: "<<_ctx.error().message()<<" system error: "<<_ctx.systemError().message());
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
    frame::mprpc::MessagePointerT<front::auth::CaptchaRequest>&  _rsent_msg_ptr,
    frame::mprpc::MessagePointerT<front::auth::CaptchaResponse>& _rrecv_msg_ptr,
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
    frame::mprpc::MessagePointerT<front::core::AuthResponse>& _rrecv_msg_ptr,
    ErrorConditionT const&                _rerror)
{
    if (_rrecv_msg_ptr) {
        solid_log(logger, Info, "AuthResponse: " << _rrecv_msg_ptr->error_);
        if (_rrecv_msg_ptr->error_ == myapps::utility::error_authentication_validate.value()) {
            auth_token_ = std::move(_rrecv_msg_ptr->message_);
            if (!_rctx.isConnectionActive()) {
                _rctx.service().connectionNotifyEnterActiveState(_rctx.recipientId());
            }
            main_window_.authValidateSignal();
        }else if(_rrecv_msg_ptr->error_){
            main_window_.authSignal(QString::fromStdString(!_rrecv_msg_ptr->message_.empty() ?  _rrecv_msg_ptr->message_ : "Unknown error"));
            //this_thread::sleep_for(chrono::seconds(2));
            onConnectionInit(_rctx);
        } else {
            solid_log(logger, Info, "Auth Success");
            if (!_rrecv_msg_ptr->message_.empty()) {
                auth_token_ = _rrecv_msg_ptr->message_;
                storeAuthData();
            }

            main_window_.authSignal({});

            //main_window_.closeSignal();
        }
    } else {
        solid_log(logger, Info, "No AuthResponse");
        //offline
    }
}

bool Engine::logout() {
    lock_guard<mutex> lock(mutex_);
    auth_token_.clear();
    storeAuthData();
    if (!front_recipient_id_.empty()) {
        front_rpc_service_.closeConnection(front_recipient_id_);
    }
    main_window_.authSignal("Logged out");
    return true;
}

void Engine::loadAuthData()
{
    const auto path = authDataFilePath();

    myapps::client::utility::auth_read(path, auth_endpoint_, auth_login_, auth_token_);

    if (auth_endpoint_ != params_.front_endpoint) {
        auth_login_.clear();
        auth_token_.clear();
        auth_endpoint_ = params_.front_endpoint;
    }
}

void Engine::storeAuthData()
{
    fs::create_directories(authDataDirectoryPath());
    const auto path = authDataFilePath();

    myapps::client::utility::auth_write(path, auth_endpoint_, auth_login_, auth_token_);
#if 0
    ofstream ofs(path.generic_string(), std::ios::trunc);
    if (ofs) {
        ofs << auth_endpoint_ << endl;
        ofs << _user << endl;
        ofs << myapps::utility::base64_encode(_token) << endl;
        ofs.flush();
        solid_log(logger, Info, "Stored auth data to: " << path.generic_string());
    } else {
        solid_log(logger, Error, "Failed storing auth data to: " << path.generic_string());
    }
#endif
}

bool Engine::passwordForgot(const string& _login, const string& _code)
{
    auto req_ptr     = frame::mprpc::make_message<front::auth::ResetRequest>();
    req_ptr->login_   = _login;
    req_ptr->captcha_text_ = _code;
    req_ptr->captcha_token_ = captcha_token_;

    lock_guard<mutex> lock(mutex_);
    if (!front_recipient_id_.empty()) {
        auto lambda = [this](
                          frame::mprpc::ConnectionContext&             _rctx,
                          frame::mprpc::MessagePointerT<front::auth::ResetRequest>& _rsent_msg_ptr,
                          frame::mprpc::MessagePointerT<front::core::AuthResponse>&        _rrecv_msg_ptr,
                          ErrorConditionT const&                       _rerror) {
            main_window_.authSignal("Forgot password");
            //this_thread::sleep_for(chrono::seconds(2));
            onConnectionInit(_rctx);
        };
        front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
        return true;
    }
    return false;
}
bool Engine::passwordReset(const string& _token, const string& _pass, const string &_code)
{
    auto req_ptr            = frame::mprpc::make_message<front::auth::ResetRequest>();
    req_ptr->login_         = utility::base64_decode(_token);
    req_ptr->pass_          = _pass;
    req_ptr->captcha_text_  = _code;
    req_ptr->captcha_token_ = captcha_token_;

    lock_guard<mutex> lock(mutex_);
    if (!front_recipient_id_.empty()) {
        auto lambda = [this](
                          frame::mprpc::ConnectionContext&          _rctx,
                          frame::mprpc::MessagePointerT<front::auth::ResetRequest>& _rsent_msg_ptr,
                          frame::mprpc::MessagePointerT<front::core::AuthResponse>&     _rrecv_msg_ptr,
                          ErrorConditionT const&                    _rerror) {
            if (_rrecv_msg_ptr) {
                if (_rrecv_msg_ptr->error_ != 0) {
                    lock_guard<mutex> lock(mutex_);
                    auth_token_.clear();
                }
                onAuthResponse(_rctx, _rrecv_msg_ptr, _rerror);
            }
        };
        front_rpc_service_.sendRequest(front_recipient_id_, req_ptr, lambda);
        return true;
    }
    return false;
}

} //namespace
