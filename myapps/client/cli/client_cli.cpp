#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"
#include "solid/system/directory.hpp"
#include "solid/system/log.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcprotocol_serialization_v3.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"

#include "solid/utility/threadpool.hpp"

#include "myapps/common/front_protocol_main.hpp"
#include "myapps/common/utility/encode.hpp"

#include "myapps/common/utility/archive.hpp"
#include "myapps/common/utility/version.hpp"

#include "myapps/client/utility/auth_file.hpp"

#include <signal.h>

#include "boost/program_options.hpp"

#include "boost/filesystem.hpp"

#include <iomanip>

#define REPLXX_STATIC
#include "replxx.hxx"

#include "yaml-cpp/yaml.h"

#include "lz4.h"

#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>

using namespace std;
using namespace solid;
using namespace myapps;
using namespace myapps::front;

using Replxx = replxx::Replxx;

namespace fs = boost::filesystem;

namespace {

constexpr string_view service_name("myapps_client_cli");
const solid::LoggerT  logger("cli");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor<frame::mprpc::EventT>>;
using CallPoolT     = ThreadPool<Function<void()>, Function<void()>>;

string env_config_path_prefix();
string get_home_env();
string get_temp_env();
string path(const std::string& _path);
string system_path(const std::string& _path);
bool   read(string& _rs, istream& _ris, size_t _sz);

//-----------------------------------------------------------------------------
//      Parameters
//-----------------------------------------------------------------------------
struct Parameters {
    Parameters()
    {
    }

    vector<string> debug_modules;
    string         debug_addr;
    string         debug_port;
    bool           debug_console;
    bool           debug_buffered;
    bool           secure;
    bool           compress;
    string         front_endpoint;
    string         secure_prefix;
    string         auth_token;
    bool           no_history;

    string securePath(const string& _name) const
    {
        return secure_prefix + '/' + _name;
    }

    string path_prefix_;

    string configPath(const string& _path_prefix) const;
    template <class F>
    Parameters(int argc, char* argv[], F _f)
    {
        parse(argc, argv);
        _f(*this);
    }

    void                                  parse(int argc, char* argv[]);
    boost::program_options::variables_map bootstrapCommandLine(int argc, char* argv[]);
    void                                  writeConfigurationFile(string _path, const boost::program_options::options_description& _od, const boost::program_options::variables_map& _vm) const;
};

//-----------------------------------------------------------------------------

using RecipientQueueT = std::queue<frame::mprpc::RecipientId>;

struct Engine {
    frame::mprpc::ServiceT& rrpc_service_;
    const Parameters&       rparams_;
    atomic<bool>            running_;
    mutex                   mutex_;
    string                  auth_endpoint_;
    string                  auth_user_;
    string                  auth_token_;
    string                  path_prefix_;

    fs::path authDataDirectoryPath() const
    {
        fs::path p = path_prefix_;
        p /= "config";
        return p;
    }

    fs::path authDataFilePath() const
    {
        return authDataDirectoryPath() / "auth.data";
    }

    Engine(
        frame::mprpc::ServiceT& _rrpc_service,
        const Parameters&       _rparams)
        : rrpc_service_(_rrpc_service)
        , rparams_(_rparams)
        , running_(true)
    {
    }

    void start()
    {

        if (rparams_.auth_token.empty()) {
            const auto path = authDataFilePath();
            myapps::client::utility::auth_read(path, auth_endpoint_, auth_user_, auth_token_);
        } else {
            solid_check(!rparams_.front_endpoint.empty(), "front_enpoint required");
            auth_endpoint_ = rparams_.front_endpoint;
            auth_token_    = myapps::utility::base64_decode(rparams_.auth_token);
        }
        solid_check(!auth_token_.empty(), "Please authenticate using myapps_auth application");
    }

    frame::mprpc::ServiceT& rpcService() const
    {
        return rrpc_service_;
    }

    const Parameters& params() const
    {
        return rparams_;
    }

    const string& serverEndpoint() const
    {
        return auth_endpoint_;
    }

    void onConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void onConnectionInit(frame::mprpc::ConnectionContext& _ctx);
    void authRun();
    void onAuthResponse(frame::mprpc::ConnectionContext& _ctx, core::AuthResponse& _rresponse);

    void stop()
    {
        running_ = false;
    }
};

//-----------------------------------------------------------------------------

bool parse_arguments(Parameters& _par, int argc, char* argv[]);

string get_command(const string& _line);

void configure_service(Engine& _reng, AioSchedulerT& _rsch, frame::aio::Resolver& _rres);

void handle_help(istream& _ris, Engine& _reng);
void handle_list(istream& _ris, Engine& _reng);
void handle_fetch(istream& _ris, Engine& _reng);
void handle_create(istream& _ris, Engine& _reng);
void handle_generate(istream& _ris, Engine& _reng);
void handle_acquire(istream& _ris, Engine& _reng);
void handle_parse(istream& _ris, Engine& _reng);
void handle_change(istream& _ris, Engine& _reng);

void uninstall_cleanup();

string env_log_path_prefix()
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

} // namespace

int main(int argc, char* argv[])
{
    const Parameters params(argc, argv,
        [](Parameters& _rparams) {
#ifdef SOLID_ON_WINDOWS
            TCHAR szFileName[MAX_PATH];

            GetModuleFileName(NULL, szFileName, MAX_PATH);

            fs::path exe_path{szFileName};

            _rparams.secure_prefix = (exe_path.parent_path() / _rparams.secure_prefix).generic_string();
#endif
        });

#ifndef SOLID_ON_WINDOWS
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
            (env_log_path_prefix() + "\\log\\cli").c_str(),
            params.debug_modules,
            params.debug_buffered,
            3,
            1024 * 1024 * 64);
    }
    AioSchedulerT          scheduler;
    frame::Manager         manager;
    CallPoolT              cwp{{1, 1000, 0}, [](const size_t) {}, [](const size_t) {}};
    frame::aio::Resolver   resolver([&cwp](std::function<void()>&& _fnc) { cwp.pushOne(std::move(_fnc)); });
    frame::mprpc::ServiceT rpc_service(manager);
    Engine                 engine(rpc_service, params);

    scheduler.start(1);
    solid_log(logger, Verbose, "");

    engine.path_prefix_ = env_config_path_prefix();

    solid_log(logger, Verbose, "");

    engine.start();

    solid_log(logger, Verbose, "");

    configure_service(engine, scheduler, resolver);

    Replxx rx;
    rx.install_window_change_handler();

    solid_log(logger, Verbose, "");

    // the path to the history file
    const std::string history_file{engine.path_prefix_ + "/history.txt"};

    // load the history file if it exists
    rx.history_load(history_file);

    solid_log(logger, Verbose, "");

    // set the max history size
    rx.set_max_history_size(128);

    // set the max number of hint rows to show
    rx.set_max_hint_rows(3);

    solid_log(logger, Verbose, "");

#if 1
    const std::string prompt{"> "};
    for (;;) {
        // display the prompt and retrieve input from the user
        char const* cinput{nullptr};

        do {
            cinput = rx.input(prompt);
        } while ((cinput == nullptr) && (errno == EAGAIN));

        if (cinput == nullptr) {
            break;
        }

        // change cinput into a std::string
        // easier to manipulate
        string        line{cinput};
        istringstream iss(cinput);
        string        cmd;
        iss >> cmd;

        if (line == "q" || line == "Q" || line == "quit") {
            if (!params.no_history) {
                rx.history_add(line);
            }
            break;
        }

        if (cmd == "list") {
            handle_list(iss, engine);
        } else if (cmd == "fetch") {
            handle_fetch(iss, engine);
        } else if (cmd == "create") {
            handle_create(iss, engine);
        } else if (cmd == "generate") {
            handle_generate(iss, engine);
        } else if (cmd == "parse") {
            handle_parse(iss, engine);
        } else if (cmd == "acquire") {
            handle_acquire(iss, engine);
        } else if (cmd == "help" || line == "h") {
            handle_help(iss, engine);
        } else if (cmd == "change") {
            handle_change(iss, engine);
        } else if (cmd == "clear") {
            rx.clear_screen();
        } else if (cmd == "history") {
            auto h = rx.history_scan();
            for (size_t i = 0; h.next(); ++i) {
                std::cout << std::setw(4) << i << ": " << h.get().text() << "\n";
            }
        }
        if (!params.no_history) {
            rx.history_add(line);
        }
    }
    if (!params.no_history) {
        rx.history_save(history_file);
        cerr << "command history written to: " << history_file << endl;
    }
#else
    string line;

    while (true) {
        cout << '>' << flush;
        line.clear();
        do {
            getline(cin, line);
        } while (line.empty());

        if (line == "q" || line == "Q" || line == "quit") {
            break;
        }
        istringstream iss(line);
        string        cmd;
        iss >> cmd;

        if (cmd == "list") {
            handle_list(iss, engine);
        } else if (cmd == "fetch") {
            handle_fetch(iss, engine);
        } else if (cmd == "create") {
            handle_create(iss, engine);
        } else if (cmd == "generate") {
            handle_generate(iss, engine);
        } else if (cmd == "acquire") {
            handle_acquire(iss, engine);
        } else if (cmd == "help" || line == "h") {
            handle_help(iss, engine);
        }
    }

#endif
    engine.stop();
    rpc_service.stop(); // need this because rpc_service uses the engine
    return 0;
}

namespace std {
std::ostream& operator<<(std::ostream& os, const std::vector<string>& vec)
{
    for (auto item : vec) {
        os << item << ",";
    }
    return os;
}
} // namespace std

namespace {
//-----------------------------------------------------------------------------
// Parameters
//-----------------------------------------------------------------------------
string Parameters::configPath(const std::string& _path_prefix) const
{
    return _path_prefix + "\\config\\" + string(service_name) + ".config";
}
//-----------------------------------------------------------------------------
boost::program_options::variables_map Parameters::bootstrapCommandLine(int argc, char* argv[])
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

void Parameters::parse(int argc, char* argv[])
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
            ("uninstall-cleanup", "Uninstall cleanup")
            ("auth", value<std::string>(&auth_token), "Authentication token")
            ("generate-config", value<bool>(&generate_config_file)->implicit_value(true)->default_value(false), "Write configuration file and exit")
            ;
        // clang-format on
        options_description config(string(service_name) + " configuration options");
        // clang-format off
        config.add_options()
            ("debug-modules,M", value<std::vector<std::string>>(&this->debug_modules)->default_value(std::vector<std::string>{"myapps::.*:EWX", ".*:EWX"}), "Debug logging modules")
            ("debug-address,A", value<string>(&debug_addr)->default_value(""), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&debug_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&debug_console)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-buffered,S", value<bool>(&this->debug_buffered)->implicit_value(true)->default_value(true), "Debug unbuffered")
            ("secure,s", value<bool>(&secure)->implicit_value(true)->default_value(true), "Use SSL to secure communication")
            ("compress", value<bool>(&compress)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("front-endpoint", value<std::string>(&front_endpoint)->default_value(string(MYAPPS_FRONT_URL)), "MyApps.directory Front Endpoint")
            ("no-history", value<bool>(&no_history)->implicit_value(true)->default_value(false), "Disable history log")
            ("secure-prefix", value<std::string>(&secure_prefix)->default_value("certs"), "Secure Path prefix")
            ("path-prefix", value<std::string>(&path_prefix_)->default_value(env_config_path_prefix()), "Path prefix")
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
            exit(0);
        }

        if (bootstrap.count("version") != 0u) {
            cout << myapps::utility::version_full() << endl;
            cout << "SolidFrame: " << solid::version_full() << endl;
            exit(0);
        }

        if (vm.count("uninstall-cleanup")) {
            uninstall_cleanup();
            exit(0);
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
            exit(0);
        }

        if (!cfg_path.empty()) {
            ifstream ifs(cfg_path);
            if (!ifs) {
                cout << "cannot open config file: " << cfg_path << endl;
                if (bootstrap.count("config")) {
                    //exit only if the config path was explicitly given
                    exit(0);
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
        exit(0);
    }
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
string get_command(const string &_line){
    size_t offset = _line.find(' ');
    if (offset != string::npos) {
        return _line.substr(0, offset);
    }
    return _line;
}

//-----------------------------------------------------------------------------
// Front
//-----------------------------------------------------------------------------
void configure_service(Engine &_reng, AioSchedulerT &_rsch, frame::aio::Resolver &_rres){
    auto                        proto = frame::mprpc::serialization_v3::create_protocol<reflection::v1::metadata::Variant, myapps::front::ProtocolTypeIdT>(
        myapps::utility::metadata_factory,
        [&](auto& _rmap) {
            auto lambda = [&](const myapps::front::ProtocolTypeIdT _id, const std::string_view _name, auto const& _rtype) {
                using TypeT = typename std::decay_t<decltype(_rtype)>::TypeT;
                _rmap.template registerMessage<TypeT>(_id, _name, complete_message<TypeT>);
            };
            myapps::front::core::configure_protocol(lambda);
            myapps::front::main::configure_protocol(lambda);
        }
    );
    frame::mprpc::Configuration cfg(_rsch, proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, myapps::front::default_port());
    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;
    cfg.client.connection_timeout_keepalive = std::chrono::seconds(10);
    cfg.pool_max_active_connection_count  = 1;
    cfg.pool_max_pending_connection_count = 1;
    cfg.connection_recv_buffer_start_capacity_kb = myapps::utility::client_connection_recv_buffer_start_capacity_kb;
    cfg.connection_send_buffer_start_capacity_kb = myapps::utility::client_connection_send_buffer_start_capacity_kb;

    {
//         auto connection_stop_lambda = [&_rctx](frame::mpipc::ConnectionContext &_ctx){
//             engine_ptr->onConnectionStop(_ctx);
//         };
        auto connection_start_lambda = [&_reng](frame::mprpc::ConnectionContext &_rctx){
            _rctx.any() = std::make_tuple(core::version, main::version, myapps::utility::version);
            _reng.onConnectionStart(_rctx);
        };
        //cfg.connection_stop_fnc = std::move(connection_stop_lambda);
        cfg.client.connection_start_fnc = std::move(connection_start_lambda);
    }

    if (_reng.params().secure) {
        frame::mprpc::openssl::setup_client(
            cfg,
            [&_reng](frame::aio::openssl::Context& _rctx) -> ErrorCodeT {
                _rctx.loadVerifyFile(_reng.params().securePath("ola-ca-cert.pem").c_str());
                //_rctx.loadCertificateFile(_reng.params().securePath("ola-client-front-cert.pem").c_str());
                //_rctx.loadPrivateKeyFile(_reng.params().securePath("ola-client-front-key.pem").c_str());
                return ErrorCodeT();
            },
            frame::mprpc::openssl::NameCheckSecureStart{"front.myapps.directory"});
    }
    
    if(_reng.params().compress){
        frame::mprpc::snappy::setup(cfg);
    }

    _reng.rpcService().start(std::move(cfg));
}

void handle_help(istream& _ris, Engine &_reng){
    cout<<"Commands:\n\n";
    cout<<"> list oses\n\n";
    cout<<"> list apps o/a/A\n";
    cout<<"\to - owned applications\n";
    cout<<"\ta - aquired applications\n";
    cout<<"\tA - All applications\n\n";
    cout<<"> list store STORAGE_ID PATH\n\n";
    cout<<"> fetch app APP_ID [OS_ID]\n\n";
    cout<<"> fetch build APP_ID BUILD_ID\n\n";
    cout<<"> fetch config APP_ID LANGUAGE_ID OS_ID\n\n"; 
    cout<<"> generate build ~/path/to/build.yml\n\n";
    cout << "> parse build ~/path/to/build.yml\n\n";
    cout<<"> create app\n\n";
    cout<<"> create build APP_ID BUILD_TAG ~/path/to/build.yml ~/path/to/build_folder ~/path/to/build_icon.png\n";
    cout<<"> fetch updates LANGUAGE_ID OS_ID APP_ID [APP_ID]\n";
    cout << "> change state m|M|b|B APP_ID OS_ID ITEM_NAME ITEM_STATE\n";
    cout<<"\nExamples:\n";
    cout<<"> create app bubbles.app\n";
    cout<<"> create build l/AQPpeZWqoR1Fcngt3t2w== first bubbles.build.yml ~/tmp/bubbles_client ~/tmp/bubbles.png\n";
    cout<<"> create media l/AQPpeZWqoR1Fcngt3t2w== first ~/tmp/bubbles_media\n";
    cout<<"> fetch config l/AQPpeZWqoR1Fcngt3t2w== en-US Windows10x86_64 desc\n";
    cout<<"> fetch config uv0oHriZYsfwec566VTXew== US_en Windows10x86_64\n";
    cout<<"> fetch media uv0oHriZYsfwec566VTXew== US_en Windows10x86_64\n";
    cout<<"> list store 82zWrPIuni/1jWA8V53N51AlOYx9q9rRXZcyZm73BGpyesjP5aI0YLfG+bZfwg7LDyMtQnn55CN6o/VzgvWYDzn0GeY57wPDDUViKNVVJcw= bubbles_client.exe\n";
    
    cout<<endl;
}

//-----------------------------------------------------------------------------
//  Command handlers
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//  List
//-----------------------------------------------------------------------------

void handle_list_oses(istream& /*_ris*/, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::ListOSesRequest>();
    
    promise<void> prom;
    const auto start = std::chrono::high_resolution_clock::now();
    auto lambda = [&prom, &start](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::ListOSesRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::ListOSesResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        using namespace std::chrono;
        if(_rrecv_msg_ptr){
            const auto now = std::chrono::high_resolution_clock::now();
            cout<<"{\n";
            for(const auto & os: _rrecv_msg_ptr->osvec_){
                cout<<os<<'\n';
            }
            const auto duration = duration_cast<microseconds>(now - start).count();
            cout<<"} "<<duration<<"us"<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_list_apps(istream& _ris, Engine &_reng){
    using namespace std::chrono;

    auto req_ptr = frame::mprpc::make_message<main::ListAppsRequest>();
    
    //o - owned applications
    //a - aquired applications
    //A - all applications
    _ris>>req_ptr->choice_;
    
    promise<void> prom;
    const auto start = std::chrono::high_resolution_clock::now();
    
    auto lambda = [&prom, &start](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::ListAppsRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::ListAppsResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            const auto now = std::chrono::high_resolution_clock::now();
            cout<<"{\n";
            for(const auto& app_id: _rrecv_msg_ptr->app_vec_){
                cout<<'\t'<<utility::base64_encode(app_id.id_)<<"\t"<<utility::base64_encode(app_id.unique_)<<'\t'<<app_id.name_<<endl;
            }
            const auto duration = duration_cast<microseconds>(now - start).count();
            cout<<"} "<<duration<<"us"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
    
}

//-----------------------------------------------------------------------------

void handle_list_store(istream& _ris, Engine &_reng){
    using namespace std::chrono;
    auto req_ptr = frame::mprpc::make_message<main::ListStoreRequest>();
    
    _ris>>req_ptr->shard_id_;
    _ris>>std::quoted(req_ptr->storage_id_);
    _ris>>std::quoted(req_ptr->path_);
    
    req_ptr->storage_id_ = utility::base64_decode(req_ptr->storage_id_);
    
    
    promise<void> prom;
    const auto start = std::chrono::high_resolution_clock::now();
    
    auto lambda = [&prom, &start](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::ListStoreRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::ListStoreResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            const auto now = std::chrono::high_resolution_clock::now();
            cout<<"{\n";
            for(const auto& node: _rrecv_msg_ptr->node_dq_){
                cout<<'\t'<<node.name_<<'\t'<<node.size_<<endl;
            }
            const auto duration = duration_cast<microseconds>(now - start).count();
            cout<<"} "<<duration<<"us"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
    
}

//-----------------------------------------------------------------------------

void handle_list(istream& _ris, Engine &_reng){
    string what;
    _ris>>std::quoted(what);
    
    if(what == "oses"){
        handle_list_oses(_ris, _reng);
    }else if(what == "apps"){
        handle_list_apps(_ris, _reng);
    }else if(what == "store"){
        handle_list_store(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Change
//-----------------------------------------------------------------------------

void handle_change_state(istream& _ris, Engine& _reng) {
    auto req_ptr = frame::mprpc::make_message<main::ChangeAppItemStateRequest>();

    char item_type = '\0';//m/M->media, b/B->build
    string state_name;

    _ris >> item_type >> std::quoted(req_ptr->application_id_) >> std::quoted(req_ptr->os_id_) >> std::quoted(req_ptr->item_.name_) >> std::quoted(state_name);

    auto state = myapps::utility::app_item_state_from_name(state_name.c_str());
    if (state == myapps::utility::AppItemStateE::StateCount) {
        cout << "Error: invalid state name " << state_name << endl;
        return;
    }

    if (item_type == 'b' || item_type == 'B')
    {
        req_ptr->item_.type(myapps::utility::AppItemTypeE::Build);
    }
    else if (item_type == 'm' || item_type == 'M') {
        req_ptr->item_.type(myapps::utility::AppItemTypeE::Media);
    }
    else {
        cout << "Error: invalid item type " << item_type << endl;
        return;
    }
    
    req_ptr->application_id_ = utility::base64_decode(req_ptr->application_id_);
    req_ptr->new_state_ = static_cast<uint8_t>(state);

    promise<void> prom;

    auto lambda = [&prom](
        frame::mprpc::ConnectionContext& _rctx,
        frame::mprpc::MessagePointerT<myapps::front::main::ChangeAppItemStateRequest>& _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<myapps::front::core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const& _rerror) {

        if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
            cout << "Success" << endl;
        }
        else if (!_rrecv_msg_ptr) {
            cout << "Error - no response: " << _rerror.message() << endl;
        }
        else {
            cout << "Error received from server: " << _rrecv_msg_ptr->error_ << " : "<< _rrecv_msg_ptr->message_<< endl;
        }
        prom.set_value();
    };

    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

void handle_change(istream& _ris, Engine& _reng) {
    string what;
    _ris >> std::quoted(what);

    if (what == "state") {
        handle_change_state(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Fetch
//-----------------------------------------------------------------------------

ostream& operator<<(ostream &_ros, const utility::Application &_cfg){

    _ros<<"Name: "<<_cfg.name_<<endl;
    return _ros;
}

void handle_fetch_app(istream& _ris, Engine &_reng){
     auto req_ptr = frame::mprpc::make_message<main::FetchAppRequest>();
    
    _ris>>std::quoted(req_ptr->application_id_);
    _ris>>std::quoted(req_ptr->os_id_);
    
    req_ptr->application_id_ = utility::base64_decode(req_ptr->application_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::FetchAppRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::FetchAppResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout << "Items: {"<<endl;
            for(const auto& item: _rrecv_msg_ptr->item_vec_){
                //cout<<utility::base64_encode(build_id)<<endl;
                cout<<'\t'<<item.name_<<" "<< myapps::utility::app_item_type_name(item.type())<<" "<< myapps::utility::app_item_state_name(item.state()) <<endl;
            }
            cout<<'}'<<endl;
            cout<<_rrecv_msg_ptr->application_;
            cout<<endl;
            cout<<"}"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

ostream& operator<<(ostream &_ros, const utility::Build::Configuration &c){
    _ros<<"Name: "<<c.name_<<endl;
    _ros<<"Directory: "<<c.directory_<<endl;
    _ros<<"Oses: ";
    for(const auto &o: c.os_vec_){
        _ros<<o<<' ';
    }
    _ros<<endl;
    _ros<<"Mounts: ";
    for(const auto &m: c.mount_vec_){
        _ros<<'['<<m.first<<" | "<<m.second<<']';
    }
    _ros<<endl;
    _ros<<"Exes:";
    for(const auto &e: c.exe_vec_){
        _ros<<e<<' ';
    }
    _ros<<endl;
    _ros<<"Shortcuts: {\n";
    for(const auto &s: c.shortcut_vec_){
        _ros<<"Name:      "<<s.name_<<endl;
        _ros<<"Command:   "<<s.command_<<endl;
        _ros<<"Arguments: "<<s.arguments_<<endl;
        _ros<<"Run Fld:   "<<s.run_folder_<<endl;
        _ros<<"Icon:      "<<s.icon_<<endl;
        _ros<<endl;
    }
    _ros<<"}\n";
    _ros<<"Properties:{";
    for(const auto& p: c.property_vec_){
        _ros<<"{["<<p.first<<"]["<<p.second<<"]} ";
    }
    _ros<<"}\n";
    
    _ros << "media:{"<<endl;
    _ros << "name: " << c.media_.name_ << endl;
    _ros << "entries:{\n";
    for (const auto& e : c.media_.entry_vec_) {
        _ros << "\t{[" << e.thumbnail_path_ << "][" << e.path_ << "]}\n";
    }
    _ros << "}\n";
    return _ros;
}

ostream& operator<<(ostream &_ros, const utility::Build &_cfg){
    _ros<<"Name : "<<_cfg.name_<<endl;
    _ros<<"Tag: "<<_cfg.tag_<<endl;

    _ros << "Dictionary:{";
    for (const auto& p : _cfg.dictionary_dq_) {
        _ros << "{[" << p.first << "][" << p.second << "]} ";
    }
    _ros << '}' << endl;

    _ros<<"Properties:{";
    for(const auto& p: _cfg.property_vec_){
        _ros<<"{["<<p.first<<"]["<<p.second<<"]} ";
    }
    _ros<<'}'<<endl;
    _ros<<"Configurations: {\n";
    for(const auto& c: _cfg.configuration_vec_){
        _ros<<c<<"\n\n";
    }
    _ros<<'}'<<endl;
    return _ros;
}

void handle_fetch_build(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::FetchBuildRequest>();
    
    _ris>>std::quoted(req_ptr->application_id_);
    _ris>>std::quoted(req_ptr->build_id_);
    
    req_ptr->application_id_ = utility::base64_decode(req_ptr->application_id_);
    req_ptr->build_id_ = req_ptr->build_id_;//utility::base64_decode(req_ptr->build_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::FetchBuildRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::FetchBuildResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout<<"Remote shard: "<<_rrecv_msg_ptr->shard_id_<<endl;
            cout<<"Remote Root: "<<utility::base64_encode(_rrecv_msg_ptr->storage_id_)<<endl;
            cout<<"Icon of size: "<<_rrecv_msg_ptr->image_blob_.size()<<endl;
            cout<<_rrecv_msg_ptr->build_;
            cout<<endl;
            cout<<"}"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

void handle_fetch_config(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::FetchBuildConfigurationRequest>();
    
    _ris>>std::quoted(req_ptr->application_id_);
    _ris>>std::quoted(req_ptr->lang_);
    _ris>>std::quoted(req_ptr->os_id_);
    
    while(_ris){
        string prop;
        _ris>>prop;
        if(prop.empty()){
            break;
        }
        req_ptr->property_vec_.emplace_back(std::move(prop));
    }
    req_ptr->fetch_options_.set();
    req_ptr->application_id_ = utility::base64_decode(req_ptr->application_id_);    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout<< "Build Remote Shard: "<<_rrecv_msg_ptr->build_shard_id_<<endl;
            cout << "Build Remote Root: "<<utility::base64_encode(_rrecv_msg_ptr->build_storage_id_)<<endl;
            cout << "Media Remote Shard: " << _rrecv_msg_ptr->media_shard_id_ << endl;
            cout << "Media Remote Root: " << utility::base64_encode(_rrecv_msg_ptr->media_storage_id_) << endl;
            cout<<"Application unique: "<<_rrecv_msg_ptr->app_unique_<<endl;
            cout<<"Build unique: "<<_rrecv_msg_ptr->build_unique_<<endl;
            cout<<_rrecv_msg_ptr->configuration_;
            cout<<endl;
            cout<<"}"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

uint64_t stream_copy(std::ostream &_ros, std::istream &_ris){
    constexpr size_t buffer_size = 1024 * 32;
    char buffer[buffer_size];
    uint64_t size = 0;
    
    do{
        _ris.read(buffer, buffer_size);
        auto read_count = _ris.gcount();
        if(read_count){
            _ros.write(buffer, read_count);
            size += read_count;
        }
    }while(!_ris.eof());
    return size;
}


uint64_t stream_copy(string& _str, std::istream& _ris) {
    constexpr size_t buffer_size = 1024 * 32;
    char buffer[buffer_size];
    uint64_t size = 0;

    do {
        _ris.read(buffer, buffer_size);
        auto read_count = _ris.gcount();
        if (read_count) {
            _str.append(buffer, read_count);
            size += read_count;
        }
    } while (!_ris.eof());
    return size;
}

struct StoreFetchStub {
    ofstream ofs_;
    uint64_t size_ = 0;
    uint64_t decompressed_size_ = 0;
    string   compressed_chunk_;
    uint32_t current_chunk_index_ = 0;
    uint32_t current_chunk_offset_ = 0;
    uint32_t compress_chunk_capacity_ = 0;
    uint8_t  compress_algorithm_type_ = 0;
    frame::mprpc::MessagePointerT<main::FetchStoreRequest> request_ptr_;
    frame::mprpc::MessagePointerT<main::FetchStoreResponse>   response_ptr_[2];
    bool pending_request_ = false;


    bool isLastChunk()const{
        return current_chunk_index_ == -1 || ((current_chunk_index_ + 1) * compress_chunk_capacity_) >= size_;
    }

    void pendingRequest(const bool _b) {
        pending_request_ = _b;
    }

    bool pendingRequest()const {
        return pending_request_;
    }

    uint32_t currentChunkOffset()const {
        return current_chunk_offset_;
    }
    uint32_t currentChunkIndex()const {
        return current_chunk_index_;
    }

    bool isExpectedResponse(const uint32_t _chunk_index, const uint32_t _chunk_offset) const {
        return current_chunk_index_ == _chunk_index && current_chunk_offset_ >= _chunk_offset;
    }

    void nextChunk() {
        if (!isLastChunk()) {
            ++current_chunk_index_;
        }
        else {
            current_chunk_index_ = -1;
        }
    }

    uint32_t peekNextChunk()const {
        solid_assert(current_chunk_index_ != -1);
        return current_chunk_index_ + 1;
    }

    void storeResponse(frame::mprpc::MessagePointerT<front::main::FetchStoreResponse>& _rres_ptr) {
        if (!response_ptr_[0]) {
            response_ptr_[0] = _rres_ptr;
        }
        else {
            solid_check(!response_ptr_[1]);
            response_ptr_[1] = _rres_ptr;
        }
    }

    void storeRequest(frame::mprpc::MessagePointerT<front::main::FetchStoreRequest>&& _rres_ptr)
    {
        request_ptr_ = std::move(_rres_ptr);
    }

    uint32_t copy(istream& _ris, const uint64_t _chunk_size, const bool _is_compressed) {
        uint32_t size = 0;
        if (_is_compressed) {
            size = stream_copy(compressed_chunk_, _ris);
            current_chunk_offset_ += size;
            solid_check(current_chunk_offset_ <= _chunk_size);
            if (current_chunk_offset_ == _chunk_size) {
                string uncompressed_data;
                size_t uncompressed_size;
                uncompressed_data.reserve(compress_chunk_capacity_);
                
                if (compress_algorithm_type_ == 1) {
                    const auto rv = LZ4_decompress_safe(compressed_chunk_.data(), uncompressed_data.data(), compressed_chunk_.size(), compress_chunk_capacity_);
                    solid_check(rv > 0);
                    uncompressed_size = rv;
                }
                else if(compress_algorithm_type_ == 0){
                    solid_check(snappy::Uncompress(compressed_chunk_.data(), compressed_chunk_.size(), &uncompressed_data));
                    uncompressed_size = uncompressed_data.size();
                }
                else {
                    solid_throw("Unkown compress algorithm type: " << (int)compress_algorithm_type_);
                }

                ofs_.write(uncompressed_data.data(), uncompressed_size);
                
                decompressed_size_ += uncompressed_size;
                compressed_chunk_.clear();
                current_chunk_offset_ = 0;
                nextChunk();
            }
        }
        else {
            size = stream_copy(ofs_, _ris);
            current_chunk_offset_ += size;
            solid_check(current_chunk_offset_ <= _chunk_size);
            if (current_chunk_offset_ == _chunk_size) {
                decompressed_size_ += _chunk_size;
                current_chunk_offset_ = 0;
                nextChunk();
            }
    }

        return size;
    }
};

void fetch_remote_file(
    frame::mprpc::ConnectionContext* _pctx,
    Engine& _reng,
    promise<uint32_t>& _rprom,
    StoreFetchStub& _rfetch_stub,
    frame::mprpc::MessagePointerT<main::FetchStoreRequest>& _rreq_msg_ptr,
    const uint32_t _chunk_index = 0, const uint32_t _chunk_offset = 0);

void handle_response(
    frame::mprpc::ConnectionContext& _rctx,
    Engine& _reng,
    promise<uint32_t>& _rprom,
    StoreFetchStub& _rfetch_stub,
    frame::mprpc::MessagePointerT<main::FetchStoreRequest>& _rsent_msg_ptr,
    frame::mprpc::MessagePointerT<main::FetchStoreResponse>& _rrecv_msg_ptr
) {
    const uint32_t received_size = _rfetch_stub.copy(_rrecv_msg_ptr->ioss_, _rrecv_msg_ptr->chunk_.size_, _rrecv_msg_ptr->chunk_.isCompressed());

    solid_log(logger, Warning, "Received " << received_size << " offset " << _rfetch_stub.current_chunk_offset_ << " cid " << _rfetch_stub.current_chunk_index_ << " totalsz " << _rrecv_msg_ptr->chunk_.size_);

    if (_rfetch_stub.response_ptr_[0]) {
        auto res_ptr1 = std::move(_rfetch_stub.response_ptr_[0]);
        auto res_ptr2 = std::move(_rfetch_stub.response_ptr_[1]);
        handle_response(_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, res_ptr1);
        if (res_ptr2) {
            handle_response(_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, res_ptr2);
        }
        return;
    }

    if (_rrecv_msg_ptr->isResponsePart()) {
        //do we need to request more data for current chunk:
        if ((_rrecv_msg_ptr->chunk_.size_ - _rfetch_stub.currentChunkOffset()) > received_size) {
            _rfetch_stub.pendingRequest(true);
            //asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.currentChunkIndex(), rfile_data.currentChunkOffset() + received_size);
            fetch_remote_file(&_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, _rfetch_stub.currentChunkIndex(), _rfetch_stub.currentChunkOffset() + received_size);
            return;
        }
        else {
            _rfetch_stub.pendingRequest(false);
        }
    }
    else if (_rfetch_stub.currentChunkOffset() == 0 && !_rfetch_stub.pendingRequest()) {//should try send another request
        _rfetch_stub.storeRequest(std::move(_rsent_msg_ptr));
    }
    else if (_rfetch_stub.currentChunkOffset() == 0 && _rfetch_stub.pendingRequest() && (received_size == _rrecv_msg_ptr->chunk_.size_)) {//should try send another request
        _rfetch_stub.storeRequest(std::move(_rsent_msg_ptr));
        _rfetch_stub.pendingRequest(false);
    }
    else {
        _rfetch_stub.storeRequest(std::move(_rsent_msg_ptr));
        //solid_log(logger, Warning, _rentry_ptr->name_ << "");
        _rfetch_stub.pendingRequest(false);
        return;
    }

    //is there a next chunk

    if (_rfetch_stub.currentChunkIndex() != -1 && _rfetch_stub.currentChunkOffset() == 0) {
        _rfetch_stub.pendingRequest(true);
        //asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.currentChunkIndex(), 0);
        fetch_remote_file(&_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, _rfetch_stub.currentChunkIndex());
    }
    else if (!_rfetch_stub.isLastChunk()) {
        _rfetch_stub.pendingRequest(true);
        //asyncFetchStoreFile(&_rctx, _rentry_ptr, _rsent_msg_ptr, rfile_data.peekNextChunk(), 0);
        fetch_remote_file(&_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, _rfetch_stub.peekNextChunk());
    }
    else if(_rfetch_stub.decompressed_size_ == _rfetch_stub.size_){
        solid_log(logger, Warning, "");
        _rprom.set_value(0);
    }
}

void fetch_remote_file(
    frame::mprpc::ConnectionContext* _pctx,
    Engine &_reng,
    promise<uint32_t> &_rprom,
    StoreFetchStub&_rfetch_stub,
    frame::mprpc::MessagePointerT<main::FetchStoreRequest>&  _rreq_msg_ptr,
    const uint32_t _chunk_index, const uint32_t _chunk_offset){
    
    auto lambda = [&_rprom, &_rfetch_stub, &_reng, _chunk_index, _chunk_offset](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::FetchStoreRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::FetchStoreResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    )mutable{
        
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ == 0){
                _rrecv_msg_ptr->ioss_.seekg(0);

                if (_rfetch_stub.isExpectedResponse(_rsent_msg_ptr->chunk_index_, _rsent_msg_ptr->chunk_offset_)) {
                    handle_response(_rctx, _reng, _rprom, _rfetch_stub, _rsent_msg_ptr, _rrecv_msg_ptr);
                }
                else {
                    _rfetch_stub.storeResponse(_rrecv_msg_ptr);
                }
            
            }else{
                _rprom.set_value(_rrecv_msg_ptr->error_);
            }
        }else{
            _rprom.set_value(-1);
        }
    };

    if (_pctx) {
        frame::mprpc::MessagePointerT<main::FetchStoreRequest> req_ptr;
        if (_rfetch_stub.request_ptr_) {
            req_ptr = std::move(_rfetch_stub.request_ptr_);
        }
        else {
            req_ptr = frame::mprpc::make_message<main::FetchStoreRequest>();
            req_ptr->shard_id_ = _rreq_msg_ptr->shard_id_;
            req_ptr->storage_id_ = _rreq_msg_ptr->storage_id_;
            req_ptr->path_ = _rreq_msg_ptr->path_;
        }
        req_ptr->chunk_index_ = _chunk_index;
        req_ptr->chunk_offset_ = _chunk_offset;
        const auto err = _pctx->service().sendRequest({_pctx->recipientId()}, req_ptr, lambda);
        if (err) {
            _rprom.set_value(-1);
        }
    }else{
        const auto err = _reng.rpcService().sendRequest({_reng.serverEndpoint()}, _rreq_msg_ptr, lambda);
        if (err) {
            _rprom.set_value(-1);
        }
    }
}

void handle_fetch_store(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::FetchStoreRequest>();
    string local_path;
    
    _ris>>req_ptr->shard_id_;
    _ris>>std::quoted(req_ptr->storage_id_);
    _ris>>std::quoted(req_ptr->path_);
    _ris>>std::quoted(local_path);
    
    req_ptr->storage_id_ = utility::base64_decode(req_ptr->storage_id_);
    
    StoreFetchStub fetch_stub;

    {
        auto lst_req_ptr = frame::mprpc::make_message<main::ListStoreRequest>();

        lst_req_ptr->path_ = req_ptr->path_;
        lst_req_ptr->storage_id_ = req_ptr->storage_id_;

        promise<uint32_t> prom;

        auto lambda = [&prom, &fetch_stub](
            frame::mprpc::ConnectionContext& _rctx,
            frame::mprpc::MessagePointerT<main::ListStoreRequest>& _rsent_msg_ptr,
            frame::mprpc::MessagePointerT<main::ListStoreResponse>& _rrecv_msg_ptr,
            ErrorConditionT const& _rerror
            ) {
                if (_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0) {
                    solid_check(_rrecv_msg_ptr->node_dq_.size() == 1 && _rrecv_msg_ptr->node_dq_.front().name_.empty());
                    fetch_stub.size_ = _rrecv_msg_ptr->node_dq_.front().size_;
                    fetch_stub.compress_chunk_capacity_ = _rrecv_msg_ptr->compress_chunk_capacity_;
                    fetch_stub.compress_algorithm_type_ = _rrecv_msg_ptr->compress_algorithm_type_;

                    prom.set_value(0);
                }
                else if (!_rrecv_msg_ptr) {
                    prom.set_value(-1);
                }
                else {
                    prom.set_value(_rrecv_msg_ptr->error_);
                }
        };
        _reng.rpcService().sendRequest({_reng.serverEndpoint()}, lst_req_ptr, lambda);

        auto fut = prom.get_future();
        solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
        auto err = fut.get();
        if (err) {
            cout << "list store failed for " << req_ptr->path_ << " error = " << err << endl;
            return;
        }

    }

    fetch_stub.ofs_.open(local_path, ofstream::binary);
    
    if(fetch_stub.ofs_){
        
        promise<uint32_t> prom;
        const auto start_time = std::chrono::steady_clock::now();
        fetch_remote_file(nullptr, _reng, prom, fetch_stub, req_ptr);
        
        auto fut = prom.get_future();
        solid_check(fut.wait_for(chrono::seconds(100000)) == future_status::ready, "Taking too long - waited 100 secs");
        auto err = fut.get();
        if(err == 0){
            const auto duration = chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);
            solid_check(fetch_stub.size_ == fetch_stub.decompressed_size_, "Decompressed size "<< fetch_stub.decompressed_size_<<" doesn't match known file size "<<fetch_stub.size_)
            cout<<"File transferred: "<< fetch_stub.decompressed_size_<<' '<<duration.count()<<"msecs"<<endl;
        }else{
            cout<<"File transfer failed: "<<err<<endl; 
        }
    }else{
        cout<<"Error opening for writing local file: "<<local_path<<endl;
    }
}

void handle_fetch_updates(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::FetchBuildUpdatesRequest>();
    
    _ris>>std::quoted(req_ptr->lang_);
    _ris>>std::quoted(req_ptr->os_id_);
    
    while(!_ris.eof()){
        req_ptr->app_id_vec_.emplace_back();
        _ris>>std::quoted(req_ptr->app_id_vec_.back().first);
        req_ptr->app_id_vec_.back().first = utility::base64_decode(req_ptr->app_id_vec_.back().first);
    }
    
    if(!req_ptr->app_id_vec_.empty() && req_ptr->app_id_vec_.back().first.empty()){
        req_ptr->app_id_vec_.pop_back();
    }
    
    if(req_ptr->app_id_vec_.empty()){
        cout<<"Error at least one application id is required!"<<endl;
        return;
    }
    
    promise<void> prom;
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::FetchBuildUpdatesRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<main::FetchBuildUpdatesResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            for(size_t i = 0; i < _rrecv_msg_ptr->app_vec_.size(); ++i){
                const string app_id = utility::base64_encode(_rsent_msg_ptr->app_id_vec_[i].first);
                const string& app_unique = _rrecv_msg_ptr->app_vec_[i].first;
                const string& build_unique = _rrecv_msg_ptr->app_vec_[i].second;
                cout<<app_id<<" -> [app_unique: "<<app_unique<<" build_unique: "<<build_unique<<']'<<endl;
            }
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_fetch(istream& _ris, Engine& _reng){
    string what;
    _ris>>std::quoted(what);
    
    if(what == "app"){
        handle_fetch_app(_ris, _reng);
    }else if(what == "build"){
        handle_fetch_build(_ris, _reng);
    }else if(what == "config"){
        handle_fetch_config(_ris, _reng);
    }else if(what == "store"){
        handle_fetch_store(_ris, _reng);
    }
    else if(what == "updates"){
        handle_fetch_updates(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Create
//-----------------------------------------------------------------------------
#ifdef APP_CONFIG
bool load_app_config(myapps::utility::Application &_rcfg, const string &_path);
bool store_app_config(const myapps::utility::Application &_rcfg, const string &_path);
#endif
string generate_temp_name();

void handle_create_app ( istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::CreateAppRequest>();
    
#ifdef APP_CONFIG
    string config_path;
    //_ris>>std::quoted(config_path);
    
    if(!load_app_config(req_ptr->application_, path(config_path))){
        return;
    }
#endif

    _ris>>req_ptr->application_.name_;
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&     _rctx,
        frame::mprpc::MessagePointerT<main::CreateAppRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::Response>&          _rrecv_msg_ptr,
        ErrorConditionT const&              _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"{\n";
            cout<<"\terror = "<<_rrecv_msg_ptr->error_<<endl;
            if(_rrecv_msg_ptr->error_ == myapps::utility::error_exist.value() || _rrecv_msg_ptr->error_ == 0){
                cout<<"\tmessage = "<<myapps::utility::base64_encode(_rrecv_msg_ptr->message_)<<endl;
            }else{
                cout<<"\tmessage = "<<_rrecv_msg_ptr->message_<<endl;
            }
            cout<<'}'<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

bool load_build_config(myapps::utility::Build &_rbuild_cfg, const string &_path);
bool store_build_config(const myapps::utility::Build &_rbuild_cfg, const string &_path);

void on_upload_receive_last_response(
    frame::mprpc::ConnectionContext& _rctx,
    frame::mprpc::MessagePointerT<main::UploadRequest>&        _rsent_msg_ptr,
    frame::mprpc::MessagePointerT<core::Response>&       _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror,
    promise<void> &prom,
    const string &zip_path)
{
    solid_check(_rrecv_msg_ptr);
    //cout<<"on_upload_receive_last_response"<<endl;
    
    if(_rrecv_msg_ptr){
        if(_rrecv_msg_ptr->error_ == 0){
            cout<<"Success uploading: "<<zip_path<<endl;
        }else{
            cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
        }
    }else{
        cout<<"Error - no response: "<<_rerror.message()<<endl;
    }
	_rsent_msg_ptr->ifs_.close();
    boost::filesystem::remove(zip_path);
    prom.set_value();
}

void on_upload_receive_response(
    frame::mprpc::ConnectionContext& _rctx,
    frame::mprpc::MessagePointerT<main::UploadRequest>&        _rsent_msg_ptr,
    frame::mprpc::MessagePointerT<core::Response>&       _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror,
    promise<void> &prom,
    const string &zip_path)
{
    //cout<<"on_upload_receive_response"<<endl;
    if (!_rsent_msg_ptr->ifs_.eof()) {
        auto lambda = [&prom, &zip_path](
            frame::mprpc::ConnectionContext&        _rctx,
            frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
            frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
            ErrorConditionT const&                  _rerror
        ){
            on_upload_receive_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
        };
        frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponsePart, frame::mprpc::MessageFlagsE::AwaitResponse};
        _rctx.service().sendMessage(_rctx.recipientId(), _rsent_msg_ptr, lambda, flags);
        flags.reset(frame::mprpc::MessageFlagsE::AwaitResponse);
        _rctx.service().sendMessage(_rctx.recipientId(), _rsent_msg_ptr, flags);
    } else {
        auto lambda = [&prom, &zip_path](
            frame::mprpc::ConnectionContext&        _rctx,
            frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
            frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
            ErrorConditionT const&                  _rerror
        ){
            on_upload_receive_last_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
        };
    
        frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponseLast, frame::mprpc::MessageFlagsE::AwaitResponse};
        _rctx.service().sendMessage(_rctx.recipientId(), _rsent_msg_ptr, lambda, flags);
    }
}

//-----------------------------------------------------------------------------
bool load_icon(std::vector<char> &_ricon_blob, const std::string &_path){
    std::ifstream ifs{_path, std::ios::binary};
    
    if(!ifs){
        cout<<"Cannot open: "<<_path<<endl;
        return false;
    }
    
    std::streampos fsize = 0;
    fsize = ifs.tellg();
    ifs.seekg( 0, std::ios::end );
    fsize = ifs.tellg() - fsize;
    ifs.seekg(0);
    
    _ricon_blob.reserve(fsize);
    _ricon_blob.resize(fsize);
    
    char *pbuf = const_cast<char*>(_ricon_blob.data());
    
    ifs.read(pbuf, fsize);
    
    return ifs.gcount() == fsize;
}
namespace {
int64_t get_file_base_time(const string& _file_path)
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
}//namespace
void handle_create_build(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::CreateBuildRequest>();
    
    string config_path, build_path, icon_path;
    _ris>>std::quoted(req_ptr->app_id_)>>std::quoted(req_ptr->unique_);
    _ris>>std::quoted(config_path)>>std::quoted(build_path)>>std::quoted(icon_path);
    
    req_ptr->app_id_ = myapps::utility::base64_decode(req_ptr->app_id_);
    
    if(!load_build_config(req_ptr->build_, path(config_path))){
        return;
    }
    
    if(!load_icon(req_ptr->image_blob_, path(icon_path))){
        return;
    }
    
    //create archive from build_path/*
    
    string zip_path = system_path(get_temp_env() + "/myapps_cli_" + generate_temp_name() + ".zip");

    {
        auto compute_base_time_lambda = [](const std::string& _path, vector<uint8_t>& _rdata) {
            _rdata.resize(sizeof(uint64_t));
            uint64_t base_time = get_file_base_time(_path);
            solid::serialization::binary::store(reinterpret_cast<char*>(_rdata.data()), base_time);
        };

        if (!myapps::utility::archive_create(zip_path, path(build_path), req_ptr->size_, compute_base_time_lambda)) {
            return;
        }
    }
    {
        ifstream ifs(zip_path, std::ifstream::binary);
        if(ifs){
            req_ptr->sha_sum_ = myapps::utility::hex_encode(myapps::utility::sha256(ifs));
            cout<<"sha_sum for "<<zip_path<<": "<<req_ptr->sha_sum_<<endl;
        }else{
            cout<<"could not open "<<zip_path<<" for reading"<<endl;
            return;
        }
    }
    
    req_ptr->size_ += boost::filesystem::file_size(zip_path);
    
    promise<void> prom;
    
    auto lambda = [&prom, &zip_path](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::CreateBuildRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ != 0){
                cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
                prom.set_value();
            }else{
                cout<<"Start uploading build file: "<<zip_path<<" for build tagged: "<<_rsent_msg_ptr->unique_<<endl;
                //now we must upload the file
                auto req_ptr = frame::mprpc::make_message<main::UploadRequest>();
                req_ptr->ifs_.open(zip_path, std::ifstream::binary);
                solid_check(req_ptr->ifs_, "failed open file: "<<zip_path);
                req_ptr->header(_rrecv_msg_ptr->header());
                
                if (!req_ptr->ifs_.eof()) {
                    
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
                        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
                        ErrorConditionT const&                  _rerror
                    ){
                        on_upload_receive_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
                    };
                    
                    solid_log(logger, Verbose, "client: sending " << zip_path << " to " << _rctx.recipientId());
                    frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponsePart, frame::mprpc::MessageFlagsE::AwaitResponse};
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, lambda, flags);
                    flags.reset(frame::mprpc::MessageFlagsE::AwaitResponse);
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, flags);
                } else {
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
                        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
                        ErrorConditionT const&                  _rerror
                    ){
                        on_upload_receive_last_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
                    };
                    
                    solid_log(logger, Verbose, "client: sending " << zip_path << " to " << _rctx.recipientId() << " last");
                    frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponseLast, frame::mprpc::MessageFlagsE::AwaitResponse};
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, lambda, flags);
                }
            }
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
            prom.set_value();
        }
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(600)) == future_status::ready, "Taking too long - waited 600 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_create_media(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::CreateMediaRequest>();
    
    string media_path;
    _ris>>std::quoted(req_ptr->app_id_)>>std::quoted(req_ptr->unique_);

    _ris>>std::quoted(media_path);

    
    req_ptr->app_id_ = myapps::utility::base64_decode(req_ptr->app_id_);
    
    //create archive from build_path/*
    
    string zip_path = system_path(get_temp_env() + "/myapps_cli_" + generate_temp_name() + ".zip");

    {
        auto compute_base_time_lambda = [](const std::string& _path, vector<uint8_t>& _rdata) {
            _rdata.resize(sizeof(uint64_t));
            uint64_t base_time = get_file_base_time(_path);
            solid::serialization::binary::store(reinterpret_cast<char*>(_rdata.data()), base_time);
        };

        if (!myapps::utility::archive_create(zip_path, path(media_path), req_ptr->size_, compute_base_time_lambda)) {
            return;
        }
    }
    
    {
        ifstream ifs(zip_path, std::ifstream::binary);
        if(ifs){
            req_ptr->sha_sum_ = myapps::utility::hex_encode(myapps::utility::sha256(ifs));
            cout<<"sha_sum for "<<zip_path<<": "<<req_ptr->sha_sum_<<endl;
        }else{
            cout<<"could not open "<<zip_path<<" for reading"<<endl;
            return;
        }
    }
    
    req_ptr->size_ += boost::filesystem::file_size(zip_path);
    
    promise<void> prom;
    
    auto lambda = [&prom, &zip_path](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::CreateMediaRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ != 0){
                cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
                prom.set_value();
            }else{
                cout<<"Start uploading media file: "<<zip_path<<" for build tagged: "<<_rsent_msg_ptr->unique_<<endl;
                //now we must upload the file
                auto req_ptr = frame::mprpc::make_message<main::UploadRequest>();
                req_ptr->ifs_.open(zip_path, std::ifstream::binary);
                solid_check(req_ptr->ifs_, "failed open file: "<<zip_path);
                req_ptr->header(_rrecv_msg_ptr->header());
                
                if (!req_ptr->ifs_.eof()) {
                    
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
                        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
                        ErrorConditionT const&                  _rerror
                    ){
                        on_upload_receive_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
                    };
                    
                    solid_log(logger, Verbose, "client: sending " << zip_path << " to " << _rctx.recipientId());
                    frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponsePart, frame::mprpc::MessageFlagsE::AwaitResponse};
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, lambda, flags);
                    flags.reset(frame::mprpc::MessageFlagsE::AwaitResponse);
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, flags);
                } else {
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        frame::mprpc::MessagePointerT<main::UploadRequest>&  _rsent_msg_ptr,
                        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
                        ErrorConditionT const&                  _rerror
                    ){
                        on_upload_receive_last_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
                    };
                    
                    solid_log(logger, Verbose, "client: sending " << zip_path << " to " << _rctx.recipientId() << " last");
                    frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponseLast, frame::mprpc::MessageFlagsE::AwaitResponse};
                    _rctx.service().sendMessage(_rctx.recipientId(), req_ptr, lambda, flags);
                }
            }
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
            prom.set_value();
        }
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_create(istream& _ris, Engine &_reng){
    string what;
    _ris>>std::quoted(what);
    
    if(what == "app"){
        handle_create_app(_ris, _reng);
    }else if(what == "build"){
        handle_create_build(_ris, _reng);
    }else if(what == "media"){
        handle_create_media(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Generate
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

void handle_generate_buid(istream& _ris, Engine &_reng){
    string config_path;
    _ris>>std::quoted(config_path);
    
    myapps::utility::Build cfg;
    
    cfg.name_ = "windows";
    cfg.tag_ = "r1.3";
    
    cfg.dictionary_dq_ = {
        {"", "en-US"},
        {"name", "Bubbles"},
        {"description", "Bubbles description\non multiple\nrows"},
        {"", "ro-RO"},
        {"name", "Bule"},
        {"description", "Descriere Bule\r\npe mai multe\r\nranduri"},
    };
    
    cfg.property_vec_ = {
        {"name", "${name}"},
        {"description", "${description}"}
    };
    
    cfg.configuration_vec_ = myapps::utility::Build::ConfigurationVectorT{
        {
            {
                "windows32bit",
                "${name}",//directory
                myapps::utility::Build::Configuration::compute_flags({"HiddenDirectory"}),
                {"Windows10x86_32", "Windows10x86_64"},
                {{"bin", "bin32"}, {"lib", "lib32"}},
                {"bin/bubbles.exe"},
                {
                    {
                        "Bubbles",
                        "bin/bubbles.exe",
                        "--about",
                        "bin",
                        "bubbles.ico"
                    }
                },
                {
                    {"name", "${name}"},
                    {"description", "${description}"}
                }//properties
            },
            {
                "windows64bit",
                "${name}",//directory
                myapps::utility::Build::Configuration::compute_flags({}),
                {"Windows10x86_64"},
                {{"bin", "bin64"}, {"lib", "lib64"}},
                {"bin/bubbles.exe"},
                {
                    {
                        "${name}",
                        "bin/bubbles.exe",
                        "--help",
                        "bin",
                        "bubbles.ico"
                    }
                },
                {
                    {"name", "${name}"},
                    {"description", "${description}"}
                }//properties
            }
        }
    };
    
    store_build_config(cfg, path(config_path));
    {
        myapps::utility::Build cfg_check;
        load_build_config(cfg_check, path(config_path));
        solid_check(cfg == cfg_check);
    }
}

//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------

void handle_generate(istream& _ris, Engine &_reng){
    string what;
    _ris>>std::quoted(what);

    if(what == "build"){
        handle_generate_buid(_ris, _reng);
    }
}
//-----------------------------------------------------------------------------
//  Parse
//-----------------------------------------------------------------------------

void handle_parse_buid(istream& _ris, Engine& _reng) {
    string config_path;
    _ris >> std::quoted(config_path);

    myapps::utility::Build cfg;
    if (load_build_config(cfg, path(config_path))){
        cout << endl;
        cout << cfg << endl;
    }
}

void handle_parse(istream& _ris, Engine& _reng) {
    string what;
    _ris >> std::quoted(what);

    if (what == "build") {
        handle_parse_buid(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Acquire
//-----------------------------------------------------------------------------

void handle_acquire(istream& _ris, Engine &_reng){
    auto req_ptr = frame::mprpc::make_message<main::AcquireAppRequest>();

    _ris >> std::quoted(req_ptr->app_id_);
    
    req_ptr->app_id_ = myapps::utility::base64_decode(req_ptr->app_id_);

    promise<void> prom;

    auto lambda = [&prom](
        frame::mprpc::ConnectionContext& _rctx,
        frame::mprpc::MessagePointerT<main::AcquireAppRequest>& _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const& _rerror
        ) {
            if (_rrecv_msg_ptr) {
                cout << "Response: error = " << _rrecv_msg_ptr->error_ <<" message = "<< _rrecv_msg_ptr->message_ << endl;
            }
            else {
                cout << "Error - no response: " << _rerror.message() << endl;
            }
            prom.set_value();
    };
    _reng.rpcService().sendRequest({_reng.serverEndpoint()}, req_ptr, lambda);

    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------
// Engine
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

void Engine::onConnectionStart(frame::mprpc::ConnectionContext &_ctx){
    auto req_ptr = frame::mprpc::make_message<main::InitRequest>();
    auto lambda = [this](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<main::InitRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::InitResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ == 0){
                onConnectionInit(_rctx);
            }else{
                cout<<"ERROR initiating connection: error "<<_rrecv_msg_ptr->error_<<':'<<_rrecv_msg_ptr->message_<<endl;
            }
        }
    };
    
    rpcService().sendRequest(_ctx.recipientId(), req_ptr, lambda);
}
//-----------------------------------------------------------------------------

void Engine::onConnectionInit(frame::mprpc::ConnectionContext &_ctx){
    solid_check(!auth_token_.empty());
    std::lock_guard<mutex> lock(mutex_);
    auto req_ptr = frame::mprpc::make_message<core::AuthRequest>();
    req_ptr->pass_ = auth_token_;
    auto lambda = [this](
        frame::mprpc::ConnectionContext&        _rctx,
        frame::mprpc::MessagePointerT<core::AuthRequest>&  _rsent_msg_ptr,
        frame::mprpc::MessagePointerT<core::AuthResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            onAuthResponse(_rctx, *_rrecv_msg_ptr);
        }
    };
        
    rpcService().sendRequest(_ctx.recipientId(), req_ptr, lambda);
}

//-----------------------------------------------------------------------------

void Engine::onAuthResponse(frame::mprpc::ConnectionContext &_ctx, core::AuthResponse &_rresponse){
    solid_check(_rresponse.error_ == 0, "Please authenticate using myapps_client_auth");

    if(!_rresponse.message_.empty()){
        std::lock_guard<mutex> lock(mutex_);
        auth_token_ = _rresponse.message_;
    }
    rrpc_service_.connectionNotifyEnterActiveState(_ctx.recipientId());
}

//-----------------------------------------------------------------------------
// Utilities
//-----------------------------------------------------------------------------

string get_home_env()
{
#ifdef SOLID_ON_WINDOWS
	const char* pname = getenv("HOME");
	if(pname == nullptr){
		const char *pdrive = getenv("HOMEDRIVE");
		if(pdrive == nullptr){
			return "c:";
		}else{
			pname = getenv("HOMEPATH");
			if(pname == nullptr){
				return pdrive; 
			}else{
				return string(pdrive) + pname;
			}
		}
	}
    return pname;
#else
    const char* pname = getenv("HOME");

    return pname == nullptr ? "" : pname;
#endif
}

string env_config_path_prefix()
{
#ifdef SOLID_ON_WINDOWS
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
#else
    return get_home_env() + "/.myapps.dir";
#endif
}

string get_temp_env()
{
#ifdef SOLID_ON_WINDOWS
	const char* v = getenv("TEMP");
    if (v == nullptr) {
        v = getenv("TMP");
        if (v == nullptr) {
            v = "c:";
        }
    }

    return v;
#else
    const char* pname = getenv("temp");
    if(pname == nullptr){
        pname = getenv("tmp");
    }
    return pname == nullptr ? "/tmp" : pname;
#endif
}
//-----------------------------------------------------------------------------

bool read(string& _rs, istream& _ris, size_t _sz)
{
    static constexpr size_t bufcp = 1024 * 2;
    char                    buf[bufcp];
    while (!_ris.eof() && _sz != 0) {
        size_t toread = bufcp;
        if (toread > _sz) {
            toread = _sz;
        }

        _ris.read(buf, toread);
        _rs.append(buf, _ris.gcount());
        _sz -= _ris.gcount();
    }
    return _sz == 0;
}

//-----------------------------------------------------------------------------
#ifdef APP_CONFIG
bool load_app_config(myapps::utility::Application &_rcfg, const string &_path){
    using namespace libconfig;
    Config cfg;
    cfg.setOptions(Config::OptionFsync
                 | Config::OptionSemicolonSeparators
                 | Config::OptionColonAssignmentForGroups
                 | Config::OptionOpenBraceOnSeparateLine);
    try
    {
        cfg.readFile(_path.c_str());
    }
    catch(const FileIOException &fioex)
    {
        std::cerr << "I/O error while reading file." << std::endl;
        return false;
    }
    catch(const ParseException &pex)
    {
        std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
                << " - " << pex.getError() << std::endl;
        return false;
    }
    
    Setting &root = cfg.getRoot();
    
    if(root.exists("dictionary")){
        Setting &names = root.lookup("dictionary");
        
        for(auto dicit = names.begin(); dicit != names.end(); ++dicit){
            _rcfg.dictionary_dq_.emplace_back("", dicit->getName());
            
            for(auto it = dicit->begin(); it != dicit->end(); ++it){
                _rcfg.dictionary_dq_.emplace_back(it->getName(), *it);
            }
        }
    }
    
    if(root.exists("properties")){
        Setting &names = root.lookup("properties");
        
        for(auto it = names.begin(); it != names.end(); ++it){
            _rcfg.property_vec_.emplace_back(it->getName(), *it);
        }
    }

    return true;
}

//-----------------------------------------------------------------------------

bool store_app_config(const myapps::utility::Application &_rcfg, const string &_path){
    using namespace libconfig;
    Config cfg;
    
    cfg.setOptions(Config::OptionFsync
                 | Config::OptionSemicolonSeparators
                 | Config::OptionColonAssignmentForGroups
                 | Config::OptionOpenBraceOnSeparateLine);
    
    Setting &root = cfg.getRoot();
    
    {
        Setting &dic = root.add("dictionary", Setting::TypeGroup);
        Setting *plang = nullptr;
        for(auto v: _rcfg.dictionary_dq_){
            
            if(v.first.empty()){
                plang = &dic.add(v.second, Setting::TypeGroup);
                continue;
            }
            if(plang == nullptr) plang = &dic.add("", Setting::TypeGroup);
            
            plang->add(v.first, Setting::TypeString) = v.second;
        }
    }
    
    {
        Setting &props = root.add("properties", Setting::TypeGroup);
        
        for(auto v: _rcfg.property_vec_){
            props.add(v.first, Setting::TypeString) = v.second;
        }
    }
    
    try
    {
        cfg.writeFile(_path.c_str());
        cerr << "Updated configuration successfully written to: " << _path << endl;
    }
    catch(const FileIOException &fioex)
    {
        cerr << "I/O error while writing file: " << _path << endl;
        return false;
    }
    return true;
}
#endif

//-----------------------------------------------------------------------------
bool load_build_config(myapps::utility::Build& _rcfg, const string& _path) {
    using namespace YAML;
    Node config;
    try {
        config = LoadFile(_path);
    }
    catch (std::runtime_error& err) {
        cout << "Error loading " << _path << ": " << err.what() << endl;
        return false;
    }
    
    if (config["name"]) {
        _rcfg.name_ = config["name"].as<string>();
    }
    else {
        cout << "Error: build name not found" << endl;
        return false;
    }

    if (config["tag"]) {
        _rcfg.tag_ = config["tag"].as<string>();
    }
    else {
        cout << "Error: build tag not found" << endl;
        return false;
    }
    try {
        {
            Node dictionary = config["dictionary"];
            if (dictionary) {
                if (dictionary.Type() == NodeType::Sequence) {
                    for (const_iterator it = dictionary.begin(); it != dictionary.end(); ++it) {
                        Node language = (*it)["language"];
                        if (language) {
                            _rcfg.dictionary_dq_.emplace_back("", language.as<string>());
                        }
                        else {
                            cout << "Error: dictionary item must contain language" << endl;
                            return false;
                        }

                        for (const_iterator it2 = it->begin(); it2 != it->end(); ++it2) {
                            if (it2->first.as<string>() != "language") {
                                _rcfg.dictionary_dq_.emplace_back(it2->first.as<string>(), it2->second.as<string>());
                            }
                        }
                    }
                }
                else {
                    cout << "Error: dictionary should be a sequence" << endl;
                    return false;
                }
            }
        }

        {
            Node properties = config["properties"];
            if (properties) {
                if (properties.Type() == NodeType::Map) {
                    for (const_iterator it = properties.begin(); it != properties.end(); ++it) {
                        _rcfg.property_vec_.emplace_back(it->first.as<string>(), it->second.as<string>());
                    }
                }
                else {
                    cout << "Error: properties entry should be a map" << endl;
                    return false;
                }

            }
        }

        {
            Node configurations = config["configurations"];
            if (configurations) {
                if (configurations.Type() == NodeType::Sequence) {
                    for (const_iterator it = configurations.begin(); it != configurations.end(); ++it) {
                        myapps::utility::Build::Configuration c;
                        if (it->Type() == NodeType::Map) {
                            if ((*it)["name"]) {
                                c.name_ = (*it)["name"].as<string>();
                            }
                            else {
                                cout << "Error: configuration must have a name" << endl;
                                return false;
                            }

                            if ((*it)["directory"]) {
                                c.directory_ = (*it)["directory"].as<string>();
                            }
                            else {
                                cout << "Error: configuration must have a directory" << endl;
                                return false;
                            }

                            if ((*it)["oses"] && (*it)["oses"].Type() == NodeType::Sequence) {
                                Node oses = (*it)["oses"];
                                for (const_iterator it = oses.begin(); it != oses.end(); ++it) {
                                    c.os_vec_.emplace_back(it->as<string>());
                                }
                            }
                            else {
                                cout << "Error: configuration must have an oses sequence field" << endl;
                                return false;
                            }

                            if ((*it)["flags"] && (*it)["flags"].Type() == NodeType::Sequence) {
                                Node flags = (*it)["flags"];
                                for (const_iterator it = flags.begin(); it != flags.end(); ++it) {
                                    c.flags_ |= myapps::utility::Build::Configuration::flag(it->as<string>().c_str());
                                }
                            }

                            if ((*it)["exes"] && (*it)["exes"].Type() == NodeType::Sequence) {
                                Node exes = (*it)["exes"];
                                for (const_iterator it = exes.begin(); it != exes.end(); ++it) {
                                    c.exe_vec_.emplace_back(it->as<string>());
                                }
                            }
                            else {
                                cout << "Error: configuration must have an exes sequence field" << endl;
                                return false;
                            }

                            if ((*it)["mount-points"] && (*it)["mount-points"].Type() == NodeType::Sequence) {
                                Node mounts = (*it)["mount-points"];
                                for (const_iterator it = mounts.begin(); it != mounts.end(); ++it) {
                                    string local;
                                    string remote;
                                    if ((*it)["local"]) {
                                        local = (*it)["local"].as<string>();
                                    }
                                    else {
                                        cout << "Error: mount must contain local field" << endl;
                                        return false;
                                    }

                                    if ((*it)["remote"]) {
                                        remote = (*it)["remote"].as<string>();
                                    }
                                    else {
                                        cout << "Error: mount must contain remote field" << endl;
                                        return false;
                                    }
                                    c.mount_vec_.emplace_back(local, remote);
                                }
                            }
                            else {
                                cout << "Error: configuration must have an mount-points sequence field" << endl;
                                return false;
                            }

                            if ((*it)["properties"] && (*it)["properties"].Type() == NodeType::Map) {
                                Node properties = (*it)["properties"];
                                for (const_iterator it = properties.begin(); it != properties.end(); ++it) {
                                    c.property_vec_.emplace_back(it->first.as<string>(), it->second.as<string>());
                                }
                            }

                            if ((*it)["shortcuts"] && (*it)["shortcuts"].Type() == NodeType::Sequence) {
                                Node shortcuts = (*it)["shortcuts"];
                                for (const_iterator it = shortcuts.begin(); it != shortcuts.end(); ++it) {
                                    myapps::utility::Build::Shortcut s;

                                    s.name_ = (*it)["name"].as<string>();
                                    s.command_ = (*it)["command"].as<string>();
                                    s.arguments_ = (*it)["arguments"].as<string>();
                                    s.run_folder_ = (*it)["run_folder"].as<string>();
                                    s.icon_ = (*it)["icon"].as<string>();

                                    c.shortcut_vec_.emplace_back(std::move(s));
                                }
                            }
                            else {
                                cout << "Error: configuration must have an shortcuts sequence field" << endl;
                                return false;
                            }

                            if ((*it)["media"] && (*it)["media"].Type() == NodeType::Map) {
                                Node media = (*it)["media"];
                                c.media_.name_ = media["name"].as<string>();

                                if (media["entries"] && media["entries"].Type() == NodeType::Sequence) {
                                    Node entries = media["entries"];
                                    for (const_iterator it = entries.begin(); it != entries.end(); ++it) {
                                        myapps::utility::Build::Media::Entry e;

                                        e.thumbnail_path_ = (*it)["thumbnail"].as<string>();
                                        e.path_ = (*it)["file"].as<string>();

                                        c.media_.entry_vec_.emplace_back(std::move(e));
                                    }
                                }
                                else {
                                    cout << "Error: configuration.media must have an entry sequence field" << endl;
                                    return false;
                                }
                            }
                            else {
                                cout << "Error: configuration must have a media map field" << endl;
                                return false;
                            }

                            _rcfg.configuration_vec_.emplace_back(std::move(c));
                        }
                        else {
                            cout << "Error: configurations not a map" << endl;
                            return false;
                        }
                    }
                }
                else {
                    cout << "Error: configurations entry should be a sequence" << endl;
                    return false;
                }

            }
            else {
                cout << "Error: configurations entry should exist" << endl;
                return false;
            }
        }
    }
    catch (std::runtime_error& err) {
        cout << "Error interpreting " << _path << ": " << err.what() << endl;
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------
bool store_build_config(const myapps::utility::Build& _rcfg, const string& _path) {
    using namespace YAML;

    Node config;

    config["name"] = _rcfg.name_;
    config["tag"] = _rcfg.tag_;

    {
        Node dictionary;
        Node item;
        for (auto v : _rcfg.dictionary_dq_) {

            if (v.first.empty()) {
                if (!item.IsNull()) {
                    dictionary.push_back(item);
                }
                item.reset();
                item["language"] = v.second;
                continue;
            }
            else {
                item[v.first] = v.second;
            }
        }
        if (item.IsDefined()) {
            dictionary.push_back(item);
        }
        config["dictionary"] = dictionary;
    }

    {
        Node properties;
        for (auto v : _rcfg.property_vec_) {
            properties[v.first] = v.second;
        }
        config["properties"] = properties;
    }

    {
        Node configurations;
        for (const auto& component : _rcfg.configuration_vec_) {
            Node item;
            item["name"] = component.name_;
            item["directory"] = component.directory_;
            
            {
                Node flags;

                myapps::utility::Build::Configuration::for_each_flag(
                    component.flags_,
                    [&flags](const char* _name) {
                        flags.push_back(std::string(_name));
                    });

                item["flags"] = flags;
            }
            
            {
                Node oses;
                for (auto& v : component.os_vec_) {
                    oses.push_back(v);
                }
                item["oses"] = oses;
            }

            {
                Node exes;
                for (auto& v : component.exe_vec_) {
                    exes.push_back(v);
                }
                item["exes"] = exes;
            }
            {
                Node mounts;
                for (auto& v : component.mount_vec_) {
                    Node mount;
                    mount["local"] = v.first;
                    mount["remote"] = v.second;

                    mounts.push_back(mount);
                }
                item["mount-points"] = mounts;
            }

            {
                Node properties;
                for (auto v : component.property_vec_) {
                    properties[v.first] = v.second;
                }

                item["properties"] = properties;
            }
            {
                Node shortcuts;
                for (auto& v : component.shortcut_vec_) {
                    Node item;
                    item["name"] = v.name_;
                    item["command"] = v.command_;
                    item["arguments"] = v.arguments_;
                    item["icon"] = v.icon_;
                    item["run_folder"] = v.run_folder_;

                    shortcuts.push_back(item);
                }

                item["shortcuts"] = shortcuts;
            }
            {
                Node media;
                media["name"] = component.media_.name_;
                Node media_entries;
                for (auto& e : component.media_.entry_vec_) {
                    Node entry;
                    entry["thumbnail"] = e.thumbnail_path_;
                    entry["file"] = e.path_;

                    media_entries.push_back(entry);
                }
                media["entries"] = media_entries;
            }
            configurations.push_back(item);
        }
        config["configurations"] = configurations;
    }

    std::ofstream fout(_path);
    try {
        fout << config;
    }
    catch (runtime_error& err) {
        cout << "Failed generating yml file: " << err.what() << endl;
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------

string path(const std::string &_path){
    if(_path.empty()){
        return _path;
    }
    if(_path.front() == '~'){
        return get_home_env() + (_path.c_str() + 1);
    }
    return _path;
}

//-----------------------------------------------------------------------------

string system_path(const std::string &_path){
#ifdef SOLID_ON_WINDOWS
    string o;
	for(auto c: _path){
		if(c == '/'){
			o += '\\';
		}else{
			o += c;
		}
	}
    return o;
#else
	return _path;
#endif
}

//-----------------------------------------------------------------------------

string generate_temp_name(){
    uint64_t salt = chrono::steady_clock::now().time_since_epoch().count();

    ostringstream oss;
    oss << salt;
    return oss.str();
}
//-----------------------------------------------------------------------------
void uninstall_cleanup(){
    boost::system::error_code err;

    boost::filesystem::remove_all(env_config_path_prefix(), err);
    boost::filesystem::remove_all(boost::filesystem::path(env_log_path_prefix()).parent_path(), err);
    cout << "Deleted: " << env_config_path_prefix() << " and " << boost::filesystem::path(env_log_path_prefix()).parent_path().generic_string() << endl;
    cin.ignore();
}
}//namespace

