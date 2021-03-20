#include "solid/frame/manager.hpp"
#include "solid/frame/scheduler.hpp"
#include "solid/frame/service.hpp"
#include "solid/system/directory.hpp"
#include "solid/system/log.hpp"

#include "solid/frame/aio/aioresolver.hpp"

#include "solid/frame/mprpc/mprpccompression_snappy.hpp"
#include "solid/frame/mprpc/mprpcconfiguration.hpp"
#include "solid/frame/mprpc/mprpcservice.hpp"
#include "solid/frame/mprpc/mprpcsocketstub_openssl.hpp"
#include "solid/frame/mprpc/mprpcprotocol_serialization_v3.hpp"

#include "ola/common/utility/encode.hpp"
#include "ola/common/ola_front_protocol_main.hpp"

#include "ola/common/utility/version.hpp"

#include "ola/client/utility/auth_file.hpp"

#include <signal.h>

#include "boost/program_options.hpp"

#include "boost/filesystem.hpp"

#include <iomanip>

#define REPLXX_STATIC
#include "replxx.hxx"
#include "zip.h"

#include "yaml-cpp/yaml.h"

#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>

using namespace std;
using namespace solid;
using namespace ola;
using namespace ola::front;

using Replxx = replxx::Replxx;

namespace fs = boost::filesystem;

namespace {

const solid::LoggerT logger("cli");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;

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

    vector<string> dbg_modules = {"ola::.*:VIEW"};
    string         dbg_addr;
    string         dbg_port;
    bool           dbg_console  = false;
    bool           dbg_buffered = false;
    bool           secure;
    bool           compress;
    string         front_endpoint;
    string         secure_prefix;
    string         auth_token;

    string securePath(const string& _name) const
    {
        return secure_prefix + '/' + _name;
    }
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
            ola::client::utility::auth_read(path, auth_endpoint_, auth_user_, auth_token_);
        }
        else {
            solid_check(!rparams_.front_endpoint.empty(), "front_enpoint required");
            auth_endpoint_ = rparams_.front_endpoint;
            auth_token_ = ola::utility::base64_decode(rparams_.auth_token);
        }
        solid_check(!auth_token_.empty(), "Please authenticate using ola_client_auth application");
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
    r += "\\MyApps.space\\client";
    return r;
}

} //namespace

int main(int argc, char* argv[])
{
    Parameters params;

    if (parse_arguments(params, argc, argv))
        return 0;

#ifndef SOLID_ON_WINDOWS
    signal(SIGPIPE, SIG_IGN);
#else
    TCHAR szFileName[MAX_PATH];

    GetModuleFileName(NULL, szFileName, MAX_PATH);

    fs::path exe_path{szFileName};

    params.secure_prefix = (exe_path.parent_path() / params.secure_prefix).generic_string();
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
            (env_log_path_prefix() + "\\log\\cli").c_str(),
            params.dbg_modules,
            params.dbg_buffered,
            3,
            1024 * 1024 * 64);
    }
    AioSchedulerT          scheduler;
    frame::Manager         manager;
    CallPool<void()>       cwp{WorkPoolConfiguration(), 1};
    frame::aio::Resolver   resolver(cwp);
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
            rx.history_add(line);
            break;
        }

        if (cmd == "list") {
            handle_list(iss, engine);
            rx.history_add(line);
        } else if (cmd == "fetch") {
            handle_fetch(iss, engine);
            rx.history_add(line);
        } else if (cmd == "create") {
            handle_create(iss, engine);
            rx.history_add(line);
        } else if (cmd == "generate") {
            handle_generate(iss, engine);
            rx.history_add(line);
        } else if (cmd == "parse") {
            handle_parse(iss, engine);
            rx.history_add(line);
        } else if (cmd == "acquire") {
            handle_acquire(iss, engine);
            rx.history_add(line);
        } else if (cmd == "help" || line == "h") {
            handle_help(iss, engine);
            rx.history_add(line);
        } else if (cmd == "change") {
            handle_change(iss, engine);
            rx.history_add(line);
        } else if (cmd == "clear") {
            rx.clear_screen();

            rx.history_add(line);
        } else if (cmd == "history") {
            //for (size_t i = 0, sz = rx.history_size(); i < sz; ++i) {
            //    std::cout << std::setw(4) << i << ": " << rx.history_line(i) << "\n";
            //}
            auto h = rx.history_scan();
            for (size_t i = 0; h.next(); ++i) {
                std::cout << std::setw(4) << i << ": " << h.get().text() << "\n";
            }

            rx.history_add(line);
        }
    }
    rx.history_save(history_file);
    cerr << "command history written to: " << history_file << endl;
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
    rpc_service.stop(); //need this because rpc_service uses the engine
    return 0;
}

namespace {
//-----------------------------------------------------------------------------
bool parse_arguments(Parameters& _par, int argc, char* argv[])
{
    using namespace boost::program_options;
    try {
        options_description desc("ola_client_cli");
        // clang-format off
        desc.add_options()
            ("help,h", "List program options")
            ("version,v", "Version")
            ("debug-modules,M", value<vector<string>>(&_par.dbg_modules), "Debug logging modules")
            ("debug-address,A", value<string>(&_par.dbg_addr), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&_par.dbg_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&_par.dbg_console)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-buffered,S", value<bool>(&_par.dbg_buffered)->implicit_value(true)->default_value(false), "Debug buffered")
            ("unsecure", value<bool>(&_par.secure)->implicit_value(false)->default_value(true), "Use SSL to secure communication")
            ("compress", value<bool>(&_par.compress)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("front-endpoint", value<std::string>(&_par.front_endpoint)->default_value(string(OLA_FRONT_URL)), "MyApps.space Front Endpoint")
            ("auth", value<std::string>(&_par.auth_token), "Authentication token")
            ("secure-prefix", value<std::string>(&_par.secure_prefix)->default_value("certs"), "Secure Path prefix")
            ("uninstall-cleanup", "Uninstall cleanup")
        ;
        // clang-format off
        variables_map vm;
        store(parse_command_line(argc, argv, desc), vm);
        notify(vm);
        if (vm.count("help")) {
            cout << desc << "\n";
            return true;
        }

        if (vm.count("version")) {
            cout << ola::utility::version_full() << endl;
            cout << "SolidFrame: " << solid::version_full() << endl;
            return true;
        }

        if (vm.count("uninstall-cleanup")) {
            uninstall_cleanup();
            return true;
        }

        return false;
    } catch (exception& e) {
        cout << e.what() << "\n";
        exit(0);
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
    auto                        proto = frame::mprpc::serialization_v3::create_protocol<reflection::v1::metadata::Variant, ola::front::ProtocolTypeIndexT>(
        ola::utility::metadata_factory,
        [&](auto& _rmap) {
            auto lambda = [&](const ola::front::ProtocolTypeIndexT _id, const std::string_view _name, auto const& _rtype) {
                using TypeT = typename std::decay_t<decltype(_rtype)>::TypeT;
                _rmap.template registerMessage<TypeT>(_id, _name, complete_message<TypeT>);
            };
            ola::front::core::configure_protocol(lambda);
            ola::front::main::configure_protocol(lambda);
        }
    );
    frame::mprpc::Configuration cfg(_rsch, proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, ola::front::default_port());

    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;
    
    {
//         auto connection_stop_lambda = [&_rctx](frame::mpipc::ConnectionContext &_ctx){
//             engine_ptr->onConnectionStop(_ctx);
//         };
        auto connection_start_lambda = [&_reng](frame::mprpc::ConnectionContext &_rctx){
            _rctx.anyTuple() = std::make_tuple(core::version, main::version, ola::utility::version);
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
            frame::mprpc::openssl::NameCheckSecureStart{"front.myapps.space"});
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
    auto req_ptr = make_shared<main::ListOSesRequest>();
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::ListOSesRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::ListOSesResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"{\n";
            for(const auto & os: _rrecv_msg_ptr->osvec_){
                cout<<os<<'\n';
            }
            cout<<'}'<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_list_apps(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::ListAppsRequest>();
    
    //o - owned applications
    //a - aquired applications
    //A - all applications
    _ris>>req_ptr->choice_;
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::ListAppsRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::ListAppsResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            for(const auto& app_id: _rrecv_msg_ptr->app_vec_){
                cout<<'\t'<<utility::base64_encode(app_id.id_)<<"\t"<<app_id.unique_<<'\t'<<app_id.name_<<endl;
            }
            cout<<"}"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
    
}

//-----------------------------------------------------------------------------

void handle_list_store(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::ListStoreRequest>();
    
    _ris>>std::quoted(req_ptr->storage_id_);
    _ris>>std::quoted(req_ptr->path_);
    
    req_ptr->storage_id_ = utility::base64_decode(req_ptr->storage_id_);
    
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::ListStoreRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::ListStoreResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            for(const auto& node: _rrecv_msg_ptr->node_dq_){
                cout<<'\t'<<node.name_<<'\t'<<node.size_<<endl;
            }
            cout<<"}"<<endl;
        }else if(!_rrecv_msg_ptr){
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }else{
            cout<<"Error received from server: "<<_rrecv_msg_ptr->error_ <<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
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
    auto req_ptr = make_shared<main::ChangeAppItemStateRequest>();

    char item_type = '\0';//m/M->media, b/B->build
    string state_name;

    _ris >> item_type >> std::quoted(req_ptr->app_id_) >> std::quoted(req_ptr->os_id_) >> std::quoted(req_ptr->item_.name_) >> std::quoted(state_name);

    auto state = ola::utility::app_item_state_from_name(state_name.c_str());
    if (state == ola::utility::AppItemStateE::StateCount) {
        cout << "Error: invalid state name " << state_name << endl;
        return;
    }

    if (item_type == 'b' || item_type == 'B')
    {
        req_ptr->item_.type(ola::utility::AppItemTypeE::Build);
    }
    else if (item_type == 'm' || item_type == 'M') {
        req_ptr->item_.type(ola::utility::AppItemTypeE::Media);
    }
    else {
        cout << "Error: invalid item type " << item_type << endl;
        return;
    }
    
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);
    req_ptr->new_state_ = static_cast<uint8_t>(state);

    promise<void> prom;

    auto lambda = [&prom](
        frame::mprpc::ConnectionContext& _rctx,
        std::shared_ptr<ola::front::main::ChangeAppItemStateRequest>& _rsent_msg_ptr,
        std::shared_ptr<ola::front::core::Response>& _rrecv_msg_ptr,
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

    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
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
     auto req_ptr = make_shared<main::FetchAppRequest>();
    
    _ris>>std::quoted(req_ptr->app_id_);
    _ris>>std::quoted(req_ptr->os_id_);
    
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::FetchAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::FetchAppResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout << "Items: {"<<endl;
            for(const auto& item: _rrecv_msg_ptr->item_vec_){
                //cout<<utility::base64_encode(build_id)<<endl;
                cout<<'\t'<<item.name_<<" "<< ola::utility::app_item_type_name(item.type())<<" "<< ola::utility::app_item_state_name(item.state()) <<endl;
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
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
    auto req_ptr = make_shared<main::FetchBuildRequest>();
    
    _ris>>std::quoted(req_ptr->app_id_);
    _ris>>std::quoted(req_ptr->build_id_);
    
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);
    req_ptr->build_id_ = req_ptr->build_id_;//utility::base64_decode(req_ptr->build_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::FetchBuildRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::FetchBuildResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

void handle_fetch_config(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::FetchBuildConfigurationRequest>();
    
    _ris>>std::quoted(req_ptr->app_id_);
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
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::FetchBuildConfigurationRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::FetchBuildConfigurationResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout << "Build Remote Root: "<<utility::base64_encode(_rrecv_msg_ptr->build_storage_id_)<<endl;
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
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

bool fetch_remote_file(Engine &_reng, promise<uint32_t> &_rprom, ofstream &_rofs, std::shared_ptr<main::FetchStoreRequest>&  _rreq_msg_ptr, uint64_t &_rfile_size){
    
    auto lambda = [&_rprom, &_rofs, &_reng, &_rfile_size](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::FetchStoreRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::FetchStoreResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ == 0){
                _rrecv_msg_ptr->ioss_.seekg(0);
                _rfile_size += stream_copy(_rofs, _rrecv_msg_ptr->ioss_);
                if(_rrecv_msg_ptr->size_ > 0){
                    _rsent_msg_ptr->offset_ = _rfile_size;
                    fetch_remote_file(_reng, _rprom, _rofs, _rsent_msg_ptr, _rfile_size);
                }else{
                    _rprom.set_value(0);
                }
            }else{
                _rprom.set_value(_rrecv_msg_ptr->error_);
            }
        }else{
            _rprom.set_value(-1);
        }
    };
    
    auto err = _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), _rreq_msg_ptr, lambda);
    if(err){
        _rprom.set_value(-1);
    }
    return true;
}

void handle_fetch_store(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::FetchStoreRequest>();
    string local_path;
    
    _ris>>std::quoted(req_ptr->storage_id_);
    _ris>>std::quoted(req_ptr->path_);
    _ris>>std::quoted(local_path);
    
    req_ptr->storage_id_ = utility::base64_decode(req_ptr->storage_id_);
    
    ofstream ofs(local_path);
    
    if(ofs){
        promise<uint32_t> prom;
        uint64_t file_size = 0;
        fetch_remote_file(_reng, prom, ofs, req_ptr, file_size);
        
        auto fut = prom.get_future();
        solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
        auto err = fut.get();
        if(err == 0){
            cout<<"File transferred: "<<file_size<<endl;
        }else{
            cout<<"File transfer failed: "<<err<<endl; 
        }
    }else{
        cout<<"Error opening for writing local file: "<<local_path<<endl;
    }
}

void handle_fetch_updates(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::FetchBuildUpdatesRequest>();
    
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
        std::shared_ptr<main::FetchBuildUpdatesRequest>&  _rsent_msg_ptr,
        std::shared_ptr<main::FetchBuildUpdatesResponse>& _rrecv_msg_ptr,
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
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
bool load_app_config(ola::utility::Application &_rcfg, const string &_path);
bool store_app_config(const ola::utility::Application &_rcfg, const string &_path);
#endif
string generate_temp_name();

void handle_create_app ( istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::CreateAppRequest>();
    
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
        std::shared_ptr<main::CreateAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<core::Response>&          _rrecv_msg_ptr,
        ErrorConditionT const&              _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"{\n";
            cout<<"\terror = "<<_rrecv_msg_ptr->error_<<endl;
            if(_rrecv_msg_ptr->error_ == ola::utility::error_exist.value() || _rrecv_msg_ptr->error_ == 0){
                cout<<"\tmessage = "<<ola::utility::base64_encode(_rrecv_msg_ptr->message_)<<endl;
            }else{
                cout<<"\tmessage = "<<_rrecv_msg_ptr->message_<<endl;
            }
            cout<<'}'<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

bool load_build_config(ola::utility::Build &_rbuild_cfg, const string &_path);
bool store_build_config(const ola::utility::Build &_rbuild_cfg, const string &_path);

bool zip_create(const string &_zip_path, string _root, uint64_t &_rsize);

void on_upload_receive_last_response(
    frame::mprpc::ConnectionContext& _rctx,
    std::shared_ptr<main::UploadRequest>&        _rsent_msg_ptr,
    std::shared_ptr<core::Response>&       _rrecv_msg_ptr,
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
    std::shared_ptr<main::UploadRequest>&        _rsent_msg_ptr,
    std::shared_ptr<core::Response>&       _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror,
    promise<void> &prom,
    const string &zip_path)
{
    //cout<<"on_upload_receive_response"<<endl;
    if (!_rsent_msg_ptr->ifs_.eof()) {
        auto lambda = [&prom, &zip_path](
            frame::mprpc::ConnectionContext&        _rctx,
            std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
            std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
            std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
            std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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

void handle_create_build(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::CreateBuildRequest>();
    
    string config_path, build_path, icon_path;
    _ris>>std::quoted(req_ptr->app_id_)>>std::quoted(req_ptr->unique_);
    _ris>>std::quoted(config_path)>>std::quoted(build_path)>>std::quoted(icon_path);
    
    req_ptr->app_id_ = ola::utility::base64_decode(req_ptr->app_id_);
    
    if(!load_build_config(req_ptr->build_, path(config_path))){
        return;
    }
    
    if(!load_icon(req_ptr->image_blob_, path(icon_path))){
        return;
    }
    
    //create archive from build_path/*
    
    string zip_path = system_path(get_temp_env() + "/ola_client_cli_" + generate_temp_name() + ".zip");

    
    if(!zip_create(zip_path, path(build_path), req_ptr->size_)){
        return;
    }
    
    {
        ifstream ifs(zip_path, std::ifstream::binary);
        if(ifs){
            req_ptr->sha_sum_ = ola::utility::sha256hex(ifs);
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
        std::shared_ptr<main::CreateBuildRequest>&  _rsent_msg_ptr,
        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ != 0){
                cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
                prom.set_value();
            }else{
                cout<<"Start uploading build file: "<<zip_path<<" for build tagged: "<<_rsent_msg_ptr->unique_<<endl;
                //now we must upload the file
                auto req_ptr = make_shared<main::UploadRequest>();
                req_ptr->ifs_.open(zip_path, std::ifstream::binary);
                solid_check(req_ptr->ifs_, "failed open file: "<<zip_path);
                req_ptr->header(_rrecv_msg_ptr->header());
                
                if (!req_ptr->ifs_.eof()) {
                    
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
                        std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------

void handle_create_media(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<main::CreateMediaRequest>();
    
    string media_path;
    _ris>>std::quoted(req_ptr->app_id_)>>std::quoted(req_ptr->unique_);

    _ris>>std::quoted(media_path);

    
    req_ptr->app_id_ = ola::utility::base64_decode(req_ptr->app_id_);
    
    //create archive from build_path/*
    
    string zip_path = system_path(get_temp_env() + "/ola_client_cli_" + generate_temp_name() + ".zip");

    
    if(!zip_create(zip_path, path(media_path), req_ptr->size_)){
        return;
    }
    
    {
        ifstream ifs(zip_path, std::ifstream::binary);
        if(ifs){
            req_ptr->sha_sum_ = ola::utility::sha256hex(ifs);
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
        std::shared_ptr<main::CreateMediaRequest>&  _rsent_msg_ptr,
        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ != 0){
                cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
                prom.set_value();
            }else{
                cout<<"Start uploading media file: "<<zip_path<<" for build tagged: "<<_rsent_msg_ptr->unique_<<endl;
                //now we must upload the file
                auto req_ptr = make_shared<main::UploadRequest>();
                req_ptr->ifs_.open(zip_path, std::ifstream::binary);
                solid_check(req_ptr->ifs_, "failed open file: "<<zip_path);
                req_ptr->header(_rrecv_msg_ptr->header());
                
                if (!req_ptr->ifs_.eof()) {
                    
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
                        std::shared_ptr<main::UploadRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
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
    
    ola::utility::Build cfg;
    
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
    
    cfg.configuration_vec_ = ola::utility::Build::ConfigurationVectorT{
        {
            {
                "windows32bit",
                "${name}",//directory
                ola::utility::Build::Configuration::compute_flags({"HiddenDirectory"}),
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
                ola::utility::Build::Configuration::compute_flags({}),
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
        ola::utility::Build cfg_check;
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

    ola::utility::Build cfg;
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
    auto req_ptr = make_shared<main::AcquireAppRequest>();

    _ris >> std::quoted(req_ptr->app_id_);
    
    req_ptr->app_id_ = ola::utility::base64_decode(req_ptr->app_id_);

    promise<void> prom;

    auto lambda = [&prom](
        frame::mprpc::ConnectionContext& _rctx,
        std::shared_ptr<main::AcquireAppRequest>& _rsent_msg_ptr,
        std::shared_ptr<core::Response>& _rrecv_msg_ptr,
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
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);

    auto fut = prom.get_future();
    solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    fut.get();
}

//-----------------------------------------------------------------------------
// Engine
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------

void Engine::onConnectionStart(frame::mprpc::ConnectionContext &_ctx){
    auto req_ptr = std::make_shared<main::InitRequest>();
    auto lambda = [this](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<main::InitRequest>&  _rsent_msg_ptr,
        std::shared_ptr<core::InitResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ == 0){
                onConnectionInit(_rctx);
            }else{
                cout<<"ERROR initiating connection: version "<<_rctx.peerVersionMajor()<<'.'<<_rctx.peerVersionMinor()<<" error "<<_rrecv_msg_ptr->error_<<':'<<_rrecv_msg_ptr->message_<<endl;
            }
        }
    };
    
    rpcService().sendRequest(_ctx.recipientId(), req_ptr, lambda);
}
//-----------------------------------------------------------------------------

void Engine::onConnectionInit(frame::mprpc::ConnectionContext &_ctx){
    solid_check(!auth_token_.empty());
    std::lock_guard<mutex> lock(mutex_);
    auto req_ptr = std::make_shared<core::AuthRequest>();
    req_ptr->pass_ = auth_token_;
    auto lambda = [this](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<core::AuthRequest>&  _rsent_msg_ptr,
        std::shared_ptr<core::AuthResponse>& _rrecv_msg_ptr,
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
    solid_check(_rresponse.error_ == 0, "Please authenticate using ola_client_auth");

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
    r += "\\MyApps.space";
    return r;
#else
    return get_home_env() + "/.myapps.space";
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

string envConfigPathPrefix()
{
    const char* v = getenv("APPDATA");
    if (v == nullptr) {
        v = getenv("LOCALAPPDATA");
        if (v == nullptr) {
            v = "c:";
        }
    }

    string r = v;
    r += "\\MyApps.space";
    return r;
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
bool load_app_config(ola::utility::Application &_rcfg, const string &_path){
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

bool store_app_config(const ola::utility::Application &_rcfg, const string &_path){
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
bool load_build_config(ola::utility::Build& _rcfg, const string& _path) {
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
                        ola::utility::Build::Configuration c;
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
                                    c.flags_ |= ola::utility::Build::Configuration::flag(it->as<string>().c_str());
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
                                    ola::utility::Build::Shortcut s;

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
                                        ola::utility::Build::Media::Entry e;

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
bool store_build_config(const ola::utility::Build& _rcfg, const string& _path) {
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

                ola::utility::Build::Configuration::for_each_flag(
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

bool zip_add_file(zip_t *_pzip, const boost::filesystem::path &_path, size_t _base_path_len, uint64_t &_rsize){
	string path = _path.generic_string();
    zip_source_t *psrc = zip_source_file(_pzip, path.c_str(), 0, 0);
    if(psrc != nullptr){
        _rsize += file_size(_path);
        zip_int64_t err = zip_file_add(_pzip, (path.c_str() + _base_path_len), psrc, ZIP_FL_ENC_UTF_8);
        cout<<"zip_add_file: "<<(path.c_str() + _base_path_len)<<" rv = "<<err<<endl;
        if(err < 0){
            zip_source_free(psrc);
        }
    }
    return true;
}

//-----------------------------------------------------------------------------

bool zip_add_dir(zip_t *_pzip, const boost::filesystem::path &_path, size_t _base_path_len, uint64_t &_rsize){
    using namespace boost::filesystem;
    string path = _path.generic_string();
    zip_int64_t err = zip_dir_add(_pzip, (path.c_str() + _base_path_len), ZIP_FL_ENC_UTF_8);
    
    cout<<"zip_add_dir: "<<(path.c_str() + _base_path_len)<<" rv = "<<err<<endl;
    
    for (directory_entry& x : directory_iterator(_path)){
        auto p = x.path();
        if(is_directory(p)){
            zip_add_dir(_pzip, p, _base_path_len, _rsize);
        }else{
            zip_add_file(_pzip, p, _base_path_len, _rsize);
        }        
    }
    return true;
}

//-----------------------------------------------------------------------------

bool unzip(const std::string& _zip_path, const std::string& _fld, uint64_t& _total_size)
{
    using namespace boost::filesystem;
    
    int err;
    zip_t *pzip = zip_open(_zip_path.c_str(), ZIP_RDONLY, &err);
    zip_stat_t stat;
    constexpr size_t bufcp = 1024 * 64;
    char buf[bufcp];
    
    for (int64_t i = 0; i < zip_get_num_entries(pzip, 0); i++) {
        if (zip_stat_index(pzip, i, 0, &stat) == 0) {
            _total_size += stat.size;
            cout<<stat.name<<" "<<stat.size<<endl;
            size_t name_len = strlen(stat.name);
            if(stat.name[name_len - 1] == '/'){
                //folder
                create_directory(_fld + '/' + stat.name);
            }else{
                zip_file *pzf = zip_fopen_index(pzip, i, 0);
                
                if(pzf){
                    std::ofstream ofs(_fld + '/' + stat.name);
                    uint64_t fsz = 0;
                    do{
                        auto v =  zip_fread(pzf, buf, bufcp);
                        if(v > 0){
                            ofs.write(buf, v);
                            fsz += v;
                        }else{
                            break;
                        }
                    }while(true);
                    if(fsz != stat.size){
                        return false;
                    }
                }else{
                    return false;
                }
            }
        }
    }
    return true;
}

//-----------------------------------------------------------------------------

bool zip_create(const string &_zip_path, string _root, uint64_t &_rsize){
    using namespace boost::filesystem;
    
    int err;
    zip_t *pzip = zip_open(_zip_path.c_str(), ZIP_CREATE| ZIP_EXCL, &err);
    
    if(pzip == nullptr){
        zip_error_t error;
        zip_error_init_with_code(&error, err);
        cout<<"Failed creating zip: "<<zip_error_strerror(&error)<<endl;
        zip_error_fini(&error);
        return false;
    }
    
    if(!_root.empty() && _root.back() != '/'){
        _root += '/';
    }
    
    cout<<"Creating zip archive: "<<_zip_path <<" from "<<_root<<endl;
    
    _rsize = 0;
    
    if(!is_directory(_root)){
        cout<<"Path: "<<_root<<" not a directory"<<endl;
        return false;
    }
    
    for (directory_entry& x : directory_iterator(_root)){
        auto p = x.path();
        if(is_directory(p)){
            zip_add_dir(pzip, p, _root.size(), _rsize);
        }else{
            zip_add_file(pzip, p, _root.size(), _rsize);
        }
        
    }
    zip_close(pzip);
    if(0){
        remove_all(get_temp_env() + "/ola_client_cli_unzip");
        create_directory(get_temp_env() + "/ola_client_cli_unzip");
        uint64_t total_size = 0;
        unzip(_zip_path, get_temp_env() + "/ola_client_cli_unzip", total_size);
        solid_check(total_size == _rsize);
    }
    return true;
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

