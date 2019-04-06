
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

#include "ola/common/utility/crypto.hpp"

#include "ola/common/ola_front_protocol.hpp"

#include <signal.h>

#include "boost/program_options.hpp"

#include "boost/filesystem.hpp"

#include "zip.h"

#define LIBCONFIGXX_STATIC
#define LIBCONFIG_STATIC
#include "libconfig.h++"

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

namespace {

const solid::LoggerT logger("cli");

using AioSchedulerT = frame::Scheduler<frame::aio::Reactor>;

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
};

//-----------------------------------------------------------------------------

using RecipientQueueT = std::queue<frame::mprpc::RecipientId>;

struct Engine {
    frame::mprpc::ServiceT& rrpc_service_;
    const Parameters&       rparams_;
    atomic<bool>            running_;
    mutex                   mutex_;
    string                  auth_token_;
    thread                  auth_thread_;
    RecipientQueueT         auth_recipient_q_;
    string                  path_prefix_;

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
        ifstream ifs(authTokenStorePath(), std::ifstream::binary);

        if (ifs) {
            read(auth_token_, ifs, -1);
        }
    }

    string authTokenStorePath() const
    {
        return path_prefix_ + "/auth.data";
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
        return params().front_endpoint;
    }

    void onConnectionStart(frame::mprpc::ConnectionContext& _ctx);
    void authRun();
    void onAuthResponse(frame::mprpc::ConnectionContext& _ctx, AuthResponse& _rresponse);

    void stop()
    {
        running_ = false;
        if (auth_thread_.joinable()) {
            auth_thread_.join();
        }
        if (!auth_token_.empty()) {
            Directory::create_all(path_prefix_.c_str());
            ofstream ofs(authTokenStorePath());
            ofs << auth_token_;
            ofs.flush();
        }
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

} //namespace

int main(int argc, char* argv[])
{
    Parameters params;

    if (parse_arguments(params, argc, argv))
        return 0;
#ifndef SOLID_ON_WINDOWS
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
            *argv[0] == '.' ? argv[0] + 2 : argv[0],
            params.dbg_modules,
            params.dbg_buffered,
            3,
            1024 * 1024 * 64);
    }
    AioSchedulerT          scheduler;
    frame::Manager         manager;
    FunctionWorkPool<>     fwp{WorkPoolConfiguration()};
    frame::aio::Resolver   resolver(fwp);
    frame::mprpc::ServiceT rpc_service(manager);
    Engine                 engine(rpc_service, params);

    scheduler.start(1);

    {
        string home = get_home_env();
        if (home.empty()) {
            home = '.';
        }
        home += "/.ola";
        engine.path_prefix_ = std::move(home);
    }

    engine.start();

    configure_service(engine, scheduler, resolver);

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
        options_description desc("ola_auth_service");
        // clang-format off
        desc.add_options()
            ("help,h", "List program options")
            ("debug-modules,M", value<vector<string>>(&_par.dbg_modules), "Debug logging modules")
            ("debug-address,A", value<string>(&_par.dbg_addr), "Debug server address (e.g. on linux use: nc -l 9999)")
            ("debug-port,P", value<string>(&_par.dbg_port)->default_value("9999"), "Debug server port (e.g. on linux use: nc -l 9999)")
            ("debug-console,C", value<bool>(&_par.dbg_console)->implicit_value(true)->default_value(false), "Debug console")
            ("debug-buffered,S", value<bool>(&_par.dbg_buffered)->implicit_value(true)->default_value(false), "Debug buffered")
            ("secure,s", value<bool>(&_par.secure)->implicit_value(true)->default_value(false), "Use SSL to secure communication")
            ("compress", value<bool>(&_par.compress)->implicit_value(true)->default_value(false), "Use Snappy to compress communication")
            ("front", value<std::string>(&_par.front_endpoint)->default_value(string("localhost:") + ola::front::default_port()), "OLA Front Endpoint");
        // clang-format off
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
struct FrontSetup {
    template <class T>
    void operator()(front::ProtocolT& _rprotocol, TypeToType<T> _t2t, const front::ProtocolT::TypeIdT& _rtid)
    {
        _rprotocol.registerMessage<T>(complete_message<T>, _rtid);
    }
};

void configure_service(Engine &_reng, AioSchedulerT &_rsch, frame::aio::Resolver &_rres){
    auto                        proto = front::ProtocolT::create();
    frame::mprpc::Configuration cfg(_rsch, proto);

    front::protocol_setup(FrontSetup(), *proto);

    cfg.client.name_resolve_fnc = frame::mprpc::InternetResolverF(_rres, ola::front::default_port());

    cfg.client.connection_start_state = frame::mprpc::ConnectionState::Passive;
    
    {
//         auto connection_stop_lambda = [&_rctx](frame::mpipc::ConnectionContext &_ctx){
//             engine_ptr->onConnectionStop(_ctx);
//         };
        auto connection_start_lambda = [&_reng](frame::mprpc::ConnectionContext &_ctx){
            _reng.onConnectionStart(_ctx);
        };
        //cfg.connection_stop_fnc = std::move(connection_stop_lambda);
        cfg.client.connection_start_fnc = std::move(connection_start_lambda);
    }

    if (_reng.params().secure) {
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
    
    if(_reng.params().compress){
        frame::mprpc::snappy::setup(cfg);
    }

    _reng.rpcService().start(std::move(cfg));
}

void handle_help(istream& _ris, Engine &_reng){
    cout<<"Commands:\n\n";
    cout<<"> list oses\n\n";
    cout<<"> list apps o/a/A i|n|s|d [*field_name]\n";
    cout<<"\to - owned applications\n";
    cout<<"\ta - aquired applications\n";
    cout<<"\tA - All applications\n";
    cout<<"\n\ti - id\n\tn - name\n\ts - short description\n\td - description\n\n";
    cout<<"> list builds APP_ID\n\n";
    cout<<"> generate app ~/path/to/app.cfg\n\n";
    cout<<"> generate build ~/path/to/build.cfg\n\n";
    cout<<"> create app ~/path/to/app.cfg\n\n";
    cout<<"> create build APP_ID BUILD_TAG ~/path/to/build.cfg ~/path/to/build_folder\r\n";
    cout<<endl;
}

//-----------------------------------------------------------------------------
//  Command handlers
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
//  List
//-----------------------------------------------------------------------------

void handle_list_oses(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<ListOSesRequest>();
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<ListOSesRequest>&  _rsent_msg_ptr,
        std::shared_ptr<ListOSesResponse>& _rrecv_msg_ptr,
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

//-----------------------------------------------------------------------------

void handle_list_apps(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<ListAppsRequest>();
    
    //o - owned applications
    //a - aquired applications
    //A - all applications
    _ris>>req_ptr->choice_;
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<ListAppsRequest>&  _rsent_msg_ptr,
        std::shared_ptr<ListAppsResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            for(const auto& app_id: _rrecv_msg_ptr->app_id_vec_){
                cout<<'\t'<<utility::base64_encode(app_id)<<endl;
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    
}

//-----------------------------------------------------------------------------

void handle_list_store(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<ListStoreRequest>();
    
    _ris>>req_ptr->storage_id_;
    _ris>>req_ptr->path_;
    
    req_ptr->storage_id_ = utility::base64_decode(req_ptr->storage_id_);
    
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<ListStoreRequest>&  _rsent_msg_ptr,
        std::shared_ptr<ListStoreResponse>& _rrecv_msg_ptr,
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    
}

//-----------------------------------------------------------------------------

void handle_list(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "oses"){
        handle_list_oses(_ris, _reng);
    }else if(what == "apps"){
        handle_list_apps(_ris, _reng);
    }else if(what == "store"){
        handle_list_store(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Fetch
//-----------------------------------------------------------------------------

ostream& operator<<(ostream &_ros, const utility::AppConfig &_cfg){
    _ros<<"Name : "<<_cfg.name_<<endl;
    _ros<<"Short: "<<_cfg.short_description_<<endl;
    _ros<<"Desc : "<<_cfg.description_<<endl;
    _ros<<"Names: ";
    for(const auto& p: _cfg.name_vec_){
        _ros<<"{["<<p.first<<"]["<<p.second<<"]} ";
    }
    _ros<<endl;
    return _ros;
}

void handle_fetch_app(istream& _ris, Engine &_reng){
     auto req_ptr = make_shared<FetchAppRequest>();
    
    _ris>>req_ptr->app_id_;
    _ris>>req_ptr->lang_;
    
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<FetchAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<FetchAppResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout<<"Builds: ";
            for(const auto& build_id: _rrecv_msg_ptr->build_id_vec_){
                cout<<utility::base64_encode(build_id)<<endl;
            }
            cout<<endl;
            cout<<_rrecv_msg_ptr->config_;
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

//-----------------------------------------------------------------------------

ostream& operator<<(ostream &_ros, const utility::BuildConfig &_cfg){
    _ros<<"Name : "<<_cfg.name_<<endl;
    _ros<<"Tag: "<<_cfg.tag_<<endl;
    _ros<<"Components: {\n";
    for(const auto& c: _cfg.component_vec_){
        _ros<<"Name: "<<c.name_<<endl;
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
            _ros<<"Name:   "<<s.name_<<endl;
            _ros<<"Command:"<<s.command_<<endl;
            _ros<<"Run Fld:"<<s.run_folder_<<endl;
            _ros<<"Icon:   "<<s.icon_<<endl;
            _ros<<endl;
        }
        _ros<<"}\n";
    }
    _ros<<'}'<<endl;
    return _ros;
}

void handle_fetch_build(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<FetchBuildRequest>();
    
    _ris>>req_ptr->app_id_;
    _ris>>req_ptr->build_id_;
    _ris>>req_ptr->lang_;
    _ris>>req_ptr->os_id_;
    
    req_ptr->app_id_ = utility::base64_decode(req_ptr->app_id_);
    req_ptr->build_id_ = utility::base64_decode(req_ptr->build_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<FetchBuildRequest>&  _rsent_msg_ptr,
        std::shared_ptr<FetchBuildResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr && _rrecv_msg_ptr->error_ == 0){
            cout<<"{\n";
            cout<<"Remote Root: "<<utility::base64_encode(_rrecv_msg_ptr->storage_id_)<<endl;
            cout<<_rrecv_msg_ptr->config_;
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

//-----------------------------------------------------------------------------

void handle_fetch(istream& _ris, Engine& _reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_fetch_app(_ris, _reng);
    }else if(what == "build"){
        handle_fetch_build(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Create
//-----------------------------------------------------------------------------

bool load_app_config(ola::utility::AppConfig &_rcfg, const string &_path);
bool store_app_config(const ola::utility::AppConfig &_rcfg, const string &_path);
string generate_temp_name();

void handle_create_app ( istream& _ris, Engine &_reng){
    string config_path;
    _ris>>config_path;
    
    auto req_ptr = make_shared<CreateAppRequest>();
    
    if(!load_app_config(req_ptr->config_, path(config_path))){
        return;
    }
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&     _rctx,
        std::shared_ptr<CreateAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<Response>&          _rrecv_msg_ptr,
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

//-----------------------------------------------------------------------------

bool load_build_config(ola::utility::BuildConfig &_rbuild_cfg, const string &_path);
bool store_build_config(const ola::utility::BuildConfig &_rbuild_cfg, const string &_path);

bool zip_create(const string &_zip_path, string _root, uint64_t &_rsize);

void on_upload_receive_last_response(
    frame::mprpc::ConnectionContext& _rctx,
    std::shared_ptr<UploadBuildRequest>&        _rsent_msg_ptr,
    std::shared_ptr<Response>&       _rrecv_msg_ptr,
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
    std::shared_ptr<UploadBuildRequest>&        _rsent_msg_ptr,
    std::shared_ptr<Response>&       _rrecv_msg_ptr,
    ErrorConditionT const&           _rerror,
    promise<void> &prom,
    const string &zip_path)
{
    //cout<<"on_upload_receive_response"<<endl;
    if (!_rsent_msg_ptr->ifs_.eof()) {
        auto lambda = [&prom, &zip_path](
            frame::mprpc::ConnectionContext&        _rctx,
            std::shared_ptr<UploadBuildRequest>&  _rsent_msg_ptr,
            std::shared_ptr<Response>& _rrecv_msg_ptr,
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
            std::shared_ptr<UploadBuildRequest>&  _rsent_msg_ptr,
            std::shared_ptr<Response>& _rrecv_msg_ptr,
            ErrorConditionT const&                  _rerror
        ){
            on_upload_receive_last_response(_rctx, _rsent_msg_ptr, _rrecv_msg_ptr, _rerror, prom, zip_path);
        };
    
        frame::mprpc::MessageFlagsT flags{frame::mprpc::MessageFlagsE::ResponseLast, frame::mprpc::MessageFlagsE::AwaitResponse};
        _rctx.service().sendMessage(_rctx.recipientId(), _rsent_msg_ptr, lambda, flags);
    }
}

//-----------------------------------------------------------------------------

void handle_create_build(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<CreateBuildRequest>();
    
    string config_path, build_path;
    _ris>>req_ptr->app_id_>>req_ptr->unique_;
    _ris>>config_path>>build_path;
    
    req_ptr->app_id_ = ola::utility::base64_decode(req_ptr->app_id_);
    
    if(!load_build_config(req_ptr->config_, path(config_path))){
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
            req_ptr->sha_sum_ = ola::utility::sha256(ifs);
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
        std::shared_ptr<CreateBuildRequest>&  _rsent_msg_ptr,
        std::shared_ptr<Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            if(_rrecv_msg_ptr->error_ != 0){
                cout<<"Error: "<<_rrecv_msg_ptr->error_<<" message: "<<_rrecv_msg_ptr->message_<<endl;
                prom.set_value();
            }else{
                cout<<"Start uploading build file: "<<zip_path<<" for build tagged: "<<_rsent_msg_ptr->unique_<<endl;
                //now we must upload the file
                auto req_ptr = make_shared<UploadBuildRequest>();
                req_ptr->ifs_.open(zip_path, std::ifstream::binary);
                solid_check(req_ptr->ifs_, "failed open file: "<<zip_path);
                req_ptr->header(_rrecv_msg_ptr->header());
                
                if (!req_ptr->ifs_.eof()) {
                    
                    auto lambda = [&prom, &zip_path](
                        frame::mprpc::ConnectionContext&        _rctx,
                        std::shared_ptr<UploadBuildRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<Response>& _rrecv_msg_ptr,
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
                        std::shared_ptr<UploadBuildRequest>&  _rsent_msg_ptr,
                        std::shared_ptr<Response>& _rrecv_msg_ptr,
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
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

//-----------------------------------------------------------------------------

void handle_create(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_create_app(_ris, _reng);
    }else if(what == "build"){
        handle_create_build(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
//  Generate
//-----------------------------------------------------------------------------

void handle_generate_app(istream& _ris, Engine &_reng){
    string config_path;
    _ris>>config_path;
    
    ola::utility::AppConfig cfg;
    cfg.name_ = "generic_name";
    cfg.description_ = "multi-line app description";
    cfg.short_description_ = "short single line app description";
    cfg.name_vec_.emplace_back(make_pair("name_en", "generic_name"));
    store_app_config(cfg, path(config_path));
    {
        ola::utility::AppConfig cfg_check;
        load_app_config(cfg_check, path(config_path));
        solid_check(cfg == cfg_check);
    }
}

//-----------------------------------------------------------------------------

void handle_generate_buid(istream& _ris, Engine &_reng){
    string config_path;
    _ris>>config_path;
    
    ola::utility::BuildConfig cfg;
    
    cfg.name_ = "windows";
    cfg.tag_ = "r1.3";
    cfg.component_vec_ = ola::utility::BuildConfig::ComponentVectorT{
        {
            {
                "windows32bit",
                {"Windows10x86_32", "Windows10x86_64"},
                {{"bin", "bin32"}, {"lib", "lib32"}},
                {"bin/bubbles.exe"},
                {
                    {
                        "Bubbles",
                        "bin/bubbles.exe",
                        "bin",
                        "bubbles_icon"
                    }
                }
            },
            {
                "windows64bit",
                {"Windows10x86_64"},
                {{"bin", "bin64"}, {"lib", "lib64"}},
                {"bin/bubbles.exe"},
                {
                    {
                        "Bubbles",
                        "bin/bubbles.exe",
                        "bin",
                        "bubbles_icon"
                    }
                }
            }
        }
    };
    
    store_build_config(cfg, path(config_path));
    {
        ola::utility::BuildConfig cfg_check;
        load_build_config(cfg_check, path(config_path));
        solid_check(cfg == cfg_check);
    }
}

//-----------------------------------------------------------------------------

void handle_generate(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_generate_app(_ris, _reng);
    }else if(what == "build"){
        handle_generate_buid(_ris, _reng);
    }
}


//-----------------------------------------------------------------------------
//  Acquire
//-----------------------------------------------------------------------------

void handle_acquire_app(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<AcquireAppRequest>();
    
    _ris>>req_ptr->app_id_;
    
    req_ptr->app_id_ = ola::utility::base64_decode(req_ptr->app_id_);
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<AcquireAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"Acquire response: "<<_rrecv_msg_ptr->error_<<" "<<_rrecv_msg_ptr->message_<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
};

//-----------------------------------------------------------------------------

void handle_acquire(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_acquire_app(_ris, _reng);
    }
}

//-----------------------------------------------------------------------------
// Engine
//-----------------------------------------------------------------------------

void Engine::authRun(){
    
    shared_ptr<AuthRequest> req_ptr;
    
    while(running_){
        
        if(!req_ptr){
            req_ptr = std::make_shared<AuthRequest>();
            cout<<"User: "<<flush;cin>>req_ptr->auth_;
            cout<<"Pass: "<<flush;cin>>req_ptr->pass_;
        
            req_ptr->pass_ = ola::utility::sha256(req_ptr->pass_);
        }
        
        promise<int> prom;
        
        auto lambda = [this, &prom, &req_ptr](
            frame::mprpc::ConnectionContext&        _rctx,
            std::shared_ptr<AuthRequest>&  _rsent_msg_ptr,
            std::shared_ptr<AuthResponse>& _rrecv_msg_ptr,
            ErrorConditionT const&                  _rerror
        ){
            if(_rrecv_msg_ptr){
                solid_log(logger, Info, "received authentication response: "<<_rrecv_msg_ptr->error_<<" "<<_rrecv_msg_ptr->message_);
                if(_rrecv_msg_ptr->error_ == 0){
                    //authentication success
                    {
                        std::lock_guard<mutex> lock(mutex_);
                        auth_token_ = _rrecv_msg_ptr->message_;
                        
                        solid_check(!auth_recipient_q_.empty());
                        
                        rrpc_service_.connectionNotifyEnterActiveState(auth_recipient_q_.front());
                        auth_recipient_q_.pop();
                    }
                    prom.set_value(0);
                }else{
                    //authentication fail
                    req_ptr.reset();
                    cout<<"Fail: "<<_rrecv_msg_ptr->message_<<endl;
                    prom.set_value(-1);
                }
            }else{
                prom.set_value(-1);
            }
        };
        
        {
            lock_guard<mutex> lock(mutex_);
            solid_check(!auth_recipient_q_.empty());
    
            while(!auth_recipient_q_.empty()){
                auto err = rpcService().sendRequest(auth_recipient_q_.front(), req_ptr, lambda);
                if(err){
                    if(auth_recipient_q_.size() == 1){
                        err = rpcService().sendRequest(serverEndpoint().c_str(), req_ptr, lambda, auth_recipient_q_.front());
                        if(err){
                            auth_recipient_q_.pop();
                            prom.set_value(-1);
                            break;
                        }else{
                            //success
                            break;
                        }
                    }else{
                        auth_recipient_q_.pop();
                    }
                }else{
                    //success
                    break;
                }
            }
        }
        
        auto fut = prom.get_future();
        
        solid_check(fut.wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
        
        if(fut.get() == 0){
            lock_guard<mutex> lock(mutex_);
            auto lambda = [this](
                frame::mprpc::ConnectionContext&        _rctx,
                std::shared_ptr<AuthRequest>&  _rsent_msg_ptr,
                std::shared_ptr<AuthResponse>& _rrecv_msg_ptr,
                ErrorConditionT const&                  _rerror
            ){
                if(_rrecv_msg_ptr){
                    onAuthResponse(_rctx, *_rrecv_msg_ptr);
                }
            };
            
            while(!auth_recipient_q_.empty()){
                rpcService().sendRequest(auth_recipient_q_.front(), std::make_shared<AuthRequest>(auth_token_), lambda);
                auth_recipient_q_.pop();
            }
            break;
        }
    }
}

//-----------------------------------------------------------------------------

void Engine::onConnectionStart(frame::mprpc::ConnectionContext &_ctx){
    string auth_token;
    {
        std::lock_guard<mutex> lock(mutex_);
        if(!auth_token_.empty()){
            auth_token = auth_token_;
        }else if(auth_recipient_q_.empty()){
            auth_recipient_q_.emplace(_ctx.recipientId());
        }else if(_ctx.recipientId() == auth_recipient_q_.front()){
            return;
        }else{
            auth_recipient_q_.emplace(_ctx.recipientId());
        }
    }
    if(!auth_token.empty()){
        auto req_ptr = std::make_shared<AuthRequest>(auth_token);
        auto lambda = [this](
            frame::mprpc::ConnectionContext&        _rctx,
            std::shared_ptr<AuthRequest>&  _rsent_msg_ptr,
            std::shared_ptr<AuthResponse>& _rrecv_msg_ptr,
            ErrorConditionT const&                  _rerror
        ){
            if(_rrecv_msg_ptr){
                onAuthResponse(_rctx, *_rrecv_msg_ptr);
            }
        };
        
        rpcService().sendRequest(_ctx.recipientId(), req_ptr, lambda);
    }else{
        if(auth_thread_.joinable()){
            auth_thread_.join();
        }
        auth_thread_ = std::thread(&Engine::authRun, this);
    }
}

//-----------------------------------------------------------------------------

void Engine::onAuthResponse(frame::mprpc::ConnectionContext &_ctx, AuthResponse &_rresponse){
    if(_rresponse.error_ == 0){
        {
            std::lock_guard<mutex> lock(mutex_);
            auth_token_ = _rresponse.message_;
        }
        rrpc_service_.connectionNotifyEnterActiveState(_ctx.recipientId());
    }else{
        bool   start_auth_thread = false;
        {
            std::lock_guard<mutex> lock(mutex_);
            auth_recipient_q_.emplace(_ctx.recipientId());
            
            if(auth_recipient_q_.size() != 1){
                return;
            }
        }
        if(auth_thread_.joinable()){
            auth_thread_.join();
        }
        auth_thread_ = std::thread(&Engine::authRun, this);
    }
}

//-----------------------------------------------------------------------------
// Utilities
//-----------------------------------------------------------------------------

string get_home_env()
{
    const char* pname = getenv("HOME");

    return pname == nullptr ? "" : pname;
}

string get_temp_env()
{
    const char* pname = getenv("temp");
    if(pname == nullptr){
        pname = getenv("tmp");
    }
    return pname == nullptr ? "/tmp" : pname;
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
        _rs.append(buf, toread);
        _sz -= toread;
    }
    return _sz == 0;
}

//-----------------------------------------------------------------------------

bool load_app_config(ola::utility::AppConfig &_rcfg, const string &_path){
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
    
    if(!root.lookupValue("name", _rcfg.name_)){
        cout<<"Error: app name not found in configuration"<<endl;
        return false;
    }
    if(!root.lookupValue("description", _rcfg.description_)){
        cout<<"Error: app description not found in configuration"<<endl;
        return false;
    }
    if(!root.lookupValue("short_description", _rcfg.short_description_)){
        cout<<"Error: app short_description not found in configuration"<<endl;
        return false;
    }
    
    if(root.exists("names")){
        Setting &names = root.lookup("names");
        
        for(auto it = names.begin(); it != names.end(); ++it){
            _rcfg.name_vec_.emplace_back(it->getName(), *it);
        }
    }

    return true;
}

//-----------------------------------------------------------------------------

bool store_app_config(const ola::utility::AppConfig &_rcfg, const string &_path){
    using namespace libconfig;
    Config cfg;
    
    cfg.setOptions(Config::OptionFsync
                 | Config::OptionSemicolonSeparators
                 | Config::OptionColonAssignmentForGroups
                 | Config::OptionOpenBraceOnSeparateLine);
    
    Setting &root = cfg.getRoot();
    
    root.add("name", Setting::TypeString) = _rcfg.name_;
    root.add("description", Setting::TypeString) = _rcfg.description_;
    root.add("short_description", Setting::TypeString) = _rcfg.short_description_;
    
    Setting &names = root.add("names", Setting::TypeGroup);
    
    for(auto v: _rcfg.name_vec_){
        names.add(v.first, Setting::TypeString) = v.second;
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

//-----------------------------------------------------------------------------

bool load_build_config(ola::utility::BuildConfig &_rcfg, const string &_path){
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
    
    if(!root.lookupValue("name", _rcfg.name_)){
        cout<<"Error: build name not found in configuration"<<endl;
        return false;
    }
    
    if(!root.lookupValue("tag", _rcfg.tag_)){
        cout<<"Error: build name not found in configuration"<<endl;
        return false;
    }
    
    if(root.exists("components")){
        Setting &components = root.lookup("components");
        for(auto it = components.begin(); it != components.end(); ++it){
            ola::utility::BuildConfig::Component c;
            
            if(!it->lookupValue("name", c.name_)){
                cout<<"Error: component name not found in configuration"<<endl;
                return false;
            }
            
            if(it->exists("oses")){
                Setting &oses = it->lookup("oses");
                for(auto it = oses.begin(); it != oses.end(); ++it){
                    c.os_vec_.emplace_back(static_cast<const string&>(*it));
                }
            }else{
                cout<<"Error: component oses not fount in configuration"<<endl;
                return false;
            }
            
            
            if(it->exists("exes")){
                Setting &exes = it->lookup("exes");
                for(auto it = exes.begin(); it != exes.end(); ++it){
                    c.exe_vec_.emplace_back(static_cast<const string&>(*it));
                }
            }else{
                cout<<"Error: component exes not fount in configuration"<<endl;
                return false;
            }
            
            if(it->exists("mounts")){
                Setting &mounts = it->lookup("mounts");
                
                for(auto it = mounts.begin(); it != mounts.end(); ++it){
                    string local;
                    string remote;
                    it->lookupValue("local", local);
                    it->lookupValue("remote", remote);
                    
                    c.mount_vec_.emplace_back(local, remote);
                }
            }else{
                cout<<"Error: component mounts not fount in configuration"<<endl;
                return false;
            }
            
            if(it->exists("shortcuts")){
                Setting &shortcuts = it->lookup("shortcuts");
                
                for(auto it = shortcuts.begin(); it != shortcuts.end(); ++it){
                    ola::utility::BuildConfig::Shortcut s;
                    
                    it->lookupValue("name", s.name_);
                    it->lookupValue("command", s.command_);
                    it->lookupValue("run_folder", s.run_folder_);
                    it->lookupValue("icon", s.icon_);
                    
                    c.shortcut_vec_.emplace_back(std::move(s));
                }
            }else{
                cout<<"Error: component mounts not fount in configuration"<<endl;
                return false;
            }
            
            _rcfg.component_vec_.emplace_back(std::move(c));
        }
    }else{
        cout<<"Error: no component found"<<endl;
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------

bool store_build_config(const ola::utility::BuildConfig &_rcfg, const string &_path){
    using namespace libconfig;
    Config cfg;
    
    cfg.setOptions(Config::OptionFsync
                 | Config::OptionSemicolonSeparators
                 | Config::OptionColonAssignmentForGroups
                 | Config::OptionOpenBraceOnSeparateLine);
    
    Setting &root = cfg.getRoot();
    
    root.add("name", Setting::TypeString) = _rcfg.name_;
    root.add("tag", Setting::TypeString) = _rcfg.tag_;
    
    Setting &os_specific = root.add("components", Setting::TypeList);
    
    for(const auto &component: _rcfg.component_vec_){
        Setting &cmp_g = os_specific.add(Setting::TypeGroup);
        {
            cmp_g.add("name", Setting::TypeString) = component.name_;
            Setting &oses = cmp_g.add("oses", Setting::TypeArray);
            for(auto &v: component.os_vec_){
                oses.add(Setting::TypeString) = v;
            }
            Setting &mount = cmp_g.add("mounts", Setting::TypeList);
            for(auto& v: component.mount_vec_){
                Setting &g  = mount.add(Setting::TypeGroup);
                g.add("local", Setting::TypeString) = v.first;
                g.add("remote", Setting::TypeString) = v.second;
            }
            Setting &exe = cmp_g.add("exes", Setting::TypeArray);
            for(auto &v: component.exe_vec_){
                exe.add(Setting::TypeString) = v;
            }
            
            Setting &shortcut_list = cmp_g.add("shortcuts", Setting::TypeList);
            for(auto &v: component.shortcut_vec_){
                Setting &g  = shortcut_list.add(Setting::TypeGroup);
                g.add("name", Setting::TypeString) = v.name_;
                g.add("command", Setting::TypeString) = v.command_;
                g.add("icon", Setting::TypeString) = v.icon_;
                g.add("run_folder", Setting::TypeString) = v.run_folder_;
            }
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
	string path = _path.string();
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
    string path = _path.string();
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

}//namespace

