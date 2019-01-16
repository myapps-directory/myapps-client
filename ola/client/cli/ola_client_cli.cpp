
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
bool   read(string& _rs, istream& _ris, size_t _sz);

//-----------------------------------------------------------------------------
//      Parameters
//-----------------------------------------------------------------------------
struct Parameters {
    Parameters()
    {
    }

    vector<string> dbg_modules;
    string         dbg_addr;
    string         dbg_port;
    bool           dbg_console;
    bool           dbg_buffered;
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
        ifstream ifs(authTokenStorePath());

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

void handle_list(istream& _ris, Engine& _reng);
void handle_create(istream& _ris, Engine& _reng);
void handle_generate(istream& _ris, Engine& _reng);

} //namespace

int main(int argc, char* argv[])
{
    Parameters params;

    if (parse_arguments(params, argc, argv))
        return 0;

    signal(SIGPIPE, SIG_IGN);

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
    FunctionWorkPool       fwp{WorkPoolConfiguration()};
    frame::aio::Resolver   resolver(fwp);
    frame::mprpc::ServiceT rpc_service(manager);
    Engine                 engine(rpc_service, params);
    ErrorConditionT        err;

    err = scheduler.start(1);

    if (err) {
        solid_log(logger, Error, "Starting aio scheduler: " << err.message());
        return 0;
    }

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
        } else if (cmd == "create") {
            handle_create(iss, engine);
        } else if (cmd == "generate") {
            handle_generate(iss, engine);
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
            ("debug-unbuffered,S", value<bool>(&_par.dbg_buffered)->implicit_value(false)->default_value(true), "Debug unbuffered")
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
    solid_check(false); //this method should not be called
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

    ErrorConditionT err = _reng.rpcService().reconfigure(std::move(cfg));

    if (err) {
        cout << "Error starting ipcservice: " << err.message() << endl;
        exit(0);
    }
}

//-----------------------------------------------------------------------------
// Command handlers
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

void handle_list_apps(istream& _ris, Engine &_reng){
    auto req_ptr = make_shared<ListAppsRequest>();
    //o - owned applications
    //a - aquired applications
    //A - all applications
    _ris>>req_ptr->choice_;
    //i - id
    //n - name
    //s - short description
    //d - description
    _ris>>req_ptr->static_fields_;
    while(!_ris.eof()){
        string f;
        _ris>>f;
        
        if(!f.empty()){
            req_ptr->field_vec_.emplace_back(f);
        }else{
            break;
        }
    }
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<ListAppsRequest>&  _rsent_msg_ptr,
        std::shared_ptr<ListAppsResponse>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"{\n";
            auto lambda = [](const char _static_field, const string &_field, const string &_v, const bool _is_first, const bool _is_last){
                if(_is_first){
                    cout<<"\t{\n";
                }
                
                switch(_static_field){
                    case 'i': cout<<"\tID:\t"<<ola::utility::base64_encode(_v)<<"\n";break;
                    case 'n': cout<<"\tName:\t"<<_v<<"\n";break;
                    case 's': cout<<"\tShort:\t"<<_v<<"\n";break;
                    case 'd': cout<<"\tDesc:\t"<<_v<<"\n";break;
                    default:
                        cout<<'\t'<<_field<<":\t"<<_v<<"\n";break;
                }
                
                if(_is_last){
                    cout<<"\t}\n";
                }
            };
            _rrecv_msg_ptr->visit(lambda, _rsent_msg_ptr->static_fields_, _rsent_msg_ptr->field_vec_);
            cout<<"}"<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
    
}

void handle_list(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "oses"){
        handle_list_oses(_ris, _reng);
    }else if(what == "apps"){
        handle_list_apps(_ris, _reng);
    }
}

bool load_app_config(ola::utility::AppConfig &_app_cfg, const string &_path);
bool store_app_config(const ola::utility::AppConfig &_app_cfg, const string &_path);

void handle_create_app(istream& _ris, Engine &_reng){
    string config_path;
    _ris>>config_path;
    
    auto req_ptr = make_shared<CreateAppRequest>();
    
    if(!load_app_config(req_ptr->config_, config_path)){
        return;
    }
    
    promise<void> prom;
    
    auto lambda = [&prom](
        frame::mprpc::ConnectionContext&        _rctx,
        std::shared_ptr<CreateAppRequest>&  _rsent_msg_ptr,
        std::shared_ptr<Response>& _rrecv_msg_ptr,
        ErrorConditionT const&                  _rerror
    ){
        if(_rrecv_msg_ptr){
            cout<<"{\n";
            cout<<"\terror = "<<_rrecv_msg_ptr->error_<<endl;
            cout<<"\tmessage = "<<_rrecv_msg_ptr->message_<<endl;
            cout<<'}'<<endl;
        }else{
            cout<<"Error - no response: "<<_rerror.message()<<endl;
        }
        prom.set_value();
    };
    _reng.rpcService().sendRequest(_reng.serverEndpoint().c_str(), req_ptr, lambda);
    
    solid_check(prom.get_future().wait_for(chrono::seconds(100)) == future_status::ready, "Taking too long - waited 100 secs");
}

void handle_create(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_create_app(_ris, _reng);
    }
}

void handle_generate_app(istream& _ris, Engine &_reng){
    string config_path;
    _ris>>config_path;
    
    ola::utility::AppConfig cfg;
    cfg.name_ = "generic_name";
    cfg.description_ = "multi-line app description";
    cfg.short_description_ = "short single line app description";
    cfg.name_vec_.emplace_back(make_pair("name_en", "generic_name"));
    store_app_config(cfg, config_path);
}

void handle_generate(istream& _ris, Engine &_reng){
    string what;
    _ris>>what;
    
    if(what == "app"){
        handle_generate_app(_ris, _reng);
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

bool load_app_config(ola::utility::AppConfig &_app_cfg, const string &_path){
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
    
    if(!root.lookupValue("name", _app_cfg.name_)){
        cout<<"Error: app name not found in configuration"<<endl;
        return false;
    }
    if(!root.lookupValue("description", _app_cfg.description_)){
        cout<<"Error: app description not found in configuration"<<endl;
        return false;
    }
    if(!root.lookupValue("short_description", _app_cfg.short_description_)){
        cout<<"Error: app short_description not found in configuration"<<endl;
        return false;
    }
    
    if(root.exists("names")){
        Setting &names = root.lookup("names");
        
        for(auto it = names.begin(); it != names.end(); ++it){
            _app_cfg.name_vec_.emplace_back(it->getName(), *it);
        }
    }

    return true;
}

bool store_app_config(const ola::utility::AppConfig &_app_cfg, const string &_path){
    using namespace libconfig;
    Config cfg;
    
    cfg.setOptions(Config::OptionFsync
                 | Config::OptionSemicolonSeparators
                 | Config::OptionColonAssignmentForGroups
                 | Config::OptionOpenBraceOnSeparateLine);
    
    Setting &root = cfg.getRoot();
    
    root.add("name", Setting::TypeString) = _app_cfg.name_;
    root.add("description", Setting::TypeString) = _app_cfg.description_;
    root.add("short_description", Setting::TypeString) = _app_cfg.short_description_;
    
    Setting &names = root.add("names", Setting::TypeGroup);
    
    for(auto v: _app_cfg.name_vec_){
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

}//namespace

