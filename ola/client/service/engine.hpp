#pragma once

#include "boost/filesystem.hpp"
#include <functional>
#include <memory>
#include <string>


#include "ola/common/ola_front_protocol_main.hpp"

namespace ola {
namespace client {
namespace service {

namespace fs = boost::filesystem;

enum struct NodeFlagsE : uint32_t {
    Directory = 0,
    File,
    Hidden,
};

using NodeFlagsT = std::underlying_type<NodeFlagsE>::type;

inline NodeFlagsT node_flag(const NodeFlagsE _flag)
{
    return 1 << static_cast<NodeFlagsT>(_flag);
}

struct GuiProtocolSetup;
struct Descriptor;

struct Configuration {
    using FolderUpdateFunctionT = std::function<void(const std::string&)>;
    using AuthOnResponseFunctionT = std::function<void(uint32_t, const std::string&)>;
    using AuthGetTokenFunctionT = std::function<std::string ()>;

    bool              compress_ = true;
    bool              secure_   = true;
    std::string       path_prefix_;
    std::string       temp_folder_;
    std::string       mount_prefix_;
    std::string       secure_prefix_;
    std::string       app_list_path_;
    FolderUpdateFunctionT folder_update_fnc_;
    AuthOnResponseFunctionT auth_on_response_fnc_;
    AuthGetTokenFunctionT auth_get_token_fnc_;
    size_t            mutex_count_ = 1;
    size_t            cv_count_    = 1;
    std::string       os_;
    std::string       language_;
    std::string       auth_endpoint_;
    uint64_t          max_stream_size_           = 100 * 1024;
    size_t            min_contiguous_read_count_ = 3;
    size_t            media_cache_size_          = 2;
    size_t            update_poll_seconds_       = 5;

    std::string securePath(const std::string& _name) const
    {
        return secure_prefix_ + '/' + _name;
    }
};

class Engine {
    friend struct GuiProtocolSetup;
    struct Implementation;
    std::unique_ptr<Implementation> pimpl_;

public:
    Engine();
    ~Engine();
    void start(const Configuration& _rcfg);
    void stop();

    void relogin();

    void appListUpdate();

    Descriptor* open(const fs::path& _path, uint32_t _create_flags, uint32_t _granted_access);

    void cleanup(Descriptor* _pdesc);

    void close(Descriptor* _pdesc);

    void*& buffer(Descriptor& _rdesc);

    bool info(const fs::path& _path, NodeFlagsT& _rnode_type, uint64_t& _rsize);

    void info(Descriptor* _pdesc, NodeFlagsT& _rnode_type, uint64_t& _rsize);

    bool list(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, NodeFlagsT& _rentry_type, uint64_t& _rsize);

    bool read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);
};

} //namespace service
} //namespace client
} //namespace ola