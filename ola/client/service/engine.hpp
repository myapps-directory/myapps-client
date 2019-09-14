#pragma once

#include "boost/filesystem.hpp"
#include "ola/client/utility/arrvec.hpp"
#include <functional>
#include <memory>
#include <string>

namespace ola {
namespace client {
namespace service {

namespace fs = boost::filesystem;

using EntryIdT = ola::client::utility::ArrVec<16, size_t>;

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
    using GuiStartFunctionT = std::function<void(int)>;
    using GuiFailFunctionT  = std::function<void()>;

    bool              compress_ = true;
    bool              secure_   = true;
    std::string       front_endpoint_;
    std::string       path_prefix_;
    std::string       temp_folder_;
    std::string       mount_prefix_;
    GuiStartFunctionT gui_start_fnc_;
    GuiFailFunctionT  gui_fail_fnc_;
    size_t            mutex_count_ = 1;
    size_t            cv_count_    = 1;
    std::string       os_;
    std::string       language_;
    uint64_t          max_stream_size_           = 100 * 1024;
    size_t            min_contiguous_read_count_ = 3;
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

    Descriptor* open(const fs::path& _path, uint32_t _create_flags);

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