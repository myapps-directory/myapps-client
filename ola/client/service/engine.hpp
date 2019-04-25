#pragma once

#include <functional>
#include <memory>
#include <string>
#include "ola/client/utility/arrvec.hpp"

namespace ola {
namespace client {
namespace service {

using EntryIdT = ola::client::utility::ArrVec<16, size_t>;

enum struct EntryTypeE {
	Directory,
	File
};

struct GuiProtocolSetup;

struct Configuration {
    using GuiStartFunctionT = std::function<void(int)>;
    using GuiFailFunctionT  = std::function<void()>;

    bool              compress_;
    bool              secure_;
    std::string       front_endpoint_;
    std::string       path_prefix_;
    GuiStartFunctionT gui_start_fnc_;
    GuiFailFunctionT  gui_fail_fnc_;

    Configuration()
        : compress_(true)
        , secure_(true)
    {
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

	bool entry(const EntryIdT& _entry_id, size_t& _rcrt, std::wstring& _rname, uint64_t& _rsize, EntryTypeE& _rentry_type);
    bool entry(const wchar_t* _path, EntryIdT& _entry_id);
    bool entry(const EntryIdT& _entry_id, uint64_t& _rsize, EntryTypeE& _rentry_type);
};

} //namespace service
} //namespace client
} //namespace ola