#pragma once

#include <memory>
#include <string>
#include <functional>

namespace ola {
namespace client {
namespace service {

struct GuiProtocolSetup;

struct Configuration {
    using GuiStartFunctionT = std::function<bool(int)>;

    bool        compress_;
    bool        secure_;
    std::string front_endpoint_;
	std::string path_prefix_;
    GuiStartFunctionT gui_start_fnc_;

    Configuration()
        : compress_(true)
        , secure_(true)
    {
    }
};

class Engine {
    friend struct GuiProtocolSetup;
    struct Data;
    std::unique_ptr<Data> pimpl_;

public:
    Engine();
    ~Engine();
    void start(const Configuration& _rcfg);
    void stop();
};

} //namespace service
} //namespace client
} //namespace ola