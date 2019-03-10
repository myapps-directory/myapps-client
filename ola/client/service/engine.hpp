#pragma once

#include <memory>
#include <string>

namespace ola {
namespace client {
namespace service {

struct Configuration {
    std::string front_endpoint_;
    bool        compress_;
    bool        secure_;

    Configuration()
        : compress_(true)
        , secure_(true)
    {
    }
};

class Engine {
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