#pragma once

#include <ostream>
#include <solid/system/error.hpp>
#include <solid/system/pimpl.hpp>
#include <string>

namespace myapps {
namespace client {
namespace service {

class ShortcutCreator {
public:
    ShortcutCreator(const std::string& _temp_folder);
    ~ShortcutCreator();

    size_t create(
        std::ostream&      _ros,
        const std::string& _command,
        const std::string& _arguments,
        const std::string& _run_folder,
        const std::string& _icon,
        const std::string& _description);

private:
    struct Implementation;
    solid::PimplT<Implementation> pimpl_;
};

} //namespace service
} //namespace client
} //namespace myapps