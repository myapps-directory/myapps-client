// myapps/client/service/shorcut_creator.hpp

// This file is part of MyApps.directory project
// Copyright (C) 2020, 2021, 2022, 2023, 2024, 2025 Valentin Palade (vipalade @ gmail . com)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// at your option any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

} // namespace service
} // namespace client
} // namespace myapps