// myapps/client/service/engine.hpp

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

#include "boost/filesystem.hpp"
#include <functional>
#include <memory>
#include <string>

#include "myapps/common/front_protocol_main.hpp"

namespace myapps {
namespace client {
namespace service {

namespace fs = boost::filesystem;

enum struct NodeFlagsE : uint32_t {
    Directory = 0,
    File,
    Hidden,
    PendingDelete,
};

using NodeFlagsT = std::underlying_type<NodeFlagsE>::type;

inline NodeFlagsT node_flag(const NodeFlagsE _flag)
{
    return 1 << static_cast<NodeFlagsT>(_flag);
}

struct GuiProtocolSetup;
struct Descriptor;

struct Configuration {
    using FolderUpdateFunctionT    = std::function<void(const std::string&)>;
    using InvalidateCacheFunctionT = std::function<void(const std::string&)>;
    using AuthOnResponseFunctionT  = std::function<void(uint32_t, const std::string&)>;
    using AuthGetTokenFunctionT    = std::function<std::string()>;
    using AuthGetTokenFunctionT    = std::function<std::string()>;

    bool                     compress_ = true;
    bool                     secure_   = true;
    std::string              path_prefix_;
    std::string              temp_folder_;
    std::string              mount_prefix_;
    std::string              secure_prefix_;
    std::string              app_list_path_;
    FolderUpdateFunctionT    folder_update_fnc_;
    InvalidateCacheFunctionT invalidate_cache_fnc_;
    AuthOnResponseFunctionT  auth_on_response_fnc_;
    AuthGetTokenFunctionT    auth_get_token_fnc_;
    size_t                   mutex_count_ = 1;
    size_t                   cv_count_    = 1;
    std::string              os_;
    std::string              language_;
    std::string              auth_endpoint_;
    uint64_t                 max_stream_size_           = 100 * 1024;
    size_t                   min_contiguous_read_count_ = 3;
    size_t                   media_cache_size_          = 2;
    size_t                   update_poll_seconds_       = 5;

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

    bool info(const fs::path& _path, NodeFlagsT& _rnode_type, uint64_t& _rsize, int64_t& _rbase_time);

    void info(Descriptor* _pdesc, NodeFlagsT& _rnode_type, uint64_t& _rsize, int64_t& _rbase_time);

    bool list(Descriptor* _pdesc, void*& _rpctx, std::wstring& _rname, NodeFlagsT& _rentry_type, uint64_t& _rsize, int64_t& _rbase_time);

    bool read(Descriptor* _pdesc, void* _pbuf, uint64_t _offset, unsigned long _length, unsigned long& _rbytes_transfered);

    void post(std::function<void(Engine&)>&&);
};

} // namespace service
} // namespace client
} // namespace myapps