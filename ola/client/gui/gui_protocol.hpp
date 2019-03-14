#pragma once

#include "solid/frame/mprpc/mprpcprotocol_serialization_v2.hpp"

namespace ola{
namespace client{
namespace gui{

struct AuthMessage : solid::frame::mprpc::Message {
    std::string auth_;

    AuthMessage() {}

    AuthMessage(
        const std::string& _auth)
        : auth_(_auth)
    {
    }

    SOLID_PROTOCOL_V2(_s, _rthis, _rctx, _name)
    {
        _s.add(_rthis.auth_, _rctx, "auth");
    }
};

using ProtocolT = solid::frame::mprpc::serialization_v2::Protocol<uint8_t>;

template <class R>
inline void protocol_setup(R _r, ProtocolT& _rproto)
{
    _rproto.null(static_cast<ProtocolT::TypeIdT>(0));

    _r(_rproto, solid::TypeToType<AuthMessage>(), 1);
}

}//namespace gui
}//namespace client
}//namespace ola