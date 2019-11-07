#pragma once

#include "solid/frame/mprpc/mprpcprotocol_serialization_v2.hpp"

namespace ola {
namespace client {
namespace auth {

struct RegisterRequest : solid::frame::mprpc::Message {
    SOLID_PROTOCOL_V2(_s, _rthis, _rctx, _name)
    {
    }
};

struct RegisterResponse : solid::frame::mprpc::Message {
    int         error_ = -1;
    std::string user_;

    RegisterResponse() {}

    RegisterResponse(const RegisterRequest& _rreq)
        : Message(_rreq)
    {
    }

    SOLID_PROTOCOL_V2(_s, _rthis, _rctx, _name)
    {
        _s.add(_rthis.error_, _rctx, "error");
        _s.add(_rthis.user_, _rctx, "user");
    }
};

struct AuthRequest : solid::frame::mprpc::Message {
    std::string user_;
    std::string token_;

    AuthRequest() {}

    AuthRequest(const RegisterResponse& _rmsg)
        : Message(_rmsg)
    {
    }

    SOLID_PROTOCOL_V2(_s, _rthis, _rctx, _name)
    {
        _s.add(_rthis.user_, _rctx, "user");
        _s.add(_rthis.token_, _rctx, "token");
    }
};

struct AuthResponse : solid::frame::mprpc::Message {
    AuthResponse() {}
    AuthResponse(const AuthRequest& _req)
        : Message(_req)
    {
    }
    SOLID_PROTOCOL_V2(_s, _rthis, _rctx, _name)
    {
    }
};

using ProtocolT = solid::frame::mprpc::serialization_v2::Protocol<uint8_t>;

template <class R>
inline void protocol_setup(R _r, ProtocolT& _rproto)
{
    _rproto.null(static_cast<ProtocolT::TypeIdT>(0));

    _r(_rproto, solid::TypeToType<RegisterRequest>(), 1);
    _r(_rproto, solid::TypeToType<RegisterResponse>(), 2);
    _r(_rproto, solid::TypeToType<AuthRequest>(), 3);
    _r(_rproto, solid::TypeToType<AuthResponse>(), 4);
}

} //namespace auth
} //namespace client
} //namespace ola