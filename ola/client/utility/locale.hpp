#pragma once

#include <locale>
#include <string>
#include <codecvt>

namespace ola {
namespace client {
namespace utility {

inline std::string narrow(const std::wstring& wstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> convert;
    return convert.to_bytes(wstr);
}

inline std::wstring widen(const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> convert;
    return convert.from_bytes(str);
}

} //namespace utility
} //namespace client
} //namespace ola