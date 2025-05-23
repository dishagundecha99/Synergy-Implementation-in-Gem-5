/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_GDBRecv_HH__
#define __DEBUG_GDBRecv_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union GDBRecv
{
    ~GDBRecv() {}
    SimpleFlag GDBRecv = {
        "GDBRecv", "Messages received from the remote application", false
    };
} GDBRecv;
} // namespace unions

inline constexpr const auto& GDBRecv =
    ::gem5::debug::unions::GDBRecv.GDBRecv;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_GDBRecv_HH__
