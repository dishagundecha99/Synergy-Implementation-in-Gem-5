/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_CachePort_HH__
#define __DEBUG_CachePort_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union CachePort
{
    ~CachePort() {}
    SimpleFlag CachePort = {
        "CachePort", "", false
    };
} CachePort;
} // namespace unions

inline constexpr const auto& CachePort =
    ::gem5::debug::unions::CachePort.CachePort;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_CachePort_HH__
