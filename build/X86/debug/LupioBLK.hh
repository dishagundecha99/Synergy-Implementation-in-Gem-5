/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_LupioBLK_HH__
#define __DEBUG_LupioBLK_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union LupioBLK
{
    ~LupioBLK() {}
    SimpleFlag LupioBLK = {
        "LupioBLK", "", false
    };
} LupioBLK;
} // namespace unions

inline constexpr const auto& LupioBLK =
    ::gem5::debug::unions::LupioBLK.LupioBLK;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_LupioBLK_HH__
