/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_DRAMPower_HH__
#define __DEBUG_DRAMPower_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union DRAMPower
{
    ~DRAMPower() {}
    SimpleFlag DRAMPower = {
        "DRAMPower", "", false
    };
} DRAMPower;
} // namespace unions

inline constexpr const auto& DRAMPower =
    ::gem5::debug::unions::DRAMPower.DRAMPower;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_DRAMPower_HH__
