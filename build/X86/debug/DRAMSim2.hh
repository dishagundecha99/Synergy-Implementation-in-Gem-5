/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_DRAMSim2_HH__
#define __DEBUG_DRAMSim2_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union DRAMSim2
{
    ~DRAMSim2() {}
    SimpleFlag DRAMSim2 = {
        "DRAMSim2", "", false
    };
} DRAMSim2;
} // namespace unions

inline constexpr const auto& DRAMSim2 =
    ::gem5::debug::unions::DRAMSim2.DRAMSim2;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_DRAMSim2_HH__
