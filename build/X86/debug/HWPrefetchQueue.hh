/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_HWPrefetchQueue_HH__
#define __DEBUG_HWPrefetchQueue_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union HWPrefetchQueue
{
    ~HWPrefetchQueue() {}
    SimpleFlag HWPrefetchQueue = {
        "HWPrefetchQueue", "", false
    };
} HWPrefetchQueue;
} // namespace unions

inline constexpr const auto& HWPrefetchQueue =
    ::gem5::debug::unions::HWPrefetchQueue.HWPrefetchQueue;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_HWPrefetchQueue_HH__
