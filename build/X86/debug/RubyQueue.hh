/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_RubyQueue_HH__
#define __DEBUG_RubyQueue_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union RubyQueue
{
    ~RubyQueue() {}
    SimpleFlag RubyQueue = {
        "RubyQueue", "", false
    };
} RubyQueue;
} // namespace unions

inline constexpr const auto& RubyQueue =
    ::gem5::debug::unions::RubyQueue.RubyQueue;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_RubyQueue_HH__
