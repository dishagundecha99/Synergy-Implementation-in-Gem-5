/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/debugflaghh.py:139
 */

#ifndef __DEBUG_RubyCacheTrace_HH__
#define __DEBUG_RubyCacheTrace_HH__

#include "base/compiler.hh" // For namespace deprecation
#include "base/debug.hh"
namespace gem5
{

namespace debug
{

namespace unions
{
inline union RubyCacheTrace
{
    ~RubyCacheTrace() {}
    SimpleFlag RubyCacheTrace = {
        "RubyCacheTrace", "", false
    };
} RubyCacheTrace;
} // namespace unions

inline constexpr const auto& RubyCacheTrace =
    ::gem5::debug::unions::RubyCacheTrace.RubyCacheTrace;

} // namespace debug
} // namespace gem5

#endif // __DEBUG_RubyCacheTrace_HH__
