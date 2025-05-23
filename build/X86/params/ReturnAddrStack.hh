/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__ReturnAddrStack__
#define __PARAMS__ReturnAddrStack__

namespace gem5 {
namespace branch_prediction {
class ReturnAddrStack;
} // namespace branch_prediction
} // namespace gem5
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "base/types.hh"

#include "params/SimObject.hh"

namespace gem5
{
struct ReturnAddrStackParams
    : public SimObjectParams
{
    gem5::branch_prediction::ReturnAddrStack * create() const;
    unsigned numEntries;
    unsigned numThreads;
};

} // namespace gem5

#endif // __PARAMS__ReturnAddrStack__
