/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__RandomRP__
#define __PARAMS__RandomRP__

namespace gem5 {
namespace replacement_policy {
class Random;
} // namespace replacement_policy
} // namespace gem5

#include "params/BaseReplacementPolicy.hh"

namespace gem5
{
struct RandomRPParams
    : public BaseReplacementPolicyParams
{
    gem5::replacement_policy::Random * create() const;
};

} // namespace gem5

#endif // __PARAMS__RandomRP__
