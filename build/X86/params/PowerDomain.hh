/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__PowerDomain__
#define __PARAMS__PowerDomain__

namespace gem5 {
class PowerDomain;
} // namespace gem5

#include "params/PowerState.hh"

namespace gem5
{
struct PowerDomainParams
    : public PowerStateParams
{
    gem5::PowerDomain * create() const;
};

} // namespace gem5

#endif // __PARAMS__PowerDomain__
