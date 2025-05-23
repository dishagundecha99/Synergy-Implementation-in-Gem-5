/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__X86ISA__
#define __PARAMS__X86ISA__

namespace gem5 {
namespace X86ISA {
class ISA;
} // namespace X86ISA
} // namespace gem5
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <vector>
#include "base/types.hh"
#include <cstddef>
#include <string>
#include <cstddef>
#include <string>

#include "params/BaseISA.hh"

namespace gem5
{
struct X86ISAParams
    : public BaseISAParams
{
    gem5::X86ISA::ISA * create() const;
    std::vector< uint32_t > APMInfo;
    std::vector< uint32_t > CacheParams;
    std::vector< uint32_t > ExtendedFeatures;
    std::vector< uint32_t > ExtendedState;
    std::vector< uint32_t > FamilyModelStepping;
    std::vector< uint32_t > FamilyModelSteppingBrandFeatures;
    std::vector< uint32_t > L1CacheAndTLB;
    std::vector< uint32_t > L2L3CacheAndL2TLB;
    std::vector< uint32_t > LongModeAddressSize;
    std::string name_string;
    std::string vendor_string;
};

} // namespace gem5

#endif // __PARAMS__X86ISA__
