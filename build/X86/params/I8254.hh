/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__I8254__
#define __PARAMS__I8254__

namespace gem5 {
namespace X86ISA {
class I8254;
} // namespace X86ISA
} // namespace gem5

#include "params/BasicPioDevice.hh"

namespace gem5
{
struct I8254Params
    : public BasicPioDeviceParams
{
    gem5::X86ISA::I8254 * create() const;
    unsigned int port_int_pin_connection_count;
};

} // namespace gem5

#endif // __PARAMS__I8254__
