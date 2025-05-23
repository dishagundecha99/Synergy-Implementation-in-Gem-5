/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__SouthBridge__
#define __PARAMS__SouthBridge__

namespace gem5 {
class SouthBridge;
} // namespace gem5
#include <cstddef>
#include "params/Cmos.hh"
#include <cstddef>
#include "params/I8237.hh"
#include <cstddef>
#include "params/I82094AA.hh"
#include <cstddef>
#include "params/I8042.hh"
#include <cstddef>
#include "params/I8259.hh"
#include <cstddef>
#include "params/I8259.hh"
#include <cstddef>
#include "params/I8254.hh"
#include <cstddef>
#include "params/PcSpeaker.hh"

#include "params/SimObject.hh"

namespace gem5
{
struct SouthBridgeParams
    : public SimObjectParams
{
    gem5::SouthBridge * create() const;
    gem5::X86ISA::Cmos * cmos;
    gem5::X86ISA::I8237 * dma1;
    gem5::X86ISA::I82094AA * io_apic;
    gem5::X86ISA::I8042 * keyboard;
    gem5::X86ISA::I8259 * pic1;
    gem5::X86ISA::I8259 * pic2;
    gem5::X86ISA::I8254 * pit;
    gem5::X86ISA::Speaker * speaker;
};

} // namespace gem5

#endif // __PARAMS__SouthBridge__
