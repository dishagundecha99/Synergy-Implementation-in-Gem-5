// DO NOT EDIT
// This file was automatically generated from an ISA description:
//   x86/isa/main.isa

#include "base/bitfield.hh"

#include <array>
#include <cstring>
#include <iostream>
#include <sstream>

#include "arch/generic/debugfaults.hh"
#include "arch/x86/emulenv.hh"
#include "arch/x86/insts/decode_fault.hh"
#include "arch/x86/insts/macroop.hh"
#include "arch/x86/insts/microdebug.hh"
#include "arch/x86/insts/microfpop.hh"
#include "arch/x86/insts/microldstop.hh"
#include "arch/x86/insts/micromediaop.hh"
#include "arch/x86/insts/microregop.hh"
#include "arch/x86/insts/microspecop.hh"
#include "arch/x86/insts/static_inst.hh"
#include "arch/x86/isa.hh"
#include "arch/x86/regs/ccr.hh"
#include "arch/x86/regs/int.hh"
#include "arch/x86/regs/misc.hh"
#include "arch/x86/types.hh"
#include "arch/x86/utility.hh"
#include "base/logging.hh"
#include "cpu/static_inst.hh"
#include "mem/packet.hh"
#include "sim/faults.hh"

namespace gem5::X86ISAInst
{
using namespace X86ISA;
} // namespace gem5::X86ISAInst
