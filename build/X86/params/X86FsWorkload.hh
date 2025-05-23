/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__X86FsWorkload__
#define __PARAMS__X86FsWorkload__

namespace gem5 {
namespace X86ISA {
class FsWorkload;
} // namespace X86ISA
} // namespace gem5
#include <cstddef>
#include "params/X86ACPIRSDP.hh"
#include <cstddef>
#include <cstddef>
#include "params/X86IntelMPFloatingPointer.hh"
#include <cstddef>
#include "params/X86IntelMPConfigTable.hh"
#include <cstddef>
#include "params/X86SMBiosSMBiosTable.hh"

#include "params/KernelWorkload.hh"

namespace gem5
{
struct X86FsWorkloadParams
    : public KernelWorkloadParams
{
    gem5::X86ISA::FsWorkload * create() const;
    gem5::X86ISA::ACPI::RSDP * acpi_description_table_pointer;
    bool enable_osxsave;
    gem5::X86ISA::intelmp::FloatingPointer * intel_mp_pointer;
    gem5::X86ISA::intelmp::ConfigTable * intel_mp_table;
    gem5::X86ISA::smbios::SMBiosTable * smbios_table;
};

} // namespace gem5

#endif // __PARAMS__X86FsWorkload__
