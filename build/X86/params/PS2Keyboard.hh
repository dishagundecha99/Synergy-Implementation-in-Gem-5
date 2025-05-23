/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__PS2Keyboard__
#define __PARAMS__PS2Keyboard__

namespace gem5 {
namespace ps2 {
class PS2Keyboard;
} // namespace ps2
} // namespace gem5
#include <cstddef>
#include "params/VncInput.hh"

#include "params/PS2Device.hh"

namespace gem5
{
struct PS2KeyboardParams
    : public PS2DeviceParams
{
    gem5::ps2::PS2Keyboard * create() const;
    gem5::VncInput * vnc;
};

} // namespace gem5

#endif // __PARAMS__PS2Keyboard__
