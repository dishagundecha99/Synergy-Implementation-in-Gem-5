/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__NetworkBridge__
#define __PARAMS__NetworkBridge__

namespace gem5 {
namespace ruby {
namespace garnet {
class NetworkBridge;
} // namespace garnet
} // namespace ruby
} // namespace gem5
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "params/NetworkLink.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "enums/CDCType.hh"

#include "params/CreditLink.hh"

#include "enums/CDCType.hh"

namespace gem5
{
struct NetworkBridgeParams
    : public CreditLinkParams
{
    gem5::ruby::garnet::NetworkBridge * create() const;
    Cycles cdc_latency;
    gem5::ruby::garnet::NetworkLink * link;
    Cycles serdes_latency;
    enums::CDCType vtype;
};

} // namespace gem5

#endif // __PARAMS__NetworkBridge__
