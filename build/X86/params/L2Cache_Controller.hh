/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__L2Cache_Controller__
#define __PARAMS__L2Cache_Controller__

namespace gem5 {
namespace ruby {
class L2Cache_Controller;
} // namespace ruby
} // namespace gem5
#include <cstddef>
#include "params/MessageBuffer.hh"
#include <cstddef>
#include "params/MessageBuffer.hh"
#include <cstddef>
#include "params/MessageBuffer.hh"
#include <cstddef>
#include "params/RubyCache.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "params/MessageBuffer.hh"
#include <cstddef>
#include "params/MessageBuffer.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "params/MessageBuffer.hh"

#include "params/RubyController.hh"

namespace gem5
{
struct L2Cache_ControllerParams
    : public RubyControllerParams
{
    gem5::ruby::L2Cache_Controller * create() const;
    gem5::ruby::MessageBuffer * DirRequestFromL2Cache;
    gem5::ruby::MessageBuffer * L1RequestFromL2Cache;
    gem5::ruby::MessageBuffer * L1RequestToL2Cache;
    gem5::ruby::CacheMemory * L2cache;
    Cycles l2_request_latency;
    Cycles l2_response_latency;
    gem5::ruby::MessageBuffer * responseFromL2Cache;
    gem5::ruby::MessageBuffer * responseToL2Cache;
    Cycles to_l1_latency;
    gem5::ruby::MessageBuffer * unblockToL2Cache;
};

} // namespace gem5

#endif // __PARAMS__L2Cache_Controller__
