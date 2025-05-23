/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__CoherentXBar__
#define __PARAMS__CoherentXBar__

namespace gem5 {
class CoherentXBar;
} // namespace gem5
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include <cstddef>
#include <cstddef>
#include "params/SnoopFilter.hh"
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "params/System.hh"

#include "params/BaseXBar.hh"

namespace gem5
{
struct CoherentXBarParams
    : public BaseXBarParams
{
    gem5::CoherentXBar * create() const;
    int max_outstanding_snoops;
    int max_routing_table_size;
    bool point_of_coherency;
    bool point_of_unification;
    gem5::SnoopFilter * snoop_filter;
    Cycles snoop_response_latency;
    gem5::System * system;
};

} // namespace gem5

#endif // __PARAMS__CoherentXBar__
