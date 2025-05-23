/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__TaggedPrefetcher__
#define __PARAMS__TaggedPrefetcher__

namespace gem5 {
namespace prefetch {
class Tagged;
} // namespace prefetch
} // namespace gem5
#include <cstddef>
#include "base/types.hh"

#include "params/QueuedPrefetcher.hh"

namespace gem5
{
struct TaggedPrefetcherParams
    : public QueuedPrefetcherParams
{
    gem5::prefetch::Tagged * create() const;
    int degree;
};

} // namespace gem5

#endif // __PARAMS__TaggedPrefetcher__
