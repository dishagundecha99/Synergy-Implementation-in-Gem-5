/**
 * DO NOT EDIT THIS FILE!
 * File automatically generated by
 *   build_tools/sim_object_param_struct_hh.py:234
 */

#ifndef __PARAMS__SignaturePathPrefetcherV2__
#define __PARAMS__SignaturePathPrefetcherV2__

namespace gem5 {
namespace prefetch {
class SignaturePathV2;
} // namespace prefetch
} // namespace gem5
#include <cstddef>
#include "base/types.hh"
#include <cstddef>
#include "params/BaseIndexingPolicy.hh"
#include <cstddef>
#include "params/BaseReplacementPolicy.hh"

#include "params/SignaturePathPrefetcher.hh"

namespace gem5
{
struct SignaturePathPrefetcherV2Params
    : public SignaturePathPrefetcherParams
{
    gem5::prefetch::SignaturePathV2 * create() const;
    uint64_t global_history_register_entries;
    gem5::BaseIndexingPolicy * global_history_register_indexing_policy;
    gem5::replacement_policy::Base * global_history_register_replacement_policy;
};

} // namespace gem5

#endif // __PARAMS__SignaturePathPrefetcherV2__
